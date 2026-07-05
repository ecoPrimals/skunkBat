// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Security-domain dispatch handlers.
//!
//! Handles `security.*`, `threat.report`, `baseline.observe`, and the
//! Tower HTTP Gateway `security.advisory` method.

use skunk_bat_core::SkunkBat;
use skunk_bat_core::observability::audit_log::{EventKind, EventSeverity, EventSource};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::dispatch::{serialize, try_serialize};
use super::jsonrpc::{self, Response};

/// Parse a required `Threat` payload from JSON-RPC params.
///
/// Shared by `security.respond` and `response.evaluate` to avoid
/// duplicated deserialization boilerplate.
#[expect(
    clippy::result_large_err,
    reason = "Response is the standard JSON-RPC error type"
)]
pub(super) fn parse_threat_params(
    id: &serde_json::Value,
    params: Option<serde_json::Value>,
) -> Result<skunk_bat_core::threats::Threat, Response> {
    let Some(params) = params else {
        return Err(Response::error(
            id.clone(),
            jsonrpc::INVALID_PARAMS,
            "params required",
        ));
    };

    serde_json::from_value(params).map_err(|e| {
        Response::error(
            id.clone(),
            jsonrpc::INVALID_PARAMS,
            format!("invalid threat: {e}"),
        )
    })
}

/// Security domain: `security.scan`, `security.detect`, `security.metrics`, `security.audit_log`.
pub(super) async fn dispatch_security(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
    method: &str,
    params: Option<serde_json::Value>,
) -> Response {
    match method {
        "security.scan" => try_serialize(id, state.read().await.scan_network().await),
        "security.detect" => {
            let sb = state.read().await;
            let result = sb.detect_threats().await;
            if let Ok(ref threats) = result {
                for t in threats {
                    sb.audit_log()
                        .record(
                            EventSource::ThreatDetection,
                            EventSeverity::Warn,
                            EventKind::ThreatDetected {
                                threat_id: t.id.clone(),
                                threat_type: format!("{:?}", t.threat_type),
                                severity: format!("{:?}", t.severity),
                                source: t.source.clone(),
                            },
                        )
                        .await;
                }
            }
            drop(sb);
            try_serialize(id, result)
        }
        "security.metrics" => serialize(id, state.read().await.get_security_metrics()),
        "security.audit_log" => dispatch_audit_log(state, id, params).await,
        _ => unreachable!(),
    }
}

/// Handle `security.respond` — requires params with a threat payload.
pub(super) async fn dispatch_respond(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let threat = match parse_threat_params(&id, params) {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    let sb = state.read().await;
    match sb.respond_to_threat(&threat) {
        Ok(action) => {
            let severity = match action {
                skunk_bat_core::defense::ActionType::Block
                | skunk_bat_core::defense::ActionType::Quarantine
                | skunk_bat_core::defense::ActionType::QuarantineAndAlert
                | skunk_bat_core::defense::ActionType::MonitorAndAlert => EventSeverity::Warn,
            };
            sb.audit_log()
                .record(
                    EventSource::DefenseEngine,
                    severity,
                    EventKind::DefenseAction {
                        threat_id: threat.id.clone(),
                        action: format!("{action:?}"),
                    },
                )
                .await;
            drop(sb);
            Response::success(
                id,
                serde_json::json!({"status": "ok", "action": format!("{action:?}")}),
            )
        }
        Err(e) => {
            drop(sb);
            Response::error(id, jsonrpc::INTERNAL_ERROR, e.to_string())
        }
    }
}

/// Handle `security.advisory` — advisory check for Tower HTTP Gateway.
///
/// Accepts `{"source": "<ip>"}`. Returns an `AdvisoryVerdict` with verdict,
/// reason, and any associated threat IDs. The gateway uses this to decide
/// whether to route, warn-log, or reject an inbound request.
pub(super) async fn dispatch_advisory(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let source = params
        .as_ref()
        .and_then(|p| p.get("source"))
        .and_then(|v| v.as_str());

    let Some(source) = source else {
        return Response::error(
            id,
            jsonrpc::INVALID_PARAMS,
            "missing required field: source",
        );
    };

    let sb = state.read().await;
    let verdict = sb.advisory_check(source);
    drop(sb);

    Response::success(id, serde_json::to_value(&verdict).unwrap_or_default())
}

/// Handle `baseline.observe` — feed a live observation into the threat profiler.
///
/// Accepts an `Observation` JSON payload. Returns `{"status":"ok"}` on success.
pub(super) async fn dispatch_baseline_observe(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let Some(params) = params else {
        return Response::error(id, jsonrpc::INVALID_PARAMS, "params required");
    };

    let observation: skunk_bat_core::threats::types::Observation =
        match serde_json::from_value(params) {
            Ok(o) => o,
            Err(e) => {
                return Response::error(
                    id,
                    jsonrpc::INVALID_PARAMS,
                    format!("invalid observation: {e}"),
                );
            }
        };

    let sb = state.read().await;
    let result = sb.observe(&observation).await;
    let rate = observation.connection_rate;
    match result {
        Ok(()) => {
            sb.audit_log()
                .record(
                    EventSource::ThreatDetection,
                    EventSeverity::Info,
                    EventKind::BaselineObservation {
                        connection_rate: rate,
                    },
                )
                .await;
            drop(sb);
            Response::success(id, serde_json::json!({"status": "ok"}))
        }
        Err(e) => {
            drop(sb);
            Response::error(id, jsonrpc::INTERNAL_ERROR, e.to_string())
        }
    }
}

/// Structured threat report — detection results + defense posture in one call.
pub(super) async fn dispatch_threat_report(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
) -> Response {
    let sb = state.read().await;
    let threats_result = sb.detect_threats().await;
    let metrics = sb.get_security_metrics();
    let defense = sb.defense_status();
    drop(sb);

    match threats_result {
        Ok(threats) => {
            let threat_count = threats.len();
            let threat_summaries: Vec<serde_json::Value> = threats
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "id": t.id,
                        "type": format!("{:?}", t.threat_type),
                        "severity": format!("{:?}", t.severity),
                        "source": t.source,
                        "confidence": t.confidence,
                        "description": t.description,
                    })
                })
                .collect();
            Response::success(
                id,
                serde_json::json!({
                    "threat_count": threat_count,
                    "threats": threat_summaries,
                    "metrics": metrics,
                    "defense": defense,
                }),
            )
        }
        Err(e) => Response::error(id, -32000, format!("threat detection failed: {e}")),
    }
}

/// Handle `security.audit_log` — query the audit event trail.
///
/// Params (all optional):
/// - `since_seq`: sequence cursor (default 0, returns events after this seq)
/// - `limit`: max events to return (default 100, max 1000)
pub(super) async fn dispatch_audit_log(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let since_seq = params
        .as_ref()
        .and_then(|p| p.get("since_seq"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    let limit = params
        .as_ref()
        .and_then(|p| p.get("limit"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(100)
        .min(1000) as usize;

    let sb = state.read().await;
    let events = sb.audit_log().query(since_seq, limit).await;
    let latest_seq = sb.audit_log().latest_seq().await;
    drop(sb);

    serialize(
        id,
        serde_json::json!({
            "events": events,
            "latest_seq": latest_seq,
            "count": events.len()
        }),
    )
}

/// Expose `parse_threat_params` for `dispatch_composable.rs` (`response.evaluate`).
pub(super) use self::parse_threat_params as parse_threat;

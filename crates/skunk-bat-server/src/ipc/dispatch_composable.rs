// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Composable primitive dispatch handlers.
//!
//! These implement the composable IPC methods from `COMPOSABLE_PRIMITIVES_SPEC.md`:
//! - `defense.quarantine` / `defense.release`
//! - `response.evaluate`
//! - `baseline.query` / `baseline.anomaly` / `baseline.reset`

use skunk_bat_core::SkunkBat;
use skunk_bat_core::observability::audit_log::{EventKind, EventSeverity, EventSource};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::jsonrpc::{self, Response};

/// Handle `defense.quarantine` — manually quarantine a source address.
///
/// Params: `{ source: string, reason: string, threat_id: string }`
pub(super) async fn dispatch_defense_quarantine(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let Some(params) = params else {
        return Response::error(id, jsonrpc::INVALID_PARAMS, "params required");
    };

    let source = match params.get("source").and_then(serde_json::Value::as_str) {
        Some(s) if !s.is_empty() => s,
        _ => {
            return Response::error(id, jsonrpc::INVALID_PARAMS, "source (string) required");
        }
    };
    let reason = params
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("manual quarantine");
    let threat_id = params
        .get("threat_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("manual");

    let sb = state.read().await;
    sb.quarantine(source, reason, threat_id);
    sb.audit_log()
        .record(
            EventSource::DefenseEngine,
            EventSeverity::Warn,
            EventKind::DefenseAction {
                threat_id: threat_id.to_owned(),
                action: format!("Quarantine({source})"),
            },
        )
        .await;
    drop(sb);

    Response::success(
        id,
        serde_json::json!({"status": "quarantined", "source": source}),
    )
}

/// Handle `defense.release` — release a source from quarantine.
///
/// Params: `{ source: string }`
pub(super) async fn dispatch_defense_release(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let Some(params) = params else {
        return Response::error(id, jsonrpc::INVALID_PARAMS, "params required");
    };

    let source = match params.get("source").and_then(serde_json::Value::as_str) {
        Some(s) if !s.is_empty() => s,
        _ => {
            return Response::error(id, jsonrpc::INVALID_PARAMS, "source (string) required");
        }
    };

    let sb = state.read().await;
    let released = sb.release_quarantine(source);
    if released {
        sb.audit_log()
            .record(
                EventSource::DefenseEngine,
                EventSeverity::Info,
                EventKind::DefenseAction {
                    threat_id: "release".to_owned(),
                    action: format!("Release({source})"),
                },
            )
            .await;
    }
    drop(sb);

    Response::success(
        id,
        serde_json::json!({"released": released, "source": source}),
    )
}

/// Handle `response.evaluate` — evaluate a threat without executing the response.
///
/// Returns the recommended action type, target, approval requirement, and reason.
pub(super) async fn dispatch_response_evaluate(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let Some(params) = params else {
        return Response::error(id, jsonrpc::INVALID_PARAMS, "params required");
    };

    let threat: skunk_bat_core::threats::Threat = match serde_json::from_value(params) {
        Ok(t) => t,
        Err(e) => {
            return Response::error(id, jsonrpc::INVALID_PARAMS, format!("invalid threat: {e}"));
        }
    };

    let sb = state.read().await;
    let action = sb.evaluate_threat(&threat);
    drop(sb);

    Response::success(
        id,
        serde_json::json!({
            "action_type": format!("{:?}", action.action_type),
            "target": action.target,
            "requires_approval": action.requires_approval,
            "reason": action.reason,
        }),
    )
}

/// Handle `baseline.query` — query the baseline profiler's current statistics.
pub(super) async fn dispatch_baseline_query(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
) -> Response {
    let sb = state.read().await;
    let baseline = sb.baseline_stats().await;
    drop(sb);

    match baseline {
        Some(s) => match serde_json::to_value(&s) {
            Ok(v) => Response::success(id, v),
            Err(e) => Response::error(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
        },
        None => Response::success(
            id,
            serde_json::json!({"established": false, "message": "baseline not yet established (< 10 observations)"}),
        ),
    }
}

/// Handle `baseline.anomaly` — check an observation for anomalies without feeding it.
///
/// Params: `Observation { connection_rate, traffic_volume, ports_accessed, timestamp }`
pub(super) async fn dispatch_baseline_anomaly(
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
    let result = sb.check_anomalies(&observation).await;
    drop(sb);

    match result {
        Ok(anomalies) => match serde_json::to_value(&anomalies) {
            Ok(v) => Response::success(
                id,
                serde_json::json!({"anomaly_count": anomalies.len(), "anomalies": v}),
            ),
            Err(e) => Response::error(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
        },
        Err(e) => Response::error(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

/// Handle `baseline.reset` — reset the baseline profiler.
///
/// Params (optional): `{ reseed: bool }` (default: true)
pub(super) async fn dispatch_baseline_reset(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let reseed = params
        .as_ref()
        .and_then(|p| p.get("reseed"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);

    let sb = state.read().await;
    sb.reset_baseline(reseed).await;
    sb.audit_log()
        .record(
            EventSource::ThreatDetection,
            EventSeverity::Info,
            EventKind::BaselineObservation {
                connection_rate: 0.0,
            },
        )
        .await;
    drop(sb);

    Response::success(
        id,
        serde_json::json!({"status": "reset", "reseeded": reseed}),
    )
}

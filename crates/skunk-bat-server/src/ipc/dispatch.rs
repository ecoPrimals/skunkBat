// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Method dispatch — routes `domain.verb` methods to handlers.
//!
//! Implements Capability Wire Standard L2 (`capabilities.list`, `identity.get`)
//! and Primal IPC Protocol v3.1 semantic method naming.

use serde::Serialize;
use skunk_bat_core::PrimalHealth;
use skunk_bat_core::SkunkBat;
use skunk_bat_core::observability::audit_log::{EventKind, EventSeverity, EventSource};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::jsonrpc::{self, Request, Response};
use super::method_gate::{CallerContext, EnforcementMode, MethodGate, PERMISSION_DENIED};

/// Application-layer methods routed through `dispatch()`.
const METHODS: &[&str] = &[
    "health.liveness",
    "health.readiness",
    "health.check",
    "security.scan",
    "security.detect",
    "security.respond",
    "security.metrics",
    "security.audit_log",
    "baseline.observe",
    "defense.status",
    "lifecycle.state",
    "lifecycle.status",
    "lifecycle.capabilities",
    "capabilities.list",
    "identity.get",
    "auth.check",
    "auth.mode",
    "auth.peer_info",
];

/// Transport-layer methods handled by the connection handler before dispatch.
/// Listed here for `capabilities.list` completeness only — not routed by `dispatch()`.
const TRANSPORT_METHODS: &[&str] = &["btsp.negotiate", "btsp.capabilities"];

const PRIMAL_VERSION: &str = env!("CARGO_PKG_VERSION");
const PRIMAL_DOMAIN: &str = "security";
const PRIMAL_LICENSE: &str = "AGPL-3.0-or-later";

/// IPC methods this primal calls on other primals (runtime-discovered).
const CONSUMED_CAPABILITIES: &[&str] = &[
    "btsp.server.verify",
    "lineage.verify",
    "lineage.list",
    "capabilities.list",
    "federation.broadcast",
    "discovery.find_by_capability",
];

/// Serialize a fallible operation result into a JSON-RPC response.
fn try_serialize<T: Serialize, E: std::fmt::Display>(
    id: serde_json::Value,
    result: Result<T, E>,
) -> Response {
    match result {
        Ok(val) => serialize(id, val),
        Err(e) => Response::error(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

/// Serialize an infallible value into a JSON-RPC response.
fn serialize<T: Serialize>(id: serde_json::Value, value: T) -> Response {
    match serde_json::to_value(value) {
        Ok(v) => Response::success(id, v),
        Err(e) => Response::error(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

/// Build the Capability Wire Standard L2/L3 response body.
fn capabilities_response() -> serde_json::Value {
    let all: Vec<&str> = METHODS.iter().chain(TRANSPORT_METHODS).copied().collect();
    let count = all.len();
    serde_json::json!({
        "primal": skunk_bat_core::PRIMAL_ID,
        "version": PRIMAL_VERSION,
        "capabilities": all,
        "count": count,
        "methods": METHODS.iter().chain(TRANSPORT_METHODS).copied().collect::<Vec<&str>>(),
        "provided_capabilities": [
            {
                "type": "security",
                "methods": ["scan", "detect", "respond", "metrics", "audit_log"],
                "version": PRIMAL_VERSION,
                "description": "Network reconnaissance, threat detection, and automated defense"
            },
            {
                "type": "health",
                "methods": ["liveness", "readiness", "check"],
                "version": PRIMAL_VERSION,
                "description": "Health monitoring endpoints"
            },
            {
                "type": "btsp",
                "methods": ["negotiate", "capabilities"],
                "version": PRIMAL_VERSION,
                "description": "BTSP Phase 3 transport encryption"
            }
        ],
        "consumed_capabilities": CONSUMED_CAPABILITIES,
        "protocol": "jsonrpc-2.0",
        "transport": ["uds", "tcp"]
    })
}

/// Dispatch a JSON-RPC request to the appropriate handler.
///
/// The [`MethodGate`] performs pre-dispatch authorization. In permissive mode
/// (default), all calls are allowed with a tracing warning for unauthenticated
/// access to protected methods. In enforced mode, unauthenticated calls to
/// protected methods are rejected with `-32001 PERMISSION_DENIED`.
pub(super) async fn dispatch(
    state: &Arc<RwLock<SkunkBat>>,
    gate: &MethodGate,
    caller: &CallerContext,
    request: Request,
) -> Response {
    if let Err(resp) = request.validate() {
        return resp;
    }

    let id = request.id_or_null();
    let caller = caller.with_request_token(request.params.as_ref());

    if let Err(resp) = enforce_gate(state, gate, &caller, &request, &id).await {
        return resp;
    }

    match request.method.as_str() {
        "health.liveness" | "health.readiness" | "health.check" => {
            dispatch_health(state, id, &request.method).await
        }
        "security.scan" | "security.detect" | "security.metrics" | "security.audit_log" => {
            dispatch_security(state, id, &request.method, request.params).await
        }
        "security.respond" => dispatch_respond(state, id, request.params).await,
        "baseline.observe" => dispatch_baseline_observe(state, id, request.params).await,
        "defense.status" => {
            let sb = state.read().await;
            let status = sb.defense_status();
            drop(sb);
            Response::success(id, status)
        }
        "lifecycle.state" | "lifecycle.status" | "lifecycle.capabilities" => {
            dispatch_lifecycle(state, id, &request.method).await
        }
        "capabilities.list" | "capability.list" => Response::success(id, capabilities_response()),
        "identity.get" => dispatch_identity(id),
        "auth.check" | "auth.mode" | "auth.peer_info" => {
            dispatch_auth(id, gate, &caller, &request.method)
        }
        "btsp.capabilities" => dispatch_btsp_capabilities(id),
        _ => Response::error(
            id,
            jsonrpc::METHOD_NOT_FOUND,
            format!("unknown method: {}", request.method),
        ),
    }
}

/// Run method-gate authorization and audit any gate events.
///
/// Checks quarantine status before method-gate authorization:
/// quarantined sources are rejected with `PERMISSION_DENIED` regardless
/// of method or token. Health probes are exempt so monitoring stays alive.
async fn enforce_gate(
    state: &Arc<RwLock<SkunkBat>>,
    gate: &MethodGate,
    caller: &CallerContext,
    request: &Request,
    id: &serde_json::Value,
) -> Result<(), Response> {
    if let Some(ref addr) = caller.source_addr {
        let host = addr.rsplit_once(':').map_or(addr.as_str(), |(h, _)| h);
        let is_health = request.method.starts_with("health.") || request.method == "health";
        if !is_health && state.read().await.is_quarantined(host) {
            tracing::warn!(
                method = request.method,
                source = addr,
                "Rejecting request from quarantined source"
            );
            state
                .read()
                .await
                .audit_log()
                .record(
                    EventSource::MethodGate,
                    EventSeverity::Warn,
                    EventKind::GateRejection {
                        method: request.method.clone(),
                        origin: format!("quarantined:{addr}"),
                    },
                )
                .await;
            return Err(Response::error(
                id.clone(),
                PERMISSION_DENIED,
                format!("source '{addr}' is quarantined"),
            ));
        }
    }

    if let Err(resp) = gate.check(&request.method, id, caller) {
        state
            .read()
            .await
            .audit_log()
            .record(
                EventSource::MethodGate,
                EventSeverity::Warn,
                EventKind::GateRejection {
                    method: request.method.clone(),
                    origin: format!("{:?}", caller.origin),
                },
            )
            .await;
        return Err(resp);
    }

    if gate.mode() == EnforcementMode::Permissive
        && caller.bearer_token.is_none()
        && super::method_gate::classify_method(&request.method)
            == super::method_gate::MethodAccessLevel::Protected
    {
        state
            .read()
            .await
            .audit_log()
            .record(
                EventSource::MethodGate,
                EventSeverity::Info,
                EventKind::GatePermissiveAllow {
                    method: request.method.clone(),
                    origin: format!("{:?}", caller.origin),
                },
            )
            .await;
    }
    Ok(())
}

/// Health domain: `health.liveness`, `health.readiness`, `health.check`.
async fn dispatch_health(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
    method: &str,
) -> Response {
    match method {
        "health.liveness" => Response::success(id, serde_json::json!({"status": "alive"})),
        "health.readiness" => {
            let (ready, state_str) = {
                let sb = state.read().await;
                (sb.state().is_running(), sb.state().to_string())
            };
            Response::success(id, serde_json::json!({"ready": ready, "state": state_str}))
        }
        "health.check" => try_serialize(id, state.read().await.health_check().await),
        _ => unreachable!(),
    }
}

/// Security domain: `security.scan`, `security.detect`, `security.metrics`, `security.audit_log`.
async fn dispatch_security(
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

/// Lifecycle domain: `lifecycle.state`, `lifecycle.status`, `lifecycle.capabilities`.
async fn dispatch_lifecycle(
    state: &Arc<RwLock<SkunkBat>>,
    id: serde_json::Value,
    method: &str,
) -> Response {
    match method {
        "lifecycle.state" => {
            let state_str = state.read().await.state().to_string();
            Response::success(id, serde_json::json!({"state": state_str}))
        }
        "lifecycle.status" => {
            let status = state.read().await.state().to_string();
            Response::success(
                id,
                serde_json::json!({
                    "primal": skunk_bat_core::PRIMAL_ID,
                    "version": PRIMAL_VERSION,
                    "status": status
                }),
            )
        }
        "lifecycle.capabilities" => {
            let all: Vec<&str> = METHODS.iter().chain(TRANSPORT_METHODS).copied().collect();
            Response::success(id, serde_json::json!({"capabilities": all}))
        }
        _ => unreachable!(),
    }
}

/// Identity: `identity.get` — Wire Standard L2.
fn dispatch_identity(id: serde_json::Value) -> Response {
    Response::success(
        id,
        serde_json::json!({
            "primal": skunk_bat_core::PRIMAL_ID,
            "version": PRIMAL_VERSION,
            "domain": PRIMAL_DOMAIN,
            "license": PRIMAL_LICENSE,
            "protocol": "jsonrpc-2.0",
            "transport": ["uds", "tcp"]
        }),
    )
}

/// Auth domain: `auth.check`, `auth.mode`, `auth.peer_info`.
fn dispatch_auth(
    id: serde_json::Value,
    gate: &MethodGate,
    caller: &CallerContext,
    method: &str,
) -> Response {
    match method {
        "auth.check" => Response::success(
            id,
            serde_json::json!({
                "authenticated": caller.bearer_token.is_some(),
                "mode": gate.mode().as_str()
            }),
        ),
        "auth.mode" => Response::success(id, serde_json::json!({ "mode": gate.mode().as_str() })),
        "auth.peer_info" => Response::success(
            id,
            serde_json::json!({
                "origin": format!("{:?}", caller.origin),
                "has_token": caller.bearer_token.is_some()
            }),
        ),
        _ => unreachable!(),
    }
}

/// BTSP transport capabilities.
fn dispatch_btsp_capabilities(id: serde_json::Value) -> Response {
    Response::success(
        id,
        serde_json::json!({
            "protocol": "btsp-v1",
            "phase": 3,
            "ciphers": ["chacha20-poly1305", "null"],
            "preferred": "chacha20-poly1305",
            "key_derivation": "hkdf-sha256",
            "handshake": "btsp.negotiate"
        }),
    )
}

/// Handle `security.respond` — requires params with a threat payload.
async fn dispatch_respond(
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

/// Handle `baseline.observe` — feed a live observation into the threat profiler.
///
/// Accepts an `Observation` JSON payload. Returns `{"status":"ok"}` on success.
async fn dispatch_baseline_observe(
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

/// Handle `security.audit_log` — query the audit event trail.
///
/// Params (all optional):
/// - `since_seq`: sequence cursor (default 0, returns events after this seq)
/// - `limit`: max events to return (default 100, max 1000)
async fn dispatch_audit_log(
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

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod tests;

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
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;

static ACTIVE_TRANSPORTS: OnceLock<&'static [&'static str]> = OnceLock::new();

/// Initialize the runtime transport metadata from CLI flags.
///
/// Called once at server startup. Subsequent calls are no-ops.
pub(super) fn set_active_transports(no_tcp: bool, no_uds: bool) {
    let transports: &'static [&'static str] = match (no_tcp, no_uds) {
        (false, false) => &["uds", "tcp"],
        (true, false) => &["uds"],
        (false, true) => &["tcp"],
        (true, true) => &[],
    };
    ACTIVE_TRANSPORTS.get_or_init(|| transports);
}

fn active_transports() -> &'static [&'static str] {
    ACTIVE_TRANSPORTS.get().copied().unwrap_or(&["uds", "tcp"])
}

use super::jsonrpc::{self, Request, Response};
use super::method_gate::{CallerContext, EnforcementMode, MethodGate};

/// Application-layer methods routed through `dispatch()`.
const METHODS: &[&str] = &[
    "health.liveness",
    "health.readiness",
    "health.check",
    "defense.status",
    "security.scan",
    "security.detect",
    "security.respond",
    "security.metrics",
    "security.audit_log",
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
    serde_json::json!({
        "primal": skunk_bat_core::PRIMAL_ID,
        "version": PRIMAL_VERSION,
        "capabilities": &all,
        "count": all.len(),
        "methods": &all,
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
        "transport": active_transports()
    })
}

/// Dispatch a JSON-RPC request to the appropriate handler.
///
/// The [`MethodGate`] performs pre-dispatch authorization. In permissive mode
/// (default), all calls are allowed with a tracing warning for unauthenticated
/// access to protected methods. In enforced mode, unauthenticated calls to
/// protected methods are rejected with `-32001 PERMISSION_DENIED`.
/// Pre-dispatch authorization gate with audit trail.
///
/// Returns `Some(Response)` if the request was rejected; `None` if allowed.
async fn authorize(
    state: &Arc<RwLock<SkunkBat>>,
    gate: &MethodGate,
    caller: &CallerContext,
    method: &str,
    id: &serde_json::Value,
) -> Option<Response> {
    if let Err(resp) = gate.check(method, id.clone(), caller) {
        let log = state.read().await.audit_log().clone();
        log.record(
            EventSource::MethodGate,
            EventSeverity::Warn,
            EventKind::GateRejection {
                method: method.to_owned(),
                origin: format!("{:?}", caller.origin),
            },
        )
        .await;
        return Some(resp);
    }

    if gate.mode() == EnforcementMode::Permissive
        && caller.bearer_token.is_none()
        && super::method_gate::classify_method(method)
            == super::method_gate::MethodAccessLevel::Protected
    {
        let log = state.read().await.audit_log().clone();
        log.record(
            EventSource::MethodGate,
            EventSeverity::Info,
            EventKind::GatePermissiveAllow {
                method: method.to_owned(),
                origin: format!("{:?}", caller.origin),
            },
        )
        .await;
    }
    None
}

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

    if let Some(rejection) = authorize(state, gate, caller, &request.method, &id).await {
        return rejection;
    }

    match request.method.as_str() {
        "health.liveness" => Response::success(id, serde_json::json!({"status": "alive"})),

        "health.readiness" => {
            let sb = state.read().await;
            let ready = sb.state().is_running();
            let state_str = sb.state().to_string();
            drop(sb);
            Response::success(id, serde_json::json!({"ready": ready, "state": state_str}))
        }

        "health.check" => try_serialize(id, state.read().await.health_check().await),
        "security.scan" => try_serialize(id, state.read().await.scan_network().await),
        "security.detect" => dispatch_detect(state, id).await,
        "security.respond" => dispatch_respond(state, id, request.params).await,
        "security.metrics" => serialize(id, state.read().await.get_security_metrics()),
        "security.audit_log" => dispatch_audit_log(state, id, request.params).await,

        "defense.status" => dispatch_defense_status(state, id).await,

        "lifecycle.state" => {
            let state_str = state.read().await.state().to_string();
            Response::success(id, serde_json::json!({"state": state_str}))
        }

        "lifecycle.status" => Response::success(
            id,
            serde_json::json!({
                "primal": skunk_bat_core::PRIMAL_ID,
                "version": PRIMAL_VERSION,
                "status": "running"
            }),
        ),

        "lifecycle.capabilities" => {
            let all: Vec<&str> = METHODS.iter().chain(TRANSPORT_METHODS).copied().collect();
            Response::success(id, serde_json::json!({"capabilities": all}))
        }

        "capabilities.list" | "capability.list" => Response::success(id, capabilities_response()),

        "identity.get" => Response::success(
            id,
            serde_json::json!({
                "primal": skunk_bat_core::PRIMAL_ID,
                "version": PRIMAL_VERSION,
                "domain": PRIMAL_DOMAIN,
                "license": PRIMAL_LICENSE,
                "protocol": "jsonrpc-2.0",
                "transport": active_transports()
            }),
        ),

        "auth.check" => {
            let has_token = caller.bearer_token.is_some();
            Response::success(
                id,
                serde_json::json!({
                    "authenticated": has_token,
                    "mode": gate.mode().as_str()
                }),
            )
        }

        "auth.mode" => Response::success(id, serde_json::json!({ "mode": gate.mode().as_str() })),

        "auth.peer_info" => Response::success(
            id,
            serde_json::json!({
                "origin": format!("{:?}", caller.origin),
                "has_token": caller.bearer_token.is_some()
            }),
        ),

        "btsp.capabilities" => Response::success(
            id,
            serde_json::json!({
                "protocol": "btsp-v1",
                "phase": 3,
                "ciphers": ["chacha20-poly1305", "hmac-plain", "null"],
                "preferred": "chacha20-poly1305",
                "key_derivation": "hkdf-sha256",
                "handshake": "btsp.negotiate"
            }),
        ),

        _ => Response::error(
            id,
            jsonrpc::METHOD_NOT_FOUND,
            format!("unknown method: {}", request.method),
        ),
    }
}

/// Handle `security.detect` — run threat detection with audit trail.
async fn dispatch_detect(state: &Arc<RwLock<SkunkBat>>, id: serde_json::Value) -> Response {
    let sb = state.read().await;
    let result = sb.detect_threats().await;
    let log = sb.audit_log().clone();
    drop(sb);
    if let Ok(ref threats) = result {
        for t in threats {
            log.record(
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
    try_serialize(id, result)
}

/// Handle `defense.status` — returns defense subsystem health for gate probing.
async fn dispatch_defense_status(state: &Arc<RwLock<SkunkBat>>, id: serde_json::Value) -> Response {
    let sb = state.read().await;
    let quarantine = sb.defense_quarantine_snapshot();
    let metrics = sb.get_security_metrics();
    let defense_enabled = sb.defense_healthy();
    let threat_detection_enabled = sb.threat_detection_healthy();
    let auto_response = sb.auto_response_enabled();
    drop(sb);

    Response::success(
        id,
        serde_json::json!({
            "primal": skunk_bat_core::PRIMAL_ID,
            "version": PRIMAL_VERSION,
            "status": "active",
            "defense_enabled": defense_enabled,
            "threat_detection_enabled": threat_detection_enabled,
            "auto_response": auto_response,
            "quarantine_count": quarantine.len(),
            "metrics": {
                "threats_detected": metrics.threats_detected,
                "threats_mitigated": metrics.threats_mitigated,
                "scans_performed": metrics.scans_performed,
            }
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
    let result = sb.respond_to_threat(&threat);
    let log = sb.audit_log().clone();
    drop(sb);

    match result {
        Ok(()) => {
            log.record(
                EventSource::DefenseEngine,
                EventSeverity::Info,
                EventKind::DefenseAction {
                    threat_id: threat.id.clone(),
                    action: "responded".to_owned(),
                },
            )
            .await;
            Response::success(id, serde_json::json!({"status": "ok"}))
        }
        Err(e) => Response::error(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
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

    let log = state.read().await.audit_log().clone();
    let events = log.query(since_seq, limit).await;
    let latest_seq = log.latest_seq().await;

    serialize(
        id,
        serde_json::json!({
            "events": events,
            "latest_seq": latest_seq,
            "count": events.len()
        }),
    )
}

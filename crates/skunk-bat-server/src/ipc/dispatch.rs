// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Method dispatch — routes `domain.verb` methods to handlers.
//!
//! Implements Capability Wire Standard L2 (`capabilities.list`, `identity.get`)
//! and Primal IPC Protocol v3.1 semantic method naming.

use serde::Serialize;
use skunk_bat_core::PrimalHealth;
use skunk_bat_core::observability::audit_log::{EventKind, EventSeverity, EventSource};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::App;
use super::jsonrpc::{self, Request, Response};
use super::method_gate::{CallerContext, EnforcementMode, MethodGate, PERMISSION_DENIED};

/// Application-layer methods routed through `dispatch()`.
const METHODS: &[&str] = &[
    "health.liveness",
    "health.readiness",
    "health.check",
    "security.scan",
    "security.detect",
    "security.advisory",
    "security.respond",
    "security.metrics",
    "security.audit_log",
    "baseline.observe",
    "baseline.query",
    "baseline.anomaly",
    "baseline.reset",
    "defense.status",
    "defense.quarantine",
    "defense.release",
    "response.evaluate",
    "method_gate.status",
    "threat.report",
    "lifecycle.state",
    "lifecycle.status",
    "lifecycle.capabilities",
    "capabilities.list",
    "capability.list",
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
pub(super) fn try_serialize<T: Serialize, E: std::fmt::Display>(
    id: serde_json::Value,
    result: Result<T, E>,
) -> Response {
    match result {
        Ok(val) => serialize(id, val),
        Err(e) => Response::error(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

/// Serialize an infallible value into a JSON-RPC response.
pub(super) fn serialize<T: Serialize>(id: serde_json::Value, value: T) -> Response {
    match serde_json::to_value(value) {
        Ok(v) => Response::success(id, v),
        Err(e) => Response::error(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

/// All advertised methods (application + transport) for registration payloads.
pub(super) fn all_methods() -> Vec<&'static str> {
    METHODS.iter().chain(TRANSPORT_METHODS).copied().collect()
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
            { "type": "security", "methods": ["scan", "detect", "respond", "metrics", "audit_log", "advisory"] },
            { "type": "health", "methods": ["liveness", "readiness", "check"] },
            { "type": "defense", "methods": ["status", "quarantine", "release"] },
            { "type": "baseline", "methods": ["observe", "query", "anomaly", "reset"] },
            { "type": "response", "methods": ["evaluate"] },
            { "type": "threat", "methods": ["report"] },
            { "type": "method_gate", "methods": ["status"] },
            { "type": "auth", "methods": ["check", "mode", "peer_info"] },
            { "type": "lifecycle", "methods": ["state", "status", "capabilities"] },
            { "type": "btsp", "methods": ["negotiate", "capabilities"] },
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
    state: &Arc<RwLock<App>>,
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
            super::dispatch_security::dispatch_security(state, id, &request.method, request.params)
                .await
        }
        "security.advisory" => {
            super::dispatch_security::dispatch_advisory(state, id, request.params).await
        }
        "security.respond" => {
            super::dispatch_security::dispatch_respond(state, id, request.params).await
        }
        "baseline.observe" => {
            super::dispatch_security::dispatch_baseline_observe(state, id, request.params).await
        }
        "baseline.query" => super::dispatch_composable::dispatch_baseline_query(state, id).await,
        "baseline.anomaly" => {
            super::dispatch_composable::dispatch_baseline_anomaly(state, id, request.params).await
        }
        "baseline.reset" => {
            super::dispatch_composable::dispatch_baseline_reset(state, id, request.params).await
        }
        "defense.status" => {
            let sb = state.read().await;
            let status = sb.defense_status();
            drop(sb);
            Response::success(id, status)
        }
        "defense.quarantine" => {
            super::dispatch_composable::dispatch_defense_quarantine(state, id, request.params).await
        }
        "defense.release" => {
            super::dispatch_composable::dispatch_defense_release(state, id, request.params).await
        }
        "response.evaluate" => {
            super::dispatch_composable::dispatch_response_evaluate(state, id, request.params).await
        }
        "lifecycle.state" | "lifecycle.status" | "lifecycle.capabilities" => {
            dispatch_lifecycle(state, id, &request.method).await
        }
        "capabilities.list" | "capability.list" => Response::success(id, capabilities_response()),
        "identity.get" => dispatch_identity(id),
        "auth.check" | "auth.mode" | "auth.peer_info" => {
            dispatch_auth(id, gate, &caller, &request.method)
        }
        "method_gate.status" => dispatch_method_gate_status(id, gate),
        "threat.report" => super::dispatch_security::dispatch_threat_report(state, id).await,
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
    state: &Arc<RwLock<App>>,
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
    state: &Arc<RwLock<App>>,
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
        other => Response::error(
            id,
            super::jsonrpc::METHOD_NOT_FOUND,
            format!("unknown health method: {other}"),
        ),
    }
}

/// Lifecycle domain: `lifecycle.state`, `lifecycle.status`, `lifecycle.capabilities`.
async fn dispatch_lifecycle(
    state: &Arc<RwLock<App>>,
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
        other => Response::error(
            id,
            super::jsonrpc::METHOD_NOT_FOUND,
            format!("unknown lifecycle method: {other}"),
        ),
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
        other => Response::error(
            id,
            super::jsonrpc::METHOD_NOT_FOUND,
            format!("unknown auth method: {other}"),
        ),
    }
}

/// `MethodGate` introspection — reports enforcement posture for cross-gate probes.
fn dispatch_method_gate_status(id: serde_json::Value, gate: &MethodGate) -> Response {
    use super::method_gate::{PUBLIC_METHOD_PREFIXES, PUBLIC_METHODS};
    Response::success(
        id,
        serde_json::json!({
            "mode": gate.mode().as_str(),
            "origin_trust": {
                "unix": "bypass",
                "loopback": "bypass",
                "remote": "token_required"
            },
            "public_methods": PUBLIC_METHODS,
            "public_prefixes": PUBLIC_METHOD_PREFIXES,
            "token_extraction": "_auth.token",
            "btsp_elevation": true,
        }),
    )
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

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "dispatch_tests_gate.rs"]
mod tests_gate;

#[cfg(test)]
#[path = "dispatch_tests_composable.rs"]
mod tests_composable;

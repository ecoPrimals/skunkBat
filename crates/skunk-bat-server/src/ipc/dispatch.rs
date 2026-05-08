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
use super::method_gate::{CallerContext, EnforcementMode, MethodGate};

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
    "lifecycle.state",
    "lifecycle.capabilities",
    "capabilities.list",
    "identity.get",
    "auth.check",
    "auth.mode",
    "auth.peer_info",
];

/// Transport-layer methods handled by the connection handler before dispatch.
/// Listed here for `capabilities.list` completeness only — not routed by `dispatch()`.
const TRANSPORT_METHODS: &[&str] = &["btsp.negotiate"];

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

    match gate.check(&request.method, id.clone(), caller) {
        Err(resp) => {
            let audit = state.read().await;
            audit
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
            drop(audit);
            return resp;
        }
        Ok(()) => {
            if gate.mode() == EnforcementMode::Permissive
                && caller.bearer_token.is_none()
                && super::method_gate::classify_method(&request.method)
                    == super::method_gate::MethodAccessLevel::Protected
            {
                let audit = state.read().await;
                audit
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
                drop(audit);
            }
        }
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
        "security.detect" => try_serialize(id, state.read().await.detect_threats().await),
        "security.respond" => dispatch_respond(state, id, request.params).await,
        "security.metrics" => serialize(id, state.read().await.get_security_metrics()),
        "security.audit_log" => dispatch_audit_log(state, id, request.params).await,

        "lifecycle.state" => {
            let state_str = state.read().await.state().to_string();
            Response::success(id, serde_json::json!({"state": state_str}))
        }

        "lifecycle.capabilities" => {
            let all: Vec<&str> = METHODS.iter().chain(TRANSPORT_METHODS).copied().collect();
            Response::success(id, serde_json::json!({"capabilities": all}))
        }

        "capabilities.list" | "capability.list" => Response::success(
            id,
            serde_json::json!({
                "primal": skunk_bat_core::PRIMAL_ID,
                "version": PRIMAL_VERSION,
                "methods": METHODS.iter().chain(TRANSPORT_METHODS).copied().collect::<Vec<&str>>(),
                "provided_capabilities": [
                    {
                        "type": "security",
                        "methods": ["scan", "detect", "respond", "metrics"],
                        "version": PRIMAL_VERSION,
                        "description": "Network reconnaissance, threat detection, and automated defense"
                    },
                    {
                        "type": "health",
                        "methods": ["liveness", "readiness", "check"],
                        "version": PRIMAL_VERSION,
                        "description": "Health monitoring endpoints"
                    }
                ],
                "consumed_capabilities": CONSUMED_CAPABILITIES,
                "protocol": "jsonrpc-2.0",
                "transport": ["uds", "tcp"]
            }),
        ),

        "identity.get" => Response::success(
            id,
            serde_json::json!({
                "primal": skunk_bat_core::PRIMAL_ID,
                "version": PRIMAL_VERSION,
                "domain": PRIMAL_DOMAIN,
                "license": PRIMAL_LICENSE,
                "protocol": "jsonrpc-2.0",
                "transport": ["uds", "tcp"]
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

        _ => Response::error(
            id,
            jsonrpc::METHOD_NOT_FOUND,
            format!("unknown method: {}", request.method),
        ),
    }
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
        Ok(()) => Response::success(id, serde_json::json!({"status": "ok"})),
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
mod tests {
    use super::super::method_gate::{CallerContext, EnforcementMode, MethodGate};
    use super::*;
    use skunk_bat_core::SkunkBatConfig;

    use skunk_bat_core::PrimalLifecycle;

    fn make_state() -> Arc<RwLock<SkunkBat>> {
        Arc::new(RwLock::new(SkunkBat::new(SkunkBatConfig::default())))
    }

    fn make_gate() -> MethodGate {
        MethodGate::new(EnforcementMode::Permissive)
    }

    fn make_caller() -> CallerContext {
        CallerContext::loopback()
    }

    fn make_request(method: &str) -> Request {
        Request {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: None,
            id: Some(serde_json::json!(1)),
        }
    }

    #[tokio::test]
    async fn test_health_liveness() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("health.liveness"),
        )
        .await;
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn test_security_scan() {
        let state = make_state();
        state.write().await.start().await.expect("start");
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("security.scan"),
        )
        .await;
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn test_security_detect() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("security.detect"),
        )
        .await;
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn test_lifecycle_capabilities() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("lifecycle.capabilities"),
        )
        .await;
        assert!(resp.error.is_none());
        let caps = resp.result.expect("result");
        assert!(caps["capabilities"].is_array());
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("bogus.method"),
        )
        .await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, jsonrpc::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn test_invalid_jsonrpc_version() {
        let state = make_state();
        let req = Request {
            jsonrpc: "1.0".to_string(),
            method: "health.liveness".to_string(),
            params: None,
            id: Some(serde_json::json!(1)),
        };
        let resp = dispatch(&state, &make_gate(), &make_caller(), req).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn test_security_metrics() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("security.metrics"),
        )
        .await;
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn test_health_readiness() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("health.readiness"),
        )
        .await;
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn test_health_check() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("health.check"),
        )
        .await;
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn test_lifecycle_state() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("lifecycle.state"),
        )
        .await;
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn test_security_respond_missing_params() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("security.respond"),
        )
        .await;
        assert!(resp.error.is_some());
    }

    // ── Capability Wire Standard L2 tests ────────────────────────

    #[tokio::test]
    async fn test_capabilities_list_wire_standard_l2() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("capabilities.list"),
        )
        .await;
        assert!(resp.error.is_none());

        let result = resp.result.expect("result");
        assert_eq!(result["primal"], "skunkbat");
        assert!(result["version"].is_string());
        assert!(result["methods"].is_array());

        let methods = result["methods"].as_array().expect("methods array");
        assert!(methods.iter().any(|m| m == "health.liveness"));
        assert!(methods.iter().any(|m| m == "security.scan"));
        assert!(methods.iter().any(|m| m == "capabilities.list"));
    }

    #[tokio::test]
    async fn test_capabilities_list_alias() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("capability.list"),
        )
        .await;
        assert!(resp.error.is_none());
        let result = resp.result.expect("result");
        assert_eq!(result["primal"], "skunkbat");
    }

    #[tokio::test]
    async fn test_identity_get() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("identity.get"),
        )
        .await;
        assert!(resp.error.is_none());

        let result = resp.result.expect("result");
        assert_eq!(result["primal"], "skunkbat");
        assert_eq!(result["domain"], "security");
        assert_eq!(result["license"], "AGPL-3.0-or-later");
    }

    #[tokio::test]
    async fn test_provided_capabilities_l3() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("capabilities.list"),
        )
        .await;
        let result = resp.result.expect("result");

        let caps = result["provided_capabilities"]
            .as_array()
            .expect("provided_capabilities");
        assert!(caps.iter().any(|c| c["type"] == "security"));
        assert!(caps.iter().any(|c| c["type"] == "health"));
    }

    #[tokio::test]
    async fn test_consumed_capabilities_l3() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("capabilities.list"),
        )
        .await;
        let result = resp.result.expect("result");

        let consumed = result["consumed_capabilities"]
            .as_array()
            .expect("consumed_capabilities");
        assert!(!consumed.is_empty());
        assert!(consumed.iter().any(|c| c == "lineage.verify"));
    }

    #[tokio::test]
    async fn test_security_respond_valid_threat() {
        let state = make_state();
        let req = Request {
            jsonrpc: "2.0".to_string(),
            method: "security.respond".to_string(),
            params: Some(serde_json::json!({
                "id": "threat-test-1",
                "threat_type": {"IntrusionAttempt": {"attack_type": "scan", "signature": "rapid"}},
                "severity": "High",
                "source": "192.168.1.100",
                "target": "192.168.1.1",
                "detected_at": {"secs_since_epoch": 0, "nanos_since_epoch": 0},
                "description": "Test intrusion",
                "confidence": 0.85
            })),
            id: Some(serde_json::json!(42)),
        };
        let resp = dispatch(&state, &make_gate(), &make_caller(), req).await;
        assert!(resp.error.is_none());
        let result = resp.result.expect("result");
        assert_eq!(result["status"], "ok");
    }

    #[tokio::test]
    async fn test_security_respond_invalid_params() {
        let state = make_state();
        let req = Request {
            jsonrpc: "2.0".to_string(),
            method: "security.respond".to_string(),
            params: Some(serde_json::json!({"not": "a threat"})),
            id: Some(serde_json::json!(43)),
        };
        let resp = dispatch(&state, &make_gate(), &make_caller(), req).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn btsp_negotiate_is_transport_only() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("btsp.negotiate"),
        )
        .await;
        assert!(
            resp.error.is_some(),
            "btsp.negotiate must NOT be dispatch-routed (transport-layer only)"
        );
    }

    #[tokio::test]
    async fn capabilities_list_includes_transport_methods() {
        let state = make_state();
        let resp = dispatch(
            &state,
            &make_gate(),
            &make_caller(),
            make_request("capabilities.list"),
        )
        .await;
        let result = resp.result.expect("capabilities should succeed");
        let methods = result["methods"].as_array().expect("methods array");
        let method_strs: Vec<&str> = methods.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            method_strs.contains(&"btsp.negotiate"),
            "capabilities.list must advertise transport methods"
        );
        assert!(
            method_strs.contains(&"health.liveness"),
            "capabilities.list must advertise application methods"
        );
    }
}

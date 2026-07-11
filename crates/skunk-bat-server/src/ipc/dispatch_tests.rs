// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Core IPC dispatch tests — health, security, lifecycle, capabilities, wire standard.

use super::super::method_gate::{CallerContext, EnforcementMode, MethodGate};
use super::*;
use skunk_bat_core::{PrimalLifecycle, SkunkBat, SkunkBatConfig};
use skunk_bat_integrations::verifier::RuntimeVerifier;

fn make_state() -> Arc<RwLock<App>> {
    Arc::new(RwLock::new(SkunkBat::with_verifier(
        SkunkBatConfig::default(),
        RuntimeVerifier::from_env(),
    )))
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

#[allow(dead_code)]
fn make_request_with_token(method: &str, token: &str) -> Request {
    Request {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params: Some(serde_json::json!({ "_auth": { "token": token } })),
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
#[expect(clippy::cast_possible_truncation, reason = "test assertion narrowing")]
async fn test_security_audit_log() {
    let state = make_state();
    let resp = dispatch(
        &state,
        &make_gate(),
        &make_caller(),
        Request {
            jsonrpc: "2.0".to_string(),
            method: "security.audit_log".to_string(),
            params: Some(serde_json::json!({"since_seq": 0, "limit": 10})),
            id: Some(serde_json::json!(1)),
        },
    )
    .await;
    assert!(resp.error.is_none());
    let result = resp.result.expect("result");
    let count = result["count"].as_u64().unwrap();
    let latest_seq = result["latest_seq"].as_u64().unwrap();
    assert_eq!(count as usize, latest_seq as usize);
    assert!(latest_seq >= 1, "gate permissive-allow event recorded");
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

    let security_cap = caps.iter().find(|c| c["type"] == "security").unwrap();
    let methods = security_cap["methods"].as_array().unwrap();
    assert!(
        methods
            .iter()
            .filter_map(|m| m.as_str())
            .any(|m| m == "audit_log"),
        "security capability must include audit_log"
    );
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

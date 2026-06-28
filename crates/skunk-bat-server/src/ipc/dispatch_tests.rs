// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

use super::super::method_gate::{CallerContext, EnforcementMode, MethodGate};
use super::*;
use skunk_bat_core::PrimalLifecycle;
use skunk_bat_core::SkunkBatConfig;

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

#[tokio::test]
async fn enforced_gate_rejects_protected_without_token() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let resp = dispatch(&state, &gate, &caller, make_request("security.scan")).await;
    assert!(resp.error.is_some());
    assert_eq!(resp.error.as_ref().unwrap().code, -32001);
}

#[tokio::test]
async fn enforced_gate_allows_public_without_token() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let resp = dispatch(&state, &gate, &caller, make_request("health.liveness")).await;
    assert!(resp.error.is_none());
}

#[tokio::test]
async fn enforced_gate_allows_protected_with_token() {
    use super::super::method_gate::ConnectionOrigin;
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext {
        bearer_token: Some("test-ionic-token".to_owned()),
        origin: ConnectionOrigin::Remote,
        source_addr: None,
    };
    let resp = dispatch(&state, &gate, &caller, make_request("security.scan")).await;
    assert!(resp.error.is_none());
}

#[tokio::test]
async fn enforced_gate_records_rejection_to_audit_log() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let _ = dispatch(&state, &gate, &caller, make_request("security.detect")).await;

    let events = state.read().await.audit_log().query(0, 10).await;
    assert!(
        events.iter().any(|e| matches!(
            &e.kind,
            skunk_bat_core::observability::audit_log::EventKind::GateRejection { .. }
        )),
        "enforced rejection must be recorded in audit log"
    );
}

// === Wave 123: MethodGate enforcement validation ===

#[tokio::test]
async fn origin_unix_bypasses_enforcement() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::unix();
    let resp = dispatch(&state, &gate, &caller, make_request("security.scan")).await;
    assert!(
        resp.error.is_none(),
        "UDS origin must bypass enforcement for protected methods"
    );
}

#[tokio::test]
async fn origin_loopback_bypasses_enforcement() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::loopback();
    let resp = dispatch(&state, &gate, &caller, make_request("security.scan")).await;
    assert!(
        resp.error.is_none(),
        "loopback origin must bypass enforcement for protected methods"
    );
}

#[tokio::test]
async fn remote_without_token_rejected_under_enforcement() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let resp = dispatch(&state, &gate, &caller, make_request("security.scan")).await;
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        -32001,
        "remote + enforced + no token must yield PERMISSION_DENIED"
    );
}

#[tokio::test]
async fn remote_with_request_token_passes_enforcement() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let resp = dispatch(
        &state,
        &gate,
        &caller,
        make_request_with_token("security.scan", "ionic-token-abc"),
    )
    .await;
    assert!(
        resp.error.is_none(),
        "remote + enforced + request token must be permitted"
    );
}

#[tokio::test]
async fn btsp_session_token_passes_enforcement() {
    use super::super::method_gate::ConnectionOrigin;
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext {
        bearer_token: Some("btsp:session-001".to_owned()),
        origin: ConnectionOrigin::Remote,
        source_addr: Some("10.0.0.5:4321".to_owned()),
    };
    let resp = dispatch(&state, &gate, &caller, make_request("security.scan")).await;
    assert!(
        resp.error.is_none(),
        "BTSP-authenticated remote must pass enforcement"
    );
}

#[tokio::test]
async fn defense_status_is_protected() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let resp = dispatch(&state, &gate, &caller, make_request("defense.status")).await;
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        -32001,
        "defense.status must be protected under enforcement"
    );
}

#[tokio::test]
async fn defense_status_allowed_from_local() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::unix();
    let resp = dispatch(&state, &gate, &caller, make_request("defense.status")).await;
    assert!(
        resp.error.is_none(),
        "defense.status must be allowed from local origin"
    );
}

#[tokio::test]
async fn permissive_remote_no_token_allows_but_audits() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Permissive);
    let caller = CallerContext::remote();
    let resp = dispatch(&state, &gate, &caller, make_request("security.scan")).await;
    assert!(
        resp.error.is_none(),
        "permissive mode allows remote unauthenticated protected calls"
    );

    let events = state.read().await.audit_log().query(0, 10).await;
    assert!(
        events.iter().any(|e| matches!(
            &e.kind,
            skunk_bat_core::observability::audit_log::EventKind::GatePermissiveAllow { .. }
        )),
        "permissive allow must be audit-logged"
    );
}

#[tokio::test]
async fn quarantine_blocks_remote_dispatch() {
    let state = make_state();
    let gate = make_gate();
    state
        .read()
        .await
        .quarantine("10.0.0.99", "test quarantine", "test-threat-1");
    let caller = CallerContext::remote_with_addr("10.0.0.99:9999".to_owned());
    let resp = dispatch(&state, &gate, &caller, make_request("security.scan")).await;
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        -32001,
        "quarantined source must be rejected"
    );
}

#[tokio::test]
async fn quarantine_exempts_health_prefix() {
    let state = make_state();
    let gate = make_gate();
    state
        .read()
        .await
        .quarantine("10.0.0.99", "test quarantine", "test-threat-2");
    let caller = CallerContext::remote_with_addr("10.0.0.99:9999".to_owned());
    let resp = dispatch(&state, &gate, &caller, make_request("health.liveness")).await;
    assert!(
        resp.error.is_none(),
        "health.* must be exempt from quarantine"
    );
}

#[tokio::test]
async fn quarantine_exempts_bare_health() {
    let state = make_state();
    let gate = make_gate();
    state
        .read()
        .await
        .quarantine("10.0.0.99", "test quarantine", "test-threat-3");
    let caller = CallerContext::remote_with_addr("10.0.0.99:9999".to_owned());
    let resp = dispatch(&state, &gate, &caller, make_request("health")).await;
    let code = resp.error.as_ref().map(|e| e.code);
    assert_ne!(
        code,
        Some(-32001),
        "bare 'health' must be exempt from quarantine (may still 404)"
    );
}

#[tokio::test]
async fn quarantine_records_rejection_audit() {
    let state = make_state();
    let gate = make_gate();
    state
        .read()
        .await
        .quarantine("10.0.0.99", "test quarantine", "test-threat-4");
    let caller = CallerContext::remote_with_addr("10.0.0.99:9999".to_owned());
    let _ = dispatch(&state, &gate, &caller, make_request("security.scan")).await;

    let events = state.read().await.audit_log().query(0, 10).await;
    let has_quarantine_rejection = events.iter().any(|e| match &e.kind {
        skunk_bat_core::observability::audit_log::EventKind::GateRejection { origin, .. } => {
            origin.starts_with("quarantined:")
        }
        _ => false,
    });
    assert!(
        has_quarantine_rejection,
        "quarantine rejection must be audit-logged with 'quarantined:' origin"
    );
}

#[tokio::test]
async fn unknown_method_enforced_gets_permission_denied() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let resp = dispatch(&state, &gate, &caller, make_request("bogus.method")).await;
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        -32001,
        "unknown methods classify as Protected; enforced rejects before METHOD_NOT_FOUND"
    );
}

#[tokio::test]
async fn unknown_method_permissive_gets_method_not_found() {
    let state = make_state();
    let gate = make_gate();
    let caller = CallerContext::remote();
    let resp = dispatch(&state, &gate, &caller, make_request("bogus.method")).await;
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        -32601,
        "unknown methods in permissive mode pass gate and get METHOD_NOT_FOUND from dispatch"
    );
}

// === Wave 124: method_gate.status + threat.report ===

#[tokio::test]
async fn method_gate_status_returns_enforcement_posture() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = make_caller();
    let resp = dispatch(&state, &gate, &caller, make_request("method_gate.status")).await;
    assert!(resp.error.is_none(), "method_gate.status must succeed");
    let result = resp.result.unwrap();
    assert_eq!(result["mode"], "enforced");
    assert_eq!(result["origin_trust"]["unix"], "bypass");
    assert_eq!(result["origin_trust"]["loopback"], "bypass");
    assert_eq!(result["origin_trust"]["remote"], "token_required");
    assert!(result["public_methods"].is_array());
    assert!(result["public_prefixes"].is_array());
    assert_eq!(result["btsp_elevation"], true);
    assert_eq!(result["token_extraction"], "_auth.token");
}

#[tokio::test]
async fn method_gate_status_is_public() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let resp = dispatch(&state, &gate, &caller, make_request("method_gate.status")).await;
    assert!(
        resp.error.is_none(),
        "method_gate.status must be public (accessible without token from remote)"
    );
}

#[tokio::test]
async fn method_gate_status_permissive_mode() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();
    let resp = dispatch(&state, &gate, &caller, make_request("method_gate.status")).await;
    let result = resp.result.unwrap();
    assert_eq!(result["mode"], "permissive");
}

#[tokio::test]
async fn threat_report_returns_structured_report() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();
    let resp = dispatch(&state, &gate, &caller, make_request("threat.report")).await;
    assert!(resp.error.is_none(), "threat.report must succeed");
    let result = resp.result.unwrap();
    assert!(result["threat_count"].is_number());
    assert!(result["threats"].is_array());
    assert!(result["metrics"].is_object());
    assert!(result["defense"].is_object());
    assert!(result["metrics"]["scans_performed"].is_number());
    assert!(result["metrics"]["threats_detected"].is_number());
    assert!(result["defense"]["enabled"].is_boolean());
}

#[tokio::test]
async fn threat_report_is_protected() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let resp = dispatch(&state, &gate, &caller, make_request("threat.report")).await;
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        -32001,
        "threat.report must be protected under enforcement"
    );
}

#[tokio::test]
async fn threat_report_allowed_from_local() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::unix();
    let resp = dispatch(&state, &gate, &caller, make_request("threat.report")).await;
    assert!(
        resp.error.is_none(),
        "threat.report must be allowed from local UDS origin"
    );
}

// --- Composable Primitive Tests (Wave 128) ---

#[tokio::test]
async fn defense_quarantine_adds_source() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "defense.quarantine".to_string(),
        params: Some(serde_json::json!({
            "source": "10.0.0.99",
            "reason": "test quarantine",
            "threat_id": "test-001"
        })),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert!(resp.error.is_none(), "defense.quarantine must succeed");
    let result = resp.result.unwrap();
    assert_eq!(result["status"], "quarantined");
    assert_eq!(result["source"], "10.0.0.99");
    assert!(state.read().await.is_quarantined("10.0.0.99"));
}

#[tokio::test]
async fn defense_quarantine_requires_source() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "defense.quarantine".to_string(),
        params: Some(serde_json::json!({"reason": "no source"})),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert!(resp.error.is_some(), "must fail without source");
}

#[tokio::test]
async fn defense_quarantine_is_protected() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "defense.quarantine".to_string(),
        params: Some(serde_json::json!({"source": "x", "reason": "x", "threat_id": "x"})),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert_eq!(resp.error.as_ref().unwrap().code, -32001);
}

#[tokio::test]
async fn defense_release_removes_quarantine() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();

    state.read().await.quarantine("10.0.0.99", "test", "t-001");
    assert!(state.read().await.is_quarantined("10.0.0.99"));

    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "defense.release".to_string(),
        params: Some(serde_json::json!({"source": "10.0.0.99"})),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert!(resp.error.is_none());
    let result = resp.result.unwrap();
    assert_eq!(result["released"], true);
    assert!(!state.read().await.is_quarantined("10.0.0.99"));
}

#[tokio::test]
async fn defense_release_not_quarantined() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "defense.release".to_string(),
        params: Some(serde_json::json!({"source": "nobody"})),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    let result = resp.result.unwrap();
    assert_eq!(result["released"], false);
}

#[tokio::test]
async fn response_evaluate_returns_action() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();
    let threat = serde_json::json!({
        "id": "eval-test",
        "threat_type": {"IntrusionAttempt": {"attack_type": "scan", "signature": "nmap"}},
        "severity": "Critical",
        "source": "10.0.0.1",
        "target": "local",
        "detected_at": {"secs_since_epoch": 0, "nanos_since_epoch": 0},
        "description": "test",
        "confidence": 0.95
    });
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "response.evaluate".to_string(),
        params: Some(threat),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert!(resp.error.is_none(), "response.evaluate must succeed");
    let result = resp.result.unwrap();
    assert!(result["action_type"].is_string());
    assert!(result["target"].is_string());
    assert!(result["requires_approval"].is_boolean());
    assert!(result["reason"].is_string());
}

#[tokio::test]
async fn response_evaluate_is_protected() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "response.evaluate".to_string(),
        params: None,
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert_eq!(resp.error.as_ref().unwrap().code, -32001);
}

#[tokio::test]
async fn baseline_query_returns_stats() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();
    let resp = dispatch(&state, &gate, &caller, make_request("baseline.query")).await;
    assert!(resp.error.is_none(), "baseline.query must succeed");
    let result = resp.result.unwrap();
    assert!(
        result.get("observation_count").is_some() || result.get("established").is_some(),
        "must return stats or not-established indicator"
    );
}

#[tokio::test]
async fn baseline_query_is_public() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let resp = dispatch(&state, &gate, &caller, make_request("baseline.query")).await;
    assert!(
        resp.error.is_none(),
        "baseline.query must be public (read-only introspection)"
    );
}

#[tokio::test]
async fn baseline_anomaly_detects_spike() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "baseline.anomaly".to_string(),
        params: Some(serde_json::json!({
            "connection_rate": 99999.0,
            "traffic_volume": 99_999_999,
            "ports_accessed": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            "timestamp": {"secs_since_epoch": 0, "nanos_since_epoch": 0}
        })),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert!(resp.error.is_none(), "baseline.anomaly must succeed");
    let result = resp.result.unwrap();
    assert!(result["anomaly_count"].is_number());
    assert!(result["anomalies"].is_array());
}

#[tokio::test]
async fn baseline_anomaly_is_public() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "baseline.anomaly".to_string(),
        params: Some(serde_json::json!({
            "connection_rate": 1.0,
            "traffic_volume": 100,
            "ports_accessed": [80],
            "timestamp": {"secs_since_epoch": 0, "nanos_since_epoch": 0}
        })),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert!(resp.error.is_none(), "baseline.anomaly must be public");
}

#[tokio::test]
async fn baseline_reset_succeeds() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "baseline.reset".to_string(),
        params: Some(serde_json::json!({"reseed": true})),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert!(resp.error.is_none(), "baseline.reset must succeed");
    let result = resp.result.unwrap();
    assert_eq!(result["status"], "reset");
    assert_eq!(result["reseeded"], true);
}

#[tokio::test]
async fn baseline_reset_is_protected() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "baseline.reset".to_string(),
        params: None,
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert_eq!(
        resp.error.as_ref().unwrap().code,
        -32001,
        "baseline.reset must be protected"
    );
}

#[tokio::test]
async fn baseline_reset_then_query_shows_reseeded() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();

    let reset_req = Request {
        jsonrpc: "2.0".to_string(),
        method: "baseline.reset".to_string(),
        params: Some(serde_json::json!({"reseed": true})),
        id: Some(serde_json::json!(1)),
    };
    dispatch(&state, &gate, &caller, reset_req).await;

    let query_resp = dispatch(&state, &gate, &caller, make_request("baseline.query")).await;
    let result = query_resp.result.unwrap();
    assert!(
        result.get("observation_count").is_some(),
        "reseeded baseline should be established"
    );
}

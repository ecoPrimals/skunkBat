// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! `MethodGate` enforcement tests — origin trust, quarantine, token extraction.

use super::super::method_gate::{CallerContext, ConnectionOrigin, EnforcementMode, MethodGate};
use super::*;
use skunk_bat_core::SkunkBatConfig;

fn make_state() -> Arc<RwLock<SkunkBat>> {
    Arc::new(RwLock::new(SkunkBat::new(SkunkBatConfig::default())))
}

fn make_gate() -> MethodGate {
    MethodGate::new(EnforcementMode::Permissive)
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

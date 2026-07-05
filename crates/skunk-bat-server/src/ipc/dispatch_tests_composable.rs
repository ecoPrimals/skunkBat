// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Tests for composable primitive IPC methods (Wave 124 + Wave 128).
//!
//! Covers: `method_gate.status`, `threat.report`, `defense.{quarantine,release}`,
//! `response.evaluate`, `baseline.{query,anomaly,reset}`.

use super::super::method_gate::{CallerContext, EnforcementMode, MethodGate};
use super::*;
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
    assert!(result["metrics"]["scanning"]["performed"].is_number());
    assert!(result["metrics"]["threats"]["detected"].is_number());
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
        params: Some(serde_json::json!({"reseed": false})),
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

// --- Tower HTTP Gateway Advisory Tests (Wave 132) ---

#[tokio::test]
async fn security_advisory_clean_source() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "security.advisory".to_string(),
        params: Some(serde_json::json!({"source": "192.168.1.50"})),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert!(resp.error.is_none(), "advisory must succeed");
    let result = resp.result.unwrap();
    assert_eq!(result["verdict"], "allow");
    assert_eq!(result["source"], "192.168.1.50");
    assert!(result["threat_ids"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn security_advisory_quarantined_source() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();

    state
        .read()
        .await
        .quarantine("10.0.0.99", "malicious scan", "threat-xyz");

    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "security.advisory".to_string(),
        params: Some(serde_json::json!({"source": "10.0.0.99"})),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert!(
        resp.error.is_none(),
        "advisory must succeed even for blocked"
    );
    let result = resp.result.unwrap();
    assert_eq!(result["verdict"], "block");
    assert!(result["reason"].as_str().unwrap().contains("quarantined"));
    assert!(!result["threat_ids"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn security_advisory_requires_source() {
    let state = make_state();
    let gate = make_gate();
    let caller = make_caller();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "security.advisory".to_string(),
        params: None,
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert!(resp.error.is_some(), "must fail without source param");
}

#[tokio::test]
async fn security_advisory_is_public() {
    let state = make_state();
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let req = Request {
        jsonrpc: "2.0".to_string(),
        method: "security.advisory".to_string(),
        params: Some(serde_json::json!({"source": "1.2.3.4"})),
        id: Some(serde_json::json!(1)),
    };
    let resp = dispatch(&state, &gate, &caller, req).await;
    assert!(
        resp.error.is_none(),
        "security.advisory must be public (mesh peers call it without token)"
    );
}

use super::*;

#[test]
fn health_methods_are_public() {
    assert_eq!(classify_method("health"), MethodAccessLevel::Public);
    assert_eq!(classify_method("health.check"), MethodAccessLevel::Public);
    assert_eq!(
        classify_method("health.liveness"),
        MethodAccessLevel::Public
    );
    assert_eq!(
        classify_method("health.readiness"),
        MethodAccessLevel::Public
    );
}

#[test]
fn identity_and_capabilities_are_public() {
    assert_eq!(classify_method("identity.get"), MethodAccessLevel::Public);
    assert_eq!(
        classify_method("capabilities.list"),
        MethodAccessLevel::Public
    );
    assert_eq!(
        classify_method("capability.list"),
        MethodAccessLevel::Public
    );
}

#[test]
fn auth_introspection_is_public() {
    assert_eq!(classify_method("auth.check"), MethodAccessLevel::Public);
    assert_eq!(classify_method("auth.mode"), MethodAccessLevel::Public);
    assert_eq!(classify_method("auth.peer_info"), MethodAccessLevel::Public);
}

#[test]
fn method_gate_status_is_public() {
    assert_eq!(
        classify_method("method_gate.status"),
        MethodAccessLevel::Public
    );
}

#[test]
fn threat_report_is_protected() {
    assert_eq!(
        classify_method("threat.report"),
        MethodAccessLevel::Protected
    );
}

#[test]
fn lifecycle_state_is_public() {
    assert_eq!(
        classify_method("lifecycle.state"),
        MethodAccessLevel::Public
    );
    assert_eq!(
        classify_method("lifecycle.capabilities"),
        MethodAccessLevel::Public
    );
}

#[test]
fn security_methods_are_protected() {
    assert_eq!(
        classify_method("security.scan"),
        MethodAccessLevel::Protected
    );
    assert_eq!(
        classify_method("security.detect"),
        MethodAccessLevel::Protected
    );
    assert_eq!(
        classify_method("security.respond"),
        MethodAccessLevel::Protected
    );
    assert_eq!(
        classify_method("security.metrics"),
        MethodAccessLevel::Protected
    );
}

#[test]
fn unknown_methods_are_protected() {
    assert_eq!(
        classify_method("bogus.method"),
        MethodAccessLevel::Protected
    );
    assert_eq!(classify_method(""), MethodAccessLevel::Protected);
}

#[test]
fn enforcement_mode_as_str() {
    assert_eq!(EnforcementMode::Permissive.as_str(), "permissive");
    assert_eq!(EnforcementMode::Enforced.as_str(), "enforced");
}

#[test]
fn public_method_always_passes_enforced() {
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::loopback();
    let id = serde_json::json!(1);
    assert!(gate.check("health.check", &id, &caller).is_ok());
    assert!(gate.check("identity.get", &id, &caller).is_ok());
    assert!(gate.check("auth.mode", &id, &caller).is_ok());
}

#[test]
fn protected_method_passes_permissive() {
    let gate = MethodGate::new(EnforcementMode::Permissive);
    let caller = CallerContext::loopback();
    let id = serde_json::json!(1);
    assert!(gate.check("security.scan", &id, &caller).is_ok());
}

#[test]
fn protected_method_rejected_enforced_without_token() {
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let id = serde_json::json!(1);
    let result = gate.check("security.scan", &id, &caller);
    assert!(result.is_err());
    let resp = result.unwrap_err();
    assert_eq!(resp.error.as_ref().unwrap().code, PERMISSION_DENIED);
}

#[test]
fn protected_method_passes_enforced_with_token() {
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext {
        bearer_token: Some("valid-ionic-token".to_owned()),
        origin: ConnectionOrigin::Remote,
        source_addr: None,
    };
    let id = serde_json::json!(1);
    assert!(gate.check("security.scan", &id, &caller).is_ok());
}

#[test]
fn defense_status_is_protected() {
    assert_eq!(
        classify_method("defense.status"),
        MethodAccessLevel::Protected
    );
}

#[test]
fn unix_origin_bypasses_enforced_gate() {
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::unix();
    let id = serde_json::json!(1);
    assert!(
        gate.check("security.scan", &id, &caller).is_ok(),
        "UDS must bypass enforcement"
    );
}

#[test]
fn loopback_origin_bypasses_enforced_gate() {
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::loopback();
    let id = serde_json::json!(1);
    assert!(
        gate.check("security.scan", &id, &caller).is_ok(),
        "loopback must bypass enforcement"
    );
}

#[test]
fn remote_origin_rejected_enforced_no_token() {
    let gate = MethodGate::new(EnforcementMode::Enforced);
    let caller = CallerContext::remote();
    let id = serde_json::json!(1);
    assert!(
        gate.check("security.scan", &id, &caller).is_err(),
        "remote without token must be rejected under enforcement"
    );
}

#[test]
fn remote_permissive_allows_no_token() {
    let gate = MethodGate::new(EnforcementMode::Permissive);
    let caller = CallerContext::remote();
    let id = serde_json::json!(1);
    assert!(
        gate.check("security.scan", &id, &caller).is_ok(),
        "remote without token must be allowed under permissive"
    );
}

#[test]
fn with_request_token_extracts_auth_token() {
    let caller = CallerContext::remote();
    let params = Some(serde_json::json!({ "_auth": { "token": "my-token" } }));
    let derived = caller.with_request_token(params.as_ref());
    assert_eq!(
        derived.bearer_token.as_deref(),
        Some("my-token"),
        "_auth.token must be extracted from params"
    );
}

#[test]
fn with_request_token_missing_auth_no_token() {
    let caller = CallerContext::remote();
    let params = Some(serde_json::json!({ "data": 42 }));
    let derived = caller.with_request_token(params.as_ref());
    assert!(
        derived.bearer_token.is_none(),
        "missing _auth must yield no token"
    );
}

#[test]
fn with_request_token_preserves_connection_token() {
    let caller = CallerContext {
        bearer_token: Some("btsp:session-1".to_owned()),
        origin: ConnectionOrigin::Remote,
        source_addr: None,
    };
    let params = None;
    let derived = caller.with_request_token(params.as_ref());
    assert_eq!(
        derived.bearer_token.as_deref(),
        Some("btsp:session-1"),
        "connection-level token must be preserved when no request token"
    );
}

#[test]
fn with_request_token_connection_takes_precedence() {
    let caller = CallerContext {
        bearer_token: Some("btsp:session-1".to_owned()),
        origin: ConnectionOrigin::Remote,
        source_addr: None,
    };
    let params = Some(serde_json::json!({ "_auth": { "token": "ionic-override" } }));
    let derived = caller.with_request_token(params.as_ref());
    assert_eq!(
        derived.bearer_token.as_deref(),
        Some("btsp:session-1"),
        "connection-level (BTSP) token takes precedence over request token"
    );
}

#[test]
fn parse_empty_is_permissive() {
    assert_eq!(EnforcementMode::parse(""), EnforcementMode::Permissive);
}

#[test]
fn parse_enforced_variants() {
    for val in &["enforced", "enforce", "strict", "ENFORCED", "Strict"] {
        assert_eq!(
            EnforcementMode::parse(val),
            EnforcementMode::Enforced,
            "'{val}' must parse as Enforced"
        );
    }
}

#[test]
fn parse_unknown_is_permissive() {
    assert_eq!(
        EnforcementMode::parse("foobar"),
        EnforcementMode::Permissive
    );
    assert_eq!(
        EnforcementMode::parse("permissive"),
        EnforcementMode::Permissive
    );
}

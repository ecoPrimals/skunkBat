// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Pre-dispatch capability gate for JSON-RPC methods (JH-0).
//!
//! Every incoming RPC call passes through [`MethodGate::check`] *before*
//! reaching the dispatch table. The gate classifies methods into
//! [`MethodAccessLevel::Public`] (always allowed — health, identity,
//! capability advertisement) and [`MethodAccessLevel::Protected`]
//! (require a valid capability token when enforcement is active).
//!
//! Enforcement modes:
//! - **Permissive** (default): protected methods are logged but allowed.
//! - **Enforced**: protected methods without a token are rejected with
//!   `PERMISSION_DENIED` (-32001).
//!
//! Error codes:
//! - `-32001`: `PERMISSION_DENIED` (missing/insufficient token)
//! - `-32000`: `UNAUTHORIZED` (reserved for invalid token signature)

use super::jsonrpc::Response;

/// Standard ecosystem error codes for auth failures.
pub(super) const PERMISSION_DENIED: i32 = -32001;

/// Access level for a JSON-RPC method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MethodAccessLevel {
    /// Health probes, identity, capability advertisement — always allowed.
    Public,
    /// Requires a valid capability token when enforcement is active.
    Protected,
}

/// Methods that are always public (prefix matching).
const PUBLIC_METHOD_PREFIXES: &[&str] = &["health.", "btsp."];

/// Methods that are always public (exact matching).
const PUBLIC_METHODS: &[&str] = &[
    "health",
    "identity.get",
    "capabilities.list",
    "capability.list",
    "defense.status",
    "lifecycle.state",
    "lifecycle.status",
    "lifecycle.capabilities",
    "auth.check",
    "auth.mode",
    "auth.peer_info",
];

/// Classify a method string into its access level.
#[must_use]
pub(super) fn classify_method(method: &str) -> MethodAccessLevel {
    if PUBLIC_METHODS.contains(&method) {
        return MethodAccessLevel::Public;
    }
    for prefix in PUBLIC_METHOD_PREFIXES {
        if method.starts_with(prefix) {
            return MethodAccessLevel::Public;
        }
    }
    MethodAccessLevel::Protected
}

/// How the caller connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConnectionOrigin {
    /// Local Unix domain socket.
    Unix,
    /// TCP loopback (127.0.0.1 / `::1`).
    Loopback,
    /// Remote TCP connection.
    Remote,
}

/// Identity and authorization context for an incoming RPC call.
#[derive(Debug, Clone)]
pub(super) struct CallerContext {
    /// Optional bearer / capability token sent in the request.
    pub bearer_token: Option<String>,
    /// Where the connection came from.
    pub origin: ConnectionOrigin,
    /// Source address for quarantine lookup (e.g. "192.168.1.5:4321").
    pub source_addr: Option<String>,
}

impl CallerContext {
    /// Context for a Unix domain socket connection (trusted local).
    #[must_use]
    pub const fn unix() -> Self {
        Self {
            bearer_token: None,
            origin: ConnectionOrigin::Unix,
            source_addr: None,
        }
    }

    /// Context for a TCP loopback connection.
    #[must_use]
    pub const fn loopback() -> Self {
        Self {
            bearer_token: None,
            origin: ConnectionOrigin::Loopback,
            source_addr: None,
        }
    }

    /// Context for a remote TCP connection.
    #[must_use]
    pub const fn remote_with_addr(addr: String) -> Self {
        Self {
            bearer_token: None,
            origin: ConnectionOrigin::Remote,
            source_addr: Some(addr),
        }
    }

    /// Context for a remote TCP connection (no address available).
    #[must_use]
    #[cfg(test)]
    pub const fn remote() -> Self {
        Self {
            bearer_token: None,
            origin: ConnectionOrigin::Remote,
            source_addr: None,
        }
    }
}

/// Enforcement mode for the method gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EnforcementMode {
    /// Log violations but allow all calls (backward-compatible default).
    Permissive,
    /// Reject unauthenticated calls to protected methods.
    Enforced,
}

impl EnforcementMode {
    /// Resolve from `SKUNKBAT_AUTH_MODE` env var.
    /// Defaults to `Permissive` if unset or unrecognized.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var(skunk_bat_core::env_keys::SKUNKBAT_AUTH_MODE)
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "enforced" | "enforce" | "strict" => Self::Enforced,
            _ => Self::Permissive,
        }
    }

    /// Human-readable label for diagnostics and `auth.mode` responses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permissive => "permissive",
            Self::Enforced => "enforced",
        }
    }
}

/// Pre-dispatch gate that checks caller authorization before method execution.
#[derive(Debug)]
pub(super) struct MethodGate {
    mode: EnforcementMode,
}

impl MethodGate {
    /// Create a gate with the given enforcement mode.
    #[must_use]
    pub const fn new(mode: EnforcementMode) -> Self {
        Self { mode }
    }

    /// Create a gate from the environment (`SKUNKBAT_AUTH_MODE`).
    #[must_use]
    pub fn from_env() -> Self {
        Self::new(EnforcementMode::from_env())
    }

    /// Current enforcement mode.
    #[must_use]
    pub const fn mode(&self) -> EnforcementMode {
        self.mode
    }

    /// Pre-dispatch authorization check.
    ///
    /// Returns `Ok(())` if the call should proceed, or a JSON-RPC error
    /// response if the call should be rejected.
    #[expect(
        clippy::result_large_err,
        reason = "Response is the natural error for pre-dispatch rejection"
    )]
    pub fn check(
        &self,
        method: &str,
        id: &serde_json::Value,
        caller: &CallerContext,
    ) -> Result<(), Response> {
        let level = classify_method(method);

        if level == MethodAccessLevel::Public {
            return Ok(());
        }

        let authorized = caller.bearer_token.is_some();

        if authorized {
            return Ok(());
        }

        match self.mode {
            EnforcementMode::Permissive => {
                tracing::warn!(
                    method,
                    origin = ?caller.origin,
                    "method gate: unauthenticated call to protected method (permissive — allowing)"
                );
                Ok(())
            }
            EnforcementMode::Enforced => {
                tracing::warn!(
                    method,
                    origin = ?caller.origin,
                    "method gate: REJECTED unauthenticated call to protected method"
                );
                Err(Response::error(
                    id.clone(),
                    PERMISSION_DENIED,
                    format!("permission denied: method '{method}' requires a capability token"),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
}

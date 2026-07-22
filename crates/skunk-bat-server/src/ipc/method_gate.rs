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
pub(super) const PUBLIC_METHOD_PREFIXES: &[&str] = &["health.", "btsp."];

/// Methods that are always public (exact matching).
pub(super) const PUBLIC_METHODS: &[&str] = &[
    "health",
    "identity.get",
    "capabilities.list",
    "capability.list",
    "lifecycle.state",
    "lifecycle.status",
    "lifecycle.capabilities",
    "auth.check",
    "auth.mode",
    "auth.peer_info",
    "method_gate.status",
    "baseline.query",
    "baseline.anomaly",
    "security.advisory",
];

/// Classify a method string into its access level.
#[must_use]
#[inline]
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
    /// Local Unix domain socket — only constructed on Unix platforms.
    #[cfg_attr(not(unix), allow(dead_code, reason = "variant used only on Unix"))]
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
    #[cfg_attr(not(unix), allow(dead_code, reason = "constructor used only on Unix"))]
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

    /// Derive a per-request context by extracting the bearer token from
    /// the JSON-RPC params `_auth.token` field (if present).
    ///
    /// The connection-level context is immutable; this produces a clone
    /// with the request-scoped token overlaid.
    #[must_use]
    pub fn with_request_token(&self, params: Option<&serde_json::Value>) -> Self {
        let token = params
            .and_then(|p| p.get("_auth"))
            .and_then(|a| a.get("token"))
            .and_then(serde_json::Value::as_str)
            .map(String::from);
        Self {
            bearer_token: self.bearer_token.clone().or(token),
            origin: self.origin,
            source_addr: self.source_addr.clone(),
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
    /// Parse a mode string (case-insensitive).
    /// Accepts `enforced`, `enforce`, `strict`; anything else → `Permissive`.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "enforced" | "enforce" | "strict" => Self::Enforced,
            _ => Self::Permissive,
        }
    }

    /// Resolve from `SKUNKBAT_AUTH_MODE` env var.
    /// Defaults to `Permissive` if unset or unrecognized.
    #[must_use]
    pub fn from_env() -> Self {
        Self::parse(
            &std::env::var(skunk_bat_core::env_keys::SKUNKBAT_AUTH_MODE).unwrap_or_default(),
        )
    }

    /// Human-readable label for diagnostics and `auth.mode` responses.
    #[must_use]
    #[inline]
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
    #[inline]
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
    #[inline]
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

        if caller.bearer_token.is_some() {
            return Ok(());
        }

        if matches!(
            caller.origin,
            ConnectionOrigin::Unix | ConnectionOrigin::Loopback
        ) {
            return Ok(());
        }

        match self.mode {
            EnforcementMode::Permissive => {
                tracing::warn!(
                    method,
                    origin = ?caller.origin,
                    "method gate: unauthenticated remote call to protected method (permissive — allowing)"
                );
                Ok(())
            }
            EnforcementMode::Enforced => {
                tracing::warn!(
                    method,
                    origin = ?caller.origin,
                    "method gate: REJECTED unauthenticated remote call to protected method"
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
#[path = "method_gate_tests.rs"]
mod tests;

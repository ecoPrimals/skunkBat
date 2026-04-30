// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! `BearDog` genetic lineage verification integration.
//!
//! Connects to whatever primal announces the `lineage-verification`
//! capability at runtime (typically `BearDog`'s `crypto.sock` or a TCP
//! endpoint discovered via `LINEAGE_ENDPOINT`).
//!
//! Gracefully degrades to the conservative local default when no
//! lineage provider is available — unknown peers are always treated as
//! "not family" until verified.

use skunk_bat_core::error::SkunkBatError;
use skunk_bat_core::threats::traits::LineageVerifier;
use std::time::Duration;

/// Default RPC timeout for lineage calls (ms).
const DEFAULT_TIMEOUT_MS: u64 = 3000;

/// Remote lineage verifier backed by a runtime-discovered capability provider.
///
/// Makes JSON-RPC calls to `lineage.list` (get lineage chain) and
/// `lineage.verify` (family membership check) on whatever primal
/// announces the `lineage-verification` capability.
///
/// Falls back to conservative deny when the provider is unreachable.
#[derive(Clone, Debug)]
pub struct RemoteLineageVerifier {
    endpoint: String,
    uds_path: Option<String>,
    timeout_ms: u64,
}

impl RemoteLineageVerifier {
    /// Create targeting a specific TCP endpoint.
    #[must_use]
    pub fn new(endpoint: String) -> Self {
        tracing::info!("Initializing remote lineage verifier");
        Self {
            endpoint,
            uds_path: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    /// Create from environment with capability-socket discovery.
    ///
    /// Reads `LINEAGE_ENDPOINT` for TCP and probes
    /// `$BIOMEOS_SOCKET_DIR/lineage-verification.sock` for UDS.
    #[must_use]
    pub fn from_env() -> Self {
        let endpoint = std::env::var("LINEAGE_ENDPOINT").unwrap_or_default();
        let uds_path = {
            let path = crate::rpc::capability_socket("lineage-verification");
            std::path::Path::new(&path).exists().then_some(path)
        };
        tracing::info!(
            endpoint = %endpoint,
            uds = ?uds_path,
            "Initializing remote lineage verifier"
        );
        Self {
            endpoint,
            uds_path,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    /// Set request timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    fn tcp_endpoint(&self) -> Option<&str> {
        if self.endpoint.is_empty() {
            None
        } else {
            Some(&self.endpoint)
        }
    }

    async fn rpc_call(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let timeout = Duration::from_millis(self.timeout_ms);
        crate::rpc::call(
            self.uds_path.as_deref(),
            self.tcp_endpoint(),
            method,
            params,
            timeout,
        )
        .await
    }
}

impl LineageVerifier for RemoteLineageVerifier {
    async fn is_family(&self, peer_id: &str) -> Result<bool, SkunkBatError> {
        let params = serde_json::json!({ "peer_id": peer_id });
        match self.rpc_call("lineage.verify", Some(params)).await {
            Ok(value) => Ok(value["is_family"].as_bool().unwrap_or(false)),
            Err(e) => {
                tracing::debug!("Lineage verification unavailable ({e}), conservative deny");
                Ok(false)
            }
        }
    }

    async fn get_lineage(&self, peer_id: &str) -> Result<Option<String>, SkunkBatError> {
        let params = serde_json::json!({ "peer_id": peer_id });
        match self.rpc_call("lineage.list", Some(params)).await {
            Ok(value) => Ok(value["lineage"].as_str().map(String::from)),
            Err(e) => {
                tracing::debug!("Lineage query unavailable ({e}), returning None");
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construction() {
        let verifier = RemoteLineageVerifier::new("10.0.0.1:9300".into());
        assert_eq!(verifier.tcp_endpoint(), Some("10.0.0.1:9300"));
    }

    #[test]
    fn test_from_env_construction() {
        let verifier = RemoteLineageVerifier::from_env();
        let _ = verifier.tcp_endpoint();
    }

    #[test]
    fn test_builder() {
        let verifier = RemoteLineageVerifier::new(String::new()).with_timeout(1000);
        assert!(verifier.tcp_endpoint().is_none());
    }

    #[tokio::test]
    async fn test_is_family_graceful_degradation() {
        let verifier = RemoteLineageVerifier::new("unreachable.invalid:9999".into());
        let result = verifier.is_family("unknown-peer").await;
        assert!(result.is_ok());
        assert!(!result.expect("ok"), "should conservatively deny");
    }

    #[tokio::test]
    async fn test_get_lineage_graceful_degradation() {
        let verifier = RemoteLineageVerifier::new("unreachable.invalid:9999".into());
        let result = verifier.get_lineage("unknown-peer").await;
        assert!(result.is_ok());
        assert!(result.expect("ok").is_none());
    }

    #[tokio::test]
    async fn test_from_env_verify() {
        let verifier = RemoteLineageVerifier::from_env();
        let result = verifier.is_family("test-peer").await;
        assert!(result.is_ok());
        assert!(!result.expect("ok"));
    }
}

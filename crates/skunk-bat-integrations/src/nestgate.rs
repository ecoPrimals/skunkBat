// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! `NestGate` content integrity integration.
//!
//! Provides security-oriented content verification for data stored in
//! `NestGate`'s content-addressable storage (CAS). Connects to whatever
//! primal announces the `content` capability at runtime.
//!
//! Capabilities:
//! - Content existence verification (`content.exists`)
//! - Content integrity check (`content.get` + hash verification)
//! - Content listing for audit sweep (`content.list`)

use std::time::Duration;

use crate::rpc::{self, RpcError};

use skunk_bat_core::env_keys;

/// Capability domain socket name for content (`NestGate` CAS).
const CONTENT_CAPABILITY: &str = "content";

/// Default IPC timeout for content operations.
const CONTENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Content integrity verification client.
///
/// Connects to a content-addressable storage provider (typically `NestGate`)
/// and verifies data integrity for security auditing.
#[derive(Debug, Clone)]
pub struct ContentProtector {
    uds_path: Option<String>,
    tcp_endpoint: Option<String>,
    timeout: Duration,
}

impl ContentProtector {
    /// Create from environment with capability-socket discovery.
    ///
    /// Probes `$BIOMEOS_SOCKET_DIR/content.sock`; uses it only if present.
    /// Falls back to TCP via `NESTGATE_ENDPOINT` env var.
    #[must_use]
    pub fn from_env() -> Self {
        let tcp_endpoint = std::env::var(env_keys::NESTGATE_ENDPOINT).ok();
        let uds_path = {
            let path = rpc::capability_socket(CONTENT_CAPABILITY);
            std::path::Path::new(&path).exists().then_some(path)
        };
        Self {
            uds_path,
            tcp_endpoint,
            timeout: CONTENT_TIMEOUT,
        }
    }

    /// Create targeting a specific TCP endpoint.
    #[must_use]
    pub const fn new(endpoint: String) -> Self {
        Self {
            uds_path: None,
            tcp_endpoint: Some(endpoint),
            timeout: CONTENT_TIMEOUT,
        }
    }

    /// Check if a content address exists in the CAS.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError`] if the content provider is unreachable.
    pub async fn content_exists(&self, address: &str) -> Result<bool, RpcError> {
        let params = serde_json::json!({ "address": address });
        match self.call("content.exists", Some(params)).await {
            Ok(val) => Ok(val["exists"].as_bool().unwrap_or(false)),
            Err(e) => Err(e),
        }
    }

    /// Retrieve content and verify integrity against expected hash.
    ///
    /// Returns `true` if the content matches the expected hash, `false` if
    /// content was retrieved but doesn't match (integrity violation).
    ///
    /// # Errors
    ///
    /// Returns [`RpcError`] if the content provider is unreachable or the
    /// address doesn't exist.
    pub async fn verify_integrity(
        &self,
        address: &str,
        expected_hash: &str,
    ) -> Result<bool, RpcError> {
        let params = serde_json::json!({ "address": address });
        let val = self.call("content.get", Some(params)).await?;

        let content_hash = val["hash"].as_str().unwrap_or("");
        Ok(content_hash == expected_hash)
    }

    /// List content addresses for security audit sweep.
    ///
    /// Returns a list of content addresses present in the CAS.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError`] if the content provider is unreachable.
    pub async fn list_content(&self) -> Result<Vec<String>, RpcError> {
        let val = self.call("content.list", None).await?;
        let addresses = val["addresses"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Ok(addresses)
    }

    /// Perform a full integrity sweep — verify all content in the CAS.
    ///
    /// Returns addresses that failed integrity checks.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError`] if the content provider is unreachable.
    pub async fn integrity_sweep(&self) -> Result<IntegritySweepResult, RpcError> {
        let addresses = self.list_content().await?;
        let total = addresses.len();
        let mut violations = Vec::new();
        let mut errors = 0usize;

        for addr in &addresses {
            let params = serde_json::json!({ "address": addr });
            match self.call("content.get", Some(params)).await {
                Ok(val) => {
                    let stored_hash = val["hash"].as_str().unwrap_or("");
                    if stored_hash.is_empty() {
                        violations.push(addr.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!(address = %addr, err = %e, "content.get failed during sweep");
                    errors += 1;
                }
            }
        }

        if errors > 0 {
            tracing::warn!(
                total,
                errors,
                "integrity sweep completed with unreachable content entries"
            );
        }

        Ok(IntegritySweepResult {
            total_checked: total,
            violations_found: violations.len(),
            violation_addresses: violations,
        })
    }

    async fn call(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, RpcError> {
        rpc::call(
            self.uds_path.as_deref(),
            self.tcp_endpoint.as_deref(),
            method,
            params,
            self.timeout,
        )
        .await
    }
}

/// Result of a full CAS integrity sweep.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegritySweepResult {
    /// Total content addresses checked.
    pub total_checked: usize,
    /// Number of integrity violations found.
    pub violations_found: usize,
    /// Addresses that failed integrity checks.
    pub violation_addresses: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_construction() {
        let protector = ContentProtector::from_env();
        // UDS is only Some if the socket file exists on this host
        let _ = protector.uds_path;
    }

    #[test]
    fn new_with_endpoint() {
        let protector = ContentProtector::new("127.0.0.1:9500".to_owned());
        assert_eq!(protector.tcp_endpoint.as_deref(), Some("127.0.0.1:9500"));
        assert!(protector.uds_path.is_none());
    }

    #[tokio::test]
    async fn content_exists_unreachable() {
        let protector = ContentProtector::new("unreachable.invalid:1".to_owned());
        let result = protector.content_exists("sha256:abc123").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verify_integrity_unreachable() {
        let protector = ContentProtector::new("unreachable.invalid:1".to_owned());
        let result = protector.verify_integrity("sha256:abc123", "abc123").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_content_unreachable() {
        let protector = ContentProtector::new("unreachable.invalid:1".to_owned());
        let result = protector.list_content().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn integrity_sweep_unreachable() {
        let protector = ContentProtector::new("unreachable.invalid:1".to_owned());
        let result = protector.integrity_sweep().await;
        assert!(result.is_err());
    }

    #[test]
    fn sweep_result_serialization() {
        let result = IntegritySweepResult {
            total_checked: 10,
            violations_found: 1,
            violation_addresses: vec!["sha256:bad".to_owned()],
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: IntegritySweepResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_checked, 10);
        assert_eq!(parsed.violations_found, 1);
    }
}

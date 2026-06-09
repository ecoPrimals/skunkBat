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

use crate::rpc::TransportEndpoint;

/// Default RPC timeout for lineage calls (ms).
const DEFAULT_TIMEOUT_MS: u64 = 3000;

/// Transport endpoint env for lineage capability (sourDough standard).
const LINEAGE_TRANSPORT_ENV: &str = "LINEAGE_TRANSPORT";

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
    transport: Option<TransportEndpoint>,
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
            transport: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    /// Create from environment with capability-socket discovery.
    ///
    /// Resolution priority:
    /// 1. `LINEAGE_TRANSPORT` env (sourDough `TransportEndpoint` JSON)
    /// 2. `LINEAGE_ENDPOINT` env (legacy TCP string)
    /// 3. Capability socket (`lineage-verification.sock`)
    #[must_use]
    pub fn from_env() -> Self {
        let transport: Option<TransportEndpoint> = std::env::var(LINEAGE_TRANSPORT_ENV)
            .ok()
            .and_then(|v| serde_json::from_str(&v).ok());

        let endpoint =
            std::env::var(skunk_bat_core::env_keys::LINEAGE_ENDPOINT).unwrap_or_default();
        let uds_path = {
            let path = crate::rpc::capability_socket("lineage-verification");
            std::path::Path::new(&path).exists().then_some(path)
        };
        tracing::info!(
            transport = ?transport,
            endpoint = %endpoint,
            uds = ?uds_path,
            "Initializing remote lineage verifier"
        );
        Self {
            endpoint,
            uds_path,
            transport,
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
    ) -> Result<serde_json::Value, crate::rpc::RpcError> {
        let timeout = Duration::from_millis(self.timeout_ms);
        if let Some(ref ep) = self.transport {
            return crate::rpc::call_endpoint(ep, method, params, timeout).await;
        }
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
                tracing::debug!("Lineage verification provider unreachable: {e}");
                Err(SkunkBatError::LineageVerification(format!(
                    "provider unreachable: {e}"
                )))
            }
        }
    }

    async fn get_lineage(&self, peer_id: &str) -> Result<Option<String>, SkunkBatError> {
        let params = serde_json::json!({ "peer_id": peer_id });
        match self.rpc_call("lineage.list", Some(params)).await {
            Ok(value) => Ok(value["lineage"].as_str().map(String::from)),
            Err(e) => {
                tracing::debug!("Lineage query provider unreachable: {e}");
                Err(SkunkBatError::LineageVerification(format!(
                    "provider unreachable: {e}"
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

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
    async fn test_is_family_returns_err_when_unreachable() {
        let verifier = RemoteLineageVerifier::new("unreachable.invalid:9999".into());
        let result = verifier.is_family("unknown-peer").await;
        assert!(result.is_err(), "unreachable provider → Err (not false)");
    }

    #[tokio::test]
    async fn test_get_lineage_returns_err_when_unreachable() {
        let verifier = RemoteLineageVerifier::new("unreachable.invalid:9999".into());
        let result = verifier.get_lineage("unknown-peer").await;
        assert!(result.is_err(), "unreachable provider → Err (not None)");
    }

    #[tokio::test]
    async fn test_from_env_verify_returns_err() {
        let verifier = RemoteLineageVerifier::from_env();
        let result = verifier.is_family("test-peer").await;
        assert!(result.is_err(), "no provider in test env → Err");
    }

    /// Integration test: mock bearDog server confirms family membership.
    #[tokio::test]
    async fn live_lineage_verify_family_member() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut reader = tokio::io::BufReader::new(&mut stream);
            let mut line = String::new();
            tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line)
                .await
                .unwrap();
            let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(req["method"], "lineage.verify");
            assert_eq!(req["params"]["peer_id"], "trusted-peer-01");

            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "result": {"is_family": true, "lineage_chain": ["root", "trusted-peer-01"]},
                "id": req["id"]
            });
            let mut resp_line = serde_json::to_string(&resp).unwrap();
            resp_line.push('\n');
            stream.write_all(resp_line.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
        });

        let verifier =
            RemoteLineageVerifier::new(format!("127.0.0.1:{}", addr.port())).with_timeout(2000);
        let result = verifier.is_family("trusted-peer-01").await.unwrap();
        assert!(result, "mock bearDog should confirm family membership");

        server.await.unwrap();
    }

    /// Integration test: mock bearDog server returns lineage chain.
    #[tokio::test]
    async fn live_lineage_get_chain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut reader = tokio::io::BufReader::new(&mut stream);
            let mut line = String::new();
            tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line)
                .await
                .unwrap();
            let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(req["method"], "lineage.list");

            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "result": {"lineage": "root → genome-alpha → trusted-peer-01"},
                "id": req["id"]
            });
            let mut resp_line = serde_json::to_string(&resp).unwrap();
            resp_line.push('\n');
            stream.write_all(resp_line.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
        });

        let verifier =
            RemoteLineageVerifier::new(format!("127.0.0.1:{}", addr.port())).with_timeout(2000);
        let lineage = verifier.get_lineage("trusted-peer-01").await.unwrap();
        assert_eq!(
            lineage.as_deref(),
            Some("root → genome-alpha → trusted-peer-01")
        );

        server.await.unwrap();
    }
}

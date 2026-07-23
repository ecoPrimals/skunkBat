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

/// RPC timeout for lineage calls (ms) — delegates to shared integration default.
fn default_timeout_ms() -> u64 {
    super::rpc::integration_timeout_ms()
}

/// Remote lineage verifier backed by a runtime-discovered capability provider.
///
/// Makes JSON-RPC calls to `lineage.list` (get lineage chain) and
/// `lineage.verify` (family membership check) on whatever primal
/// announces the `lineage-verification` capability.
///
/// Falls back to conservative deny when the provider is unreachable.
#[derive(Clone, Debug)]
pub struct RemoteLineageVerifier {
    transport: crate::rpc::CapabilityClient,
}

impl RemoteLineageVerifier {
    /// Create targeting a specific TCP endpoint.
    #[must_use]
    pub fn new(endpoint: &str) -> Self {
        tracing::info!("Initializing remote lineage verifier");
        Self {
            transport: crate::rpc::CapabilityClient::new(endpoint, default_timeout_ms()),
        }
    }

    /// Create from environment with capability-socket discovery.
    ///
    /// Reads `LINEAGE_ENDPOINT` for TCP and probes
    /// `$BIOMEOS_SOCKET_DIR/lineage-verification.sock` for UDS.
    #[must_use]
    pub fn from_env() -> Self {
        tracing::info!("Initializing remote lineage verifier from env");
        Self {
            transport: crate::rpc::CapabilityClient::from_env(
                skunk_bat_core::env_keys::LINEAGE_ENDPOINT,
                "lineage-verification",
                default_timeout_ms(),
            ),
        }
    }

    /// Set request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.transport = self.transport.with_timeout(timeout_ms);
        self
    }

    /// The TCP endpoint as `host:port` (if resolved to TCP).
    #[must_use]
    pub fn tcp_endpoint(&self) -> Option<String> {
        self.transport.tcp_endpoint()
    }

    async fn rpc_call(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, crate::rpc::RpcError> {
        self.transport.call(method, params).await
    }
}

impl LineageVerifier for RemoteLineageVerifier {
    async fn is_family(&self, peer_id: &str) -> Result<bool, SkunkBatError> {
        let params = serde_json::json!({ "peer_id": peer_id });
        match self.rpc_call("lineage.verify", Some(params)).await {
            Ok(value) => Ok(value["is_family"].as_bool().unwrap_or(false)),
            Err(e) => {
                tracing::debug!("Lineage verification unavailable ({e}), conservative deny");
                Err(SkunkBatError::Integration(format!(
                    "lineage provider unreachable: {e}"
                )))
            }
        }
    }

    async fn get_lineage(&self, peer_id: &str) -> Result<Option<String>, SkunkBatError> {
        let params = serde_json::json!({ "peer_id": peer_id });
        match self.rpc_call("lineage.list", Some(params)).await {
            Ok(value) => Ok(value["lineage"].as_str().map(String::from)),
            Err(e) => {
                tracing::debug!("Lineage query unavailable ({e}), returning None");
                Err(SkunkBatError::Integration(format!(
                    "lineage query unavailable: {e}"
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
        let verifier = RemoteLineageVerifier::new("10.0.0.1:9300");
        assert_eq!(verifier.tcp_endpoint().as_deref(), Some("10.0.0.1:9300"));
    }

    #[test]
    fn test_from_env_construction() {
        let verifier = RemoteLineageVerifier::from_env();
        let _ = verifier.tcp_endpoint();
    }

    #[test]
    fn test_builder() {
        let verifier = RemoteLineageVerifier::new("").with_timeout(1000);
        assert!(verifier.tcp_endpoint().is_none());
    }

    #[tokio::test]
    async fn test_is_family_graceful_degradation() {
        let verifier = RemoteLineageVerifier::new("unreachable.invalid:9999");
        let result = verifier.is_family("unknown-peer").await;
        assert!(result.is_err(), "unreachable provider should return Err");
    }

    #[tokio::test]
    async fn test_get_lineage_graceful_degradation() {
        let verifier = RemoteLineageVerifier::new("unreachable.invalid:9999");
        let result = verifier.get_lineage("unknown-peer").await;
        assert!(result.is_err(), "unreachable provider should return Err");
    }

    #[tokio::test]
    async fn test_from_env_verify() {
        let verifier = RemoteLineageVerifier::from_env();
        let result = verifier.is_family("test-peer").await;
        assert!(result.is_err(), "no provider should return Err");
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

        let endpoint = format!("127.0.0.1:{}", addr.port());
        let verifier = RemoteLineageVerifier::new(&endpoint).with_timeout(2000);
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

        let endpoint = format!("127.0.0.1:{}", addr.port());
        let verifier = RemoteLineageVerifier::new(&endpoint).with_timeout(2000);
        let lineage = verifier.get_lineage("trusted-peer-01").await.unwrap();
        assert_eq!(
            lineage.as_deref(),
            Some("root → genome-alpha → trusted-peer-01")
        );

        server.await.unwrap();
    }
}

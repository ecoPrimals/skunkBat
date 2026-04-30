// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Federation broadcast integration.
//!
//! Connects to whatever primal announces the `federation` capability at
//! runtime via its capability-domain symlink (`federation.sock`) or a
//! TCP endpoint discovered from `FEDERATION_ENDPOINT`.
//!
//! Gracefully degrades when no federation provider is available — threats
//! are handled locally without broadcasting.

use serde::{Deserialize, Serialize};
use skunk_bat_core::error::SkunkBatError;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

/// Default RPC timeout for federation calls (ms).
const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Federation client for threat intelligence broadcasting.
///
/// Transport is resolved at runtime — prefers the `federation.sock`
/// capability symlink (UDS), falls back to `FEDERATION_ENDPOINT` (TCP).
#[derive(Clone)]
pub struct FederationClient {
    endpoint: String,
    uds_path: Option<String>,
    node_id: String,
    connected: Arc<RwLock<bool>>,
    timeout_ms: u64,
}

/// Threat intelligence message for federation broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    /// Source node ID.
    pub source_node: String,
    /// Threat being reported.
    pub threat_type: String,
    /// Threat source identifier.
    pub threat_source: String,
    /// Threat severity.
    pub severity: String,
    /// Human-readable description.
    pub description: String,
    /// Detection timestamp.
    pub detected_at: SystemTime,
    /// Optional evidence / context.
    pub evidence: Option<String>,
}

impl FederationClient {
    /// Create a new federation client targeting a TCP endpoint.
    ///
    /// UDS is not discovered — use [`FederationClient::from_env`] for full transport
    /// resolution.
    #[must_use]
    pub fn new(endpoint: String, node_id: String) -> Self {
        tracing::info!("Initializing federation client for node {node_id}");
        Self {
            endpoint,
            uds_path: None,
            node_id,
            connected: Arc::new(RwLock::new(false)),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    /// Create from environment with capability-socket discovery.
    ///
    /// Reads `FEDERATION_ENDPOINT` for TCP, `SKUNKBAT_ID` for identity,
    /// and probes `$BIOMEOS_SOCKET_DIR/federation.sock` for UDS.
    #[must_use]
    pub fn from_env() -> Self {
        let endpoint = std::env::var("FEDERATION_ENDPOINT").unwrap_or_default();
        let node_id =
            std::env::var("SKUNKBAT_ID").unwrap_or_else(|_| skunk_bat_core::PRIMAL_ID.to_owned());
        let uds_path = {
            let path = crate::rpc::capability_socket("federation");
            std::path::Path::new(&path).exists().then_some(path)
        };
        tracing::info!(
            endpoint = %endpoint,
            uds = ?uds_path,
            "Initializing federation client for node {node_id}"
        );
        Self {
            endpoint,
            uds_path,
            node_id,
            connected: Arc::new(RwLock::new(false)),
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    /// The TCP endpoint this client targets (if any).
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
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

    /// Connect to the federation provider.
    ///
    /// Probes the provider with `health.liveness`.  If unreachable, the
    /// client stays in disconnected state — callers should check
    /// [`FederationClient::is_connected`] before broadcasting.
    ///
    /// # Errors
    ///
    /// Returns `Ok(())` even if the provider is unreachable (graceful
    /// degradation).  The connection state is tracked internally.
    pub async fn connect(&self) -> Result<(), SkunkBatError> {
        tracing::info!("Probing federation provider");

        match self.rpc_call("health.liveness", None).await {
            Ok(_) => {
                *self.connected.write().await = true;
                tracing::info!("Federation connected");
            }
            Err(e) => {
                tracing::warn!("Federation unavailable ({e}), standalone mode");
            }
        }

        Ok(())
    }

    /// Check if connected.
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// Broadcast threat intelligence via JSON-RPC `federation.broadcast`.
    ///
    /// # Errors
    ///
    /// Returns error if the client is not connected or the RPC fails.
    pub async fn broadcast_threat(&self, intel: &ThreatIntelligence) -> Result<(), SkunkBatError> {
        if !self.is_connected().await {
            return Err(SkunkBatError::Integration(
                "Not connected to federation provider".to_string(),
            ));
        }

        let params = serde_json::to_value(intel)
            .map_err(|e| SkunkBatError::Integration(format!("serialize: {e}")))?;

        match self.rpc_call("federation.broadcast", Some(params)).await {
            Ok(_) => {
                tracing::info!(
                    "Broadcast: {} from {} (severity: {})",
                    intel.threat_type,
                    intel.threat_source,
                    intel.severity,
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!("Broadcast failed: {e}");
                Err(SkunkBatError::Integration(format!("broadcast: {e}")))
            }
        }
    }

    /// Subscribe to threat intelligence from federation.
    ///
    /// # Errors
    ///
    /// Returns error if subscription fails.
    pub async fn subscribe_threats(&self) -> Result<(), SkunkBatError> {
        if !self.is_connected().await {
            return Err(SkunkBatError::Integration(
                "Not connected to federation provider".to_string(),
            ));
        }

        match self.rpc_call("federation.subscribe", None).await {
            Ok(_) => {
                tracing::info!("Subscribed to federation threat intel");
                Ok(())
            }
            Err(e) => {
                tracing::warn!("Subscribe failed: {e}");
                Err(SkunkBatError::Integration(format!("subscribe: {e}")))
            }
        }
    }
}

/// Trait for broadcasting threats to federation.
pub trait ThreatBroadcaster: Send + Sync {
    /// Broadcast threat to federation.
    ///
    /// # Errors
    ///
    /// Returns error if broadcast fails.
    fn broadcast(
        &self,
        threat_type: &str,
        source: &str,
        severity: &str,
        description: &str,
    ) -> impl std::future::Future<Output = Result<(), SkunkBatError>> + Send;

    /// Check if connected.
    fn is_connected(&self) -> impl std::future::Future<Output = bool> + Send;
}

/// Federation-backed threat broadcaster.
///
/// Gracefully degrades if no federation provider is available.
pub struct FederationThreatBroadcaster {
    client: FederationClient,
}

impl FederationThreatBroadcaster {
    /// Create a new federation threat broadcaster.
    #[must_use]
    pub fn new(client: FederationClient) -> Self {
        tracing::info!("Initializing federation threat broadcaster");
        Self { client }
    }

    /// Convert threat info to intelligence message.
    fn create_intel(
        &self,
        threat_type: &str,
        source: &str,
        severity: &str,
        description: &str,
    ) -> ThreatIntelligence {
        ThreatIntelligence {
            source_node: self.client.node_id.clone(),
            threat_type: threat_type.to_string(),
            threat_source: source.to_string(),
            severity: severity.to_string(),
            description: description.to_string(),
            detected_at: SystemTime::now(),
            evidence: None,
        }
    }
}

impl ThreatBroadcaster for FederationThreatBroadcaster {
    async fn broadcast(
        &self,
        threat_type: &str,
        source: &str,
        severity: &str,
        description: &str,
    ) -> Result<(), SkunkBatError> {
        tracing::info!("Broadcasting threat to federation: {threat_type}");

        let intel = self.create_intel(threat_type, source, severity, description);

        match self.client.broadcast_threat(&intel).await {
            Ok(()) => {
                tracing::info!("Threat broadcast successful");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Threat broadcast failed: {e}");
                tracing::warn!("Federation unavailable, continuing with local-only defense");
                Ok(())
            }
        }
    }

    async fn is_connected(&self) -> bool {
        self.client.is_connected().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_federation_broadcaster() {
        let client = FederationClient::from_env();
        client.connect().await.expect("connect should not error");

        let broadcaster = FederationThreatBroadcaster::new(client);
        let result = broadcaster
            .broadcast("TestThreat", "test", "Low", "unit test")
            .await;
        assert!(
            result.is_ok(),
            "Should gracefully degrade when disconnected"
        );
    }

    #[tokio::test]
    async fn test_graceful_degradation() {
        let client =
            FederationClient::new("unreachable.invalid:9999".to_string(), "skunkbat".into());

        let broadcaster = FederationThreatBroadcaster::new(client);

        let result = broadcaster
            .broadcast("GeneticViolation", "test-node", "High", "Test threat")
            .await;
        assert!(result.is_ok(), "Should gracefully degrade");
    }

    #[tokio::test]
    async fn test_threat_conversion() {
        let client = FederationClient::new(String::new(), "my-skunkbat".into());
        let broadcaster = FederationThreatBroadcaster::new(client);

        let intel = broadcaster.create_intel(
            "ResourceExhaustion",
            "attacker-node",
            "Critical",
            "DoS attack detected",
        );

        assert_eq!(intel.source_node, "my-skunkbat");
        assert_eq!(intel.threat_source, "attacker-node");
        assert!(intel.threat_type.contains("ResourceExhaustion"));
    }

    #[tokio::test]
    async fn test_standalone_connect() {
        let client = FederationClient::from_env();
        assert!(client.connect().await.is_ok());
    }

    #[tokio::test]
    async fn test_broadcast_without_connect() {
        let client = FederationClient::new(String::new(), "skunkbat".into());
        let result = client
            .broadcast_threat(&ThreatIntelligence {
                source_node: "test".into(),
                threat_type: "test".into(),
                threat_source: "test".into(),
                severity: "Low".into(),
                description: "test".into(),
                detected_at: SystemTime::now(),
                evidence: None,
            })
            .await;
        assert!(result.is_err(), "Should error when not connected");
    }

    #[tokio::test]
    async fn test_subscribe_without_connect() {
        let client = FederationClient::new(String::new(), "skunkbat".into());
        let result = client.subscribe_threats().await;
        assert!(result.is_err(), "Should error when not connected");
    }

    #[tokio::test]
    async fn test_is_connected_default() {
        let client = FederationClient::new("127.0.0.1:1".into(), "test".into());
        assert!(!client.is_connected().await);
    }

    #[tokio::test]
    async fn test_from_env_construction() {
        let client = FederationClient::from_env();
        assert!(!client.is_connected().await);
        assert_eq!(
            client.node_id,
            std::env::var("SKUNKBAT_ID").unwrap_or_else(|_| "skunkbat".into())
        );
    }

    #[tokio::test]
    async fn test_broadcaster_is_connected() {
        let client = FederationClient::new(String::new(), "test".into());
        let broadcaster = FederationThreatBroadcaster::new(client);
        assert!(!broadcaster.is_connected().await);
    }
}

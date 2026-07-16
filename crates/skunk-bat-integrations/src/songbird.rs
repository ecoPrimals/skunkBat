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
fn default_timeout_ms() -> u64 {
    std::env::var(skunk_bat_core::env_keys::SKUNKBAT_INTEGRATION_TIMEOUT_MS)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000)
}

/// Federation client for threat intelligence broadcasting.
///
/// Transport is resolved at runtime — prefers the `federation.sock`
/// capability symlink (UDS), falls back to `FEDERATION_ENDPOINT` (TCP).
#[derive(Clone)]
pub struct FederationClient {
    transport: crate::rpc::CapabilityClient,
    node_id: String,
    connected: Arc<RwLock<bool>>,
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
    pub fn new(endpoint: &str, node_id: String) -> Self {
        tracing::info!("Initializing federation client for node {node_id}");
        Self {
            transport: crate::rpc::CapabilityClient::new(endpoint, default_timeout_ms()),
            node_id,
            connected: Arc::new(RwLock::new(false)),
        }
    }

    /// Create from environment with capability-socket discovery.
    ///
    /// Reads `FEDERATION_ENDPOINT` for TCP, `SKUNKBAT_ID` for identity,
    /// and probes `$BIOMEOS_SOCKET_DIR/federation.sock` for UDS.
    #[must_use]
    pub fn from_env() -> Self {
        let node_id = std::env::var(skunk_bat_core::env_keys::SKUNKBAT_ID)
            .unwrap_or_else(|_| skunk_bat_core::PRIMAL_ID.to_owned());
        tracing::info!("Initializing federation client for node {node_id} from env");
        Self {
            transport: crate::rpc::CapabilityClient::from_env(
                skunk_bat_core::env_keys::FEDERATION_ENDPOINT,
                "federation",
                default_timeout_ms(),
            ),
            node_id,
            connected: Arc::new(RwLock::new(false)),
        }
    }

    /// A string summary of the endpoint for logging (empty if unresolved).
    #[must_use]
    pub fn endpoint(&self) -> String {
        self.transport.endpoint()
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
                tracing::warn!("Federation broadcast failed (local defense unaffected): {e}");
                Err(e)
            }
        }
    }

    async fn is_connected(&self) -> bool {
        self.client.is_connected().await
    }
}

/// Run a background loop that broadcasts detected threats to the federation.
///
/// Monitors the audit log for `ThreatDetected` events and broadcasts them
/// via the `FederationClient`. Probes the federation provider at startup
/// and re-probes on each poll cycle if not connected.
///
/// This function runs indefinitely — spawn it as a Tokio task.
pub async fn run_federation_loop(audit_log: skunk_bat_core::AuditLog, client: FederationClient) {
    use skunk_bat_core::observability::audit_log::{EventKind, EventSeverity};

    let broadcaster = FederationThreatBroadcaster::new(client);
    let mut cursor: u64 = audit_log.latest_seq().await;

    tracing::info!(cursor, "Federation broadcast loop started");

    let poll_secs = std::env::var(skunk_bat_core::env_keys::SKUNKBAT_FEDERATION_POLL_SECS)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10u64);
    let batch_size: usize = std::env::var(skunk_bat_core::env_keys::SKUNKBAT_FEDERATION_BATCH_SIZE)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);

    loop {
        tokio::time::sleep(Duration::from_secs(poll_secs)).await;

        if !broadcaster.is_connected().await {
            if let Err(e) = broadcaster.client.connect().await {
                tracing::debug!("Federation probe failed: {e}");
            }
            if !broadcaster.is_connected().await {
                continue;
            }
        }

        let events = audit_log.query(cursor, batch_size).await;
        if events.is_empty() {
            continue;
        }

        for event in &events {
            if event.severity < EventSeverity::Warn {
                cursor = event.seq;
                continue;
            }

            if let EventKind::ThreatDetected {
                ref threat_type,
                ref severity,
                ref source,
                ..
            } = event.kind
            {
                let desc = format!("{:?}", event.kind);
                if let Err(e) = broadcaster
                    .broadcast(threat_type, source, severity, &desc)
                    .await
                {
                    tracing::debug!("Federation broadcast failed, will retry: {e}");
                    break;
                }
            }

            cursor = event.seq;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_federation_broadcaster_propagates_error() {
        let client = FederationClient::from_env();
        client.connect().await.expect("connect should not error");

        let broadcaster = FederationThreatBroadcaster::new(client);
        let result = broadcaster
            .broadcast("TestThreat", "test", "Low", "unit test")
            .await;
        assert!(
            result.is_err(),
            "Should propagate error when federation unreachable"
        );
    }

    #[tokio::test]
    async fn test_broadcast_error_propagation() {
        let client =
            FederationClient::new("unreachable.invalid:9999", "skunkbat".into());

        let broadcaster = FederationThreatBroadcaster::new(client);

        let result = broadcaster
            .broadcast("GeneticViolation", "test-node", "High", "Test threat")
            .await;
        assert!(result.is_err(), "Should propagate RPC failure to caller");
    }

    #[tokio::test]
    async fn test_threat_conversion() {
        let client = FederationClient::new("", "my-skunkbat".into());
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
        let client = FederationClient::new("", "skunkbat".into());
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
        let client = FederationClient::new("", "skunkbat".into());
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
            std::env::var("SKUNKBAT_ID").unwrap_or_else(|_| skunk_bat_core::PRIMAL_ID.to_owned())
        );
    }

    #[tokio::test]
    async fn test_broadcaster_is_connected() {
        let client = FederationClient::new("", "test".into());
        let broadcaster = FederationThreatBroadcaster::new(client);
        assert!(!broadcaster.is_connected().await);
    }

    #[test]
    fn test_threat_intelligence_serde_roundtrip() {
        let intel = ThreatIntelligence {
            source_node: "sb-01".into(),
            threat_type: "PortScan".into(),
            threat_source: "10.0.0.99".into(),
            severity: "Medium".into(),
            description: "Sequential port probing".into(),
            detected_at: SystemTime::now(),
            evidence: Some("ports 22,80,443 in 200ms".into()),
        };
        let json = serde_json::to_string(&intel).expect("serialize");
        let parsed: ThreatIntelligence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.source_node, "sb-01");
        assert_eq!(parsed.evidence, Some("ports 22,80,443 in 200ms".into()));
    }

    #[test]
    fn test_tcp_endpoint_empty() {
        let client = FederationClient::new("", "x".into());
        assert!(client.tcp_endpoint().is_none());
        assert!(client.endpoint().is_empty());
    }

    #[test]
    fn test_tcp_endpoint_present() {
        let client = FederationClient::new("10.0.0.1:5000".into(), "x".into());
        assert_eq!(client.tcp_endpoint().as_deref(), Some("10.0.0.1:5000"));
        assert_eq!(client.endpoint(), "10.0.0.1:5000");
    }

    #[test]
    fn test_create_intel_all_fields() {
        let client = FederationClient::new("", "node-abc".into());
        let broadcaster = FederationThreatBroadcaster::new(client);
        let intel = broadcaster.create_intel(
            "GeneticViolation",
            "attacker",
            "Critical",
            "Identity mismatch",
        );
        assert_eq!(intel.source_node, "node-abc");
        assert_eq!(intel.threat_type, "GeneticViolation");
        assert_eq!(intel.severity, "Critical");
        assert!(intel.evidence.is_none());
    }

    #[tokio::test]
    async fn federation_loop_starts_without_provider() {
        use skunk_bat_core::observability::audit_log::{
            AuditLog, EventKind, EventSeverity, EventSource,
        };

        let log = AuditLog::new();
        log.record(
            EventSource::ThreatDetection,
            EventSeverity::Warn,
            EventKind::ThreatDetected {
                threat_id: "t-fed-1".to_owned(),
                threat_type: "scan".to_owned(),
                severity: "Medium".to_owned(),
                source: "10.0.0.1".to_owned(),
            },
        )
        .await;

        let client = FederationClient::new("", "test-node".into());
        let log_clone = log.clone();

        let handle = tokio::spawn(async move {
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                run_federation_loop(log_clone, client),
            )
            .await
        });

        let _ = handle.await;
        assert_eq!(log.latest_seq().await, 1);
    }
}

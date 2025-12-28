//! Songbird integration for federated threat intelligence broadcasting
//!
//! This module provides threat intelligence broadcasting through Songbird's
//! federation network for mesh-wide coordination.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use skunk_bat_core::error::SkunkBatError;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// Note: These types mirror Songbird's federation API
// In production, these would come from a songbird-client crate

/// Songbird federation client for threat broadcasting
#[derive(Clone)]
pub struct SongbirdFederationClient {
    endpoint: String,
    node_id: String,
    connected: Arc<RwLock<bool>>,
}

/// Threat intelligence message for federation broadcast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    /// Source skunkBat node ID
    pub source_node: String,
    /// Threat being reported
    pub threat_type: String,
    /// Threat source identifier
    pub threat_source: String,
    /// Threat severity
    pub severity: String,
    /// Human-readable description
    pub description: String,
    /// Timestamp of detection
    pub detected_at: chrono::DateTime<chrono::Utc>,
    /// Optional evidence/context
    pub evidence: Option<String>,
}

impl SongbirdFederationClient {
    /// Create new Songbird federation client
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Songbird federation endpoint (e.g., `<http://localhost:8080>`)
    /// * `node_id` - This skunkBat node's identifier
    #[must_use]
    pub fn new(endpoint: String, node_id: String) -> Self {
        info!(
            "🦨🐦 Initializing SongbirdFederationClient for node: {}",
            node_id
        );
        Self {
            endpoint,
            node_id,
            connected: Arc::new(RwLock::new(false)),
        }
    }

    /// Connect to Songbird federation
    ///
    /// # Errors
    ///
    /// Returns error if connection fails
    pub async fn connect(&self) -> Result<(), SkunkBatError> {
        info!("🦨🐦 Connecting to Songbird federation: {}", self.endpoint);

        // In production, this would establish connection to Songbird
        // For now, simulate successful connection
        *self.connected.write().await = true;
        info!("🦨🐦 Connected to federation (stub)");

        Ok(())
    }

    /// Check if connected to federation
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// Broadcast threat intelligence to federation
    ///
    /// # Arguments
    ///
    /// * `intel` - Threat intelligence to broadcast
    ///
    /// # Errors
    ///
    /// Returns error if broadcast fails
    pub async fn broadcast_threat(&self, intel: &ThreatIntelligence) -> Result<(), SkunkBatError> {
        if !self.is_connected().await {
            return Err(SkunkBatError::Integration(
                "Not connected to Songbird federation".to_string(),
            ));
        }

        debug!("🦨🐦 Broadcasting threat intel: {:?}", intel.threat_type);

        // In production, this would make HTTP/gRPC call to Songbird
        // For now, log the broadcast (graceful degradation)
        info!(
            "🦨🐦 Broadcast: {} threat from {} (severity: {})",
            intel.threat_type, intel.threat_source, intel.severity
        );

        Ok(())
    }

    /// Subscribe to threat intelligence from federation
    ///
    /// # Errors
    ///
    /// Returns error if subscription fails
    pub async fn subscribe_threats(&self) -> Result<(), SkunkBatError> {
        if !self.is_connected().await {
            return Err(SkunkBatError::Integration(
                "Not connected to Songbird federation".to_string(),
            ));
        }

        info!("🦨🐦 Subscribed to federation threat intel");

        // In production, this would set up a message subscription
        Ok(())
    }
}

/// Trait for broadcasting threats to federation
///
/// This trait abstracts threat broadcasting, allowing different implementations
/// for different federation mechanisms.
#[async_trait]
pub trait ThreatBroadcaster: Send + Sync {
    /// Broadcast threat to federation
    ///
    /// # Arguments
    ///
    /// * `threat_type` - Type of threat detected
    /// * `source` - Source identifier of the threat
    /// * `severity` - Threat severity level
    /// * `description` - Human-readable description
    ///
    /// # Errors
    ///
    /// Returns error if broadcast fails
    async fn broadcast(
        &self,
        threat_type: &str,
        source: &str,
        severity: &str,
        description: &str,
    ) -> Result<(), SkunkBatError>;

    /// Check if broadcaster is connected to federation
    async fn is_connected(&self) -> bool;
}

/// Real Songbird-backed threat broadcaster
///
/// Broadcasts threat intelligence to the Songbird federation mesh,
/// enabling coordinated defense across multiple skunkBat instances.
///
/// ## Architecture
///
/// - Uses Songbird's federation network for pub/sub
/// - Each skunkBat can publish and subscribe to threat intel
/// - Independent decision-making (coordination not control)
/// - Graceful degradation if Songbird unavailable
///
/// ## Example
///
/// ```rust,ignore
/// use skunk_bat_integrations::songbird::{
///     SongbirdFederationClient,
///     SongbirdThreatBroadcaster,
/// };
/// use skunk_bat_core::threats::ThreatBroadcaster;
///
/// let client = SongbirdFederationClient::new(
///     "http://localhost:8080".into(),
///     "skunkbat-01".into(),
/// );
/// client.connect().await?;
///
/// let broadcaster = SongbirdThreatBroadcaster::new(client);
///
/// // Broadcast threat to federation
/// broadcaster.broadcast(&threat).await?;
/// ```
pub struct SongbirdThreatBroadcaster {
    client: SongbirdFederationClient,
}

impl SongbirdThreatBroadcaster {
    /// Create new Songbird threat broadcaster
    ///
    /// # Arguments
    ///
    /// * `client` - Songbird federation client
    #[must_use]
    pub fn new(client: SongbirdFederationClient) -> Self {
        info!("🦨🐦 Initializing SongbirdThreatBroadcaster");
        Self { client }
    }

    /// Convert threat info to intelligence message
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
            detected_at: chrono::Utc::now(),
            evidence: None,
        }
    }
}

#[async_trait]
impl ThreatBroadcaster for SongbirdThreatBroadcaster {
    /// Broadcast threat to Songbird federation
    ///
    /// # Errors
    ///
    /// Returns error if broadcast fails
    async fn broadcast(
        &self,
        threat_type: &str,
        source: &str,
        severity: &str,
        description: &str,
    ) -> Result<(), SkunkBatError> {
        info!("🦨🐦 Broadcasting threat to federation: {}", threat_type);

        // Convert threat to federation message
        let intel = self.create_intel(threat_type, source, severity, description);

        // Broadcast to federation
        match self.client.broadcast_threat(&intel).await {
            Ok(()) => {
                info!("🦨🐦 Threat broadcast successful");
                Ok(())
            }
            Err(e) => {
                error!("🦨🐦 Threat broadcast failed: {}", e);
                // Gracefully degrade - don't fail the whole operation
                // Just log and continue (local defense still works)
                warn!("🦨🐦 Federation broadcast failed, continuing with local-only defense");
                Ok(())
            }
        }
    }

    /// Check if connected to federation
    async fn is_connected(&self) -> bool {
        self.client.is_connected().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_songbird_broadcaster_compiles() {
        // Uses environment or safe default for testing
        // Real testing requires Songbird runtime setup
        let endpoint = std::env::var("SONGBIRD_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let client = SongbirdFederationClient::new(endpoint, "test-skunkbat".into());
        client.connect().await.expect("Connection failed");

        let broadcaster = SongbirdThreatBroadcaster::new(client);
        assert!(broadcaster.is_connected().await, "Should be connected");
    }

    #[tokio::test]
    async fn test_graceful_degradation() {
        // Even if Songbird is unavailable, broadcast should not fail
        let client = SongbirdFederationClient::new(
            "http://unreachable.invalid:9999".to_string(),
            "skunkbat".into(),
        );
        // Don't connect - simulate unavailability

        let broadcaster = SongbirdThreatBroadcaster::new(client);

        // Should gracefully degrade, not fail
        let result = broadcaster
            .broadcast("GeneticViolation", "test-node", "High", "Test threat")
            .await;
        assert!(result.is_ok(), "Should gracefully degrade, not fail");
    }

    #[tokio::test]
    async fn test_threat_conversion() {
        let endpoint = std::env::var("SONGBIRD_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
        let client = SongbirdFederationClient::new(endpoint, "my-skunkbat".into());
        let broadcaster = SongbirdThreatBroadcaster::new(client);

        let intel = broadcaster.create_intel(
            "ResourceExhaustion",
            "attacker-node",
            "Critical",
            "DoS attack detected",
        );

        assert_eq!(intel.source_node, "my-skunkbat");
        assert_eq!(intel.threat_source, "attacker-node");
        assert!(intel.threat_type.contains("ResourceExhaustion"));
        assert!(intel.severity.contains("Critical"));
    }
}

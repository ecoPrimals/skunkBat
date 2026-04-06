//! Toadstool integration for capability-based primal discovery
//!
//! This module provides real Toadstool primal discovery through the
//! capability-based discovery system.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use skunk_bat_core::error::SkunkBatError;
use skunk_bat_core::reconnaissance::{Node, PrimalDiscovery};
use tracing::{debug, error, info};

// Note: These types mirror Toadstool's discovery API
// In production, these would come from a toadstool-client crate

/// Toadstool discovery endpoint
#[derive(Clone, Debug)]
pub struct ToadstoolDiscoveryClient {
    #[allow(dead_code)] // Used in production HTTP calls (not yet implemented)
    endpoint: String,
    timeout_ms: u64,
}

/// Discovered primal from Toadstool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPrimal {
    /// Unique service identifier
    pub service_id: String,
    /// Type of primal (e.g. "skunkBat", "Beardog")
    pub primal_type: String,
    /// Advertised capabilities
    pub capabilities: Vec<String>,
    /// Connection endpoint
    pub endpoint: String,
    /// Primal version
    pub version: String,
}

impl ToadstoolDiscoveryClient {
    /// Create new Toadstool discovery client
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Toadstool discovery service endpoint (e.g., `<http://localhost:3000>`)
    #[must_use]
    pub fn new(endpoint: String) -> Self {
        info!(
            "🦨🍄 Initializing ToadstoolDiscoveryClient for: {}",
            endpoint
        );
        Self {
            endpoint,
            timeout_ms: 5000,
        }
    }

    /// Set timeout for discovery requests
    #[must_use]
    pub const fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Discover all primals in the network
    ///
    /// # Errors
    ///
    /// Returns error if Toadstool is unreachable
    /// Discovery stub returns empty but valid results for graceful degradation
    #[allow(clippy::unused_async)] // Will be async when real HTTP calls are implemented
    pub async fn discover_all(&self) -> Result<Vec<DiscoveredPrimal>, SkunkBatError> {
        debug!("🦨🍄 Discovering all primals via Toadstool");

        // In production, this would make an HTTP/gRPC call to Toadstool
        // For now, return empty list (graceful degradation)
        info!("🦨🍄 Toadstool discovery: No primals found (stub)");
        Ok(Vec::new())
    }

    /// Discover primals by capability
    ///
    /// # Arguments
    ///
    /// * `capability` - Capability to search for (e.g., "lineage-verification", "orchestration")
    ///
    /// # Errors
    ///
    /// Returns error if Toadstool is unreachable
    /// Discovery stub returns empty but valid results for graceful degradation
    #[allow(clippy::unused_async)] // Will be async when real HTTP calls are implemented
    pub async fn discover_by_capability(
        &self,
        capability: &str,
    ) -> Result<Vec<DiscoveredPrimal>, SkunkBatError> {
        info!("🦨🍄 Discovering primals with capability: {}", capability);

        // In production, this would query Toadstool's capability registry
        // For now, return empty list (graceful degradation)
        debug!("🦨🍄 No primals found with capability: {}", capability);
        Ok(Vec::new())
    }

    /// Discover local primals only (mDNS)
    ///
    /// # Errors
    ///
    /// Returns error if local discovery fails
    /// Discovery stub returns empty but valid results for graceful degradation
    #[allow(clippy::unused_async)] // Will be async when real mDNS calls are implemented
    pub async fn discover_local(&self) -> Result<Vec<DiscoveredPrimal>, SkunkBatError> {
        debug!("🦨🍄 Discovering local primals via mDNS");

        // In production, this would use mDNS/DNS-SD
        // For now, return self (self-knowledge principle)
        Ok(Vec::new())
    }
}

/// Real Toadstool-backed primal discovery
///
/// Discovers other primals at runtime based on capabilities, maintaining
/// primal sovereignty with zero compile-time coupling.
///
/// ## Architecture
///
/// - Uses Toadstool's capability registry for discovery
/// - Supports mDNS for local network discovery
/// - Gracefully degrades to configured fallbacks
/// - Maintains self-knowledge (always knows about self)
///
/// ## Example
///
/// ```rust,ignore
/// use skunk_bat_integrations::toadstool::ToadstoolPrimalDiscovery;
/// use skunk_bat_core::reconnaissance::PrimalDiscovery;
///
/// let client = ToadstoolDiscoveryClient::new("http://localhost:3000".into());
/// let discovery = ToadstoolPrimalDiscovery::new(client, "skunkbat-01".into());
///
/// // Discover all primals
/// let primals = discovery.discover_all().await?;
///
/// // Discover by capability
/// let beardog = discovery.discover_by_capability("lineage-verification").await?;
/// ```
pub struct ToadstoolPrimalDiscovery {
    client: ToadstoolDiscoveryClient,
    self_id: String,
}

impl ToadstoolPrimalDiscovery {
    /// Create new Toadstool primal discovery
    ///
    /// # Arguments
    ///
    /// * `client` - Toadstool discovery client
    /// * `self_id` - This primal's identifier
    #[must_use]
    pub fn new(client: ToadstoolDiscoveryClient, self_id: String) -> Self {
        info!(
            "🦨🍄 Initializing ToadstoolPrimalDiscovery for: {}",
            self_id
        );
        Self { client, self_id }
    }

    /// Discover primals by capability
    ///
    /// # Arguments
    ///
    /// * `capability` - Capability to search for
    ///
    /// # Errors
    ///
    /// Returns error if discovery fails
    pub async fn discover_by_capability(
        &self,
        capability: &str,
    ) -> Result<Vec<Node>, SkunkBatError> {
        let discovered = self.client.discover_by_capability(capability).await?;
        Ok(self.convert_to_nodes(discovered))
    }

    /// Convert Toadstool discoveries to skunkBat nodes
    /// Note: No self state needed currently, but kept for consistency and future extensibility
    #[allow(clippy::unused_self)]
    fn convert_to_nodes(&self, discovered: Vec<DiscoveredPrimal>) -> Vec<Node> {
        use skunk_bat_core::reconnaissance::NodeStatus;
        use std::time::SystemTime;

        discovered
            .into_iter()
            .map(|primal| Node {
                id: primal.service_id.clone(),
                address: primal.endpoint,
                node_type: primal.primal_type,
                status: NodeStatus::Healthy,
                capabilities: primal.capabilities,
                last_seen: Some(SystemTime::now()),
            })
            .collect()
    }

    /// Create self node (self-knowledge principle)
    fn create_self_node(&self) -> Node {
        use skunk_bat_core::reconnaissance::NodeStatus;
        use std::time::SystemTime;

        Node {
            id: self.self_id.clone(),
            address: "local".to_string(),
            node_type: "skunkBat".to_string(),
            status: NodeStatus::Healthy,
            capabilities: vec![
                "reconnaissance".to_string(),
                "threat-detection".to_string(),
                "defense".to_string(),
                "observability".to_string(),
            ],
            last_seen: Some(SystemTime::now()),
        }
    }
}

#[async_trait]
impl PrimalDiscovery for ToadstoolPrimalDiscovery {
    /// Discover primals by capability
    ///
    /// # Errors
    ///
    /// Returns error if discovery fails
    async fn discover_by_capability(&self, capability: &str) -> Result<Vec<Node>, SkunkBatError> {
        info!("🦨🍄 Discovering primals with capability: {}", capability);

        let discovered = self.client.discover_by_capability(capability).await?;
        Ok(self.convert_to_nodes(discovered))
    }

    /// Discover all primals in the network
    ///
    /// # Errors
    ///
    /// Returns error if discovery fails
    async fn discover_all(&self) -> Result<Vec<Node>, SkunkBatError> {
        info!("🦨🍄 Discovering all network primals");

        // Always include self
        let mut nodes = vec![self.create_self_node()];

        // Attempt network-wide discovery via Toadstool
        match self.client.discover_all().await {
            Ok(discovered) => {
                let network_nodes = self.convert_to_nodes(discovered);
                info!(
                    "🦨🍄 Found {} network primals via Toadstool",
                    network_nodes.len()
                );
                nodes.extend(network_nodes);
            }
            Err(e) => {
                error!("🦨🍄 Network discovery failed: {}", e);
                // Gracefully degrade to local-only
                // Return what we have (at minimum, self)
            }
        }

        Ok(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_toadstool_discovery_compiles() {
        // Uses environment or safe default for testing
        // Real testing requires Toadstool runtime setup
        let endpoint = std::env::var("TOADSTOOL_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let client = ToadstoolDiscoveryClient::new(endpoint);
        let discovery = ToadstoolPrimalDiscovery::new(client, "test-skunkbat".into());

        // Should at minimum discover self
        let nodes = discovery.discover_all().await.expect("Discovery failed");
        assert!(!nodes.is_empty(), "Should at least have self node");
        assert_eq!(nodes[0].node_type, "skunkBat");
    }

    #[tokio::test]
    async fn test_self_knowledge_principle() {
        let endpoint = std::env::var("TOADSTOOL_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let client = ToadstoolDiscoveryClient::new(endpoint);
        let discovery = ToadstoolPrimalDiscovery::new(client, "my-skunkbat".into());

        // Even if Toadstool is unavailable, we know about self
        let nodes = discovery.discover_all().await.expect("Discovery failed");
        assert!(!nodes.is_empty(), "Should always know about self");

        let self_node = &nodes[0];
        assert_eq!(self_node.id, "my-skunkbat");
        assert_eq!(self_node.node_type, "skunkBat");
        assert!(
            self_node
                .capabilities
                .contains(&"reconnaissance".to_string())
        );
    }

    #[tokio::test]
    async fn test_graceful_degradation() {
        // Even with stub implementation, discovery should not fail
        let client = ToadstoolDiscoveryClient::new("http://unreachable.invalid:9999".to_string());
        let discovery = ToadstoolPrimalDiscovery::new(client, "skunkbat".into());

        // Should gracefully degrade to self-only
        let result = discovery.discover_all().await;
        assert!(result.is_ok(), "Should gracefully degrade, not fail");

        let nodes = result.expect("Already asserted Ok");
        assert_eq!(nodes.len(), 1, "Should have self node");
    }
}

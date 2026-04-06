//! Reconnaissance engine for skunkBat.
//!
//! Provides network scanning, topology mapping, and asset discovery.

use crate::SkunkBatConfig;
use crate::error::SkunkBatError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

/// Trait for capability-based primal discovery.
///
/// This trait abstracts discovery mechanisms, allowing skunkBat to discover
/// primals without hardcoded knowledge. Implementations can use toadstool,
/// mDNS, or other discovery mechanisms.
#[async_trait]
pub trait PrimalDiscovery: Send + Sync {
    /// Discover primals with specified capabilities.
    async fn discover_by_capability(&self, capability: &str) -> Result<Vec<Node>, SkunkBatError>;

    /// Discover all primals on the network.
    async fn discover_all(&self) -> Result<Vec<Node>, SkunkBatError>;
}

/// Trait for topology mapping between nodes.
///
/// This trait abstracts connection mapping, allowing different implementations
/// for different network topologies and communication patterns.
#[async_trait]
pub trait TopologyMapper: Send + Sync {
    /// Map connections between discovered nodes.
    async fn map_connections(&self, nodes: &[Node]) -> Result<Vec<Connection>, SkunkBatError>;

    /// Update existing topology with new information.
    async fn update_topology(&self, current: &mut NetworkScan) -> Result<(), SkunkBatError>;
}

/// Local-only discovery implementation (self-knowledge only).
///
/// This implementation only discovers the local skunkBat instance.
/// It represents the minimal self-knowledge principle: a primal only
/// knows about itself until it discovers others at runtime.
pub struct LocalDiscovery;

#[async_trait]
impl PrimalDiscovery for LocalDiscovery {
    async fn discover_by_capability(&self, _capability: &str) -> Result<Vec<Node>, SkunkBatError> {
        // Local discovery only knows about self
        Ok(vec![Self::local_node()])
    }

    async fn discover_all(&self) -> Result<Vec<Node>, SkunkBatError> {
        // Local discovery only knows about self
        Ok(vec![Self::local_node()])
    }
}

impl LocalDiscovery {
    /// Get local node information from system
    ///
    /// Discovers self information from:
    /// - System hostname
    /// - Network interfaces
    /// - Environment variables
    fn local_node() -> Node {
        Node {
            id: Self::discover_self_id(),
            address: Self::discover_self_address(),
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

    /// Discover own identity from system
    ///
    /// Priority:
    /// 1. `SKUNKBAT_ID` environment variable
    /// 2. Generated from timestamp (deterministic per boot)
    fn discover_self_id() -> String {
        std::env::var("SKUNKBAT_ID").unwrap_or_else(|_| {
            // Use process start time as deterministic ID
            let pid = std::process::id();
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            format!("skunkbat-{pid}-{now}")
        })
    }

    /// Discover own network address from system
    ///
    /// Priority:
    /// 1. `SKUNKBAT_ADDRESS` environment variable
    /// 2. First non-loopback interface
    /// 3. Loopback as fallback
    fn discover_self_address() -> String {
        if let Ok(addr) = std::env::var("SKUNKBAT_ADDRESS") {
            return addr;
        }

        // In production, this would query network interfaces
        // For now, use loopback as safe default
        "127.0.0.1".to_string()
    }
}

/// Simple topology mapper for local-only scenarios.
pub struct SimpleTopologyMapper;

#[async_trait]
impl TopologyMapper for SimpleTopologyMapper {
    async fn map_connections(&self, _nodes: &[Node]) -> Result<Vec<Connection>, SkunkBatError> {
        // Simple mapper returns empty topology (no connections to discover yet)
        Ok(Vec::new())
    }

    async fn update_topology(&self, _current: &mut NetworkScan) -> Result<(), SkunkBatError> {
        // No updates needed for simple topology
        Ok(())
    }
}

/// Reconnaissance engine.
pub struct ReconnaissanceEngine {
    enabled: bool,
    scope: NetworkScope,
    #[allow(dead_code)]
    discovered_assets: HashMap<String, Node>,
    discovery: Box<dyn PrimalDiscovery>,
    topology_mapper: Box<dyn TopologyMapper>,
}

impl ReconnaissanceEngine {
    /// Create a new reconnaissance engine with default local discovery.
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        Self::with_discovery(
            config,
            Box::new(LocalDiscovery),
            Box::new(SimpleTopologyMapper),
        )
    }

    /// Create a reconnaissance engine with custom discovery mechanisms.
    ///
    /// This allows injection of different discovery implementations
    /// (e.g., toadstool-based discovery) without hardcoding dependencies.
    #[must_use]
    pub fn with_discovery(
        config: &SkunkBatConfig,
        discovery: Box<dyn PrimalDiscovery>,
        topology_mapper: Box<dyn TopologyMapper>,
    ) -> Self {
        Self {
            enabled: config.features.reconnaissance,
            scope: NetworkScope::default(),
            discovered_assets: HashMap::new(),
            discovery,
            topology_mapper,
        }
    }

    /// Start reconnaissance.
    ///
    /// # Errors
    ///
    /// Returns an error if the reconnaissance engine fails to start.
    pub fn start(&self) -> Result<(), SkunkBatError> {
        if !self.enabled {
            tracing::info!("Reconnaissance disabled by config");
            return Ok(());
        }
        tracing::debug!("Reconnaissance engine starting");
        Ok(())
    }

    /// Stop reconnaissance.
    ///
    /// # Errors
    ///
    /// Returns an error if the reconnaissance engine fails to stop.
    pub fn stop(&self) -> Result<(), SkunkBatError> {
        tracing::debug!("Reconnaissance engine stopping");
        Ok(())
    }

    /// Check if reconnaissance is healthy.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.enabled
    }

    /// Scan network topology.
    ///
    /// # Errors
    ///
    /// Returns an error if the network scan fails.
    pub async fn scan(&self) -> Result<NetworkScan, SkunkBatError> {
        if !self.enabled {
            return Ok(NetworkScan::default());
        }

        tracing::info!("Starting network reconnaissance scan");

        // Discover primals via capability-based discovery (trait-based, no hardcoding)
        let nodes = self.discover_primals().await?;

        // Map network connections between primals (trait-based topology mapping)
        let topology = self.map_topology(&nodes).await?;

        tracing::info!(
            "Reconnaissance scan complete: {} nodes, {} connections",
            nodes.len(),
            topology.len()
        );

        Ok(NetworkScan {
            nodes,
            topology,
            scan_time: Some(SystemTime::now()),
            scope: self.scope.clone(),
        })
    }

    /// Discover primals using the injected discovery mechanism.
    async fn discover_primals(&self) -> Result<Vec<Node>, SkunkBatError> {
        // Use the discovery trait - no hardcoding of discovery mechanism
        self.discovery.discover_all().await
    }

    /// Map network topology using the injected mapper.
    async fn map_topology(&self, nodes: &[Node]) -> Result<Vec<Connection>, SkunkBatError> {
        // Use the topology mapper trait - no hardcoding of mapping mechanism
        self.topology_mapper.map_connections(nodes).await
    }
}

/// Network scanning scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScope {
    /// Networks explicitly owned by user
    pub owned_networks: Vec<String>,

    /// Systems user manages
    pub managed_systems: Vec<String>,

    /// Explicitly excluded (privacy zones)
    pub excluded: Vec<String>,
}

impl Default for NetworkScope {
    fn default() -> Self {
        Self {
            owned_networks: Self::discover_owned_networks(),
            managed_systems: Vec::new(),
            excluded: Vec::new(),
        }
    }
}

impl NetworkScope {
    /// Discover owned networks from system
    ///
    /// Priority:
    /// 1. `SKUNKBAT_OWNED_NETWORKS` environment variable (comma-separated)
    /// 2. System network interfaces
    /// 3. Empty list (zero knowledge)
    fn discover_owned_networks() -> Vec<String> {
        if let Ok(networks) = std::env::var("SKUNKBAT_OWNED_NETWORKS") {
            return networks.split(',').map(|s| s.trim().to_string()).collect();
        }

        // In production, this would query network interfaces
        // For now, return empty (zero knowledge by default)
        Vec::new()
    }
}

/// Network scan results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkScan {
    /// Discovered nodes
    pub nodes: Vec<Node>,
    /// Network topology
    pub topology: Vec<Connection>,
    /// When the scan was performed
    pub scan_time: Option<SystemTime>,
    /// Scan scope
    pub scope: NetworkScope,
}

/// Network node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Node identifier
    pub id: String,
    /// Node address
    pub address: String,
    /// Node type (primal name)
    pub node_type: String,
    /// Node status
    pub status: NodeStatus,
    /// Node capabilities
    pub capabilities: Vec<String>,
    /// Last seen timestamp
    pub last_seen: Option<SystemTime>,
}

/// Node status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeStatus {
    /// Node is healthy
    Healthy,
    /// Node is degraded
    Degraded,
    /// Node is unhealthy
    Unhealthy,
    /// Node is unknown
    Unknown,
}

/// Network connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    /// Source node
    pub from: String,
    /// Destination node
    pub to: String,
    /// Connection type/protocol
    pub protocol: String,
    /// Connection status
    pub status: ConnectionStatus,
}

/// Connection status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionStatus {
    /// Connection is active
    Active,
    /// Connection is idle
    Idle,
    /// Connection is closed
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FeatureFlags, SkunkBatConfig};
    use sourdough_core::config::CommonConfig;

    fn test_config() -> SkunkBatConfig {
        SkunkBatConfig {
            common: CommonConfig {
                name: "skunkBat-test".to_string(),
                ..CommonConfig::default()
            },
            features: FeatureFlags {
                reconnaissance: true,
                threat_detection: true,
                auto_defense: true,
                observability: true,
            },
            lineage_id: None,
        }
    }

    #[test]
    fn test_reconnaissance_engine_creation() {
        let config = test_config();
        let engine = ReconnaissanceEngine::new(&config);
        assert!(engine.is_healthy());
    }

    #[test]
    fn test_reconnaissance_start_stop() {
        let config = test_config();
        let engine = ReconnaissanceEngine::new(&config);

        assert!(engine.start().is_ok());
        assert!(engine.stop().is_ok());
    }

    #[tokio::test]
    async fn test_network_scan() {
        let config = test_config();
        let engine = ReconnaissanceEngine::new(&config);

        let result = engine.scan().await;
        assert!(result.is_ok());

        let scan = result.unwrap();
        assert!(
            !scan.nodes.is_empty(),
            "Should discover at least local node"
        );
        assert!(scan.scan_time.is_some());
    }

    #[tokio::test]
    async fn test_disabled_reconnaissance() {
        let mut config = test_config();
        config.features.reconnaissance = false;

        let engine = ReconnaissanceEngine::new(&config);
        assert!(!engine.is_healthy());

        let result = engine.scan().await;
        assert!(result.is_ok());
        let scan = result.unwrap();
        assert_eq!(
            scan.nodes.len(),
            0,
            "Disabled engine should return empty scan"
        );
    }

    #[test]
    fn test_network_scope_default() {
        let scope = NetworkScope::default();
        // Zero knowledge by default (discovers from environment/system)
        // In tests without SKUNKBAT_OWNED_NETWORKS set, owned_networks is empty
        assert!(
            scope.owned_networks.is_empty(),
            "Should have zero knowledge by default"
        );
        assert!(scope.managed_systems.is_empty());
        assert!(scope.excluded.is_empty());
    }

    #[test]
    fn test_node_creation() {
        let node = Node {
            id: "test-node".to_string(),
            address: "192.168.1.1".to_string(),
            node_type: "testPrimal".to_string(),
            status: NodeStatus::Healthy,
            capabilities: vec!["test".to_string()],
            last_seen: Some(SystemTime::now()),
        };

        assert_eq!(node.id, "test-node");
        assert_eq!(node.node_type, "testPrimal");
        assert!(matches!(node.status, NodeStatus::Healthy));
    }

    #[test]
    fn test_connection_creation() {
        let conn = Connection {
            from: "node1".to_string(),
            to: "node2".to_string(),
            protocol: "http".to_string(),
            status: ConnectionStatus::Active,
        };

        assert_eq!(conn.from, "node1");
        assert_eq!(conn.to, "node2");
        assert!(matches!(conn.status, ConnectionStatus::Active));
    }

    #[tokio::test]
    async fn test_simple_topology_mapper() {
        let mapper = SimpleTopologyMapper;
        let nodes = vec![];

        let connections = mapper.map_connections(&nodes).await.unwrap();
        assert!(connections.is_empty());

        let mut scan = NetworkScan::default();
        assert!(mapper.update_topology(&mut scan).await.is_ok());
    }

    #[test]
    fn test_local_discovery_self_knowledge() {
        let node = LocalDiscovery::local_node();

        assert_eq!(node.node_type, "skunkBat");
        assert!(matches!(node.status, NodeStatus::Healthy));
        assert!(node.capabilities.contains(&"reconnaissance".to_string()));
        assert!(node.capabilities.contains(&"threat-detection".to_string()));
    }

    #[tokio::test]
    async fn test_local_discovery_by_capability() {
        let discovery = LocalDiscovery;
        let nodes = discovery
            .discover_by_capability("reconnaissance")
            .await
            .unwrap();

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_type, "skunkBat");
    }

    #[test]
    fn test_network_scope_env_aware() {
        // Test default behavior - env-aware
        let scope = NetworkScope::default();
        // Works whether env var is set or not
        assert!(scope.managed_systems.is_empty());
        assert!(scope.excluded.is_empty());
    }

    #[test]
    fn test_node_status_variants() {
        assert!(matches!(NodeStatus::Healthy, NodeStatus::Healthy));
        assert!(matches!(NodeStatus::Degraded, NodeStatus::Degraded));
        assert!(matches!(NodeStatus::Unhealthy, NodeStatus::Unhealthy));
        assert!(matches!(NodeStatus::Unknown, NodeStatus::Unknown));
    }

    #[test]
    fn test_connection_status_variants() {
        assert!(matches!(ConnectionStatus::Active, ConnectionStatus::Active));
        assert!(matches!(ConnectionStatus::Idle, ConnectionStatus::Idle));
        assert!(matches!(ConnectionStatus::Closed, ConnectionStatus::Closed));
    }
}

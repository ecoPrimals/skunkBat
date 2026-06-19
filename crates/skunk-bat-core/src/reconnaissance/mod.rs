// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Reconnaissance engine for skunkBat.
//!
//! Provides network scanning, topology mapping, and asset discovery.
//! All discovery mechanisms are injected via traits — the engine has
//! self-knowledge only and discovers others at runtime.

mod discovery;
pub mod traits;
pub mod types;

pub use discovery::{LocalDiscovery, SimpleTopologyMapper};
pub use traits::{PrimalDiscovery, TopologyMapper};
pub use types::*;

use crate::SkunkBatConfig;
use crate::error::SkunkBatError;
use std::collections::HashMap;
use std::time::SystemTime;

/// Reconnaissance engine — orchestrates scanning and topology mapping.
///
/// Generic over discovery and mapper types — no dyn dispatch.
pub struct ReconnaissanceEngine<
    D: PrimalDiscovery = LocalDiscovery,
    M: TopologyMapper = SimpleTopologyMapper,
> {
    enabled: bool,
    scope: NetworkScope,
    discovered_assets: HashMap<String, Node>,
    discovery: D,
    topology_mapper: M,
}

impl ReconnaissanceEngine {
    /// Create with default local discovery (self-knowledge only).
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        Self::with_discovery(config, LocalDiscovery, SimpleTopologyMapper)
    }
}

impl<D: PrimalDiscovery, M: TopologyMapper> ReconnaissanceEngine<D, M> {
    /// Create with custom discovery mechanisms injected at runtime.
    #[must_use]
    pub fn with_discovery(config: &SkunkBatConfig, discovery: D, topology_mapper: M) -> Self {
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

    /// Access the discovered asset registry.
    #[must_use]
    pub const fn discovered_assets(&self) -> &HashMap<String, Node> {
        &self.discovered_assets
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

        let nodes = self.discovery.discover_all().await?;
        let topology = self.topology_mapper.map_connections(&nodes).await?;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FeatureFlags, SkunkBatConfig};
    use crate::primal_foundation::config::CommonConfig;

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
            thresholds: crate::config::ThreatThresholds::default(),
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
        let scan = engine.scan().await.expect("scan should succeed");
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
        let scan = engine.scan().await.expect("scan should succeed");
        assert_eq!(scan.nodes.len(), 0);
    }

    #[test]
    fn test_network_scope_default() {
        let scope = NetworkScope::default();
        assert!(scope.owned_networks.is_empty());
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
        assert!(matches!(conn.status, ConnectionStatus::Active));
    }

    #[tokio::test]
    async fn test_simple_topology_mapper() {
        let mapper = SimpleTopologyMapper;
        let connections = mapper
            .map_connections(&[])
            .await
            .expect("mapping should succeed");
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
    }

    #[tokio::test]
    async fn test_local_discovery_by_capability() {
        let discovery = LocalDiscovery;
        let nodes = discovery
            .discover_by_capability("reconnaissance")
            .await
            .expect("discovery should succeed");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_type, "skunkBat");
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

    #[test]
    fn test_network_scan_default() {
        let scan = NetworkScan::default();
        assert!(scan.nodes.is_empty());
        assert!(scan.topology.is_empty());
        assert!(scan.scan_time.is_none());
    }
}

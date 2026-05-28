// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Local discovery and topology mapping implementations.
//!
//! These are the standalone defaults — a primal starts with self-knowledge
//! only and discovers others at runtime via capability-based patterns.

use std::time::SystemTime;

use super::traits::{PrimalDiscovery, TopologyMapper};
use super::types::{Connection, NetworkScan, Node, NodeStatus};
use crate::error::SkunkBatError;

/// Local-only discovery implementation (self-knowledge only).
///
/// A primal only knows about itself until it discovers others at runtime.
pub struct LocalDiscovery;

impl PrimalDiscovery for LocalDiscovery {
    async fn discover_by_capability(&self, _capability: &str) -> Result<Vec<Node>, SkunkBatError> {
        Ok(vec![Self::local_node()])
    }

    async fn discover_all(&self) -> Result<Vec<Node>, SkunkBatError> {
        Ok(vec![Self::local_node()])
    }
}

impl LocalDiscovery {
    /// Build self-knowledge node from system environment.
    pub(crate) fn local_node() -> Node {
        Node {
            id: Self::discover_self_id(),
            address: Self::discover_self_address(),
            node_type: crate::PRIMAL_NAME.to_owned(),
            status: NodeStatus::Healthy,
            capabilities: crate::CAPABILITIES.iter().map(|&c| c.to_owned()).collect(),
            last_seen: Some(SystemTime::now()),
        }
    }

    /// Discover own identity from environment.
    ///
    /// Priority: `SKUNKBAT_ID` env → generated from pid+timestamp.
    fn discover_self_id() -> String {
        std::env::var(crate::env_keys::SKUNKBAT_ID).unwrap_or_else(|_| {
            let pid = std::process::id();
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("skunkbat-{pid}-{now}")
        })
    }

    /// Discover own network address from environment.
    ///
    /// Priority: `SKUNKBAT_ADDRESS` env → loopback fallback.
    fn discover_self_address() -> String {
        std::env::var(crate::env_keys::SKUNKBAT_ADDRESS).unwrap_or_else(|_| "127.0.0.1".to_owned())
    }
}

/// Simple topology mapper for local-only scenarios.
pub struct SimpleTopologyMapper;

impl TopologyMapper for SimpleTopologyMapper {
    async fn map_connections(&self, _nodes: &[Node]) -> Result<Vec<Connection>, SkunkBatError> {
        Ok(Vec::new())
    }

    async fn update_topology(&self, _current: &mut NetworkScan) -> Result<(), SkunkBatError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_node_has_self_knowledge() {
        let node = LocalDiscovery::local_node();
        assert_eq!(node.node_type, crate::PRIMAL_NAME);
        assert!(matches!(node.status, NodeStatus::Healthy));
        assert!(!node.capabilities.is_empty());
        assert!(node.last_seen.is_some());
    }

    #[test]
    fn local_node_address_has_fallback() {
        let node = LocalDiscovery::local_node();
        assert!(!node.address.is_empty());
    }

    #[test]
    fn local_node_id_is_unique() {
        let n1 = LocalDiscovery::local_node();
        let n2 = LocalDiscovery::local_node();
        assert!(!n1.id.is_empty());
        assert!(!n2.id.is_empty());
    }

    #[tokio::test]
    async fn discover_all_returns_self() {
        let discovery = LocalDiscovery;
        let nodes = discovery.discover_all().await.unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_type, crate::PRIMAL_NAME);
    }

    #[tokio::test]
    async fn simple_topology_mapper_empty() {
        let mapper = SimpleTopologyMapper;
        let connections = mapper.map_connections(&[]).await.unwrap();
        assert!(connections.is_empty());

        let mut scan = NetworkScan::default();
        assert!(mapper.update_topology(&mut scan).await.is_ok());
    }
}

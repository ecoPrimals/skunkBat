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

    /// Discover own identity from environment.
    ///
    /// Priority: `SKUNKBAT_ID` env → generated from pid+timestamp.
    fn discover_self_id() -> String {
        std::env::var("SKUNKBAT_ID").unwrap_or_else(|_| {
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
        std::env::var("SKUNKBAT_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string())
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

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Reconnaissance data types.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

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
    /// Discover owned networks from environment.
    ///
    /// Reads `SKUNKBAT_OWNED_NETWORKS` (comma-separated) or returns empty
    /// (zero-knowledge default).
    fn discover_owned_networks() -> Vec<String> {
        if let Ok(networks) = std::env::var("SKUNKBAT_OWNED_NETWORKS") {
            return networks.split(',').map(|s| s.trim().to_string()).collect();
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_scan_default() {
        let scan = NetworkScan::default();
        assert!(scan.nodes.is_empty());
        assert!(scan.topology.is_empty());
        assert!(scan.scan_time.is_none());
    }

    #[test]
    fn network_scope_default() {
        let scope = NetworkScope::default();
        assert!(scope.managed_systems.is_empty());
        assert!(scope.excluded.is_empty());
    }

    #[test]
    fn node_status_variants() {
        let statuses = [
            NodeStatus::Healthy,
            NodeStatus::Degraded,
            NodeStatus::Unhealthy,
            NodeStatus::Unknown,
        ];
        for s in &statuses {
            let json = serde_json::to_string(s).expect("serialize");
            let _: NodeStatus = serde_json::from_str(&json).expect("deserialize");
        }
    }

    #[test]
    fn connection_status_variants() {
        let statuses = [
            ConnectionStatus::Active,
            ConnectionStatus::Idle,
            ConnectionStatus::Closed,
        ];
        for s in &statuses {
            let json = serde_json::to_string(s).expect("serialize");
            let _: ConnectionStatus = serde_json::from_str(&json).expect("deserialize");
        }
    }

    #[test]
    fn node_serde_roundtrip() {
        let node = Node {
            id: "node-1".into(),
            address: "10.0.0.1".into(),
            node_type: "skunkBat".into(),
            status: NodeStatus::Healthy,
            capabilities: vec!["defense".into()],
            last_seen: Some(SystemTime::now()),
        };
        let json = serde_json::to_string(&node).expect("serialize");
        let parsed: Node = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.id, "node-1");
    }

    #[test]
    fn connection_serde_roundtrip() {
        let conn = Connection {
            from: "a".into(),
            to: "b".into(),
            protocol: "jsonrpc".into(),
            status: ConnectionStatus::Active,
        };
        let json = serde_json::to_string(&conn).expect("serialize");
        let parsed: Connection = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.protocol, "jsonrpc");
    }
}

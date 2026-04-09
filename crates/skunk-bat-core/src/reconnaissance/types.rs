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

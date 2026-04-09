// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Reconnaissance trait abstractions.
//!
//! Discovery and topology mapping are injected at runtime via these
//! traits — no primal names are embedded.

use async_trait::async_trait;

use super::types::{Connection, NetworkScan, Node};
use crate::error::SkunkBatError;

/// Capability-based primal discovery.
///
/// Implementations may use toadstool, mDNS, filesystem sockets, or any
/// discovery mechanism announced at runtime.
#[async_trait]
pub trait PrimalDiscovery: Send + Sync {
    /// Discover primals with specified capabilities.
    async fn discover_by_capability(&self, capability: &str) -> Result<Vec<Node>, SkunkBatError>;

    /// Discover all primals on the network.
    async fn discover_all(&self) -> Result<Vec<Node>, SkunkBatError>;
}

/// Topology mapping between nodes.
///
/// Abstracts connection mapping for different network topologies and
/// communication patterns.
#[async_trait]
pub trait TopologyMapper: Send + Sync {
    /// Map connections between discovered nodes.
    async fn map_connections(&self, nodes: &[Node]) -> Result<Vec<Connection>, SkunkBatError>;

    /// Update existing topology with new information.
    async fn update_topology(&self, current: &mut NetworkScan) -> Result<(), SkunkBatError>;
}

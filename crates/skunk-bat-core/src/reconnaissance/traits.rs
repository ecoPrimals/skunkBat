// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Reconnaissance trait abstractions.
//!
//! Discovery and topology mapping are injected at runtime via these
//! traits — no primal names are embedded. All traits use native
//! `async fn` (RPITIT) — no `#[async_trait]` or `dyn` dispatch.

use std::future::Future;

use super::types::{Connection, NetworkScan, Node};
use crate::error::SkunkBatError;

/// Capability-based primal discovery.
///
/// Implementations may use toadstool, mDNS, filesystem sockets, or any
/// discovery mechanism announced at runtime.
pub trait PrimalDiscovery: Send + Sync {
    /// Discover primals with specified capabilities.
    fn discover_by_capability(
        &self,
        capability: &str,
    ) -> impl Future<Output = Result<Vec<Node>, SkunkBatError>> + Send;

    /// Discover all primals on the network.
    fn discover_all(&self) -> impl Future<Output = Result<Vec<Node>, SkunkBatError>> + Send;
}

/// Topology mapping between nodes.
///
/// Abstracts connection mapping for different network topologies and
/// communication patterns.
pub trait TopologyMapper: Send + Sync {
    /// Map connections between discovered nodes.
    fn map_connections(
        &self,
        nodes: &[Node],
    ) -> impl Future<Output = Result<Vec<Connection>, SkunkBatError>> + Send;

    /// Update existing topology with new information.
    fn update_topology(
        &self,
        current: &mut NetworkScan,
    ) -> impl Future<Output = Result<(), SkunkBatError>> + Send;
}

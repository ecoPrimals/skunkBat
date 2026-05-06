// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Universal Adapter for capability-based primal discovery.
//!
//! **Status: Experimental API** — this module provides the local data structures
//! for capability indexing but is not yet wired into the main `SkunkBat` runtime
//! path. Production discovery uses `ipc.register` + `ipc.resolve` via
//! `skunk-bat-integrations`. This module is retained for future in-process
//! capability routing when multiple subsystems share a process.
//!
//! The Universal Adapter enables primals to:
//! - Announce their capabilities without naming themselves
//! - Discover other primals by capability (not by name)
//! - Build network effects without N² connections
//!
//! # Philosophy: "Zero Knowledge Bootstrap"
//!
//! Each primal starts like an infant:
//! 1. Discovers self from system
//! 2. Announces capabilities to adapter
//! 3. Discovers others by asking "who can do X?" (not "where is Y?")
//! 4. Uses services without knowing their primal identity
//!
//! # Example
//!
//! ```no_run
//! use skunk_bat_core::universal_adapter::{LocalUniversalAdapter, Capability, UniversalAdapter};
//! use std::collections::HashMap;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Create adapter
//! let adapter = LocalUniversalAdapter::new();
//!
//! // 2. Announce self (only self-knowledge)
//! adapter.announce(Capability {
//!     primal_id: "skunkbat-xyz".into(),
//!     capabilities: vec!["threat-detection".into(), "reconnaissance".into()],
//!     endpoint: "http://127.0.0.1:8000".into(),
//!     metadata: HashMap::new(),
//! }).await?;
//!
//! // 3. Discover others by capability (not by name!)
//! let verifiers = adapter.discover_capability("lineage-verification").await?;
//! // Returns whoever can verify lineage (might be Beardog, or something else)
//!
//! // 4. Use service without knowing its primal name
//! if let Some(verifier) = verifiers.first() {
//!     // Connect to verifier.endpoint and use it
//!     // We don't know or care that it's "Beardog"
//! }
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::SkunkBatError;

/// Capability announcement
///
/// A primal announces what it can do (not who it is).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    /// Self-identity (discovered from system)
    pub primal_id: String,

    /// What capabilities this primal provides
    ///
    /// Examples:
    /// - "lineage-verification"
    /// - "threat-detection"
    /// - "network-reconnaissance"
    /// - "coordination"
    /// - "data-storage"
    pub capabilities: Vec<String>,

    /// How to reach this primal
    pub endpoint: String,

    /// Optional metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Discovery result
///
/// Information about a primal that provides a capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPrimal {
    /// Primal identifier
    pub id: String,

    /// Endpoint to connect to
    pub endpoint: String,

    /// Capabilities provided
    pub capabilities: Vec<String>,

    /// Metadata
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Universal Adapter trait
///
/// Enables capability-based discovery without hardcoded primal names.
///
/// # Philosophy
///
/// Instead of asking "where is Beardog?", ask "who can verify lineage?".
/// Instead of N² connections between primals, N connections to the adapter.
///
/// # Implementations
///
/// - `LocalUniversalAdapter` - In-memory registry (single node)
/// - Future: Distributed adapter (consensus-based, federated)
pub trait UniversalAdapter: Send + Sync {
    /// Announce capabilities
    ///
    /// A primal announces what it can do. This is the only time
    /// it needs to know about itself.
    ///
    /// # Arguments
    ///
    /// * `capability` - What this primal can do
    ///
    /// # Errors
    ///
    /// Returns error if announcement fails
    fn announce(
        &self,
        capability: Capability,
    ) -> impl Future<Output = Result<(), SkunkBatError>> + Send;

    /// Discover primals by capability
    ///
    /// Ask "who can do X?" without naming specific primals.
    ///
    /// # Arguments
    ///
    /// * `capability` - What capability you need
    ///
    /// # Returns
    ///
    /// List of primals that provide this capability
    ///
    /// # Errors
    ///
    /// Returns error if discovery fails
    fn discover_capability(
        &self,
        capability: &str,
    ) -> impl Future<Output = Result<Vec<DiscoveredPrimal>, SkunkBatError>> + Send;

    /// Discover all announced primals
    ///
    /// Get complete registry view (for debugging/admin).
    ///
    /// # Errors
    ///
    /// Returns error if discovery fails
    fn discover_all(
        &self,
    ) -> impl Future<Output = Result<Vec<DiscoveredPrimal>, SkunkBatError>> + Send;

    /// Remove announcement
    ///
    /// Primal removes itself from registry (e.g., on shutdown).
    ///
    /// # Arguments
    ///
    /// * `primal_id` - ID to remove
    ///
    /// # Errors
    ///
    /// Returns error if removal fails
    fn remove(&self, primal_id: &str) -> impl Future<Output = Result<(), SkunkBatError>> + Send;
}

/// Local in-memory universal adapter
///
/// Single-node implementation for development and single-system deployments.
///
/// # Thread Safety
///
/// Uses `Arc<RwLock<>>` for thread-safe access.
///
/// # Future
///
/// For distributed systems, implement:
/// - `ConsensusUniversalAdapter` - Raft/Paxos consensus
/// - `FederatedUniversalAdapter` - Multi-region federation
/// - `HybridUniversalAdapter` - Local + remote fallback
pub struct LocalUniversalAdapter {
    /// Capability registry: capability -> list of primals
    capabilities: Arc<RwLock<HashMap<String, Vec<Capability>>>>,

    /// Primal registry: `primal_id` -> full capability announcement
    primals: Arc<RwLock<HashMap<String, Capability>>>,
}

impl LocalUniversalAdapter {
    /// Create new local universal adapter
    ///
    /// Starts with empty registry.
    #[must_use]
    pub fn new() -> Self {
        info!("Initializing LocalUniversalAdapter");
        Self {
            capabilities: Arc::new(RwLock::new(HashMap::new())),
            primals: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get statistics about registry
    ///
    /// Useful for monitoring and debugging.
    pub async fn stats(&self) -> AdapterStats {
        let primals = self.primals.read().await;
        let capabilities = self.capabilities.read().await;

        AdapterStats {
            total_primals: primals.len(),
            total_capabilities: capabilities.len(),
            capabilities_per_primal: if primals.is_empty() {
                0.0
            } else {
                #[expect(clippy::cast_precision_loss, reason = "usize counts fit in f64")]
                let avg = primals
                    .values()
                    .map(|p| p.capabilities.len())
                    .sum::<usize>() as f64
                    / primals.len() as f64;
                avg
            },
        }
    }
}

impl Default for LocalUniversalAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Adapter statistics
#[derive(Debug, Clone)]
pub struct AdapterStats {
    /// Total primals registered
    pub total_primals: usize,

    /// Total unique capabilities
    pub total_capabilities: usize,

    /// Average capabilities per primal
    pub capabilities_per_primal: f64,
}

#[expect(
    clippy::significant_drop_tightening,
    reason = "registry mutations require both locks held"
)]
impl UniversalAdapter for LocalUniversalAdapter {
    async fn announce(&self, capability: Capability) -> Result<(), SkunkBatError> {
        info!(
            "Announcing primal: {} with {} capabilities",
            capability.primal_id,
            capability.capabilities.len()
        );

        let mut capabilities = self.capabilities.write().await;
        let mut primals = self.primals.write().await;

        // Remove old announcement if exists
        if let Some(old) = primals.get(&capability.primal_id) {
            debug!("Removing old announcement for {}", capability.primal_id);
            for cap in &old.capabilities {
                if let Some(list) = capabilities.get_mut(cap) {
                    list.retain(|c| c.primal_id != capability.primal_id);
                    if list.is_empty() {
                        capabilities.remove(cap);
                    }
                }
            }
        }

        // Add new announcement
        for cap in &capability.capabilities {
            capabilities
                .entry(cap.clone())
                .or_default()
                .push(capability.clone());
            debug!("Registered capability: {} -> {}", cap, capability.primal_id);
        }

        primals.insert(capability.primal_id.clone(), capability);

        Ok(())
    }

    async fn discover_capability(
        &self,
        capability: &str,
    ) -> Result<Vec<DiscoveredPrimal>, SkunkBatError> {
        debug!("Discovering capability: {}", capability);

        let capabilities = self.capabilities.read().await;

        let discovered: Vec<DiscoveredPrimal> = capabilities
            .get(capability)
            .map(|primals| {
                primals
                    .iter()
                    .map(|p| DiscoveredPrimal {
                        id: p.primal_id.clone(),
                        endpoint: p.endpoint.clone(),
                        capabilities: p.capabilities.clone(),
                        metadata: p.metadata.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        info!(
            "Found {} primals for capability: {}",
            discovered.len(),
            capability
        );

        Ok(discovered)
    }

    async fn discover_all(&self) -> Result<Vec<DiscoveredPrimal>, SkunkBatError> {
        debug!("Discovering all primals");

        let primals = self.primals.read().await;

        let discovered = primals
            .values()
            .map(|p| DiscoveredPrimal {
                id: p.primal_id.clone(),
                endpoint: p.endpoint.clone(),
                capabilities: p.capabilities.clone(),
                metadata: p.metadata.clone(),
            })
            .collect();

        Ok(discovered)
    }

    async fn remove(&self, primal_id: &str) -> Result<(), SkunkBatError> {
        info!("Removing primal: {}", primal_id);

        let mut capabilities = self.capabilities.write().await;
        let mut primals = self.primals.write().await;

        if let Some(primal) = primals.remove(primal_id) {
            // Remove from capability indices
            for cap in &primal.capabilities {
                if let Some(list) = capabilities.get_mut(cap) {
                    list.retain(|c| c.primal_id != primal_id);
                    if list.is_empty() {
                        capabilities.remove(cap);
                    }
                }
            }
            debug!("Removed primal: {}", primal_id);
        } else {
            warn!("Primal not found for removal: {}", primal_id);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_announce_and_discover() {
        let adapter = LocalUniversalAdapter::new();

        // Announce skunkBat
        adapter
            .announce(Capability {
                primal_id: "skunkbat-01".into(),
                capabilities: vec!["threat-detection".into(), "reconnaissance".into()],
                endpoint: "http://127.0.0.1:8000".into(),
                metadata: HashMap::new(),
            })
            .await
            .unwrap();

        // Announce "Beardog" (but we don't use the name in discovery!)
        adapter
            .announce(Capability {
                primal_id: "beardog-01".into(),
                capabilities: vec!["lineage-verification".into(), "genetic-trust".into()],
                endpoint: "http://127.0.0.1:8001".into(),
                metadata: HashMap::new(),
            })
            .await
            .unwrap();

        // Discover by capability (not by name!)
        let verifiers = adapter
            .discover_capability("lineage-verification")
            .await
            .unwrap();
        assert_eq!(verifiers.len(), 1);
        assert_eq!(verifiers[0].id, "beardog-01");

        let detectors = adapter
            .discover_capability("threat-detection")
            .await
            .unwrap();
        assert_eq!(detectors.len(), 1);
        assert_eq!(detectors[0].id, "skunkbat-01");
    }

    #[tokio::test]
    async fn test_multiple_providers() {
        let adapter = LocalUniversalAdapter::new();

        // Two primals can provide same capability
        adapter
            .announce(Capability {
                primal_id: "skunkbat-01".into(),
                capabilities: vec!["threat-detection".into()],
                endpoint: "http://127.0.0.1:8000".into(),
                metadata: HashMap::new(),
            })
            .await
            .unwrap();

        adapter
            .announce(Capability {
                primal_id: "skunkbat-02".into(),
                capabilities: vec!["threat-detection".into()],
                endpoint: "http://127.0.0.1:8001".into(),
                metadata: HashMap::new(),
            })
            .await
            .unwrap();

        let detectors = adapter
            .discover_capability("threat-detection")
            .await
            .unwrap();
        assert_eq!(detectors.len(), 2);
    }

    #[tokio::test]
    async fn test_re_announce_updates() {
        let adapter = LocalUniversalAdapter::new();

        // Initial announcement
        adapter
            .announce(Capability {
                primal_id: "skunkbat-01".into(),
                capabilities: vec!["threat-detection".into()],
                endpoint: "http://127.0.0.1:8000".into(),
                metadata: HashMap::new(),
            })
            .await
            .unwrap();

        // Re-announce with updated capabilities
        adapter
            .announce(Capability {
                primal_id: "skunkbat-01".into(),
                capabilities: vec!["threat-detection".into(), "reconnaissance".into()],
                endpoint: "http://127.0.0.1:8000".into(),
                metadata: HashMap::new(),
            })
            .await
            .unwrap();

        // Should have both capabilities now
        let primals = adapter.discover_all().await.unwrap();
        assert_eq!(primals.len(), 1);
        assert_eq!(primals[0].capabilities.len(), 2);
    }

    #[tokio::test]
    async fn test_remove_primal() {
        let adapter = LocalUniversalAdapter::new();

        adapter
            .announce(Capability {
                primal_id: "skunkbat-01".into(),
                capabilities: vec!["threat-detection".into()],
                endpoint: "http://127.0.0.1:8000".into(),
                metadata: HashMap::new(),
            })
            .await
            .unwrap();

        // Remove
        adapter.remove("skunkbat-01").await.unwrap();

        // Should be gone
        let detectors = adapter
            .discover_capability("threat-detection")
            .await
            .unwrap();
        assert_eq!(detectors.len(), 0);
    }

    #[tokio::test]
    async fn test_zero_knowledge_discovery() {
        let adapter = LocalUniversalAdapter::new();

        // Primals announce without knowing each other
        adapter
            .announce(Capability {
                primal_id: "primal-a".into(),
                capabilities: vec!["capability-x".into()],
                endpoint: "http://a.local".into(),
                metadata: HashMap::new(),
            })
            .await
            .unwrap();

        adapter
            .announce(Capability {
                primal_id: "primal-b".into(),
                capabilities: vec!["capability-y".into()],
                endpoint: "http://b.local".into(),
                metadata: HashMap::new(),
            })
            .await
            .unwrap();

        // Primal B discovers capability-x without knowing it's primal-a
        let providers = adapter.discover_capability("capability-x").await.unwrap();
        assert_eq!(providers.len(), 1);
        // We got a provider, but didn't hardcode "primal-a" anywhere!
    }

    #[tokio::test]
    async fn test_adapter_stats() {
        let adapter = LocalUniversalAdapter::new();

        adapter
            .announce(Capability {
                primal_id: "primal-1".into(),
                capabilities: vec!["cap-a".into(), "cap-b".into()],
                endpoint: "http://1.local".into(),
                metadata: HashMap::new(),
            })
            .await
            .unwrap();

        adapter
            .announce(Capability {
                primal_id: "primal-2".into(),
                capabilities: vec!["cap-c".into()],
                endpoint: "http://2.local".into(),
                metadata: HashMap::new(),
            })
            .await
            .unwrap();

        let stats = adapter.stats().await;
        assert_eq!(stats.total_primals, 2);
        assert_eq!(stats.total_capabilities, 3); // cap-a, cap-b, cap-c
        assert!((stats.capabilities_per_primal - 1.5).abs() < 0.01); // (2 + 1) / 2 = 1.5
    }
}

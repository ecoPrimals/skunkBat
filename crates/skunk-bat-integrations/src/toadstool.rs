// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Capability-based primal discovery integration.
//!
//! Connects to whatever primal announces the `discovery` capability at
//! runtime via its capability-domain symlink (`discovery.sock`) or a
//! TCP endpoint discovered from `DISCOVERY_ENDPOINT`.
//!
//! Gracefully degrades to standalone mode when no discovery provider is
//! available — the primal retains self-knowledge only.

use serde::{Deserialize, Serialize};
use skunk_bat_core::error::SkunkBatError;
use skunk_bat_core::reconnaissance::{Node, NodeStatus, PrimalDiscovery};
use std::time::{Duration, SystemTime};

/// Default RPC timeout for discovery calls (ms).
const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Discovery client for capability-based primal lookup.
///
/// Transport is resolved at runtime — prefers the `discovery.sock`
/// capability symlink (UDS), falls back to `DISCOVERY_ENDPOINT` (TCP).
#[derive(Clone, Debug)]
pub struct DiscoveryClient {
    endpoint: String,
    uds_path: Option<String>,
    timeout_ms: u64,
}

/// Discovered primal from the capability registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPrimal {
    /// Unique service identifier.
    pub service_id: String,
    /// Advertised capabilities.
    pub capabilities: Vec<String>,
    /// Connection endpoint.
    pub endpoint: String,
    /// Service version.
    pub version: String,
}

impl DiscoveryClient {
    /// Create a new discovery client targeting a TCP endpoint.
    ///
    /// UDS is not discovered — use [`DiscoveryClient::from_env`] for full transport
    /// resolution.
    #[must_use]
    pub fn new(endpoint: String) -> Self {
        tracing::info!("Initializing discovery client");
        Self {
            endpoint,
            uds_path: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    /// Create from environment with capability-socket discovery.
    ///
    /// Reads `DISCOVERY_ENDPOINT` for TCP and probes
    /// `$BIOMEOS_SOCKET_DIR/discovery.sock` for UDS.
    #[must_use]
    pub fn from_env() -> Self {
        let endpoint = std::env::var("DISCOVERY_ENDPOINT").unwrap_or_default();
        let uds_path = {
            let path = crate::rpc::capability_socket("discovery");
            std::path::Path::new(&path).exists().then_some(path)
        };
        tracing::info!(
            endpoint = %endpoint,
            uds = ?uds_path,
            "Initializing discovery client"
        );
        Self {
            endpoint,
            uds_path,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }

    /// Set request timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// The TCP endpoint this client targets (if any).
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn tcp_endpoint(&self) -> Option<&str> {
        if self.endpoint.is_empty() {
            None
        } else {
            Some(&self.endpoint)
        }
    }

    async fn rpc_call(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, SkunkBatError> {
        let timeout = Duration::from_millis(self.timeout_ms);
        crate::rpc::call(
            self.uds_path.as_deref(),
            self.tcp_endpoint(),
            method,
            params,
            timeout,
        )
        .await
        .map_err(SkunkBatError::Integration)
    }

    /// Discover all primals in the network.
    ///
    /// # Errors
    ///
    /// Returns error if the discovery provider is unreachable.
    pub async fn discover_all(&self) -> Result<Vec<DiscoveredPrimal>, SkunkBatError> {
        tracing::debug!("Discovering all primals");
        match self.rpc_call("discovery.find_all", None).await {
            Ok(value) => serde_json::from_value(value)
                .map_err(|e| SkunkBatError::Integration(format!("parse: {e}"))),
            Err(e) => {
                tracing::info!("Discovery unavailable ({e}), standalone mode");
                Ok(Vec::new())
            }
        }
    }

    /// Discover primals by capability.
    ///
    /// # Errors
    ///
    /// Returns error if the discovery provider is unreachable.
    pub async fn discover_by_capability(
        &self,
        capability: &str,
    ) -> Result<Vec<DiscoveredPrimal>, SkunkBatError> {
        tracing::info!("Discovering primals with capability: {capability}");
        let params = serde_json::json!({ "capability": capability });
        match self
            .rpc_call("discovery.find_by_capability", Some(params))
            .await
        {
            Ok(value) => serde_json::from_value(value)
                .map_err(|e| SkunkBatError::Integration(format!("parse: {e}"))),
            Err(e) => {
                tracing::debug!("No primals found with capability {capability}: {e}");
                Ok(Vec::new())
            }
        }
    }

    /// Discover local primals by scanning the BIOMEOS socket directory.
    ///
    /// Probes each `.sock` file (skipping symlinks) with
    /// `capabilities.list` to learn what each primal provides.
    ///
    /// # Errors
    ///
    /// Returns error if local discovery fails.
    pub async fn discover_local(&self) -> Result<Vec<DiscoveredPrimal>, SkunkBatError> {
        tracing::debug!("Discovering local primals via socket dir");

        let dir = crate::rpc::socket_dir();
        let dir_path = std::path::Path::new(&dir);
        if !dir_path.exists() {
            return Ok(Vec::new());
        }

        let Ok(entries) = std::fs::read_dir(dir_path) else {
            return Ok(Vec::new());
        };

        let timeout = Duration::from_millis(self.timeout_ms);
        let mut discovered = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("sock") {
                continue;
            }
            if path
                .symlink_metadata()
                .map(|m| m.is_symlink())
                .unwrap_or(false)
            {
                continue;
            }

            let path_str = path.to_string_lossy().to_string();

            #[cfg(unix)]
            if let Ok(value) =
                crate::rpc::call_uds(&path_str, "capabilities.list", None, timeout).await
            {
                let service_id = value["primal"].as_str().unwrap_or("unknown").to_string();
                let version = value["version"].as_str().unwrap_or("0.0.0").to_string();
                let capabilities = value["provided_capabilities"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|c| c["type"].as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                discovered.push(DiscoveredPrimal {
                    service_id,
                    capabilities,
                    endpoint: path_str,
                    version,
                });
            }
        }

        Ok(discovered)
    }
}

/// Capability-based primal discovery backed by an external registry.
///
/// Maintains the self-knowledge principle: always knows about self,
/// discovers others at runtime.  Gracefully degrades to local-only
/// when no discovery provider is available.
pub struct CapabilityPrimalDiscovery {
    client: DiscoveryClient,
    self_id: String,
}

impl CapabilityPrimalDiscovery {
    /// Create a new capability-based discovery.
    #[must_use]
    pub fn new(client: DiscoveryClient, self_id: String) -> Self {
        tracing::info!("Initializing capability discovery for {self_id}");
        Self { client, self_id }
    }

    /// Convert registry entries to skunkBat nodes.
    fn convert_to_nodes(discovered: Vec<DiscoveredPrimal>) -> Vec<Node> {
        discovered
            .into_iter()
            .map(|primal| Node {
                id: primal.service_id,
                address: primal.endpoint,
                node_type: "primal".to_string(),
                status: NodeStatus::Healthy,
                capabilities: primal.capabilities,
                last_seen: Some(SystemTime::now()),
            })
            .collect()
    }

    /// Build the self-knowledge node.
    fn create_self_node(&self) -> Node {
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

impl PrimalDiscovery for CapabilityPrimalDiscovery {
    async fn discover_by_capability(&self, capability: &str) -> Result<Vec<Node>, SkunkBatError> {
        tracing::info!("Discovering primals with capability: {capability}");
        let discovered = self.client.discover_by_capability(capability).await?;
        Ok(Self::convert_to_nodes(discovered))
    }

    async fn discover_all(&self) -> Result<Vec<Node>, SkunkBatError> {
        tracing::info!("Discovering all network primals");

        let mut nodes = vec![self.create_self_node()];

        match self.client.discover_all().await {
            Ok(discovered) => {
                let network_nodes = Self::convert_to_nodes(discovered);
                tracing::info!("Found {} network primals", network_nodes.len());
                nodes.extend(network_nodes);
            }
            Err(e) => {
                tracing::error!("Network discovery failed: {e}");
            }
        }

        Ok(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_capability_discovery() {
        let client = DiscoveryClient::from_env();
        let discovery = CapabilityPrimalDiscovery::new(client, "test-skunkbat".into());

        let nodes = discovery.discover_all().await.expect("Discovery failed");
        assert!(!nodes.is_empty(), "Should at least have self node");
        assert_eq!(nodes[0].node_type, "skunkBat");
    }

    #[tokio::test]
    async fn test_self_knowledge_principle() {
        let client = DiscoveryClient::from_env();
        let discovery = CapabilityPrimalDiscovery::new(client, "my-skunkbat".into());

        let nodes = discovery.discover_all().await.expect("Discovery failed");
        assert!(!nodes.is_empty());

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
        let client = DiscoveryClient::new("unreachable.invalid:9999".to_string());
        let discovery = CapabilityPrimalDiscovery::new(client, "skunkbat".into());

        let result = discovery.discover_all().await;
        assert!(result.is_ok(), "Should gracefully degrade");

        let nodes = result.expect("Already asserted Ok");
        assert_eq!(nodes.len(), 1, "Should have self node");
    }

    #[tokio::test]
    async fn test_discover_by_capability_degradation() {
        let client = DiscoveryClient::new("unreachable.invalid:9999".to_string());
        let result = client.discover_by_capability("lineage-verification").await;
        assert!(result.is_ok());
        assert!(result.expect("ok").is_empty());
    }

    #[tokio::test]
    async fn test_discover_local_empty() {
        let client = DiscoveryClient::from_env();
        let result = client.discover_local().await;
        assert!(result.is_ok());
    }
}

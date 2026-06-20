// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Threat detection for skunkBat.
//!
//! Five threat categories, each backed by pluggable trait implementations
//! discovered at runtime:
//!
//! | Category | Trait | Default |
//! |----------|-------|---------|
//! | Genetic (lineage) | [`LineageVerifier`] | [`LocalLineageVerifier`] |
//! | Behavioral (anomaly) | [`BaselineProfiler`] | [`StatisticalProfiler`] |
//! | Topology (layer-hop) | [`TopologyValidator`] | [`LayerTopologyValidator`] |
//! | Intrusion (signature) | — | built-in |
//! | Resource (exhaustion) | — | built-in |

pub mod baseline;
mod behavioral;
mod detection;
mod genetic;
pub mod traits;
pub mod types;

pub use behavioral::StatisticalProfiler;
pub use genetic::{LayerTopologyValidator, LocalLineageVerifier};
pub use traits::{BaselineProfiler, LineageVerifier, TopologyValidator};
pub use types::*;

use crate::SkunkBatConfig;
use crate::config::ThreatThresholds;
use crate::error::SkunkBatError;
use std::sync::Mutex;
use std::time::SystemTime;
use tokio::sync::RwLock;

/// Threat detector — orchestrates all five detection categories.
///
/// Generic over verifier and profiler types — no dyn dispatch.
/// Use [`ThreatDetector::new`] for default types, or
/// [`ThreatDetector::with_verifiers`] for custom injection.
pub struct ThreatDetector<
    L: LineageVerifier = LocalLineageVerifier,
    B: BaselineProfiler = StatisticalProfiler,
> {
    enabled: bool,
    lineage_id: Option<String>,
    thresholds: ThreatThresholds,
    lineage_verifier: L,
    baseline_profiler: RwLock<B>,
    topology_validator: Option<LayerTopologyValidator>,
    /// Connection paths observed since the last `detect()` call.
    /// Fed by the transport layer via `record_connection_path()`.
    observed_paths: Mutex<Vec<Vec<u8>>>,
}

impl ThreatDetector {
    /// Create a threat detector with default local implementations.
    ///
    /// Automatically seeds the baseline profiler with normal traffic
    /// observations so anomaly detection is active from first `detect()` call.
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        let mut profiler = StatisticalProfiler::new(config.thresholds.sigma_threshold);
        profiler.seed_baseline(&baseline::normal_baseline_with_port(
            config.common.listen_port,
        ));
        Self::with_verifiers(config, LocalLineageVerifier, profiler)
    }
}

impl<L: LineageVerifier, B: BaselineProfiler> ThreatDetector<L, B> {
    /// Create a threat detector with custom verifiers injected at runtime.
    #[must_use]
    pub fn with_verifiers(
        config: &SkunkBatConfig,
        lineage_verifier: L,
        baseline_profiler: B,
    ) -> Self {
        let topology_validator = config
            .expected_topology_path
            .as_ref()
            .map(|path| LayerTopologyValidator::new(path.clone()));
        Self {
            enabled: config.features.threat_detection,
            lineage_id: config.lineage_id.clone(),
            thresholds: config.thresholds.clone(),
            lineage_verifier,
            baseline_profiler: RwLock::new(baseline_profiler),
            topology_validator,
            observed_paths: Mutex::new(Vec::new()),
        }
    }

    /// Start threat detection.
    ///
    /// # Errors
    ///
    /// Returns an error if the threat detector fails to start.
    pub fn start(&self) -> Result<(), SkunkBatError> {
        if !self.enabled {
            tracing::info!("Threat detection disabled by config");
            return Ok(());
        }
        tracing::debug!("Threat detector starting");
        Ok(())
    }

    /// Stop threat detection.
    ///
    /// # Errors
    ///
    /// Returns an error if the threat detector fails to stop.
    pub fn stop(&self) -> Result<(), SkunkBatError> {
        tracing::debug!("Threat detector stopping");
        Ok(())
    }

    /// Check if threat detector is healthy.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.enabled
    }

    /// Run all detection categories and return aggregated threats.
    ///
    /// # Errors
    ///
    /// Returns an error if any detection category fails.
    pub async fn detect(&self) -> Result<Vec<Threat>, SkunkBatError> {
        if !self.enabled {
            return Ok(vec![]);
        }

        let mut threats = Vec::with_capacity(8);
        threats.extend(self.detect_genetic_threats().await?);
        threats.extend(self.detect_behavioral_anomalies().await?);
        threats.extend(self.detect_intrusions().await?);
        threats.extend(self.detect_resource_exhaustion().await?);
        threats.extend(self.detect_topology_threats().await?);

        if !threats.is_empty() {
            tracing::warn!("Detected {} threats", threats.len());
        }

        Ok(threats)
    }

    /// Feed a live network observation into the baseline profiler.
    ///
    /// Updates the rolling window and keeps the anomaly baseline current
    /// with real traffic. Can be called from the IPC dispatch path
    /// or from the transport layer's connection accept loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the profiler update fails.
    pub async fn observe(&self, observation: &types::Observation) -> Result<(), SkunkBatError> {
        self.baseline_profiler
            .write()
            .await
            .update(observation)
            .await
    }

    /// Record an observed connection path for topology validation.
    ///
    /// Called by the transport layer when a connection's layer traversal
    /// is known (e.g. from BTSP handshake metadata or `CallerContext`).
    /// Paths are consumed and validated on the next `detect()` call.
    pub fn record_connection_path(&self, path: Vec<u8>) {
        if let Ok(mut paths) = self.observed_paths.lock() {
            paths.push(path);
        }
    }

    /// Access the lineage identifier (if configured).
    #[must_use]
    pub fn lineage_id(&self) -> Option<&str> {
        self.lineage_id.as_deref()
    }

    /// Access the lineage verifier.
    #[must_use]
    pub const fn lineage_verifier(&self) -> &L {
        &self.lineage_verifier
    }

    pub(crate) fn threat_id_suffix() -> u64 {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "microsecond epoch fits u64 until year 586524"
        )]
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros() as u64)
    }
}

#[cfg(test)]
#[path = "threats_tests.rs"]
mod tests;

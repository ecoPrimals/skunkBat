// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Threat detection for skunkBat.
//!
//! Six threat categories, each backed by pluggable trait implementations
//! discovered at runtime:
//!
//! | Category | Trait | Default |
//! |----------|-------|---------|
//! | Genetic (lineage) | [`LineageVerifier`] | [`LocalLineageVerifier`] |
//! | Behavioral (anomaly) | [`BaselineProfiler`] | [`StatisticalProfiler`] |
//! | Topology (layer-hop) | [`TopologyValidator`] | [`LayerTopologyValidator`] |
//! | Intrusion (signature) | — | built-in |
//! | Resource (exhaustion) | — | built-in |
//! | Configuration drift | — | built-in (snapshot comparison) |

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

/// Threat detector — orchestrates all six detection categories.
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
    /// Snapshot of config at startup for drift detection.
    config_snapshot: types::ConfigSnapshot,
}

impl ThreatDetector {
    /// Create a threat detector with default local implementations.
    ///
    /// Automatically seeds the baseline profiler with normal traffic
    /// observations so anomaly detection is active from first `detect()` call.
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        let mut profiler = StatisticalProfiler::with_config(
            config.thresholds.sigma_threshold,
            config.thresholds.behavioral_rolling_window,
            config.thresholds.behavioral_min_observations,
        );
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
        let config_snapshot = types::ConfigSnapshot::from_config(config);
        Self {
            enabled: config.features.threat_detection,
            lineage_id: config.lineage_id.clone(),
            thresholds: config.thresholds.clone(),
            lineage_verifier,
            baseline_profiler: RwLock::new(baseline_profiler),
            topology_validator,
            observed_paths: Mutex::new(Vec::new()),
            config_snapshot,
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
    #[must_use = "detected threats must be processed or logged"]
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
        threats.extend(self.detect_configuration_drift());

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

    /// Check for configuration drift against the startup snapshot.
    ///
    /// Compares security-relevant config fields captured at construction
    /// with a fresh snapshot. Drift indicates either a legitimate reload
    /// (should be coordinated) or runtime tampering.
    fn detect_configuration_drift(&self) -> Vec<Threat> {
        let current = types::ConfigSnapshot {
            features_json: self.config_snapshot.features_json.clone(),
            lineage_id: self.lineage_id.clone(),
            topology_configured: self.topology_validator.is_some(),
            threshold_fingerprint: format!(
                "sigma={:.2};dos={:.2};genetic={:.2}",
                self.thresholds.sigma_threshold,
                self.thresholds.dos_load_threshold,
                self.thresholds.genetic_confidence,
            ),
        };

        self.config_snapshot
            .diff(&current)
            .into_iter()
            .map(|(component, expected, observed)| {
                let severity = if component == "features" || component == "lineage_id" {
                    Severity::High
                } else {
                    Severity::Medium
                };
                Threat {
                    id: format!("drift-{component}-{}", Self::threat_id_suffix()),
                    threat_type: ThreatType::ConfigurationDrift {
                        component: component.clone(),
                        expected,
                        observed,
                    },
                    severity,
                    source: "config".to_owned(),
                    target: "self".to_owned(),
                    detected_at: SystemTime::now(),
                    description: format!("Configuration drift detected in '{component}'"),
                    confidence: self.thresholds.drift_confidence,
                }
            })
            .collect()
    }

    /// Query the baseline profiler's current statistics.
    ///
    /// Returns `None` if the baseline is not established (< 10 observations).
    #[must_use]
    pub async fn baseline_stats(&self) -> Option<types::BaselineStats> {
        self.baseline_profiler.read().await.query_stats()
    }

    /// Check an observation against the baseline and return any anomalies.
    ///
    /// This is the composable read-only anomaly primitive — callers can inspect
    /// deviations without feeding the observation into the rolling window.
    ///
    /// # Errors
    ///
    /// Returns an error if anomaly detection fails.
    #[must_use = "anomaly results should be inspected"]
    pub async fn check_anomalies(
        &self,
        observation: &types::Observation,
    ) -> Result<Vec<types::Anomaly>, SkunkBatError> {
        self.baseline_profiler
            .read()
            .await
            .detect_anomalies(observation)
            .await
    }

    /// Reset the baseline profiler, discarding learned observations.
    ///
    /// If `reseed` is true, re-seeds with default baseline data so anomaly
    /// detection remains active immediately after reset.
    pub async fn reset_baseline(&self, reseed: bool) {
        self.baseline_profiler.write().await.reset(reseed);
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

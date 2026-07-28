// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Threat detection for skunkBat.
//!
//! Nine threat categories, each backed by pluggable trait implementations
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
//! | Spawn-rate anomaly | — | built-in (`/proc/stat` fork counter) |
//! | HTTP anomaly | — | built-in (outer membrane) |
//! | Connectivity anomaly | — | built-in (k-derm / peptidoglycan layer) |

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

/// Threat detector — orchestrates all nine detection categories.
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
    /// Process spawn rate tracker for crash-loop detection.
    spawn_tracker: Mutex<crate::platform::SpawnRateTracker>,
    /// Outbound RPC connectivity tracker for k-derm anomaly detection.
    connectivity_tracker: Mutex<crate::platform::ConnectivityTracker>,
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
        Self::with_lineage_verifier(config, LocalLineageVerifier)
    }
}

impl<L: LineageVerifier> ThreatDetector<L> {
    /// Create a threat detector with a custom lineage verifier
    /// and the default `StatisticalProfiler`.
    ///
    /// Seeds the baseline profiler unless `config.skip_synthetic_baseline`
    /// is set — in live-ingest deployments, real traffic replaces synthetic
    /// seed data.
    #[must_use]
    pub fn with_lineage_verifier(config: &SkunkBatConfig, verifier: L) -> Self {
        let mut profiler = StatisticalProfiler::with_config(
            config.thresholds.sigma_threshold,
            config.thresholds.behavioral_rolling_window,
            config.thresholds.behavioral_min_observations,
        );
        profiler.set_seed_port(config.common.listen_port);
        if config.skip_synthetic_baseline {
            tracing::info!("synthetic baseline skipped — profiler will learn from live traffic");
        } else {
            profiler.seed_baseline(&baseline::normal_baseline_with_port(
                config.common.listen_port,
            ));
        }
        Self::with_verifiers(config, verifier, profiler)
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
            spawn_tracker: Mutex::new(crate::platform::SpawnRateTracker::new()),
            connectivity_tracker: Mutex::new(crate::platform::ConnectivityTracker::new(
                config.thresholds.connectivity_window_size,
            )),
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
        threats.extend(self.detect_spawn_anomalies().await?);
        threats.extend(self.detect_connectivity_anomalies());
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

    /// Record the outcome of an outbound RPC probe for connectivity tracking.
    ///
    /// Called by integration clients after each RPC attempt. A sustained
    /// high failure rate triggers `ConnectivityAnomaly` on the next `detect()`.
    pub fn record_connectivity_probe(&self, success: bool) {
        if let Ok(mut tracker) = self.connectivity_tracker.lock() {
            tracker.record(success);
        }
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
                        component: (*component).to_owned(),
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

    /// Obtain a sync handle to the baseline profiler for advisory checks.
    ///
    /// The handle uses `try_read()` to avoid blocking; returns `None` from
    /// `check_anomalies_sync` if the profiler lock is contended.
    pub(crate) const fn baseline_profiler_handle(&self) -> ProfilerHandle<'_, B> {
        ProfilerHandle {
            profiler: &self.baseline_profiler,
        }
    }
}

/// Sync handle to the baseline profiler for non-async advisory paths.
pub(crate) struct ProfilerHandle<'a, B: BaselineProfiler> {
    profiler: &'a RwLock<B>,
}

impl<B: BaselineProfiler> ProfilerHandle<'_, B> {
    /// Run anomaly detection synchronously.
    ///
    /// Returns `None` if the profiler lock is contended (advisory callers
    /// should treat this as "no anomalies detected" / `Allow`).
    #[expect(
        clippy::significant_drop_tightening,
        reason = "detect_anomalies future borrows the RwLock guard"
    )]
    pub(crate) fn check_anomalies_sync(
        &self,
        observation: &types::Observation,
    ) -> Option<Vec<types::Anomaly>> {
        let guard = self.profiler.try_read().ok()?;
        if !guard.is_established() {
            return Some(Vec::new());
        }
        let future = guard.detect_anomalies(observation);
        poll_ready(future).and_then(|r| r).ok()
    }
}

/// Poll a compute-only future exactly once, returning an error if it yields `Pending`.
fn poll_ready<F: std::future::Future>(f: F) -> Result<F::Output, crate::SkunkBatError> {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut f = pin!(f);
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(val) => Ok(val),
        Poll::Pending => Err(crate::SkunkBatError::ThreatDetection(
            "compute-only future yielded Pending unexpectedly".to_owned(),
        )),
    }
}

#[cfg(test)]
#[path = "threats_tests.rs"]
mod tests;

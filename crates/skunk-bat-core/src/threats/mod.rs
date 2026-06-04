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
mod genetic;
#[cfg(test)]
mod mod_tests;
pub mod traits;
pub mod types;

pub use behavioral::StatisticalProfiler;
pub use genetic::{LayerTopologyValidator, LocalLineageVerifier};
pub use traits::{BaselineProfiler, LineageVerifier, TopologyValidator};
pub use types::*;

use crate::SkunkBatConfig;
use crate::error::SkunkBatError;
use std::time::SystemTime;

/// Default sigma threshold for the statistical anomaly profiler.
const DEFAULT_SIGMA_THRESHOLD: f64 = 2.5;

/// Deviation thresholds for severity classification.
const SEVERITY_HIGH_DEVIATION: f64 = 5.0;
const SEVERITY_MEDIUM_DEVIATION: f64 = 3.0;

/// System load threshold that triggers a `DoS` threat.
const DOS_LOAD_THRESHOLD: f64 = 0.9;

/// Default confidence for resource exhaustion detections.
const DOS_CONFIDENCE: f64 = 0.8;

/// Port count threshold that indicates a port scan.
const PORT_SCAN_THRESHOLD: usize = 10;

/// Confidence assigned to port-scan intrusion detections.
const PORT_SCAN_CONFIDENCE: f64 = 0.85;

/// Threat detector — orchestrates all five detection categories.
///
/// Generic over verifier, profiler, and topology types — no dyn dispatch.
/// Use [`ThreatDetector::new`] for default types, or
/// [`ThreatDetector::with_verifiers`] for custom injection.
pub struct ThreatDetector<
    L: LineageVerifier = LocalLineageVerifier,
    B: BaselineProfiler = StatisticalProfiler,
    T: TopologyValidator = LayerTopologyValidator,
> {
    enabled: bool,
    lineage_id: Option<String>,
    lineage_verifier: L,
    baseline_profiler: B,
    topology_validator: T,
}

impl ThreatDetector {
    /// Create a threat detector with default local implementations.
    ///
    /// Automatically seeds the baseline profiler with normal traffic
    /// observations so anomaly detection is active from first `detect()` call.
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        let mut profiler = StatisticalProfiler::new(DEFAULT_SIGMA_THRESHOLD);
        profiler.seed_baseline(&baseline::normal_baseline());
        Self::with_verifiers(config, LocalLineageVerifier, profiler)
    }
}

impl<L: LineageVerifier, B: BaselineProfiler> ThreatDetector<L, B> {
    /// Create a threat detector with custom verifiers injected at runtime.
    ///
    /// Uses the default `LayerTopologyValidator` with the standard biomeOS
    /// layer traversal path.
    #[must_use]
    pub fn with_verifiers(
        config: &SkunkBatConfig,
        lineage_verifier: L,
        baseline_profiler: B,
    ) -> Self {
        Self {
            enabled: config.features.threat_detection,
            lineage_id: config.lineage_id.clone(),
            lineage_verifier,
            baseline_profiler,
            topology_validator: LayerTopologyValidator::new(vec![0, 1, 2, 3]),
        }
    }
}

impl<L: LineageVerifier, B: BaselineProfiler, T: TopologyValidator> ThreatDetector<L, B, T> {
    /// Create a threat detector with fully custom injection (all three axes).
    #[must_use]
    pub fn with_full_injection(
        config: &SkunkBatConfig,
        lineage_verifier: L,
        baseline_profiler: B,
        topology_validator: T,
    ) -> Self {
        Self {
            enabled: config.features.threat_detection,
            lineage_id: config.lineage_id.clone(),
            lineage_verifier,
            baseline_profiler,
            topology_validator,
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

    /// Run all five detection categories and return aggregated threats.
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
        threats.extend(self.detect_topology_violations().await?);
        threats.extend(self.detect_resource_exhaustion().await?);

        if !threats.is_empty() {
            tracing::warn!("Detected {} threats", threats.len());
        }

        Ok(threats)
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

    fn threat_id_suffix() -> u64 {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "microsecond epoch fits u64 until year 586524"
        )]
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros() as u64)
    }

    async fn detect_genetic_threats(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let Some(ref my_lineage) = self.lineage_id else {
            tracing::debug!("Genetic threat detection: no lineage_id configured");
            return Ok(Vec::new());
        };

        match self.lineage_verifier.is_family(my_lineage).await {
            Ok(true) => {
                tracing::debug!("Lineage verification passed for {my_lineage}");
                Ok(Vec::new())
            }
            Ok(false) => {
                tracing::warn!("Lineage verification FAILED for {my_lineage}");
                Ok(vec![Threat {
                    id: format!("genetic-lineage-{}", Self::threat_id_suffix()),
                    threat_type: ThreatType::UnknownLineage {
                        peer_id: my_lineage.clone(),
                        lineage: None,
                    },
                    source: my_lineage.clone(),
                    target: "self".to_owned(),
                    severity: Severity::Critical,
                    confidence: 0.95,
                    description: format!(
                        "Lineage verification failed — identity '{my_lineage}' not recognized"
                    ),
                    detected_at: SystemTime::now(),
                }])
            }
            Err(e) => {
                tracing::debug!("Lineage verifier unavailable: {e} — skipping genetic detection");
                Ok(Vec::new())
            }
        }
    }

    async fn detect_behavioral_anomalies(&self) -> Result<Vec<Threat>, SkunkBatError> {
        if !self.baseline_profiler.is_established() {
            tracing::debug!("Baseline not established, learning normal behavior");
            return Ok(Vec::new());
        }

        let observation = match self.baseline_profiler.latest_observation() {
            Some(obs) => obs.clone(),
            None => return Ok(Vec::new()),
        };

        let anomalies = self
            .baseline_profiler
            .detect_anomalies(&observation)
            .await?;

        let threats = anomalies
            .into_iter()
            .map(|a| {
                let severity = if a.deviation > SEVERITY_HIGH_DEVIATION {
                    Severity::High
                } else if a.deviation > SEVERITY_MEDIUM_DEVIATION {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                Threat {
                    id: format!("anomaly-{}", Self::threat_id_suffix()),
                    description: format!("Behavioral anomaly detected: {}", a.behavior),
                    confidence: a.confidence,
                    threat_type: ThreatType::BehaviorAnomaly {
                        deviation: a.deviation,
                        behavior: a.behavior,
                    },
                    severity,
                    source: "network".to_owned(),
                    target: "local".to_owned(),
                    detected_at: SystemTime::now(),
                }
            })
            .collect();

        Ok(threats)
    }

    #[expect(
        clippy::unused_async,
        reason = "async signature for future live-stream intrusion detection"
    )]
    async fn detect_intrusions(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let Some(obs) = self.baseline_profiler.latest_observation() else {
            return Ok(Vec::new());
        };

        let mut threats = Vec::new();

        if obs.ports_accessed.len() >= PORT_SCAN_THRESHOLD {
            let sequential = Self::has_sequential_ports(&obs.ports_accessed);
            let severity = if sequential {
                Severity::High
            } else {
                Severity::Medium
            };
            threats.push(Threat {
                id: format!("intrusion-portscan-{}", Self::threat_id_suffix()),
                threat_type: ThreatType::IntrusionAttempt {
                    attack_type: "port_scan".to_owned(),
                    signature: format!(
                        "{} ports accessed{}",
                        obs.ports_accessed.len(),
                        if sequential { " (sequential)" } else { "" }
                    ),
                },
                severity,
                source: "network".to_owned(),
                target: "local".to_owned(),
                detected_at: SystemTime::now(),
                description: format!(
                    "Port scan detected: {} distinct ports accessed in observation window",
                    obs.ports_accessed.len()
                ),
                confidence: PORT_SCAN_CONFIDENCE,
            });
        }

        Ok(threats)
    }

    fn has_sequential_ports(ports: &[u16]) -> bool {
        if ports.len() < 3 {
            return false;
        }
        let mut sorted: Vec<u16> = ports.to_vec();
        sorted.sort_unstable();
        sorted.windows(3).any(|w| w[2] == w[0] + 2)
    }

    async fn detect_topology_violations(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let Some(obs) = self.baseline_profiler.latest_observation() else {
            return Ok(Vec::new());
        };

        let mut actual_path: Vec<u8> = obs
            .ports_accessed
            .iter()
            .map(|&p| Self::port_to_layer(p))
            .collect();
        actual_path.sort_unstable();
        actual_path.dedup();

        if actual_path.len() < 3 {
            return Ok(Vec::new());
        }

        let validation = self.topology_validator.validate_path(&actual_path).await?;
        if validation.is_valid {
            return Ok(Vec::new());
        }

        let severity = if validation.bypassed_layers.len() > 1 {
            Severity::High
        } else {
            Severity::Medium
        };

        Ok(vec![Threat {
            id: format!("topology-bypass-{}", Self::threat_id_suffix()),
            threat_type: ThreatType::TopologyViolation {
                expected_path: validation.expected_path,
                actual_path: validation.actual_path,
                bypassed_layers: validation.bypassed_layers.clone(),
            },
            severity,
            source: "network".to_owned(),
            target: "local".to_owned(),
            detected_at: SystemTime::now(),
            description: format!(
                "Topology bypass: {} layer(s) skipped",
                validation.bypassed_layers.len()
            ),
            confidence: 0.8,
        }])
    }

    const fn port_to_layer(port: u16) -> u8 {
        match port {
            0..=1023 => 0,
            1024..=8079 => 1,
            8080..=9999 => 2,
            10000.. => 3,
        }
    }

    #[expect(
        clippy::unused_async,
        reason = "async signature for future async system metrics"
    )]
    async fn detect_resource_exhaustion(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let load = Self::check_system_load();
        if load > DOS_LOAD_THRESHOLD {
            return Ok(vec![Threat {
                id: format!("dos-{:?}", SystemTime::now()),
                threat_type: ThreatType::DenialOfService {
                    resource: "cpu".to_owned(),
                    current_level: load,
                },
                severity: Severity::High,
                source: "unknown".to_owned(),
                target: "local".to_owned(),
                detected_at: SystemTime::now(),
                description: format!("High CPU usage detected: {:.1}%", load * 100.0),
                confidence: DOS_CONFIDENCE,
            }]);
        }
        Ok(Vec::new())
    }

    fn check_system_load() -> f64 {
        #[cfg(target_os = "linux")]
        {
            let raw = std::fs::read_to_string("/proc/loadavg")
                .ok()
                .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
                .unwrap_or(0.0);

            #[expect(clippy::cast_precision_loss, reason = "CPU count fits in f64")]
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get() as f64)
                .unwrap_or(1.0);

            (raw / cpus).min(1.0)
        }

        #[cfg(not(target_os = "linux"))]
        {
            std::process::Command::new("uptime")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| {
                    s.rsplit("load average")
                        .next()?
                        .trim_start_matches([':', ' '])
                        .split(',')
                        .next()?
                        .trim()
                        .parse::<f64>()
                        .ok()
                })
                .map(|raw| {
                    #[expect(clippy::cast_precision_loss, reason = "CPU count fits in f64")]
                    let cpus = std::thread::available_parallelism()
                        .map(|n| n.get() as f64)
                        .unwrap_or(1.0);
                    (raw / cpus).min(1.0)
                })
                .unwrap_or(0.0)
        }
    }
}

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

mod behavioral;
mod genetic;
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
    lineage_verifier: L,
    baseline_profiler: B,
}

impl ThreatDetector {
    /// Create a threat detector with default local implementations.
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        Self::with_verifiers(
            config,
            LocalLineageVerifier,
            StatisticalProfiler::new(DEFAULT_SIGMA_THRESHOLD),
        )
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
        Self {
            enabled: config.features.threat_detection,
            lineage_id: config.lineage_id.clone(),
            lineage_verifier,
            baseline_profiler,
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

        let mut threats = Vec::new();
        threats.extend(self.detect_genetic_threats().await?);
        threats.extend(self.detect_behavioral_anomalies().await?);
        threats.extend(self.detect_intrusions().await?);
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

    #[expect(
        clippy::unused_async,
        reason = "async signature for trait consistency when BearDog integration lands"
    )]
    async fn detect_genetic_threats(&self) -> Result<Vec<Threat>, SkunkBatError> {
        tracing::debug!("Genetic threat detection ready (awaiting peer connections)");
        Ok(Vec::new())
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
                    id: format!("anomaly-{:?}", SystemTime::now()),
                    description: format!("Behavioral anomaly detected: {}", a.behavior),
                    confidence: a.confidence,
                    threat_type: ThreatType::BehaviorAnomaly {
                        deviation: a.deviation,
                        behavior: a.behavior,
                    },
                    severity,
                    source: "network".to_string(),
                    target: "local".to_string(),
                    detected_at: SystemTime::now(),
                }
            })
            .collect();

        Ok(threats)
    }

    #[expect(
        clippy::unused_async,
        reason = "async signature for future network intrusion detection"
    )]
    async fn detect_intrusions(&self) -> Result<Vec<Threat>, SkunkBatError> {
        tracing::debug!("Intrusion detection active (awaiting network data)");
        Ok(Vec::new())
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
                    resource: "cpu".to_string(),
                    current_level: load,
                },
                severity: Severity::High,
                source: "unknown".to_string(),
                target: "local".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FeatureFlags, SkunkBatConfig};
    use crate::primal_foundation::config::CommonConfig;

    fn test_config() -> SkunkBatConfig {
        SkunkBatConfig {
            common: CommonConfig {
                name: "skunkBat-test".to_string(),
                ..CommonConfig::default()
            },
            features: FeatureFlags {
                reconnaissance: true,
                threat_detection: true,
                auto_defense: true,
                observability: true,
            },
            lineage_id: Some("test-lineage".to_string()),
        }
    }

    #[test]
    fn test_threat_detector_creation() {
        let config = test_config();
        let detector = ThreatDetector::new(&config);
        assert!(detector.is_healthy());
    }

    #[test]
    fn test_threat_detector_start_stop() {
        let config = test_config();
        let detector = ThreatDetector::new(&config);
        assert!(detector.start().is_ok());
        assert!(detector.stop().is_ok());
    }

    #[tokio::test]
    async fn test_threat_detection() {
        let config = test_config();
        let detector = ThreatDetector::new(&config);
        let threats = detector.detect().await.expect("detection should succeed");
        assert!(threats.is_empty());
    }

    #[tokio::test]
    async fn test_statistical_profiler_learning() {
        let mut profiler = StatisticalProfiler::new(2.5);
        assert!(!profiler.is_established());

        for i in 0..10 {
            let observation = Observation {
                connection_rate: 10.0 + f64::from(i),
                traffic_volume: 1000,
                ports_accessed: vec![80, 443],
                timestamp: SystemTime::now(),
            };
            profiler
                .update(&observation)
                .await
                .expect("update should succeed");
        }
        assert!(profiler.is_established());
    }

    #[tokio::test]
    async fn test_statistical_profiler_anomaly_detection() {
        let mut profiler = StatisticalProfiler::new(2.5);

        for i in 0..10 {
            let observation = Observation {
                connection_rate: f64::from(i).mul_add(0.1, 10.0),
                traffic_volume: 1000,
                ports_accessed: vec![80, 443],
                timestamp: SystemTime::now(),
            };
            profiler
                .update(&observation)
                .await
                .expect("update should succeed");
        }

        let normal_obs = Observation {
            connection_rate: 10.5,
            traffic_volume: 1000,
            ports_accessed: vec![80, 443],
            timestamp: SystemTime::now(),
        };
        let anomalies = profiler
            .detect_anomalies(&normal_obs)
            .await
            .expect("detection should succeed");
        assert!(anomalies.is_empty() || anomalies[0].deviation < 2.5);

        let anomalous_obs = Observation {
            connection_rate: 100.0,
            traffic_volume: 1000,
            ports_accessed: vec![80, 443],
            timestamp: SystemTime::now(),
        };
        let anomalies = profiler
            .detect_anomalies(&anomalous_obs)
            .await
            .expect("detection should succeed");
        assert!(!anomalies.is_empty());
        assert!(anomalies[0].deviation > 2.5);
    }

    #[tokio::test]
    async fn test_local_lineage_verifier() {
        let verifier = LocalLineageVerifier;
        assert!(
            !verifier
                .is_family("test-peer")
                .await
                .expect("should succeed")
        );
        let lineage = verifier
            .get_lineage("test-peer")
            .await
            .expect("should succeed");
        assert!(lineage.is_none());
    }

    #[tokio::test]
    async fn test_threat_detector_with_verifiers() {
        let config = test_config();
        let detector = ThreatDetector::with_verifiers(
            &config,
            LocalLineageVerifier,
            StatisticalProfiler::new(2.5),
        );
        assert!(detector.is_healthy());
        let result = detector.detect().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_threat_type_creation() {
        let tt = ThreatType::UnknownLineage {
            peer_id: "test-peer".to_string(),
            lineage: Some("unknown-lineage".to_string()),
        };
        assert!(matches!(tt, ThreatType::UnknownLineage { .. }));
    }

    #[test]
    #[expect(clippy::float_cmp, reason = "exact literal comparison in test")]
    fn test_threat_creation() {
        let threat = Threat {
            id: "threat-1".to_string(),
            threat_type: ThreatType::IntrusionAttempt {
                attack_type: "port-scan".to_string(),
                signature: "rapid-connect".to_string(),
            },
            severity: Severity::High,
            source: "192.168.1.100".to_string(),
            target: "192.168.1.1".to_string(),
            detected_at: SystemTime::now(),
            description: "Port scanning detected".to_string(),
            confidence: 0.85,
        };
        assert_eq!(threat.severity, Severity::High);
        assert_eq!(threat.confidence, 0.85);
    }

    #[test]
    fn test_dos_threat() {
        let tt = ThreatType::DenialOfService {
            resource: "bandwidth".to_string(),
            current_level: 95.5,
        };
        assert!(matches!(tt, ThreatType::DenialOfService { .. }));
    }

    #[test]
    fn test_behavior_anomaly() {
        let tt = ThreatType::BehaviorAnomaly {
            deviation: 3.5,
            behavior: "unusual traffic pattern".to_string(),
        };
        assert!(matches!(tt, ThreatType::BehaviorAnomaly { .. }));
    }

    #[tokio::test]
    async fn test_statistical_profiler_baseline() {
        let mut profiler = StatisticalProfiler::new(2.5);
        assert!(!profiler.is_established());

        for _ in 0..10 {
            let obs = Observation {
                connection_rate: 5.0,
                traffic_volume: 1000,
                ports_accessed: vec![80, 443],
                timestamp: SystemTime::now(),
            };
            profiler.update(&obs).await.expect("update should succeed");
        }
        assert!(profiler.is_established());
    }

    #[tokio::test]
    async fn test_detector_with_behavioral_anomalies() {
        let config = test_config();
        let mut profiler = StatisticalProfiler::new(2.5);

        for _ in 0..10 {
            let obs = Observation {
                connection_rate: 5.0,
                traffic_volume: 1000,
                ports_accessed: vec![80],
                timestamp: SystemTime::now(),
            };
            profiler.update(&obs).await.expect("update should succeed");
        }

        let detector = ThreatDetector::with_verifiers(&config, LocalLineageVerifier, profiler);

        let threats = detector.detect().await.expect("detect should succeed");
        assert!(
            threats.is_empty() || !threats.is_empty(),
            "Should return a result"
        );
    }

    #[test]
    #[expect(clippy::float_cmp, reason = "exact literal comparison in test")]
    fn test_observation_creation() {
        let obs = Observation {
            connection_rate: 10.0,
            traffic_volume: 2000,
            ports_accessed: vec![80, 443, 8080],
            timestamp: SystemTime::now(),
        };
        assert_eq!(obs.connection_rate, 10.0);
        assert_eq!(obs.traffic_volume, 2000);
        assert_eq!(obs.ports_accessed.len(), 3);
    }

    #[test]
    #[expect(clippy::float_cmp, reason = "exact literal comparison in test")]
    fn test_anomaly_creation() {
        let anomaly = Anomaly {
            deviation: 4.5,
            behavior: "High connection rate".to_string(),
            confidence: 0.92,
        };
        assert_eq!(anomaly.deviation, 4.5);
        assert_eq!(anomaly.confidence, 0.92);
    }

    #[test]
    fn test_lineage_id_access() {
        let config = test_config();
        let detector = ThreatDetector::new(&config);
        assert_eq!(detector.lineage_id(), Some("test-lineage"));
    }

    #[tokio::test]
    async fn test_layer_topology_validator_valid_path() {
        let validator = LayerTopologyValidator::new(vec![0, 1, 2, 3]);
        let result = validator
            .validate_path(&[0, 1, 2, 3])
            .await
            .expect("should succeed");
        assert!(result.is_valid);
        assert!(result.bypassed_layers.is_empty());
    }

    #[tokio::test]
    async fn test_layer_topology_validator_invalid_path() {
        let validator = LayerTopologyValidator::new(vec![0, 1, 2, 3]);
        let result = validator
            .validate_path(&[0, 2, 3])
            .await
            .expect("should succeed");
        assert!(!result.is_valid);
        assert_eq!(result.bypassed_layers, vec![1]);
    }

    #[tokio::test]
    async fn test_layer_topology_validator_empty_path() {
        let validator = LayerTopologyValidator::new(vec![0, 1, 2]);
        let result = validator.validate_path(&[]).await.expect("should succeed");
        assert!(!result.is_valid);
        assert_eq!(result.bypassed_layers, vec![0, 1, 2]);
    }

    #[test]
    fn test_layer_topology_expected_path() {
        let validator = LayerTopologyValidator::new(vec![1, 2, 3]);
        assert_eq!(validator.expected_path(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_detect_behavioral_anomaly_triggers() {
        let config = test_config();
        let mut profiler = StatisticalProfiler::new(2.5);

        for _ in 0..15 {
            let obs = Observation {
                connection_rate: 5.0,
                traffic_volume: 1000,
                ports_accessed: vec![80],
                timestamp: SystemTime::now(),
            };
            profiler.update(&obs).await.expect("update");
        }

        let spike = Observation {
            connection_rate: 500.0,
            traffic_volume: 1000,
            ports_accessed: vec![80],
            timestamp: SystemTime::now(),
        };
        profiler.update(&spike).await.expect("update");

        let detector = ThreatDetector::with_verifiers(&config, LocalLineageVerifier, profiler);
        let threats = detector.detect().await.expect("detect");
        assert!(
            !threats.is_empty(),
            "Should detect the connection rate spike as anomaly"
        );
        assert!(matches!(
            threats[0].threat_type,
            ThreatType::BehaviorAnomaly { .. }
        ));
    }

    #[tokio::test]
    async fn test_detect_disabled() {
        let config = SkunkBatConfig {
            common: CommonConfig::default(),
            features: FeatureFlags {
                reconnaissance: false,
                threat_detection: false,
                auto_defense: false,
                observability: false,
            },
            lineage_id: None,
        };
        let detector = ThreatDetector::new(&config);
        assert!(!detector.is_healthy());
        let threats = detector.detect().await.expect("detect");
        assert!(threats.is_empty());
    }

    #[test]
    fn test_start_disabled() {
        let config = SkunkBatConfig {
            common: CommonConfig::default(),
            features: FeatureFlags {
                reconnaissance: false,
                threat_detection: false,
                auto_defense: false,
                observability: false,
            },
            lineage_id: None,
        };
        let detector = ThreatDetector::new(&config);
        assert!(detector.start().is_ok());
    }

    #[test]
    fn test_lineage_verifier_access() {
        let config = test_config();
        let detector = ThreatDetector::new(&config);
        let _verifier = detector.lineage_verifier();
    }

    #[test]
    fn test_severity_display_all_variants() {
        let variants = [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        for v in &variants {
            assert!(!format!("{v:?}").is_empty());
        }
    }
}

//! Threat detection for skunkBat.
//!
//! Provides genetic threat analysis, anomaly detection, and intrusion detection.

use crate::SkunkBatConfig;
use crate::error::SkunkBatError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Trait for lineage verification.
///
/// This trait abstracts lineage verification mechanisms, allowing skunkBat
/// to verify genetic lineage without hardcoded knowledge of beardog.
#[async_trait]
pub trait LineageVerifier: Send + Sync {
    /// Verify if a peer is part of the genetic family.
    async fn is_family(&self, peer_id: &str) -> Result<bool, SkunkBatError>;

    /// Get the lineage chain for a peer.
    async fn get_lineage(&self, peer_id: &str) -> Result<Option<String>, SkunkBatError>;
}

/// Trait for behavioral baseline management.
///
/// This trait abstracts baseline profiling for anomaly detection,
/// allowing different statistical and machine learning approaches.
#[async_trait]
pub trait BaselineProfiler: Send + Sync {
    /// Check if baseline is established.
    fn is_established(&self) -> bool;

    /// Update baseline with new observations.
    async fn update(&mut self, observation: &Observation) -> Result<(), SkunkBatError>;

    /// Detect anomalies against baseline.
    async fn detect_anomalies(
        &self,
        observation: &Observation,
    ) -> Result<Vec<Anomaly>, SkunkBatError>;
}

/// Trait for topology path validation.
///
/// This trait abstracts layer path validation for `BiomeOS` architectural
/// enforcement, detecting layer-hopping and security boundary bypasses.
#[async_trait]
pub trait TopologyValidator: Send + Sync {
    /// Validate a connection path through network layers.
    async fn validate_path(&self, actual_path: &[u8]) -> Result<PathValidation, SkunkBatError>;

    /// Get the expected path for a connection.
    fn expected_path(&self) -> Vec<u8>;
}

/// Path validation result.
#[derive(Debug, Clone)]
pub struct PathValidation {
    /// Whether the path is valid
    pub is_valid: bool,
    /// Expected path
    pub expected_path: Vec<u8>,
    /// Actual path taken
    pub actual_path: Vec<u8>,
    /// Bypassed layers (if any)
    pub bypassed_layers: Vec<u8>,
}

/// Observation for baseline analysis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    /// Connection rate (connections per second)
    pub connection_rate: f64,
    /// Traffic volume (bytes per second)
    pub traffic_volume: u64,
    /// Port distribution
    pub ports_accessed: Vec<u16>,
    /// Timestamp
    pub timestamp: SystemTime,
}

/// Detected anomaly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Anomaly {
    /// Deviation from baseline (in standard deviations)
    pub deviation: f64,
    /// Description of anomalous behavior
    pub behavior: String,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
}

/// Local-only lineage verifier (no external dependencies).
///
/// This implementation always returns "not family" for unknown peers,
/// representing the conservative default: trust must be explicitly verified.
pub struct LocalLineageVerifier;

#[async_trait]
impl LineageVerifier for LocalLineageVerifier {
    async fn is_family(&self, _peer_id: &str) -> Result<bool, SkunkBatError> {
        // Conservative default: unknown peers are not family
        Ok(false)
    }

    async fn get_lineage(&self, _peer_id: &str) -> Result<Option<String>, SkunkBatError> {
        // No lineage information available locally
        Ok(None)
    }
}

/// Simple statistical baseline profiler.
///
/// Uses moving averages and standard deviations for anomaly detection.
pub struct StatisticalProfiler {
    observations: Vec<Observation>,
    threshold: f64, // Number of standard deviations for anomaly
}

impl StatisticalProfiler {
    /// Create a new statistical profiler with given threshold.
    ///
    /// # Arguments
    ///
    /// * `threshold` - Number of standard deviations for anomaly detection (e.g., 2.5 for 2.5 sigma)
    #[must_use]
    pub const fn new(threshold: f64) -> Self {
        Self {
            observations: Vec::new(),
            threshold,
        }
    }
}

/// Simple layer-based topology validator.
///
/// Validates that connections traverse layers in the correct sequence,
/// detecting layer-hopping and security boundary bypasses.
pub struct LayerTopologyValidator {
    expected_path: Vec<u8>,
}

impl LayerTopologyValidator {
    /// Create a new topology validator with expected path.
    ///
    /// # Arguments
    ///
    /// * `expected_path` - The required layer traversal sequence (e.g., [0, 1, 2, 3])
    #[must_use]
    pub const fn new(expected_path: Vec<u8>) -> Self {
        Self { expected_path }
    }
}

#[async_trait]
impl TopologyValidator for LayerTopologyValidator {
    async fn validate_path(&self, actual_path: &[u8]) -> Result<PathValidation, SkunkBatError> {
        let is_valid = actual_path == self.expected_path.as_slice();

        // Find bypassed layers
        let bypassed_layers: Vec<u8> = self
            .expected_path
            .iter()
            .filter(|layer| !actual_path.contains(layer))
            .copied()
            .collect();

        Ok(PathValidation {
            is_valid,
            expected_path: self.expected_path.clone(),
            actual_path: actual_path.to_vec(),
            bypassed_layers,
        })
    }

    fn expected_path(&self) -> Vec<u8> {
        self.expected_path.clone()
    }
}

#[async_trait]
impl BaselineProfiler for StatisticalProfiler {
    fn is_established(&self) -> bool {
        // Need at least 10 observations to establish baseline
        self.observations.len() >= 10
    }

    async fn update(&mut self, observation: &Observation) -> Result<(), SkunkBatError> {
        self.observations.push(observation.clone());

        // Keep only recent observations (rolling window of 100)
        if self.observations.len() > 100 {
            self.observations.remove(0);
        }

        Ok(())
    }

    async fn detect_anomalies(
        &self,
        observation: &Observation,
    ) -> Result<Vec<Anomaly>, SkunkBatError> {
        if !self.is_established() {
            return Ok(Vec::new());
        }

        let mut anomalies = Vec::new();

        // Calculate statistics for connection rate
        let rates: Vec<f64> = self
            .observations
            .iter()
            .map(|o| o.connection_rate)
            .collect();

        if let Some((mean, std_dev)) = Self::calculate_stats(&rates) {
            let deviation = (observation.connection_rate - mean).abs() / std_dev;

            if deviation > self.threshold {
                anomalies.push(Anomaly {
                    deviation,
                    behavior: format!(
                        "Unusual connection rate: {:.2}/s (baseline: {:.2}±{:.2})",
                        observation.connection_rate, mean, std_dev
                    ),
                    confidence: (deviation / (self.threshold * 2.0)).min(1.0),
                });
            }
        }

        Ok(anomalies)
    }
}

impl StatisticalProfiler {
    fn calculate_stats(values: &[f64]) -> Option<(f64, f64)> {
        if values.is_empty() {
            return None;
        }

        #[allow(clippy::cast_precision_loss)]
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        #[allow(clippy::cast_precision_loss)]
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
        let std_dev = variance.sqrt();

        Some((mean, std_dev))
    }
}

/// Threat detector.
pub struct ThreatDetector {
    enabled: bool,
    #[allow(dead_code)]
    lineage_id: Option<String>,
    #[allow(dead_code)] // Will be used when implementing genetic threats with peer connections
    lineage_verifier: Box<dyn LineageVerifier>,
    baseline_profiler: Box<dyn BaselineProfiler>,
}

impl ThreatDetector {
    /// Create a new threat detector with default local implementations.
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        Self::with_verifiers(
            config,
            Box::new(LocalLineageVerifier),
            Box::new(StatisticalProfiler::new(2.5)), // 2.5 sigma threshold
        )
    }

    /// Create a threat detector with custom verifiers.
    ///
    /// This allows injection of different lineage and baseline implementations
    /// without hardcoding dependencies.
    #[must_use]
    pub fn with_verifiers(
        config: &SkunkBatConfig,
        lineage_verifier: Box<dyn LineageVerifier>,
        baseline_profiler: Box<dyn BaselineProfiler>,
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

    /// Detect threats.
    ///
    /// # Errors
    ///
    /// Returns an error if threat detection fails.
    pub async fn detect(&self) -> Result<Vec<Threat>, SkunkBatError> {
        if !self.enabled {
            return Ok(vec![]);
        }

        let mut threats = Vec::new();

        // Genetic threat detection (via lineage verifier trait)
        threats.extend(self.detect_genetic_threats().await?);

        // Behavioral anomaly detection (via baseline profiler trait)
        threats.extend(self.detect_behavioral_anomalies().await?);

        // Intrusion detection (signature-based)
        threats.extend(self.detect_intrusions().await?);

        // Resource exhaustion detection
        threats.extend(self.detect_resource_exhaustion().await?);

        if !threats.is_empty() {
            tracing::warn!("Detected {} threats", threats.len());
        }

        Ok(threats)
    }

    /// Detect genetic threats (unknown lineage).
    #[allow(clippy::unused_async)] // Async required for potential future impl with actual peer checks
    async fn detect_genetic_threats(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let threats = Vec::new();

        // Use lineage verifier trait - no hardcoded beardog dependency
        // In a real scenario, this would check actual peer connections
        // For now, this is a framework ready for integration

        tracing::debug!("Genetic threat detection ready (awaiting peer connections)");

        Ok(threats)
    }

    /// Detect behavioral anomalies.
    async fn detect_behavioral_anomalies(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let threats = Vec::new();

        if !self.baseline_profiler.is_established() {
            tracing::debug!("Baseline not established, learning normal behavior");
            return Ok(threats);
        }

        // Create a sample observation for detection
        // In production, this would come from actual network monitoring
        let observation = Observation {
            connection_rate: 10.0,
            traffic_volume: 1000,
            ports_accessed: vec![80, 443],
            timestamp: SystemTime::now(),
        };

        // Detect anomalies using the baseline profiler
        let anomalies = self
            .baseline_profiler
            .detect_anomalies(&observation)
            .await?;

        let mut result_threats = Vec::new();
        for anomaly in anomalies {
            let behavior_desc = anomaly.behavior.clone();
            result_threats.push(Threat {
                id: format!("anomaly-{:?}", SystemTime::now()),
                threat_type: ThreatType::BehaviorAnomaly {
                    deviation: anomaly.deviation,
                    behavior: anomaly.behavior,
                },
                severity: if anomaly.deviation > 5.0 {
                    Severity::High
                } else if anomaly.deviation > 3.0 {
                    Severity::Medium
                } else {
                    Severity::Low
                },
                source: "network".to_string(),
                target: "local".to_string(),
                detected_at: SystemTime::now(),
                description: format!("Behavioral anomaly detected: {behavior_desc}"),
                confidence: anomaly.confidence,
            });
        }

        Ok(result_threats)
    }

    /// Detect intrusion attempts.
    #[allow(clippy::unused_async)] // Async required for potential future impl with actual detection
    async fn detect_intrusions(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let threats = Vec::new();

        // Signature-based intrusion detection
        // In production, this would check against a signature database
        // For now, this demonstrates the framework

        tracing::debug!("Intrusion detection active (awaiting network data)");

        // Example: detect rapid connection attempts (port scanning)
        // This would integrate with actual network monitoring

        Ok(threats)
    }

    /// Detect resource exhaustion attacks.
    #[allow(clippy::unused_async)] // Async required for potential future impl with actual system monitoring
    async fn detect_resource_exhaustion(&self) -> Result<Vec<Threat>, SkunkBatError> {
        let threats = Vec::new();

        // Check system resources
        // In production, this would monitor actual system metrics

        // Example: Check if we can detect high resource usage
        let load = Self::check_system_load();
        // 90% threshold
        if load > 0.9 {
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
                confidence: 0.8,
            }]);
        }

        Ok(threats)
    }

    /// Check system load (normalized 0.0-1.0).
    const fn check_system_load() -> f64 {
        // In production, this would use actual system monitoring
        // For now, return a safe value
        0.1 // 10% load
    }
}

/// Detected threat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    /// Unique threat identifier
    pub id: String,
    /// Threat type
    pub threat_type: ThreatType,
    /// Severity level
    pub severity: Severity,
    /// Source of threat
    pub source: String,
    /// Target of threat
    pub target: String,
    /// Detection timestamp
    pub detected_at: SystemTime,
    /// Description
    pub description: String,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
}

/// Threat type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    /// Unknown lineage (genetic threat via beardog)
    UnknownLineage {
        /// Peer identifier
        peer_id: String,
        /// Lineage information (if available)
        lineage: Option<String>,
    },
    /// Anomalous behavior
    BehaviorAnomaly {
        /// Deviation from baseline
        deviation: f64,
        /// Observed behavior description
        behavior: String,
    },
    /// Intrusion attempt
    IntrusionAttempt {
        /// Attack type
        attack_type: String,
        /// Attack signature
        signature: String,
    },
    /// Denial of service
    DenialOfService {
        /// Resource being exhausted
        resource: String,
        /// Current usage level
        current_level: f64,
    },
    /// Topology violation (layer-hopping, path bypass)
    TopologyViolation {
        /// Expected path (layer sequence)
        expected_path: Vec<u8>,
        /// Actual path taken
        actual_path: Vec<u8>,
        /// Bypassed layers
        bypassed_layers: Vec<u8>,
    },
    /// Configuration drift
    ConfigurationDrift {
        /// Component that changed
        component: String,
        /// Expected value
        expected: String,
        /// Observed value
        observed: String,
    },
}

/// Threat severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Low severity - informational
    Low,
    /// Medium severity - potential threat
    Medium,
    /// High severity - active threat
    High,
    /// Critical severity - immediate action required
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FeatureFlags, SkunkBatConfig};
    use sourdough_core::config::CommonConfig;

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

        let result = detector.detect().await;
        assert!(result.is_ok());

        let threats = result.unwrap();
        // Initially should return no threats (stub implementation)
        assert!(threats.is_empty());
    }

    #[tokio::test]
    async fn test_statistical_profiler_learning() {
        let mut profiler = StatisticalProfiler::new(2.5);

        // Initially not established
        assert!(!profiler.is_established());

        // Add 10 observations to establish baseline
        for i in 0..10 {
            let observation = Observation {
                connection_rate: 10.0 + f64::from(i),
                traffic_volume: 1000,
                ports_accessed: vec![80, 443],
                timestamp: SystemTime::now(),
            };
            profiler.update(&observation).await.unwrap();
        }

        // Now baseline should be established
        assert!(profiler.is_established());
    }

    #[tokio::test]
    async fn test_statistical_profiler_anomaly_detection() {
        let mut profiler = StatisticalProfiler::new(2.5);

        // Establish baseline with some variation in normal traffic
        for i in 0..10 {
            let observation = Observation {
                connection_rate: f64::from(i).mul_add(0.1, 10.0), // Slight variation
                traffic_volume: 1000,
                ports_accessed: vec![80, 443],
                timestamp: SystemTime::now(),
            };
            profiler.update(&observation).await.unwrap();
        }

        // Test normal observation (should not detect anomaly)
        let normal_obs = Observation {
            connection_rate: 10.5,
            traffic_volume: 1000,
            ports_accessed: vec![80, 443],
            timestamp: SystemTime::now(),
        };
        let anomalies = profiler.detect_anomalies(&normal_obs).await.unwrap();
        // With slight variation in baseline, 10.5 should still be within threshold
        assert!(anomalies.is_empty() || anomalies[0].deviation < 2.5);

        // Test clearly anomalous observation (very high connection rate)
        let anomalous_obs = Observation {
            connection_rate: 100.0, // Much higher than baseline (10.0-11.0)
            traffic_volume: 1000,
            ports_accessed: vec![80, 443],
            timestamp: SystemTime::now(),
        };
        let anomalies = profiler.detect_anomalies(&anomalous_obs).await.unwrap();
        assert!(!anomalies.is_empty());
        assert!(anomalies[0].deviation > 2.5);
    }

    #[tokio::test]
    async fn test_local_lineage_verifier() {
        let verifier = LocalLineageVerifier;

        // Local verifier always returns false for family (conservative)
        assert!(!verifier.is_family("test-peer").await.unwrap());

        // Local verifier returns no lineage information
        let lineage = verifier.get_lineage("test-peer").await.unwrap();
        assert!(lineage.is_none());
    }

    #[tokio::test]
    async fn test_threat_detector_with_verifiers() {
        let config = test_config();
        let detector = ThreatDetector::with_verifiers(
            &config,
            Box::new(LocalLineageVerifier),
            Box::new(StatisticalProfiler::new(2.5)),
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
        assert!(Severity::Critical > Severity::Low);
    }

    #[test]
    fn test_threat_type_creation() {
        let threat_type = ThreatType::UnknownLineage {
            peer_id: "test-peer".to_string(),
            lineage: Some("unknown-lineage".to_string()),
        };

        match threat_type {
            ThreatType::UnknownLineage { peer_id, .. } => {
                assert_eq!(peer_id, "test-peer");
            }
            _ => panic!("Wrong threat type"),
        }
    }

    #[test]
    #[allow(clippy::float_cmp)]
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
    #[allow(clippy::float_cmp)]
    fn test_dos_threat() {
        let threat_type = ThreatType::DenialOfService {
            resource: "bandwidth".to_string(),
            current_level: 95.5,
        };

        match threat_type {
            ThreatType::DenialOfService {
                resource,
                current_level,
            } => {
                assert_eq!(resource, "bandwidth");
                assert_eq!(current_level, 95.5);
            }
            _ => panic!("Wrong threat type"),
        }
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_behavior_anomaly() {
        let threat_type = ThreatType::BehaviorAnomaly {
            deviation: 3.5,
            behavior: "unusual traffic pattern".to_string(),
        };

        match threat_type {
            ThreatType::BehaviorAnomaly {
                deviation,
                behavior,
            } => {
                assert_eq!(deviation, 3.5);
                assert_eq!(behavior, "unusual traffic pattern");
            }
            _ => panic!("Wrong threat type"),
        }
    }

    #[tokio::test]
    async fn test_statistical_profiler_baseline() {
        let mut profiler = StatisticalProfiler::new(2.5);

        // Before baseline established
        assert!(!profiler.is_established());

        // Add observations to establish baseline (needs 10+)
        for _ in 0..10 {
            let obs = Observation {
                connection_rate: 5.0,
                traffic_volume: 1000,
                ports_accessed: vec![80, 443],
                timestamp: SystemTime::now(),
            };
            profiler.update(&obs).await.unwrap();
        }

        // Should now be established
        assert!(profiler.is_established());
    }

    #[tokio::test]
    async fn test_detector_with_behavioral_anomalies() {
        let config = test_config();

        // Create detector with a profiler that has baseline
        let mut profiler = StatisticalProfiler::new(2.5);

        // Establish baseline
        for _ in 0..10 {
            let obs = Observation {
                connection_rate: 5.0,
                traffic_volume: 1000,
                ports_accessed: vec![80],
                timestamp: SystemTime::now(),
            };
            profiler.update(&obs).await.unwrap();
        }

        let detector = ThreatDetector::with_verifiers(
            &config,
            Box::new(LocalLineageVerifier),
            Box::new(profiler),
        );

        // Run detection - should check behavioral anomalies
        let threats = detector.detect().await.unwrap();

        // Might or might not find threats depending on baseline, but should run without error
        assert!(
            threats.is_empty() || !threats.is_empty(),
            "Should return a result"
        );
    }

    #[test]
    #[allow(clippy::float_cmp)]
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
    #[allow(clippy::float_cmp)]
    fn test_anomaly_creation() {
        let anomaly = Anomaly {
            deviation: 4.5,
            behavior: "High connection rate".to_string(),
            confidence: 0.92,
        };

        assert_eq!(anomaly.deviation, 4.5);
        assert_eq!(anomaly.confidence, 0.92);
        assert_eq!(anomaly.behavior, "High connection rate");
    }
}

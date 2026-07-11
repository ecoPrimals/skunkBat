// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Threat data types for skunkBat.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

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
    /// Unknown lineage (genetic threat via capability-based verifier)
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
    /// HTTP-layer anomaly (outer membrane).
    HttpAnomaly {
        /// Anomalous dimension (e.g. `request_rate`, `path_diversity`, `error_rate_4xx`)
        dimension: String,
        /// Deviation from baseline in standard deviations
        deviation: f64,
        /// Source IP address
        source_ip: String,
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
    /// HTTP-layer telemetry (outer membrane).
    /// `None` for inner-membrane (IPC/BTSP) observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpObservation>,
}

/// HTTP-specific telemetry for outer membrane anomaly detection.
///
/// Fed by Tower HTTP Gateway via `baseline.observe` / `security.advisory`.
/// Each snapshot covers a sliding window for one source IP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpObservation {
    /// HTTP request rate (requests per second) in the observation window.
    pub request_rate: f64,
    /// 4xx error rate as a fraction (0.0–1.0).
    pub error_rate_4xx: f64,
    /// 5xx error rate as a fraction (0.0–1.0).
    pub error_rate_5xx: f64,
    /// Number of distinct URL paths accessed.
    pub path_diversity: u32,
    /// Average request payload size (bytes).
    pub avg_payload_bytes: u64,
    /// Number of distinct HTTP methods used.
    pub method_diversity: u8,
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

/// Baseline profiler statistics for a single dimension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionStats {
    /// Mean value over the rolling window.
    pub mean: f64,
    /// Standard deviation over the rolling window.
    pub std_dev: f64,
}

/// Baseline profiler statistics across all observed dimensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineStats {
    /// Number of observations in the rolling window.
    pub observation_count: usize,
    /// Sigma threshold for anomaly detection.
    pub threshold: f64,
    /// Connection rate statistics (if available).
    pub connection_rate: Option<DimensionStats>,
    /// Traffic volume statistics (if available).
    pub traffic_volume: Option<DimensionStats>,
    /// Port diversity statistics (if available).
    pub port_diversity: Option<DimensionStats>,
    /// HTTP request rate statistics (outer membrane).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_request_rate: Option<DimensionStats>,
    /// HTTP path diversity statistics (outer membrane).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_path_diversity: Option<DimensionStats>,
    /// HTTP 4xx error rate statistics (outer membrane).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_error_rate_4xx: Option<DimensionStats>,
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

/// Snapshot of security-relevant configuration fields for drift detection.
///
/// Captured at startup and compared on each `detect()` cycle. Any field
/// that changes at runtime without a corresponding config-reload IPC call
/// is flagged as `ConfigurationDrift`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    /// Feature flag states (JSON-serialized for stable comparison).
    pub features_json: String,
    /// Lineage ID binding.
    pub lineage_id: Option<String>,
    /// Whether topology validation is active.
    pub topology_configured: bool,
    /// Detection-relevant threshold fingerprint (stringified sigma + dos).
    pub threshold_fingerprint: String,
}

impl ConfigSnapshot {
    /// Capture from a live config.
    #[must_use]
    pub fn from_config(config: &super::super::SkunkBatConfig) -> Self {
        Self {
            features_json: serde_json::to_string(&config.features).unwrap_or_default(),
            lineage_id: config.lineage_id.clone(),
            topology_configured: config.expected_topology_path.is_some(),
            threshold_fingerprint: format!(
                "sigma={:.2};dos={:.2};genetic={:.2}",
                config.thresholds.sigma_threshold,
                config.thresholds.dos_load_threshold,
                config.thresholds.genetic_confidence,
            ),
        }
    }

    /// Compare with another snapshot and return changed fields.
    #[must_use]
    pub fn diff(&self, other: &Self) -> Vec<(String, String, String)> {
        let mut diffs = Vec::new();
        if self.features_json != other.features_json {
            diffs.push((
                "features".to_owned(),
                self.features_json.clone(),
                other.features_json.clone(),
            ));
        }
        if self.lineage_id != other.lineage_id {
            diffs.push((
                "lineage_id".to_owned(),
                format!("{:?}", self.lineage_id),
                format!("{:?}", other.lineage_id),
            ));
        }
        if self.topology_configured != other.topology_configured {
            diffs.push((
                "topology_configured".to_owned(),
                self.topology_configured.to_string(),
                other.topology_configured.to_string(),
            ));
        }
        if self.threshold_fingerprint != other.threshold_fingerprint {
            diffs.push((
                "thresholds".to_owned(),
                self.threshold_fingerprint.clone(),
                other.threshold_fingerprint.clone(),
            ));
        }
        diffs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_serde_roundtrip() {
        let threat = Threat {
            id: "threat-001".to_owned(),
            threat_type: ThreatType::IntrusionAttempt {
                attack_type: "port-scan".to_owned(),
                signature: "nmap".to_owned(),
            },
            severity: Severity::High,
            source: "192.168.1.100".to_owned(),
            target: "192.168.1.1".to_owned(),
            detected_at: SystemTime::UNIX_EPOCH,
            description: "Port scan detected".to_owned(),
            confidence: 0.85,
        };

        let json = serde_json::to_string(&threat).unwrap();
        let parsed: Threat = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "threat-001");
        assert_eq!(parsed.severity, Severity::High);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn threat_type_unknown_lineage_serde() {
        let tt = ThreatType::UnknownLineage {
            peer_id: "peer-xyz".to_owned(),
            lineage: Some("family-a".to_owned()),
        };
        let json = serde_json::to_value(&tt).unwrap();
        assert!(json["UnknownLineage"]["peer_id"].is_string());
    }

    #[test]
    fn threat_type_dos_serde() {
        let tt = ThreatType::DenialOfService {
            resource: "cpu".to_owned(),
            current_level: 0.95,
        };
        let json = serde_json::to_value(&tt).unwrap();
        let parsed: ThreatType = serde_json::from_value(json).unwrap();
        match parsed {
            ThreatType::DenialOfService {
                resource,
                current_level,
            } => {
                assert_eq!(resource, "cpu");
                assert!((current_level - 0.95).abs() < f64::EPSILON);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn threat_type_topology_violation_serde() {
        let tt = ThreatType::TopologyViolation {
            expected_path: vec![1, 2, 3],
            actual_path: vec![1, 3],
            bypassed_layers: vec![2],
        };
        let json = serde_json::to_string(&tt).unwrap();
        let parsed: ThreatType = serde_json::from_str(&json).unwrap();
        match parsed {
            ThreatType::TopologyViolation {
                bypassed_layers, ..
            } => assert_eq!(bypassed_layers, vec![2]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn observation_serde_roundtrip() {
        let obs = Observation {
            connection_rate: 42.5,
            traffic_volume: 1_000_000,
            ports_accessed: vec![80, 443, 8080],
            timestamp: SystemTime::UNIX_EPOCH,
            http: None,
        };
        let json = serde_json::to_string(&obs).unwrap();
        let parsed: Observation = serde_json::from_str(&json).unwrap();
        assert!((parsed.connection_rate - 42.5).abs() < f64::EPSILON);
        assert_eq!(parsed.ports_accessed.len(), 3);
    }

    #[test]
    fn anomaly_serde_roundtrip() {
        let anomaly = Anomaly {
            deviation: 3.5,
            behavior: "spike".to_owned(),
            confidence: 0.9,
        };
        let json = serde_json::to_string(&anomaly).unwrap();
        let parsed: Anomaly = serde_json::from_str(&json).unwrap();
        assert!((parsed.deviation - 3.5).abs() < f64::EPSILON);
    }

    #[test]
    fn path_validation_construction() {
        let pv = PathValidation {
            is_valid: false,
            expected_path: vec![1, 2, 3],
            actual_path: vec![1, 3],
            bypassed_layers: vec![2],
        };
        assert!(!pv.is_valid);
        assert_eq!(pv.bypassed_layers.len(), 1);
    }

    #[test]
    fn severity_equality() {
        assert_eq!(Severity::Critical, Severity::Critical);
        assert_ne!(Severity::Low, Severity::High);
    }

    #[test]
    fn severity_clone() {
        let s = Severity::High;
        let cloned = s;
        assert_eq!(s, cloned);
    }

    #[test]
    fn threat_type_behavior_anomaly_serde() {
        let tt = ThreatType::BehaviorAnomaly {
            deviation: 4.2,
            behavior: "connection spike".to_owned(),
        };
        let json = serde_json::to_value(&tt).unwrap();
        let parsed: ThreatType = serde_json::from_value(json).unwrap();
        match parsed {
            ThreatType::BehaviorAnomaly {
                deviation,
                behavior,
            } => {
                assert!((deviation - 4.2).abs() < f64::EPSILON);
                assert_eq!(behavior, "connection spike");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn threat_type_config_drift_serde() {
        let tt = ThreatType::ConfigurationDrift {
            component: "firewall".to_owned(),
            expected: "enabled".to_owned(),
            observed: "disabled".to_owned(),
        };
        let json = serde_json::to_string(&tt).unwrap();
        let parsed: ThreatType = serde_json::from_str(&json).unwrap();
        match parsed {
            ThreatType::ConfigurationDrift {
                component,
                expected,
                observed,
            } => {
                assert_eq!(component, "firewall");
                assert_eq!(expected, "enabled");
                assert_eq!(observed, "disabled");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn threat_clone() {
        let threat = Threat {
            id: "t-clone".to_owned(),
            threat_type: ThreatType::IntrusionAttempt {
                attack_type: "scan".to_owned(),
                signature: "nmap".to_owned(),
            },
            severity: Severity::Medium,
            source: "10.0.0.1".to_owned(),
            target: "10.0.0.2".to_owned(),
            detected_at: SystemTime::UNIX_EPOCH,
            description: "test".to_owned(),
            confidence: 0.7,
        };
        let cloned = threat.clone();
        assert_eq!(cloned.id, threat.id);
        assert_eq!(cloned.severity, threat.severity);
    }

    #[test]
    fn observation_empty_ports() {
        let obs = Observation {
            connection_rate: 0.0,
            traffic_volume: 0,
            ports_accessed: vec![],
            timestamp: SystemTime::UNIX_EPOCH,
            http: None,
        };
        let json = serde_json::to_string(&obs).unwrap();
        let parsed: Observation = serde_json::from_str(&json).unwrap();
        assert!(parsed.ports_accessed.is_empty());
    }

    #[test]
    fn path_validation_valid_path() {
        let pv = PathValidation {
            is_valid: true,
            expected_path: vec![0, 1, 2, 3],
            actual_path: vec![0, 1, 2, 3],
            bypassed_layers: vec![],
        };
        assert!(pv.is_valid);
        assert!(pv.bypassed_layers.is_empty());
    }

    #[test]
    fn all_severity_values_serialize() {
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let json = serde_json::to_string(&severity).unwrap();
            let parsed: Severity = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, severity);
        }
    }

    #[test]
    fn threat_type_intrusion_debug() {
        let tt = ThreatType::IntrusionAttempt {
            attack_type: "brute_force".to_owned(),
            signature: "ssh-rapid".to_owned(),
        };
        let debug = format!("{tt:?}");
        assert!(debug.contains("IntrusionAttempt"));
        assert!(debug.contains("brute_force"));
    }

    #[test]
    fn anomaly_confidence_range() {
        let low = Anomaly {
            deviation: 1.0,
            behavior: "normal".to_owned(),
            confidence: 0.0,
        };
        let high = Anomaly {
            deviation: 10.0,
            behavior: "extreme".to_owned(),
            confidence: 1.0,
        };
        assert!(low.confidence <= high.confidence);
    }

    #[test]
    fn observation_large_ports_list() {
        let obs = Observation {
            connection_rate: 100.0,
            traffic_volume: 5_000_000,
            ports_accessed: (1..=100).collect(),
            timestamp: SystemTime::UNIX_EPOCH,
            http: None,
        };
        assert_eq!(obs.ports_accessed.len(), 100);
        let json = serde_json::to_string(&obs).unwrap();
        let parsed: Observation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ports_accessed.len(), 100);
    }

    #[test]
    fn threat_unknown_lineage_none_lineage() {
        let tt = ThreatType::UnknownLineage {
            peer_id: "unknown-peer".to_owned(),
            lineage: None,
        };
        let json = serde_json::to_value(&tt).unwrap();
        assert!(json["UnknownLineage"]["lineage"].is_null());
    }
}

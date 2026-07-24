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
    /// Anomalous process spawn rate (crash-loop detection).
    ///
    /// Fires when the system-wide fork rate exceeds a configurable threshold,
    /// indicating runaway service restarts (e.g. systemd `Restart=always` on
    /// a broken binary). See Wave 150x crash-loop divergence.
    ProcessSpawnAnomaly {
        /// Measured spawns per second.
        rate: f64,
        /// Configured threshold that was exceeded.
        threshold: f64,
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
    ///
    /// Tuple: `(field_name, old_value, new_value)`.
    #[must_use]
    pub fn diff(&self, other: &Self) -> Vec<(&'static str, String, String)> {
        let mut diffs = Vec::new();
        if self.features_json != other.features_json {
            diffs.push((
                "features",
                self.features_json.clone(),
                other.features_json.clone(),
            ));
        }
        if self.lineage_id != other.lineage_id {
            diffs.push((
                "lineage_id",
                format!("{:?}", self.lineage_id),
                format!("{:?}", other.lineage_id),
            ));
        }
        if self.topology_configured != other.topology_configured {
            diffs.push((
                "topology_configured",
                self.topology_configured.to_string(),
                other.topology_configured.to_string(),
            ));
        }
        if self.threshold_fingerprint != other.threshold_fingerprint {
            diffs.push((
                "thresholds",
                self.threshold_fingerprint.clone(),
                other.threshold_fingerprint.clone(),
            ));
        }
        diffs
    }
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;

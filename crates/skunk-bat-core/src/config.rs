// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! skunkBat configuration.

use crate::primal_foundation::config::CommonConfig;
use serde::{Deserialize, Serialize};

/// Feature flags for skunkBat capabilities.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "feature flags are naturally boolean"
)]
pub struct FeatureFlags {
    /// Enable reconnaissance
    pub reconnaissance: bool,

    /// Enable threat detection
    pub threat_detection: bool,

    /// Enable automated defense
    pub auto_defense: bool,

    /// Enable security observability
    pub observability: bool,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            reconnaissance: true,
            threat_detection: true,
            auto_defense: true,
            observability: true,
        }
    }
}

/// Tunable thresholds for threat detection — avoids hardcoded magic numbers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatThresholds {
    /// Sigma deviation that triggers an anomaly report.
    pub sigma_threshold: f64,
    /// Deviation above which anomalies are classified as `Severity::High`.
    pub severity_high_deviation: f64,
    /// Deviation above which anomalies are classified as `Severity::Medium`.
    pub severity_medium_deviation: f64,
    /// Normalized system load (0.0–1.0) that triggers a `DoS` threat.
    pub dos_load_threshold: f64,
    /// Confidence assigned to resource-exhaustion detections.
    pub dos_confidence: f64,
    /// Confidence assigned when lineage verification fails.
    pub genetic_confidence: f64,
    /// Ports that trigger a port-scan detection when 2+ are accessed.
    pub intrusion_sensitive_ports: Vec<u16>,
    /// Minimum traffic volume (bytes) before exfiltration heuristic fires.
    pub intrusion_exfil_volume: u64,
    /// Traffic-to-connection ratio above which exfiltration is suspected.
    pub intrusion_exfil_ratio: f64,
    /// Confidence assigned to port-scan detections.
    pub intrusion_portscan_confidence: f64,
    /// Confidence assigned to data-exfiltration detections.
    pub intrusion_exfil_confidence: f64,
    /// Confidence assigned when lineage verifier is unreachable (degraded mode).
    pub degraded_genetic_confidence: f64,
    /// Confidence assigned to topology violation detections.
    pub topology_confidence: f64,
    /// Confidence assigned to configuration drift detections.
    pub drift_confidence: f64,
    /// Minimum confidence for automatic quarantine of critical threats.
    pub quarantine_critical_confidence: f64,
    /// Minimum confidence for automatic quarantine of high-severity threats.
    pub quarantine_high_confidence: f64,
    /// Rolling window size for behavioral profiler observations.
    pub behavioral_rolling_window: usize,
    /// Minimum observations before baseline is considered established.
    pub behavioral_min_observations: usize,
    /// Audit log ring buffer capacity (max events retained).
    pub audit_log_capacity: usize,
}

impl Default for ThreatThresholds {
    fn default() -> Self {
        Self {
            sigma_threshold: 2.5,
            severity_high_deviation: 5.0,
            severity_medium_deviation: 3.0,
            dos_load_threshold: 0.9,
            dos_confidence: 0.8,
            genetic_confidence: 0.95,
            intrusion_sensitive_ports: vec![22, 23, 3389, 445, 135],
            intrusion_exfil_volume: 100_000,
            intrusion_exfil_ratio: 10_000.0,
            intrusion_portscan_confidence: 0.75,
            intrusion_exfil_confidence: 0.6,
            degraded_genetic_confidence: 0.5,
            topology_confidence: 0.9,
            drift_confidence: 0.85,
            quarantine_critical_confidence: 0.9,
            quarantine_high_confidence: 0.7,
            behavioral_rolling_window: 100,
            behavioral_min_observations: 10,
            audit_log_capacity: 1024,
        }
    }
}

/// Configuration for skunkBat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkunkBatConfig {
    /// Common configuration.
    #[serde(flatten)]
    pub common: CommonConfig,

    /// Feature flags
    pub features: FeatureFlags,

    /// Lineage ID for family-only monitoring
    pub lineage_id: Option<String>,

    /// Threat detection thresholds
    #[serde(default)]
    pub thresholds: ThreatThresholds,

    /// Expected layer traversal path for topology validation.
    /// When set, connections whose observed paths deviate from this
    /// sequence generate `TopologyViolation` threats.
    #[serde(default)]
    pub expected_topology_path: Option<Vec<u8>>,
}

impl Default for SkunkBatConfig {
    fn default() -> Self {
        Self {
            common: CommonConfig {
                name: crate::PRIMAL_NAME.to_owned(),
                ..CommonConfig::default()
            },
            features: FeatureFlags::default(),
            lineage_id: None,
            thresholds: ThreatThresholds::default(),
            expected_topology_path: None,
        }
    }
}

impl SkunkBatConfig {
    /// Hydrate config from environment variables, falling back to defaults.
    ///
    /// Reads identity, topology, and threat-detection thresholds from env.
    /// Fields not set in the environment retain their `Default` values.
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::default();

        config.common.data_dir = std::env::var(crate::env_keys::SKUNKBAT_DATA_DIR)
            .unwrap_or_else(|_| "./data".to_owned());

        if let Ok(id) = std::env::var(crate::env_keys::SKUNKBAT_LINEAGE_ID)
            && !id.is_empty()
        {
            config.lineage_id = Some(id);
        }

        if let Ok(path) = std::env::var(crate::env_keys::SKUNKBAT_TOPOLOGY_PATH) {
            let bytes: Vec<u8> = path
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            if !bytes.is_empty() {
                config.expected_topology_path = Some(bytes);
            }
        }

        hydrate_thresholds(&mut config.thresholds);

        config
    }
}

/// Parse env var into a typed value, logging a warning on malformed input.
fn try_env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    let val = std::env::var(key).ok()?;
    val.parse().map_or_else(
        |_| {
            tracing::warn!("ignoring malformed env var {key}={val:?}");
            None
        },
        Some,
    )
}

fn hydrate_thresholds(t: &mut ThreatThresholds) {
    if let Some(v) = try_env_parse::<f64>(crate::env_keys::SKUNKBAT_SIGMA_THRESHOLD) {
        t.sigma_threshold = v;
    }
    if let Some(v) = try_env_parse::<f64>(crate::env_keys::SKUNKBAT_DOS_LOAD_THRESHOLD) {
        t.dos_load_threshold = v;
    }
    if let Some(v) = try_env_parse::<f64>(crate::env_keys::SKUNKBAT_GENETIC_CONFIDENCE) {
        t.genetic_confidence = v;
    }
    if let Some(v) = try_env_parse::<usize>(crate::env_keys::SKUNKBAT_BEHAVIORAL_WINDOW) {
        t.behavioral_rolling_window = v;
    }
    if let Some(v) = try_env_parse::<usize>(crate::env_keys::SKUNKBAT_BEHAVIORAL_MIN_OBS) {
        t.behavioral_min_observations = v;
    }
    if let Some(v) = try_env_parse::<usize>(crate::env_keys::SKUNKBAT_AUDIT_LOG_CAPACITY) {
        t.audit_log_capacity = v;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_feature_flags_all_enabled() {
        let flags = FeatureFlags::default();
        assert!(flags.reconnaissance);
        assert!(flags.threat_detection);
        assert!(flags.auto_defense);
        assert!(flags.observability);
    }

    #[test]
    fn config_default_uses_primal_name() {
        let config = SkunkBatConfig::default();
        assert_eq!(config.common.name, crate::PRIMAL_NAME);
        assert!(config.lineage_id.is_none());
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = SkunkBatConfig {
            common: CommonConfig::default(),
            features: FeatureFlags {
                reconnaissance: true,
                threat_detection: false,
                auto_defense: true,
                observability: false,
            },
            lineage_id: Some("family-alpha".to_owned()),
            thresholds: ThreatThresholds::default(),
            expected_topology_path: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SkunkBatConfig = serde_json::from_str(&json).unwrap();
        assert!(!parsed.features.threat_detection);
        assert_eq!(parsed.lineage_id.as_deref(), Some("family-alpha"));
    }

    #[test]
    #[expect(clippy::float_cmp, reason = "exact default comparison in test")]
    fn threat_thresholds_defaults() {
        let t = ThreatThresholds::default();
        assert_eq!(t.sigma_threshold, 2.5);
        assert_eq!(t.dos_load_threshold, 0.9);
        assert_eq!(t.genetic_confidence, 0.95);
    }

    #[test]
    fn feature_flags_serde_roundtrip() {
        let flags = FeatureFlags {
            reconnaissance: false,
            threat_detection: true,
            auto_defense: false,
            observability: true,
        };
        let json = serde_json::to_string(&flags).unwrap();
        let parsed: FeatureFlags = serde_json::from_str(&json).unwrap();
        assert!(!parsed.reconnaissance);
        assert!(parsed.threat_detection);
    }

    #[test]
    fn from_env_defaults_when_unset() {
        let config = SkunkBatConfig::from_env();
        assert_eq!(config.common.name, crate::PRIMAL_NAME);
        assert!(config.lineage_id.is_none());
        assert!(config.expected_topology_path.is_none());
    }
}

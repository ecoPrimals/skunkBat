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
        }
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
}

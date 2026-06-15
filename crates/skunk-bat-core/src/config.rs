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

/// Tunable thresholds for threat detection.
///
/// Every numeric threshold is exposed here rather than buried as a
/// module-level `const`. Derivations follow the wateringHole
/// `DERIVATION_ANCHORING_STANDARD` — each value has a documented origin.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Sigma threshold for statistical anomaly detection.
    /// Origin: 2.5σ ≈ 99.38% of normal observations fall within.
    pub sigma_threshold: f64,

    /// Deviation (in σ) above which a behavioral anomaly is `High` severity.
    pub severity_high_deviation: f64,

    /// Deviation (in σ) above which a behavioral anomaly is `Medium` severity.
    pub severity_medium_deviation: f64,

    /// System load fraction that triggers a `DenialOfService` threat.
    pub dos_load_threshold: f64,

    /// Confidence assigned to resource-exhaustion detections.
    pub dos_confidence: f64,

    /// Port count threshold that triggers a port-scan detection.
    pub port_scan_threshold: usize,

    /// Confidence assigned to port-scan detections.
    pub port_scan_confidence: f64,

    /// Confidence assigned to genetic lineage verification failures.
    /// Origin: 0.95 = high confidence (identity-based, not heuristic).
    pub genetic_lineage_confidence: f64,

    /// Confidence assigned to topology bypass detections.
    /// Origin: 0.8 = moderate (port-to-layer mapping is heuristic).
    pub topology_bypass_confidence: f64,

    /// Consecutive sequential ports that indicate a port scan pattern.
    /// Origin: 3 = minimum run length for "sequential" detection.
    pub sequential_port_window: usize,

    /// Minimum distinct topology layers before evaluating bypass.
    /// Origin: 3 = need at least 3 layers for a meaningful path check.
    pub min_topology_path_layers: usize,

    /// Expected topology path for layer validation.
    /// Default `[0, 1, 2, 3]` = standard 4-layer ecoPrimals stack.
    pub expected_topology_path: Vec<u8>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            sigma_threshold: 2.5,
            severity_high_deviation: 5.0,
            severity_medium_deviation: 3.0,
            dos_load_threshold: 0.9,
            dos_confidence: 0.8,
            port_scan_threshold: 10,
            port_scan_confidence: 0.85,
            genetic_lineage_confidence: 0.95,
            topology_bypass_confidence: 0.8,
            sequential_port_window: 3,
            min_topology_path_layers: 3,
            expected_topology_path: vec![0, 1, 2, 3],
        }
    }
}

/// Tunable thresholds for the defense engine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefenseConfig {
    /// Confidence threshold for auto-quarantine of `Critical` threats.
    pub critical_confidence_threshold: f64,

    /// Confidence threshold for auto-quarantine of `High` threats.
    pub high_confidence_threshold: f64,

    /// Repeat quarantines before escalation to block.
    pub escalation_threshold: u32,
}

impl Default for DefenseConfig {
    fn default() -> Self {
        Self {
            critical_confidence_threshold: 0.9,
            high_confidence_threshold: 0.7,
            escalation_threshold: 3,
        }
    }
}

/// Configuration for skunkBat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkunkBatConfig {
    /// Common configuration.
    #[serde(flatten)]
    pub common: CommonConfig,

    /// Feature flags.
    pub features: FeatureFlags,

    /// Lineage ID for family-only monitoring.
    pub lineage_id: Option<String>,

    /// Threat detection thresholds.
    #[serde(default)]
    pub detection: DetectionConfig,

    /// Defense engine thresholds.
    #[serde(default)]
    pub defense: DefenseConfig,
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
            detection: DetectionConfig::default(),
            defense: DefenseConfig::default(),
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
            ..SkunkBatConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SkunkBatConfig = serde_json::from_str(&json).unwrap();
        assert!(!parsed.features.threat_detection);
        assert_eq!(parsed.lineage_id.as_deref(), Some("family-alpha"));
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
    fn detection_config_defaults() {
        let d = DetectionConfig::default();
        assert!((d.sigma_threshold - 2.5).abs() < f64::EPSILON);
        assert_eq!(d.port_scan_threshold, 10);
        assert!((d.dos_load_threshold - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn defense_config_defaults() {
        let d = DefenseConfig::default();
        assert!((d.critical_confidence_threshold - 0.9).abs() < f64::EPSILON);
        assert!((d.high_confidence_threshold - 0.7).abs() < f64::EPSILON);
        assert_eq!(d.escalation_threshold, 3);
    }

    #[test]
    fn detection_config_serde_roundtrip() {
        let config = DetectionConfig {
            sigma_threshold: 3.0,
            port_scan_threshold: 20,
            ..DetectionConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DetectionConfig = serde_json::from_str(&json).unwrap();
        assert!((parsed.sigma_threshold - 3.0).abs() < f64::EPSILON);
        assert_eq!(parsed.port_scan_threshold, 20);
    }

    #[test]
    fn defense_config_serde_roundtrip() {
        let config = DefenseConfig {
            escalation_threshold: 5,
            ..DefenseConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DefenseConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.escalation_threshold, 5);
    }

    #[test]
    fn config_with_detection_overrides() {
        let config = SkunkBatConfig {
            detection: DetectionConfig {
                sigma_threshold: 1.5,
                ..DetectionConfig::default()
            },
            ..SkunkBatConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SkunkBatConfig = serde_json::from_str(&json).unwrap();
        assert!((parsed.detection.sigma_threshold - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn config_missing_detection_uses_defaults() {
        let json = r#"{"name":"test","instance_id":"abc123","log_level":"info","data_dir":"./data","listen_addr":"127.0.0.1","listen_port":0,"features":{"reconnaissance":true,"threat_detection":true,"auto_defense":true,"observability":true}}"#;
        let parsed: SkunkBatConfig = serde_json::from_str(json).unwrap();
        assert!((parsed.detection.sigma_threshold - 2.5).abs() < f64::EPSILON);
        assert_eq!(parsed.defense.escalation_threshold, 3);
    }
}

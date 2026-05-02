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
}

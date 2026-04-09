// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! skunkBat configuration.

use serde::{Deserialize, Serialize};
use sourdough_core::config::CommonConfig;

/// Feature flags for skunkBat capabilities.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
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
                name: "skunkBat".to_string(),
                ..CommonConfig::default()
            },
            features: FeatureFlags::default(),
            lineage_id: None,
        }
    }
}

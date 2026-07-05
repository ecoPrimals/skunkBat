// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Shared test fixtures for `skunk-bat-core` unit tests.

#![allow(unreachable_pub)]

use crate::config::{FeatureFlags, SkunkBatConfig, ThreatThresholds};
use crate::primal_foundation::CommonConfig;

/// Standard test config with all features enabled and no lineage.
#[must_use]
pub fn test_config() -> SkunkBatConfig {
    SkunkBatConfig {
        common: CommonConfig {
            name: "skunkBat-test".to_string(),
            data_dir: String::new(),
            ..CommonConfig::default()
        },
        features: FeatureFlags {
            reconnaissance: true,
            threat_detection: true,
            auto_defense: true,
            observability: true,
        },
        lineage_id: None,
        thresholds: ThreatThresholds::default(),
        expected_topology_path: None,
    }
}

/// Test config with a lineage ID for genetic verification tests.
#[must_use]
pub fn test_config_with_lineage() -> SkunkBatConfig {
    SkunkBatConfig {
        lineage_id: Some("test-lineage".to_string()),
        ..test_config()
    }
}

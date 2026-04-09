// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Integration tests for skunkBat with beardog
//!
//! Tests genetic lineage verification integration

#[cfg(test)]
mod beardog_integration {
    use skunk_bat_core::{SkunkBat, SkunkBatConfig};
    use sourdough_core::PrimalLifecycle;

    #[tokio::test]
    #[ignore = "requires beardog integration"]
    async fn test_lineage_verification() {
        let config = SkunkBatConfig {
            lineage_id: Some("test-family-lineage".to_string()),
            ..Default::default()
        };

        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.unwrap();

        // Requires a live lineage-verification provider for full coverage.
        // Integration: register with lineage_id, verify the genetic trust chain, and surface unknown-lineage threats.

        let _threats = skunkbat.detect_threats().await.unwrap();
        // Should detect threats from unknown lineages

        skunkbat.stop().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires beardog integration"]
    async fn test_family_only_monitoring() {
        let config = SkunkBatConfig {
            lineage_id: Some("family-123".to_string()),
            ..Default::default()
        };

        let skunkbat = SkunkBat::new(config);

        // Family-scoped reconnaissance assumes beardog-backed lineage filtering when integrated.
        // Scope: restrict scans to verified lineage, flag external connections, and validate genetic threat signals.

        let scan = skunkbat.scan_network().await.unwrap();
        // Should only include family nodes
        for node in &scan.nodes {
            // Verify node lineage matches family
            assert!(node.id.contains("family") || node.id.contains("local"));
        }
    }

    #[tokio::test]
    #[ignore = "requires beardog integration"]
    async fn test_genetic_threat_response() {
        let config = SkunkBatConfig {
            lineage_id: Some("secure-family".to_string()),
            ..Default::default()
        };

        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.unwrap();

        // Exercises containment when traffic appears from an unregistered lineage.
        // Steps: simulate an unknown-lineage peer, assert detection, then assert quarantine or equivalent isolation.

        skunkbat.stop().await.unwrap();
    }
}

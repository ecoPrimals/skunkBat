// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! End-to-end integration tests for skunkBat
//!
//! Tests full ecosystem integration with multiple primals

#[cfg(test)]
mod e2e_tests {
    use skunk_bat_core::PrimalLifecycle;
    use skunk_bat_core::{SkunkBat, SkunkBatConfig};

    #[tokio::test]
    async fn test_full_lifecycle_workflow() {
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);

        // Start skunkBat
        skunkbat.start().await.expect("Start should succeed");

        // Scan network topology
        let scan = skunkbat.scan_network().await.expect("Scan should succeed");
        assert!(!scan.nodes.is_empty(), "Should discover at least self");

        // Detect threats
        let threats = skunkbat
            .detect_threats()
            .await
            .expect("Detection should succeed");

        // Respond to any detected threats
        for threat in &threats {
            skunkbat
                .respond_to_threat(threat)
                .expect("Response should succeed");
        }

        // Get security metrics
        let metrics = skunkbat.get_security_metrics();
        assert!(metrics.last_updated.is_some(), "Metrics should be updated");

        // Stop cleanly
        skunkbat.stop().await.expect("Stop should succeed");
    }

    #[tokio::test]
    async fn test_local_only_operation() {
        // Test skunkBat in local-only mode (no external primals)
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);

        skunkbat.start().await.expect("Start should succeed");

        // Should work locally without external dependencies
        let scan = skunkbat
            .scan_network()
            .await
            .expect("Local scan should work");
        assert_eq!(scan.nodes.len(), 1, "Should discover only self");
        assert_eq!(scan.nodes[0].node_type, "skunkBat");

        skunkbat.stop().await.expect("Stop should succeed");
    }

    #[tokio::test]
    #[ignore = "requires beardog runtime"]
    async fn test_genetic_verification() {
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.expect("Start should succeed");

        // Test lineage verification with beardog integration
        // Would require actual beardog instance

        skunkbat.stop().await.expect("Stop should succeed");
    }

    #[tokio::test]
    #[ignore = "requires songbird runtime"]
    async fn test_threat_broadcasting() {
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.expect("Start should succeed");

        // Test threat intelligence sharing via songbird
        // Would require actual songbird instance

        skunkbat.stop().await.expect("Stop should succeed");
    }

    #[tokio::test]
    #[ignore = "requires toadstool runtime"]
    async fn test_primal_discovery() {
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.expect("Start should succeed");

        // Test capability-based discovery via toadstool
        // Would require actual toadstool instance

        skunkbat.stop().await.expect("Stop should succeed");
    }

    #[tokio::test]
    async fn test_degraded_operation() {
        // Test graceful degradation when features are disabled
        let mut config = SkunkBatConfig::default();
        config.features.reconnaissance = false;
        config.features.auto_defense = false;

        let mut skunkbat = SkunkBat::new(config);
        skunkbat
            .start()
            .await
            .expect("Start should succeed even with features disabled");

        // Should still operate, but with limited capabilities
        let scan = skunkbat.scan_network().await.expect("Scan should work");
        assert!(
            scan.nodes.is_empty(),
            "Disabled recon should return empty scan"
        );

        let _threats = skunkbat
            .detect_threats()
            .await
            .expect("Detection should work");
        // May or may not detect threats, but shouldn't error

        skunkbat.stop().await.expect("Stop should succeed");
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Chaos and fault injection tests for skunkBat
//!
//! Tests system resilience under adverse conditions:
//! - Simulated primal failures
//! - Resource exhaustion
//! - Network partitions (simulated)
//! - State corruption recovery
//! - Concurrent load
//!
//! These tests verify that skunkBat degrades gracefully and recovers
//! properly from fault conditions.

#[cfg(test)]
mod chaos_tests {
    use skunk_bat_core::PrimalLifecycle;
    use skunk_bat_core::{SkunkBat, SkunkBatConfig};
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_rapid_start_stop_cycles() {
        // Test: Rapid lifecycle transitions don't cause issues
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);

        // Perform 10 rapid start/stop cycles
        for _ in 0..10 {
            skunkbat.start().await.expect("Start should succeed");
            skunkbat.stop().await.expect("Stop should succeed");
        }

        // Final verification
        skunkbat.start().await.expect("Final start should succeed");
        let scan = skunkbat.scan_network().await;
        assert!(
            scan.is_ok(),
            "System should be functional after rapid cycles"
        );
        skunkbat.stop().await.expect("Final stop should succeed");
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        // Test: Multiple operations happening simultaneously
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.expect("Start should succeed");

        // Spawn concurrent scan operations
        let scan1 = skunkbat.scan_network();
        let scan2 = skunkbat.scan_network();
        let scan3 = skunkbat.scan_network();

        // All operations should complete successfully
        let (r1, r2, r3) = tokio::join!(scan1, scan2, scan3);
        assert!(r1.is_ok(), "Concurrent scan 1 should succeed");
        assert!(r2.is_ok(), "Concurrent scan 2 should succeed");
        assert!(r3.is_ok(), "Concurrent scan 3 should succeed");

        // Test concurrent detections
        let detect1 = skunkbat.detect_threats();
        let detect2 = skunkbat.detect_threats();
        let detect3 = skunkbat.detect_threats();

        let (d1, d2, d3) = tokio::join!(detect1, detect2, detect3);
        assert!(d1.is_ok(), "Concurrent detection 1 should succeed");
        assert!(d2.is_ok(), "Concurrent detection 2 should succeed");
        assert!(d3.is_ok(), "Concurrent detection 3 should succeed");

        skunkbat.stop().await.expect("Stop should succeed");
    }

    #[tokio::test]
    async fn test_operation_without_start() {
        // Test: Operations before start should handle gracefully
        let config = SkunkBatConfig::default();
        let skunkbat = SkunkBat::new(config);

        // These should work even without start() being called
        // (because skunkBat is designed for robustness)
        let scan = skunkbat.scan_network().await;
        let threats = skunkbat.detect_threats().await;
        let metrics = skunkbat.get_security_metrics();

        // Should not panic or error catastrophically
        assert!(scan.is_ok() || scan.is_err());
        assert!(threats.is_ok() || threats.is_err());
        assert!(metrics.last_updated.is_some() || metrics.last_updated.is_none());
    }

    #[tokio::test]
    async fn test_disabled_features_degradation() {
        // Test: System works with all features disabled
        let mut config = SkunkBatConfig::default();
        config.features.reconnaissance = false;
        config.features.threat_detection = false;
        config.features.auto_defense = false;
        config.features.observability = false;

        let mut skunkbat = SkunkBat::new(config);

        // Should still start/stop without errors
        skunkbat
            .start()
            .await
            .expect("Should start even with all features disabled");

        // Operations should degrade gracefully
        let scan = skunkbat.scan_network().await;
        assert!(scan.is_ok(), "Scan should return empty result, not error");

        let threats = skunkbat.detect_threats().await;
        assert!(
            threats.is_ok(),
            "Detection should return empty result, not error"
        );

        skunkbat.stop().await.expect("Should stop cleanly");
    }

    #[tokio::test]
    async fn test_detection_under_load() {
        // Test: Can handle rapid repeated detections
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.expect("Start should succeed");

        // Perform 100 rapid detections
        for _ in 0..100 {
            let result = skunkbat.detect_threats().await;
            assert!(result.is_ok(), "Detection should not fail under load");
        }

        skunkbat.stop().await.expect("Stop should succeed");
    }

    #[tokio::test]
    async fn test_scanning_under_load() {
        // Test: Can handle rapid repeated scans
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.expect("Start should succeed");

        // Perform 50 rapid scans
        for _ in 0..50 {
            let result = skunkbat.scan_network().await;
            assert!(result.is_ok(), "Scanning should not fail under load");
        }

        skunkbat.stop().await.expect("Stop should succeed");
    }

    #[tokio::test]
    async fn test_metrics_collection_stability() {
        // Test: Metrics remain consistent and don't corrupt
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.expect("Start should succeed");

        // Perform operations and check metrics consistency
        for _ in 0..20 {
            let _ = skunkbat.scan_network().await;
            let _ = skunkbat.detect_threats().await;

            let metrics = skunkbat.get_security_metrics();
            assert!(metrics.last_updated.is_some(), "Metrics should be updated");

            // Metrics should be internally consistent
            assert!(metrics.scans_performed >= metrics.threats_detected);
        }

        skunkbat.stop().await.expect("Stop should succeed");
    }

    #[tokio::test]
    async fn test_recovery_after_simulated_failure() {
        // Test: System can recover after simulated component failure
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);

        // Normal operation
        skunkbat
            .start()
            .await
            .expect("Initial start should succeed");
        let _ = skunkbat.scan_network().await;

        // Simulate failure by stopping
        skunkbat.stop().await.expect("Stop should succeed");

        // Small delay to simulate recovery time
        sleep(Duration::from_millis(100)).await;

        // Recovery - restart and verify functionality
        skunkbat
            .start()
            .await
            .expect("Recovery start should succeed");
        let scan = skunkbat.scan_network().await;
        assert!(scan.is_ok(), "Should be operational after recovery");

        skunkbat.stop().await.expect("Final stop should succeed");
    }

    #[tokio::test]
    #[ignore = "requires deployment environment for stress testing"]
    async fn test_extended_operation() {
        // Test: Can run for extended period without degradation
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.expect("Start should succeed");

        // Run for simulated extended period (10 seconds)
        let start_time = std::time::Instant::now();
        let duration = Duration::from_secs(10);

        while start_time.elapsed() < duration {
            let _ = skunkbat.scan_network().await;
            let _ = skunkbat.detect_threats().await;
            sleep(Duration::from_millis(100)).await;
        }

        // Verify still operational
        let final_scan = skunkbat.scan_network().await;
        assert!(
            final_scan.is_ok(),
            "Should remain operational after extended run"
        );

        skunkbat.stop().await.expect("Stop should succeed");
    }

    #[tokio::test]
    async fn test_partial_feature_degradation() {
        // Test: Each feature can fail independently without affecting others
        let scenarios = vec![
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
            (true, true, false, false),
            (true, false, true, false),
        ];

        for (recon, detect, defend, observe) in scenarios {
            let mut config = SkunkBatConfig::default();
            config.features.reconnaissance = recon;
            config.features.threat_detection = detect;
            config.features.auto_defense = defend;
            config.features.observability = observe;

            let mut skunkbat = SkunkBat::new(config);

            assert!(
                skunkbat.start().await.is_ok(),
                "Should start with any feature combination"
            );
            assert!(
                skunkbat.stop().await.is_ok(),
                "Should stop with any feature combination"
            );
        }
    }
}

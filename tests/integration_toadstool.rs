//! Integration tests for skunkBat with toadstool
//!
//! Tests capability-based discovery integration

#[cfg(test)]
mod toadstool_integration {
    use skunk_bat_core::{SkunkBat, SkunkBatConfig};
    use sourdough_core::PrimalLifecycle;

    #[tokio::test]
    #[ignore = "requires toadstool integration"]
    async fn test_capability_discovery() {
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);

        skunkbat.start().await.unwrap();

        // TODO: Test capability-based primal discovery via toadstool
        // - Register skunkBat capabilities
        // - Discover other primals
        // - Verify discovered nodes in reconnaissance scan

        skunkbat.stop().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires toadstool integration"]
    async fn test_primal_communication() {
        let config = SkunkBatConfig::default();
        let skunkbat = SkunkBat::new(config);

        // TODO: Test communication with discovered primals
        // - Query primal capabilities
        // - Verify connection status
        // - Map network topology

        let scan = skunkbat.scan_network().await.unwrap();
        assert!(!scan.nodes.is_empty());
    }
}

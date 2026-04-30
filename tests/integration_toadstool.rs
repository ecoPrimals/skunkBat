// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Integration tests for skunkBat with toadstool
//!
//! Tests capability-based discovery integration

#[cfg(test)]
mod toadstool_integration {
    use skunk_bat_core::PrimalLifecycle;
    use skunk_bat_core::{SkunkBat, SkunkBatConfig};

    #[tokio::test]
    #[ignore = "requires toadstool integration"]
    async fn test_capability_discovery() {
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);

        skunkbat.start().await.unwrap();

        // Needs toadstool in the loop for capability advertisement and peer discovery.
        // Flow: register skunkBat capabilities, discover peers, and align reconnaissance results with discovered nodes.

        skunkbat.stop().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires toadstool integration"]
    async fn test_primal_communication() {
        let config = SkunkBatConfig::default();
        let skunkbat = SkunkBat::new(config);

        // Exercises interaction with primals surfaced by discovery rather than static fixtures alone.
        // Covers: capability queries, connection health, and topology mapping from reconnaissance output.

        let scan = skunkbat.scan_network().await.unwrap();
        assert!(!scan.nodes.is_empty());
    }
}

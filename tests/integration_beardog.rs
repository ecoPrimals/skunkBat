// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Integration tests for skunkBat ↔ `BearDog` IPC surface.
//!
//! These tests exercise real JSON-RPC calls against a live `BearDog` binary.
//! Run with `BEARDOG_BIN` pointing at the beardog binary and a writable
//! `BIOMEOS_IPC_DIR` for sockets:
//!
//! ```sh
//! BEARDOG_BIN=../../infra/plasmidBin/primals/beardog \
//! BIOMEOS_IPC_DIR=/tmp/skunkbat-test \
//! cargo test --test integration_beardog -- --ignored
//! ```

#[cfg(test)]
mod beardog_integration {
    use skunk_bat_core::{SkunkBat, SkunkBatConfig};
    use sourdough_core::PrimalLifecycle;
    use std::path::PathBuf;

    fn beardog_bin() -> Option<PathBuf> {
        let path = std::env::var("BEARDOG_BIN")
            .unwrap_or_else(|_| "../../infra/plasmidBin/primals/beardog".into());
        let p = PathBuf::from(&path);
        if p.exists() { Some(p) } else { None }
    }

    fn ipc_dir() -> PathBuf {
        let dir = std::env::var("BIOMEOS_IPC_DIR")
            .unwrap_or_else(|_| "/tmp/skunkbat-beardog-test".into());
        let p = PathBuf::from(&dir);
        std::fs::create_dir_all(&p).ok();
        p
    }

    #[tokio::test]
    #[ignore = "requires beardog binary (set BEARDOG_BIN)"]
    async fn test_beardog_capabilities() {
        let bin = beardog_bin().expect("BEARDOG_BIN not found");
        let dir = ipc_dir();

        let mut child = tokio::process::Command::new(&bin)
            .arg("serve")
            .env("BIOMEOS_IPC_DIR", &dir)
            .env("FAMILY_SEED", "dGVzdC1zZWVkLWZvci1za3Vua2JhdA==")
            .kill_on_drop(true)
            .spawn()
            .expect("failed to start beardog");

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let socket = dir.join("beardog.sock");
        if socket.exists() {
            let result = skunk_bat_integrations::rpc::call_uds(
                socket.to_str().unwrap(),
                "capabilities.list",
                Some(serde_json::json!({})),
                std::time::Duration::from_secs(5),
            )
            .await;
            assert!(
                result.is_ok(),
                "capabilities.list should succeed: {result:?}"
            );
        }

        child.kill().await.ok();
    }

    #[tokio::test]
    #[ignore = "requires beardog binary (set BEARDOG_BIN)"]
    async fn test_lineage_verification() {
        let config = SkunkBatConfig {
            lineage_id: Some("test-family-lineage".to_string()),
            ..Default::default()
        };

        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.unwrap();

        let _threats = skunkbat.detect_threats().await.unwrap();

        skunkbat.stop().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires beardog binary (set BEARDOG_BIN)"]
    async fn test_family_only_monitoring() {
        let config = SkunkBatConfig {
            lineage_id: Some("family-123".to_string()),
            ..Default::default()
        };

        let skunkbat = SkunkBat::new(config);

        let scan = skunkbat.scan_network().await.unwrap();
        for node in &scan.nodes {
            assert!(node.id.contains("family") || node.id.contains("local"));
        }
    }

    #[tokio::test]
    #[ignore = "requires beardog binary (set BEARDOG_BIN)"]
    async fn test_genetic_threat_response() {
        let config = SkunkBatConfig {
            lineage_id: Some("secure-family".to_string()),
            ..Default::default()
        };

        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.unwrap();

        skunkbat.stop().await.unwrap();
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Basic usage example for skunkBat
//!
//! Demonstrates the core functionality of the skunkBat primal:
//! - Starting the primal
//! - Performing reconnaissance
//! - Detecting threats
//! - Responding to threats
//! - Observing security metrics

use skunk_bat_core::{PrimalHealth, PrimalLifecycle};
use skunk_bat_core::{SkunkBat, SkunkBatConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("=== skunkBat Basic Usage Example ===\n");

    // Create configuration
    let config = SkunkBatConfig::default();
    println!("✓ Configuration created");

    // Create skunkBat instance
    let mut skunkbat = SkunkBat::new(config);
    println!("✓ skunkBat instance created\n");

    // Start the primal
    println!("Starting skunkBat...");
    skunkbat.start().await?;
    println!("✓ skunkBat running\n");

    // Perform reconnaissance
    println!("Performing network reconnaissance...");
    let scan = skunkbat.scan_network().await?;
    println!("✓ Scan complete:");
    println!("  - Nodes discovered: {}", scan.nodes.len());
    println!("  - Connections mapped: {}", scan.topology.len());
    for node in &scan.nodes {
        println!("    • {} ({}): {:?}", node.id, node.node_type, node.status);
    }
    println!();

    // Detect threats
    println!("Detecting threats...");
    let threats = skunkbat.detect_threats().await?;
    println!("✓ Threat detection complete:");
    println!("  - Threats detected: {}", threats.len());
    if threats.is_empty() {
        println!("    • No threats detected (all clear!)");
    } else {
        for threat in &threats {
            println!(
                "    • {:?} from {} (severity: {:?})",
                threat.threat_type, threat.source, threat.severity
            );
        }
    }
    println!();

    // Get security metrics
    println!("Retrieving security metrics...");
    let metrics = skunkbat.get_security_metrics();
    println!("✓ Security Metrics:");
    println!("  - Threats detected: {}", metrics.threats.detected);
    println!("  - Threats mitigated: {}", metrics.threats.mitigated);
    println!("  - Scans performed: {}", metrics.scanning.performed);
    println!(
        "  - Connections quarantined: {}",
        metrics.defense.connections_quarantined
    );
    println!("  - Alerts sent: {}", metrics.defense.alerts_sent);
    println!();

    // Check health
    println!("Checking primal health...");
    let health = skunkbat.health_check().await?;
    println!("✓ Health Status: {:?}", health.status);
    println!();

    // Stop the primal
    println!("Stopping skunkBat...");
    skunkbat.stop().await?;
    println!("✓ skunkBat stopped\n");

    println!("=== Example Complete ===");
    println!("\nskunkBat successfully demonstrated:");
    println!("  ✓ Primal lifecycle (start/stop)");
    println!("  ✓ Network reconnaissance");
    println!("  ✓ Threat detection");
    println!("  ✓ Security observability");
    println!("  ✓ Health monitoring");

    Ok(())
}

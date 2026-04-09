// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Continuous monitoring example for skunkBat
//!
//! Demonstrates a continuous monitoring loop that periodically:
//! - Scans the network
//! - Detects threats
//! - Responds to threats
//! - Reports metrics

use skunk_bat_core::{SkunkBat, SkunkBatConfig};
use sourdough_core::{PrimalHealth, PrimalLifecycle};
use std::time::Duration;
use tokio::time;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("=== skunkBat Continuous Monitoring Example ===\n");
    println!("Starting continuous security monitoring...");
    println!("Press Ctrl+C to stop\n");

    // Create and start skunkBat
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    // Monitoring loop
    let mut iteration = 0;
    let scan_interval = Duration::from_secs(10);

    loop {
        iteration += 1;
        println!("--- Monitoring Cycle {iteration} ---");

        // 1. Perform reconnaissance
        match skunkbat.scan_network().await {
            Ok(scan) => {
                println!("✓ Network scan complete:");
                println!("  • {} nodes discovered", scan.nodes.len());
                println!("  • {} connections active", scan.topology.len());
            }
            Err(e) => {
                eprintln!("✗ Scan failed: {e}");
            }
        }

        // 2. Detect threats
        match skunkbat.detect_threats().await {
            Ok(threats) => {
                if threats.is_empty() {
                    println!("✓ No threats detected");
                } else {
                    println!("⚠ {} threat(s) detected!", threats.len());
                    for threat in &threats {
                        println!(
                            "  • {:?} from {} (severity: {:?}, confidence: {:.2})",
                            threat.threat_type, threat.source, threat.severity, threat.confidence
                        );

                        // Respond to each threat
                        if let Err(e) = skunkbat.respond_to_threat(threat) {
                            eprintln!("  ✗ Response failed: {e}");
                        } else {
                            println!("  ✓ Response executed");
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("✗ Threat detection failed: {e}");
            }
        }

        // 3. Report metrics
        let metrics = skunkbat.get_security_metrics();
        println!("📊 Security Metrics:");
        println!("  • Threats detected: {}", metrics.threats_detected);
        println!("  • Threats mitigated: {}", metrics.threats_mitigated);
        println!("  • Scans performed: {}", metrics.scans_performed);
        println!(
            "  • Quarantines active: {}",
            metrics.connections_quarantined
        );
        println!("  • Alerts sent: {}", metrics.alerts_sent);

        // 4. Health check
        match skunkbat.health_check().await {
            Ok(report) => {
                println!("💚 Health: {:?}", report.status);
            }
            Err(e) => {
                eprintln!("💔 Health check failed: {e}");
            }
        }

        println!();

        // Wait before next cycle
        time::sleep(scan_interval).await;
    }

    // Note: This code is unreachable due to the infinite loop
    // In practice, you'd want to handle graceful shutdown with signals
    // skunkbat.stop().await?;
    // Ok(())
}

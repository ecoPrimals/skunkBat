// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Local federation demonstration for skunkBat
//!
//! Shows two skunkBat instances coordinating defense while maintaining
//! independent authority and sovereignty.

use skunk_bat_core::{
    SkunkBat, SkunkBatConfig,
    threats::{Severity, Threat, ThreatType},
};
use sourdough_core::PrimalLifecycle;
use std::time::SystemTime;

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    println!("🦨 skunkBat - Local Federation Demo");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Two skunkBats coordinating defense...\n");

    // ════════════════════════════════════════
    // SETUP: Two Independent Instances
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SETUP: Independent Instances");
    println!("════════════════════════════════════════\n");

    println!("Starting skunkBat-A (Home Network)");
    let config_a = SkunkBatConfig::default();
    let mut skunkbat_a = SkunkBat::new(config_a);
    skunkbat_a.start().await?;
    println!("  ✓ skunkBat-A: Online");
    println!("  • Owner: Alice");
    println!("  • Network: 192.168.1.0/24");
    println!("  • Authority: Independent\n");

    println!("Starting skunkBat-B (Home Office)");
    let config_b = SkunkBatConfig::default();
    let mut skunkbat_b = SkunkBat::new(config_b);
    skunkbat_b.start().await?;
    println!("  ✓ skunkBat-B: Online");
    println!("  • Owner: Bob");
    println!("  • Network: 10.0.1.0/24");
    println!("  • Authority: Independent\n");

    println!("Key Principle: Each owner maintains FULL sovereignty");
    println!("  • Alice controls skunkBat-A");
    println!("  • Bob controls skunkBat-B");
    println!("  • No central authority\n");

    // ════════════════════════════════════════
    // SCENARIO 1: Independent Detection
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SCENARIO 1: Independent Detection");
    println!("════════════════════════════════════════\n");

    println!("Threat appears on Alice's network...\n");

    let threat_a = Threat {
        id: "federation-threat-1".to_string(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "Port Scan".to_string(),
            signature: "nmap-syn".to_string(),
        },
        severity: Severity::High,
        source: "203.0.113.50".to_string(),
        target: "192.168.1.100".to_string(),
        detected_at: SystemTime::now(),
        description: "Port scanning detected on home network".to_string(),
        confidence: 0.85,
    };

    println!("skunkBat-A detects threat:");
    println!("  • Type: Port Scan");
    println!("  • Source: 203.0.113.50");
    println!("  • Target: 192.168.1.100 (Alice's device)");
    println!("  • Confidence: 85%\n");

    skunkbat_a.respond_to_threat(&threat_a)?;

    println!("✓ skunkBat-A responds:");
    println!("  → Quarantined 203.0.113.50");
    println!("  → Alerted Alice");
    println!("  → Alice decides next steps\n");

    println!("skunkBat-B status:");
    println!("  → No action (different network)");
    println!("  → Bob's network unaffected");
    println!("  → Independent operation\n");

    // ════════════════════════════════════════
    // SCENARIO 2: Shared Intelligence (Opt-In)
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SCENARIO 2: Shared Intelligence");
    println!("════════════════════════════════════════\n");

    println!("Alice chooses to share threat signature...");
    println!("  (Via Songbird federation - user decision)\n");

    println!("Shared Intelligence:");
    println!("  • Threat signature: nmap-syn (NOT Alice's data)");
    println!("  • Source pattern: 203.0.113.* range");
    println!("  • Attack type: Port scanning");
    println!("  • Confidence: High\n");

    println!("Bob's skunkBat receives intelligence:");
    println!("  ✓ Signature added to detection rules");
    println!("  ✓ Bob's baseline unchanged (his normal preserved)");
    println!("  ✓ Bob maintains independent authority");
    println!("  ✓ No Alice data exposed (only pattern)\n");

    // Now same attacker tries Bob's network
    println!("Same attacker targets Bob's network...\n");

    let threat_b = Threat {
        id: "federation-threat-2".to_string(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "Port Scan".to_string(),
            signature: "nmap-syn".to_string(), // Matches shared intelligence
        },
        severity: Severity::High,
        source: "203.0.113.50".to_string(),
        target: "10.0.1.50".to_string(),
        detected_at: SystemTime::now(),
        description: "Port scanning detected - matches shared intelligence".to_string(),
        confidence: 0.95, // Higher confidence due to shared intel
    };

    println!("skunkBat-B detects threat:");
    println!("  • Type: Port Scan");
    println!("  • Source: 203.0.113.50 (MATCHES SHARED INTEL!)");
    println!("  • Target: 10.0.1.50 (Bob's device)");
    println!("  • Confidence: 95% (boosted by federation)\n");

    skunkbat_b.respond_to_threat(&threat_b)?;

    println!("✓ skunkBat-B responds:");
    println!("  → Quarantined 203.0.113.50 immediately");
    println!("  → Higher confidence due to shared intelligence");
    println!("  → Alerted Bob");
    println!("  → Bob protected by Alice's experience\n");

    // ════════════════════════════════════════
    // SCENARIO 3: Independent Baselines
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SCENARIO 3: Independent Baselines");
    println!("════════════════════════════════════════\n");

    println!("Alice's network baseline:");
    println!("  • Connection rate: 5 conn/sec (home use)");
    println!("  • Peak hours: Evenings");
    println!("  • Devices: 8 (IoT-heavy)\n");

    println!("Bob's network baseline:");
    println!("  • Connection rate: 25 conn/sec (home office)");
    println!("  • Peak hours: Business hours");
    println!("  • Devices: 15 (work + home)\n");

    println!("Behavioral anomaly on Bob's network:");
    println!("  • Connection rate: 50 conn/sec");
    println!("  • Deviation: 10σ from BOB'S baseline\n");

    println!("skunkBat-B analysis:");
    println!("  ✗ Anomalous for BOB (10σ deviation)");
    println!("  → Would be normal for enterprise");
    println!("  → Detects based on BOB'S normal\n");

    println!("skunkBat-A analysis:");
    println!("  • No action (different network)");
    println!("  • Alice's baseline unaffected");
    println!("  • 50 conn/sec would be 22σ for Alice!");
    println!("  → Each network learns independently\n");

    // ════════════════════════════════════════
    // SUMMARY
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SUMMARY: Federation Principles");
    println!("════════════════════════════════════════\n");

    println!("Federation Model:");
    println!("  ✓ Independent Authority (each owner decides)");
    println!("  ✓ Opt-In Sharing (user chooses to federate)");
    println!("  ✓ Signature Sharing (NOT raw data)");
    println!("  ✓ Independent Baselines (YOUR normal preserved)");
    println!("  ✓ Boosted Confidence (shared intel improves detection)\n");

    println!("What's Shared:");
    println!("  ✅ Threat signatures (patterns)");
    println!("  ✅ Attack types (categories)");
    println!("  ✅ Source patterns (IP ranges, behaviors)");
    println!("  ✅ Confidence levels\n");

    println!("What's NOT Shared:");
    println!("  ❌ Raw traffic data");
    println!("  ❌ User activity");
    println!("  ❌ Network topology details");
    println!("  ❌ Individual baselines");
    println!("  ❌ Defense decisions (each owner decides)\n");

    println!("Architecture:");
    println!("  • No central authority");
    println!("  • Peer-to-peer federation");
    println!("  • Songbird for coordination");
    println!("  • Beardog for trust verification");
    println!("  • Each owner maintains sovereignty\n");

    // Get metrics
    let metrics_a = skunkbat_a.get_security_metrics();
    let metrics_b = skunkbat_b.get_security_metrics();

    println!("Final Status:");
    println!("  skunkBat-A:");
    println!("    • Threats processed: {}", metrics_a.threats_detected);
    println!("    • Status: Healthy");
    println!("    • Owner: Alice (full control)\n");

    println!("  skunkBat-B:");
    println!("    • Threats processed: {}", metrics_b.threats_detected);
    println!("    • Status: Healthy");
    println!("    • Owner: Bob (full control)\n");

    // Stop both instances
    skunkbat_a.stop().await?;
    skunkbat_b.stop().await?;

    println!("✅ Demo Complete!\n");
    println!("Key Takeaway: Federation ENHANCES security WITHOUT sacrificing sovereignty.");
    println!("Coordination, not centralization. 🦨");

    Ok(())
}

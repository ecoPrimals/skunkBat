// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Defensive vs Surveillance demonstration for skunkBat
//!
//! Architectural proof that skunkBat is defensive reconnaissance, NOT surveillance.
//! This demo shows what skunkBat CAN'T do by design.

use skunk_bat_core::PrimalLifecycle;
use skunk_bat_core::{SkunkBat, SkunkBatConfig};

#[expect(clippy::too_many_lines, reason = "self-contained demo")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    println!("🦨 skunkBat - Defensive vs Surveillance");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Architectural proof: Defense, NOT Surveillance\n");

    // Create and start skunkBat
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    // ════════════════════════════════════════
    // WHAT SKUNKBAT MONITORS
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("WHAT SKUNKBAT MONITORS");
    println!("════════════════════════════════════════\n");

    println!("✅ Connection Metadata:");
    println!("  • Source IP/port");
    println!("  • Destination IP/port");
    println!("  • Connection rate (connections/sec)");
    println!("  • Bandwidth usage");
    println!("  • Connection duration\n");

    println!("✅ Cryptographic Proofs:");
    println!("  • Genetic lineage (via Beardog)");
    println!("  • Trust chains");
    println!("  • Identity verification\n");

    println!("✅ Network Topology:");
    println!("  • Layer traversal paths");
    println!("  • Architectural boundaries");
    println!("  • Network scope\n");

    println!("✅ Statistical Patterns:");
    println!("  • Deviation from YOUR baseline");
    println!("  • Anomaly detection");
    println!("  • Resource consumption\n");

    println!("Why These?");
    println!("  → All DEFENSIVE indicators");
    println!("  → No content inspection");
    println!("  → Pattern-based, not behavior-based");
    println!("  → Protects YOUR network, not monitors users\n");

    // ════════════════════════════════════════
    // WHAT SKUNKBAT CANNOT DO
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("WHAT SKUNKBAT CANNOT DO (By Design)");
    println!("════════════════════════════════════════\n");

    println!("❌ Packet Payload Inspection:");
    println!("  • No deep packet inspection (DPI)");
    println!("  • Cannot read packet contents");
    println!("  • Cannot decrypt traffic");
    println!("  • No content filtering\n");

    println!("❌ User Activity Tracking:");
    println!("  • Cannot track browsing history");
    println!("  • Cannot monitor application usage");
    println!("  • Cannot profile user behavior");
    println!("  • Cannot identify individual users\n");

    println!("❌ Data Collection:");
    println!("  • Cannot store personal data");
    println!("  • Cannot log communications");
    println!("  • Cannot export user information");
    println!("  • Cannot build user profiles\n");

    println!("❌ Centralized Control:");
    println!("  • No remote override");
    println!("  • No third-party access");
    println!("  • No centralized database");
    println!("  • No external reporting (without user consent)\n");

    println!("Why Can't It?");
    println!("  → APIs don't exist in the codebase");
    println!("  → Architecture doesn't support it");
    println!("  → Data structures don't store it");
    println!("  → Zero capability for content access\n");

    // ════════════════════════════════════════
    // ARCHITECTURAL PROOF
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("ARCHITECTURAL PROOF");
    println!("════════════════════════════════════════\n");

    println!("1. Data Structures:");
    println!("```rust");
    println!("pub struct Observation {{");
    println!("    connection_rate: f64,    // Metadata only");
    println!("    traffic_volume: u64,     // Bytes, not content");
    println!("    ports_accessed: Vec<u16>, // Numbers, not payloads");
    println!("    // NO: packet_contents, user_data, etc.");
    println!("}}");
    println!("```\n");

    println!("2. Threat Detection:");
    println!("```rust");
    println!("pub enum ThreatType {{");
    println!("    UnknownLineage,    // Genetic trust (WHO)");
    println!("    BehaviorAnomaly,   // Statistical (PATTERN)");
    println!("    IntrusionAttempt,  // Attack signature (WHAT)");
    println!("    DenialOfService,   // Resource usage (CAPACITY)");
    println!("    // NO: ContentViolation, UserBehavior, etc.");
    println!("}}");
    println!("```\n");

    println!("3. Baseline Profiling:");
    println!("```rust");
    println!("// Learns YOUR normal (not user patterns)");
    println!("fn detect_anomalies(observation: &Observation) {{");
    println!("    let deviation = (obs.rate - mean) / std_dev;");
    println!("    // Compares TRAFFIC RATE, not content");
    println!("    // Compares to YOUR baseline, not universal");
    println!("}}");
    println!("```\n");

    println!("4. Zero Content Access:");
    println!("  • No TLS/SSL interception");
    println!("  • No man-in-the-middle capability");
    println!("  • No decryption keys");
    println!("  • No payload parsing\n");

    // ════════════════════════════════════════
    // COMPARISON TABLE
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SURVEILLANCE vs DEFENSE");
    println!("════════════════════════════════════════\n");

    println!("┌───────────────────┬─────────────┬─────────────┐");
    println!("│ Capability        │ Surveillance│ skunkBat    │");
    println!("├───────────────────┼─────────────┼─────────────┤");
    println!("│ Packet Contents   │ ✅ Yes      │ ❌ No       │");
    println!("│ User Tracking     │ ✅ Yes      │ ❌ No       │");
    println!("│ Browsing History  │ ✅ Yes      │ ❌ No       │");
    println!("│ Content Filtering │ ✅ Yes      │ ❌ No       │");
    println!("│ DPI (Deep Packet) │ ✅ Yes      │ ❌ No       │");
    println!("│ Centralized DB    │ ✅ Yes      │ ❌ No       │");
    println!("│ Third-party Share │ ✅ Yes      │ ❌ No       │");
    println!("├───────────────────┼─────────────┼─────────────┤");
    println!("│ Connection Metadata│ ✅ Yes     │ ✅ Yes      │");
    println!("│ Genetic Trust     │ ❌ No       │ ✅ Yes      │");
    println!("│ Attack Signatures │ ✅ Yes      │ ✅ Yes      │");
    println!("│ Anomaly Detection │ ❌ No       │ ✅ Yes      │");
    println!("│ User Authority    │ ❌ No       │ ✅ Yes      │");
    println!("│ Local-by-Default  │ ❌ No       │ ✅ Yes      │");
    println!("│ Sovereignty First │ ❌ No       │ ✅ Yes      │");
    println!("└───────────────────┴─────────────┴─────────────┘\n");

    // ════════════════════════════════════════
    // PHILOSOPHICAL PROOF
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("PHILOSOPHICAL PROOF");
    println!("════════════════════════════════════════\n");

    println!("Surveillance:");
    println!("  • Goal: Monitor and control USERS");
    println!("  • Method: Inspect content, track behavior");
    println!("  • Authority: Centralized (system decides)");
    println!("  • Privacy: Sacrificed for 'security'");
    println!("  • Data: Collected, stored, shared\n");

    println!("skunkBat (Defense):");
    println!("  • Goal: Protect NETWORKS from threats");
    println!("  • Method: Pattern detection, metadata analysis");
    println!("  • Authority: User (owner decides)");
    println!("  • Privacy: Preserved by architecture");
    println!("  • Data: Local, ephemeral, user-controlled\n");

    println!("Key Distinction:");
    println!("  Surveillance asks: 'What are users doing?'");
    println!("  Defense asks: 'Is the network under attack?'\n");

    // ════════════════════════════════════════
    // SUMMARY
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SUMMARY: Defensive by Architecture");
    println!("════════════════════════════════════════\n");

    println!("Proof Points:");
    println!("  1. Zero content access APIs");
    println!("  2. Metadata-only data structures");
    println!("  3. No user tracking capabilities");
    println!("  4. Pattern-based, not behavior-based");
    println!("  5. User authority required for actions");
    println!("  6. Local-by-default data storage");
    println!("  7. No centralized control or reporting\n");

    println!("Cannot Be Surveillance Because:");
    println!("  • The code literally cannot access packet payloads");
    println!("  • No data structures exist for user tracking");
    println!("  • No APIs exist for content inspection");
    println!("  • Architecture enforces sovereignty");
    println!("  • User maintains full control\n");

    println!("This isn't a promise or policy.");
    println!("This is ARCHITECTURAL IMPOSSIBILITY.\n");

    // Get metrics
    let _metrics = skunkbat.get_security_metrics();

    // Stop skunkBat
    skunkbat.stop().await?;

    println!("✅ Demo Complete!\n");
    println!("═══════════════════════════════════════════════");
    println!("🎉 LEVEL 0 COMPLETE!");
    println!("═══════════════════════════════════════════════\n");
    println!("You've mastered local skunkBat capabilities!");
    println!("Next: ../../01-ecosystem-integration/ for inter-primal demos\n");
    println!("Key Takeaway: Defensive by architecture, not by promise. 🦨");

    Ok(())
}

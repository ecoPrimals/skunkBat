// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Songbird integration demonstration for skunkBat
//!
//! Shows federated threat intelligence sharing. Demonstrates how skunkBat
//! broadcasts threat signatures (NOT raw data) across towers.

use skunk_bat_core::PrimalLifecycle;
use skunk_bat_core::{
    SkunkBat, SkunkBatConfig,
    threats::{Severity, Threat, ThreatType},
};
use std::time::SystemTime;

#[expect(clippy::too_many_lines, reason = "self-contained demo")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    println!("🦨 + 🐦 skunkBat + Songbird Integration Demo");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Federated Threat Intelligence: Share patterns, not data\n");

    // ════════════════════════════════════════
    // SETUP: Federation Architecture
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SETUP: Threat Intelligence Sharing");
    println!("════════════════════════════════════════\n");

    println!("What Gets Shared (✅):");
    println!("  ✅ Threat signatures (patterns)");
    println!("  ✅ Attack types (categories)");
    println!("  ✅ Source patterns (IP ranges, behaviors)");
    println!("  ✅ Confidence levels");
    println!("  ✅ Timestamps\n");

    println!("What Does NOT Get Shared (❌):");
    println!("  ❌ Raw traffic data");
    println!("  ❌ Packet payloads");
    println!("  ❌ User activity");
    println!("  ❌ Network topology details");
    println!("  ❌ Individual baselines\n");

    println!("Integration Pattern:");
    println!("```rust");
    println!("pub trait ThreatBroadcaster {{");
    println!("    async fn broadcast_signature(&self, sig: ThreatSignature);");
    println!("    async fn subscribe_to_intel(&self) -> Stream<ThreatIntel>;");
    println!("}}");
    println!("```\n");

    // Create two skunkBat instances (Alice and Bob)
    println!("Simulating two-tower federation...\n");

    let config_alice = SkunkBatConfig::default();
    let mut skunkbat_alice = SkunkBat::new(config_alice);
    skunkbat_alice.start().await?;
    println!("✓ skunkBat-Alice online (tower-alice)");

    let config_bob = SkunkBatConfig::default();
    let mut skunkbat_bob = SkunkBat::new(config_bob);
    skunkbat_bob.start().await?;
    println!("✓ skunkBat-Bob online (tower-bob)\n");

    // ════════════════════════════════════════
    // SCENARIO 1: Alice Detects Threat
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SCENARIO 1: Threat Detection & Broadcast");
    println!("════════════════════════════════════════\n");

    println!("Alice's network under attack...\n");

    let threat_alice = Threat {
        id: "songbird-threat-1".to_string(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "SQL Injection".to_string(),
            signature: "union-select-payload".to_string(),
        },
        severity: Severity::Critical,
        source: "203.0.113.50".to_string(),
        target: "tower-alice.local".to_string(),
        detected_at: SystemTime::now(),
        description: "SQL injection attempt detected".to_string(),
        confidence: 0.95,
    };

    println!("🦨 Alice detects:");
    println!("  • Type: SQL Injection");
    println!("  • Signature: union-select-payload");
    println!("  • Source: 203.0.113.50");
    println!("  • Severity: Critical");
    println!("  • Confidence: 95%\n");

    skunkbat_alice.respond_to_threat(&threat_alice)?;

    println!("🦨 → 🐦 Alice broadcasts (via Songbird):");
    println!("  ThreatSignature {{");
    println!("    signature: \"union-select-payload\",");
    println!("    attack_type: \"SQL Injection\",");
    println!("    source_pattern: \"203.0.113.*\",");
    println!("    severity: Critical,");
    println!("    confidence: 0.95,");
    println!("    // NO raw data, NO Alice's topology");
    println!("  }}\n");

    println!("🐦 Songbird routes:");
    println!("  • Validates signature format");
    println!("  • Checks Alice's trust level");
    println!("  • Broadcasts to federation");
    println!("  • Delivers to Bob\n");

    // ════════════════════════════════════════
    // SCENARIO 2: Bob Receives Intelligence
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SCENARIO 2: Intelligence Reception");
    println!("════════════════════════════════════════\n");

    println!("🐦 → 🦨 Bob receives federated intel:");
    println!("  From: tower-alice");
    println!("  Signature: union-select-payload");
    println!("  Attack: SQL Injection");
    println!("  Source: 203.0.113.* range\n");

    println!("🦨 Bob's processing:");
    println!("  1. Validate source trust (Alice = Family ✓)");
    println!("  2. Add signature to detection rules");
    println!("  3. Update confidence booster");
    println!("  4. Keep Bob's baseline unchanged\n");

    println!("✓ Bob's detection now enhanced:");
    println!("  • New signature: union-select-payload");
    println!("  • Boosted confidence if pattern matches");
    println!("  • Bob's network-specific baseline preserved\n");

    // ════════════════════════════════════════
    // SCENARIO 3: Bob Detects Same Attacker
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SCENARIO 3: Federated Intel Advantage");
    println!("════════════════════════════════════════\n");

    println!("Same attacker targets Bob...\n");

    let threat_bob = Threat {
        id: "songbird-threat-2".to_string(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "SQL Injection".to_string(),
            signature: "union-select-payload".to_string(), // MATCHES!
        },
        severity: Severity::Critical,
        source: "203.0.113.50".to_string(),
        target: "tower-bob.local".to_string(),
        detected_at: SystemTime::now(),
        description: "SQL injection - MATCHES FEDERATED INTEL".to_string(),
        confidence: 0.98, // Higher due to federated boost!
    };

    println!("🦨 Bob detects:");
    println!("  • Type: SQL Injection");
    println!("  • Signature: union-select-payload ⚡ MATCH!");
    println!("  • Source: 203.0.113.50");
    println!("  • Confidence: 98% (boosted from 90%)");
    println!("  • Reason: Matches Alice's intelligence\n");

    skunkbat_bob.respond_to_threat(&threat_bob)?;

    println!("🦨 Bob's response:");
    println!("  ✓ Immediate quarantine (high confidence)");
    println!("  ✓ No need to learn pattern (already shared)");
    println!("  ✓ Faster response (federated advantage)");
    println!("  ✓ Alice's experience protects Bob\n");

    // ════════════════════════════════════════
    // PRIVACY GUARANTEES
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("PRIVACY GUARANTEES");
    println!("════════════════════════════════════════\n");

    println!("What Alice Shared:");
    println!("  ✅ Attack signature: 'union-select-payload'");
    println!("  ✅ Attack type: 'SQL Injection'");
    println!("  ✅ Source pattern: '203.0.113.*'");
    println!("  ✅ Threat metadata\n");

    println!("What Alice Did NOT Share:");
    println!("  ❌ Which service was attacked");
    println!("  ❌ Alice's network topology");
    println!("  ❌ Alice's traffic patterns");
    println!("  ❌ Alice's user data");
    println!("  ❌ Packet payloads\n");

    println!("Privacy Architecture:");
    println!("  • Only PATTERNS shared");
    println!("  • Context stripped before broadcast");
    println!("  • Each tower maintains independent baseline");
    println!("  • No raw data leaves sovereign boundary\n");

    // ════════════════════════════════════════
    // COMPARISON: Centralized vs Federated
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("COMPARISON: Threat Intelligence Models");
    println!("════════════════════════════════════════\n");

    println!("┌─────────────────────┬────────────┬────────────┐");
    println!("│ Aspect              │ Centralized│ Federated  │");
    println!("├─────────────────────┼────────────┼────────────┤");
    println!("│ Data Collection     │ ✅ Central │ ❌ None    │");
    println!("│ User Privacy        │ ❌ Lost    │ ✅ Preserved│");
    println!("│ Single Point Failure│ ❌ Yes     │ ✅ No      │");
    println!("│ Authority           │ ❌ Central │ ✅ Owner   │");
    println!("│ Signature Sharing   │ ✅ Yes     │ ✅ Yes     │");
    println!("│ Raw Data Sharing    │ ✅ Yes     │ ❌ No      │");
    println!("│ Opt-Out             │ ❌ Hard    │ ✅ Easy    │");
    println!("└─────────────────────┴────────────┴────────────┘\n");

    // ════════════════════════════════════════
    // ARCHITECTURE: Opt-In Federation
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("ARCHITECTURE: Opt-In Federation");
    println!("════════════════════════════════════════\n");

    println!("User Control:");
    println!("  1. Federation is OPT-IN");
    println!("  2. Owner chooses what to share");
    println!("  3. Owner chooses who to trust");
    println!("  4. Can disable at any time\n");

    println!("Configuration:");
    println!("```rust");
    println!("let config = SkunkBatConfig {{");
    println!("    federation_enabled: true,  // User choice");
    println!("    share_intel: true,         // User choice");
    println!("    trust_level: TrustLevel::Family, // User choice");
    println!("    // ...");
    println!("}};");
    println!("```\n");

    println!("Trust Levels:");
    println!("  • FAMILY: Full intelligence sharing");
    println!("  • FEDERATED: Limited signature sharing");
    println!("  • NONE: No sharing (standalone mode)\n");

    // ════════════════════════════════════════
    // SUMMARY
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SUMMARY: Federated Threat Intelligence");
    println!("════════════════════════════════════════\n");

    println!("Integration Architecture:");
    println!("  ✓ ThreatBroadcaster trait (what skunkBat uses)");
    println!("  ✓ Songbird provides message routing");
    println!("  ✓ Signature-only broadcast (privacy-preserving)");
    println!("  ✓ Opt-in federation model\n");

    println!("Intelligence Model:");
    println!("  • PATTERNS not DATA: Signatures only");
    println!("  • BOOST not REPLACE: Enhances local detection");
    println!("  • OPT-IN not REQUIRED: User authority");
    println!("  • FEDERATED not CENTRALIZED: No single authority\n");

    println!("Scenarios Demonstrated:");
    println!("  ✅ Threat detection and broadcast");
    println!("  ✅ Intelligence reception");
    println!("  ✅ Federated advantage (confidence boost)");
    println!("  ✅ Privacy preservation\n");

    // Stop both instances
    skunkbat_alice.stop().await?;
    skunkbat_bob.stop().await?;

    println!("✅ Demo Complete!\n");
    println!("Key Takeaway: Federation ENHANCES security WITHOUT sacrificing privacy.");
    println!("Signatures shared, data protected. Coordination, not centralization. 🦨🐦");

    Ok(())
}

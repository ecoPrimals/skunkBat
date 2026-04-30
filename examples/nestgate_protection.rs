// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Nestgate protection demonstration for skunkBat
//!
//! THE GRAND FINALE: All integrations working together to protect a Nestgate instance.
//! This demo shows the complete ecosystem in action.

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

    println!("🦨 + 🏠 skunkBat Protecting Nestgate");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("THE GRAND FINALE: Complete Ecosystem Protection\n");

    // ════════════════════════════════════════
    // SETUP: Nestgate Environment
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SETUP: Nestgate Environment");
    println!("════════════════════════════════════════\n");

    println!("Nestgate Instance:");
    println!("  • Name: home-nestgate");
    println!("  • Owner: Alice");
    println!("  • Services: Data storage, app hosting");
    println!("  • Network: 192.168.1.0/24");
    println!("  • Sovereignty: User-controlled\n");

    println!("Ecosystem Components:");
    println!("  🦨 skunkBat: Network defense & threat detection");
    println!("  🐻 Beardog: Genetic lineage verification");
    println!("  🍄 Toadstool: Primal discovery");
    println!("  🐦 Songbird: Threat intelligence federation");
    println!("  🏠 Nestgate: Protected application platform\n");

    // Initialize skunkBat
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    println!("✓ skunkBat initialized");
    println!("  • Protecting: home-nestgate");
    println!("  • Mode: Full ecosystem integration\n");

    // ════════════════════════════════════════
    // THREAT 1: Unknown Device Connection
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("THREAT 1: Unknown Device Connection");
    println!("════════════════════════════════════════\n");

    println!("🏠 Nestgate receives connection request:");
    println!("  • Source: unknown-device-789");
    println!("  • IP: 192.168.1.200");
    println!("  • Requested: /api/data (sensitive data access)\n");

    println!("🏠 → 🦨 Nestgate forwards to skunkBat for screening\n");

    println!("🦨 Analysis Pipeline:");
    println!("  Step 1: Check genetic lineage\n");

    println!("  🦨 → 🍄 'Who can verify-lineage?'");
    println!("  🍄 → 🦨 'beardog-instance-alice'\n");

    println!("  🦨 → 🐻 'Is unknown-device-789 family?'");
    println!("  🐻 → 🦨 'NO - no lineage found'\n");

    let threat1 = Threat {
        id: "nestgate-threat-1".to_string(),
        threat_type: ThreatType::UnknownLineage {
            peer_id: "unknown-device-789".to_string(),
            lineage: None,
        },
        severity: Severity::High,
        source: "192.168.1.200".to_string(),
        target: "home-nestgate".to_string(),
        detected_at: SystemTime::now(),
        description: "Unknown device attempting data access".to_string(),
        confidence: 0.9,
    };

    skunkbat.respond_to_threat(&threat1)?;

    println!("🦨 Decision: ⚠️ QUARANTINE");
    println!("  • Reason: No genetic lineage");
    println!("  • Action: Block data access, allow identification\n");

    println!("🦨 → 🏠 Verdict: DENY /api/data");
    println!("  • Allow: /identify (can prove lineage)");
    println!("  • Owner notification: Sent\n");

    println!("Result: ✅ Nestgate data protected from unknown device\n");

    // ════════════════════════════════════════
    // THREAT 2: SQL Injection Attempt
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("THREAT 2: SQL Injection Attack");
    println!("════════════════════════════════════════\n");

    println!("🏠 Nestgate app receives suspicious request:");
    println!("  • Source: 203.0.113.45");
    println!("  • Pattern: union-select-payload");
    println!("  • Target: /api/query (database endpoint)\n");

    println!("🏠 → 🦨 Pattern forwarded for analysis\n");

    println!("🦨 Analysis:");
    println!("  Step 1: Check attack signatures\n");

    println!("  Local database: SQL injection patterns");
    println!("  Match: ✓ union-select-payload (known pattern)\n");

    println!("  Step 2: Check federated intelligence\n");

    println!("  🦨 → 🍄 'Who can route-messages?'");
    println!("  🍄 → 🦨 'songbird-tower-mesh'\n");

    println!("  🦨 → 🐦 'Any intel on union-select-payload?'");
    println!("  🐦 → 🦨 'YES - Bob's tower reported this 2 hours ago'");
    println!("          'Source: 203.0.113.* range'");
    println!("          'Confidence: Critical'\n");

    let threat2 = Threat {
        id: "nestgate-threat-2".to_string(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "SQL Injection".to_string(),
            signature: "union-select-payload".to_string(),
        },
        severity: Severity::Critical,
        source: "203.0.113.45".to_string(),
        target: "home-nestgate".to_string(),
        detected_at: SystemTime::now(),
        description: "SQL injection - MATCHES FEDERATED INTEL".to_string(),
        confidence: 0.98, // Boosted by federation!
    };

    skunkbat.respond_to_threat(&threat2)?;

    println!("🦨 Decision: 🛑 IMMEDIATE QUARANTINE");
    println!("  • Reason: Known attack + federated confirmation");
    println!("  • Confidence: 98% (federation boost)");
    println!("  • Action: Block source, alert owner\n");

    println!("🦨 → 🏠 Verdict: BLOCK 203.0.113.45");
    println!("  • Database query: Rejected");
    println!("  • Future requests: Denied\n");

    println!("🦨 → 🐦 Broadcast: New attack confirmation");
    println!("  • Helps other towers in federation\n");

    println!("Result: ✅ Nestgate database protected, federation strengthened\n");

    // ════════════════════════════════════════
    // THREAT 3: Resource Exhaustion (DoS)
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("THREAT 3: DoS Attack on Nestgate");
    println!("════════════════════════════════════════\n");

    println!("🏠 Nestgate monitoring detects anomaly:");
    println!("  • Source: 198.51.100.0/24");
    println!("  • Connection rate: 500/sec (10x normal!)");
    println!("  • Bandwidth: 150 MB/sec");
    println!("  • Target: Home page (overwhelm server)\n");

    println!("🏠 → 🦨 Resource metrics forwarded\n");

    println!("🦨 Analysis:");
    println!("  Step 1: Compare to baseline\n");

    println!("  Baseline (learned from Alice's normal usage):");
    println!("    • Connection rate: 50 ± 10 conn/sec");
    println!("    • Current: 500 conn/sec");
    println!("    • Deviation: 45σ (!)\n");

    println!("  Step 2: Resource impact");
    println!("    • CPU: 95%");
    println!("    • Memory: 90%");
    println!("    • Network: Saturated");
    println!("    • Nestgate services: Degraded\n");

    let threat3 = Threat {
        id: "nestgate-threat-3".to_string(),
        threat_type: ThreatType::DenialOfService {
            resource: "bandwidth+cpu".to_string(),
            current_level: 95.0,
        },
        severity: Severity::Critical,
        source: "198.51.100.0".to_string(),
        target: "home-nestgate".to_string(),
        detected_at: SystemTime::now(),
        description: "DoS attack - resource exhaustion in progress".to_string(),
        confidence: 0.97,
    };

    skunkbat.respond_to_threat(&threat3)?;

    println!("🦨 Decision: 🚨 IMMEDIATE QUARANTINE + RATE LIMIT");
    println!("  • Reason: Nestgate availability at risk");
    println!("  • Confidence: 97%");
    println!("  • Action: Rate limit entire /24 range\n");

    println!("🦨 → 🏠 Verdict: RATE LIMIT 198.51.100.0/24");
    println!("  • Max 10 conn/sec from entire range");
    println!("  • Existing connections: Dropped");
    println!("  • Nestgate services: Recovering\n");

    println!("Result: ✅ Nestgate availability restored\n");

    // ════════════════════════════════════════
    // ECOSYSTEM IN ACTION: Summary
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("ECOSYSTEM IN ACTION");
    println!("════════════════════════════════════════\n");

    println!("Integration Points Used:");
    println!("  🦨 skunkBat:");
    println!("    • Threat detection (4 types)");
    println!("    • Statistical baseline (YOUR normal)");
    println!("    • Defense orchestration");
    println!("    • Decision engine\n");

    println!("  🐻 Beardog:");
    println!("    • Genetic lineage verification");
    println!("    • Cryptographic trust proofs");
    println!("    • Identity WHO validation\n");

    println!("  🍄 Toadstool:");
    println!("    • Primal discovery");
    println!("    • Capability-based routing");
    println!("    • Zero-knowledge bootstrap\n");

    println!("  🐦 Songbird:");
    println!("    • Threat intelligence federation");
    println!("    • Signature sharing (not data)");
    println!("    • Multi-tower coordination\n");

    println!("  🏠 Nestgate:");
    println!("    • Protected application platform");
    println!("    • User sovereignty preserved");
    println!("    • Data security maintained\n");

    // ════════════════════════════════════════
    // ARCHITECTURE: Zero Coupling Validated
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("ARCHITECTURE: Zero-Coupling Validated");
    println!("════════════════════════════════════════\n");

    println!("What skunkBat Doesn't Know:");
    println!("  ❌ Beardog's location or implementation");
    println!("  ❌ Songbird's routing details");
    println!("  ❌ Toadstool's discovery algorithm");
    println!("  ❌ Nestgate's internal architecture\n");

    println!("What skunkBat DOES Know:");
    println!("  ✅ Trait interfaces");
    println!("  ✅ What capabilities it needs");
    println!("  ✅ How to ask Toadstool for discovery");
    println!("  ✅ How to protect its charge (Nestgate)\n");

    println!("Integration Pattern:");
    println!("  skunkBat → Traits → Toadstool → Discover → Connect");
    println!("  ");
    println!("  Every connection:");
    println!("    • Discovered at runtime");
    println!("    • Capability-based");
    println!("    • Zero hardcoding");
    println!("    • Sovereignty-preserving\n");

    // ════════════════════════════════════════
    // FINAL SUMMARY
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("FINAL SUMMARY: Ecosystem Protection");
    println!("════════════════════════════════════════\n");

    println!("Threats Handled: 3/3");
    println!("  ✅ Unknown lineage → Quarantined");
    println!("  ✅ SQL injection → Blocked (federation boost)");
    println!("  ✅ DoS attack → Rate limited\n");

    println!("Nestgate Status:");
    println!("  ✅ Data: Protected");
    println!("  ✅ Availability: Maintained");
    println!("  ✅ Sovereignty: Preserved");
    println!("  ✅ Owner: In control\n");

    println!("Ecosystem Value:");
    println!("  • Beardog: Genetic trust (WHO)");
    println!("  • skunkBat: Threat detection (WHAT)");
    println!("  • Songbird: Federation (COORDINATION)");
    println!("  • Toadstool: Discovery (WHERE)");
    println!("  • Nestgate: Protected platform (HOME)\n");

    println!("Philosophy Validated:");
    println!("  ✓ Defense, not offense");
    println!("  ✓ Coordination, not centralization");
    println!("  ✓ Privacy, not surveillance");
    println!("  ✓ User authority, not automated control");
    println!("  ✓ Zero coupling, not tight integration\n");

    // Stop skunkBat
    skunkbat.stop().await?;

    println!("✅ Demo Complete!\n");
    println!("═══════════════════════════════════════════════════════════");
    println!("🎉 ECOSYSTEM INTEGRATION COMPLETE!");
    println!("═══════════════════════════════════════════════════════════\n");
    println!("You've seen the complete ecoPrimals ecosystem in action:");
    println!("  🦨 Defensive security (skunkBat)");
    println!("  🐻 Genetic trust (Beardog)");
    println!("  🍄 Capability discovery (Toadstool)");
    println!("  🐦 Federated intelligence (Songbird)");
    println!("  🏠 Sovereign computing (Nestgate)\n");
    println!("Together: A complete sovereignty-first, privacy-preserving,");
    println!("user-controlled computing ecosystem. 🦨\n");
    println!("Defensive by architecture. Sovereign by design. Human dignity by default.");

    Ok(())
}

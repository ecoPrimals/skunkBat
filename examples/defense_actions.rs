// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Defense actions demonstration for skunkBat
//!
//! Shows the graduated response system:
//! 1. Monitor + Alert (Low severity, requires approval)
//! 2. Quarantine + Alert (High severity, automatic)
//! 3. Immediate Quarantine (Critical, no approval)
//! 4. Block (Explicit blocking)

use skunk_bat_core::PrimalLifecycle;
use skunk_bat_core::{
    SkunkBat, SkunkBatConfig,
    threats::{Severity, Threat, ThreatType},
};
use std::time::SystemTime;

#[tokio::main]
#[expect(
    clippy::too_many_lines,
    reason = "demo walkthrough with progressive output"
)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    println!("🦨 skunkBat - Defense Actions Demo");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Demonstrating user-approved defense responses:\n");

    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    demo_monitor(&skunkbat)?;
    demo_quarantine(&skunkbat)?;
    demo_critical(&skunkbat)?;
    demo_summary();

    let _metrics = skunkbat.get_security_metrics();
    println!("Total actions demonstrated: 3");
    println!("  • Monitor: 1");
    println!("  • Quarantine: 2");
    println!("  • Blocked: 0 (requires operator)\n");

    skunkbat.stop().await?;
    println!("✅ Demo Complete!\n");
    println!("Key Takeaway: Defense is GRADUATED and USER-CONTROLLED.");
    println!("skunkBat suggests, YOU decide. 🦨");

    Ok(())
}

fn demo_monitor(skunkbat: &SkunkBat) -> Result<(), Box<dyn std::error::Error>> {
    println!("════════════════════════════════════════");
    println!("1. MONITOR + ALERT (Low Severity)");
    println!("════════════════════════════════════════\n");

    println!("Threat: Minor behavioral anomaly");
    println!("  • Deviation: 1.2σ from baseline");
    println!("  • Confidence: 60%");
    println!("  • Severity: Low\n");

    let low_threat = Threat {
        id: "action-monitor-1".to_string(),
        threat_type: ThreatType::BehaviorAnomaly {
            deviation: 1.2,
            behavior: "Slightly unusual connection pattern".to_string(),
        },
        severity: Severity::Low,
        source: "192.168.1.50".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: SystemTime::now(),
        description: "Minor deviation from baseline".to_string(),
        confidence: 0.6,
    };

    skunkbat.respond_to_threat(&low_threat)?;

    println!("✓ Action Taken: MONITOR + ALERT");
    println!("  → Connection allowed to continue");
    println!("  → Logged for analysis");
    println!("  → Requires operator approval for escalation");
    println!("  → No disruption to legitimate traffic\n");

    println!("Why Monitor?");
    println!("  • Low confidence (60%) - could be false positive");
    println!("  • Minor deviation - not clearly malicious");
    println!("  • Owner decides if further action needed");
    println!("  • Defensive, not disruptive\n");

    Ok(())
}

fn demo_quarantine(skunkbat: &SkunkBat) -> Result<(), Box<dyn std::error::Error>> {
    println!("════════════════════════════════════════");
    println!("2. QUARANTINE + ALERT (High Severity)");
    println!("════════════════════════════════════════\n");

    println!("Threat: Unknown genetic lineage");
    println!("  • Peer: unknown-node-42");
    println!("  • Confidence: 90%");
    println!("  • Severity: High\n");

    let high_threat = Threat {
        id: "action-quarantine-1".to_string(),
        threat_type: ThreatType::UnknownLineage {
            peer_id: "unknown-node-42".to_string(),
            lineage: None,
        },
        severity: Severity::High,
        source: "unknown-node-42".to_string(),
        target: "local-node".to_string(),
        detected_at: SystemTime::now(),
        description: "Connection from unverified genetic lineage".to_string(),
        confidence: 0.9,
    };

    skunkbat.respond_to_threat(&high_threat)?;

    println!("✓ Action Taken: QUARANTINE + ALERT");
    println!("  → Connection isolated (not blocked)");
    println!("  → Traffic rate-limited automatically");
    println!("  → Operator alerted for review");
    println!("  → Can be released if verified legitimate\n");

    Ok(())
}

fn demo_critical(skunkbat: &SkunkBat) -> Result<(), Box<dyn std::error::Error>> {
    println!("════════════════════════════════════════");
    println!("3. IMMEDIATE QUARANTINE (Critical)");
    println!("════════════════════════════════════════\n");

    let critical_threat = Threat {
        id: "action-critical-1".to_string(),
        threat_type: ThreatType::DenialOfService {
            resource: "bandwidth".to_string(),
            current_level: 98.5,
        },
        severity: Severity::Critical,
        source: "198.51.100.0".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: SystemTime::now(),
        description: "DDoS attack - bandwidth exhaustion".to_string(),
        confidence: 0.95,
    };

    skunkbat.respond_to_threat(&critical_threat)?;

    println!("✓ Action Taken: IMMEDIATE QUARANTINE");
    println!("  → No approval required (critical threat)");
    println!("  → Quarantine executed instantly");
    println!("  → Service availability protected\n");

    Ok(())
}

fn demo_summary() {
    println!("════════════════════════════════════════");
    println!("SUMMARY: Graduated Response");
    println!("════════════════════════════════════════\n");

    println!("Defense Philosophy:");
    println!("  ✓ Graduated response (escalate only when needed)");
    println!("  ✓ User authority (owner approves major actions)");
    println!("  ✓ Reversible first (quarantine before block)");
    println!("  ✓ Context-aware (severity + confidence)");
    println!("  ✓ Audit logged (all actions recorded)\n");

    println!("Action Hierarchy:");
    println!("  1. Monitor → Observe, don't interfere");
    println!("  2. Quarantine → Isolate, but allow review");
    println!("  3. Block → Permanent denial (operator decision)\n");
}

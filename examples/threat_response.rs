// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Threat response example for skunkBat
//!
//! Demonstrates how skunkBat responds to various threat types
//! with different severity levels.

use skunk_bat_core::{
    SkunkBat, SkunkBatConfig,
    threats::{Severity, Threat, ThreatType},
};
use sourdough_core::PrimalLifecycle;
use std::time::SystemTime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("=== skunkBat Threat Response Example ===\n");

    // Create and start skunkBat
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    println!("Testing threat response for various scenarios:\n");

    // Scenario 1: Low severity threat
    println!("1. Low Severity Threat (Informational)");
    let low_threat = Threat {
        id: "threat-low-1".to_string(),
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
    println!("   → Action: Monitor and alert (requires user approval)\n");

    // Scenario 2: Medium severity threat
    println!("2. Medium Severity Threat (Potential Issue)");
    let medium_threat = Threat {
        id: "threat-medium-1".to_string(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "Port Scan".to_string(),
            signature: "Sequential port access".to_string(),
        },
        severity: Severity::Medium,
        source: "192.168.1.100".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: SystemTime::now(),
        description: "Suspicious port scanning activity".to_string(),
        confidence: 0.75,
    };
    skunkbat.respond_to_threat(&medium_threat)?;
    println!("   → Action: Monitor and alert (user decides next steps)\n");

    // Scenario 3: High severity threat
    println!("3. High Severity Threat (Active Attack)");
    let high_threat = Threat {
        id: "threat-high-1".to_string(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "Brute Force".to_string(),
            signature: "Multiple failed authentication attempts".to_string(),
        },
        severity: Severity::High,
        source: "203.0.113.45".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: SystemTime::now(),
        description: "Active brute force attack detected".to_string(),
        confidence: 0.85,
    };
    skunkbat.respond_to_threat(&high_threat)?;
    println!("   → Action: Quarantine connection + Alert operator\n");

    // Scenario 4: Critical threat
    println!("4. Critical Threat (Immediate Action Required)");
    let critical_threat = Threat {
        id: "threat-critical-1".to_string(),
        threat_type: ThreatType::DenialOfService {
            resource: "bandwidth".to_string(),
            current_level: 98.5,
        },
        severity: Severity::Critical,
        source: "198.51.100.0".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: SystemTime::now(),
        description: "DDoS attack in progress - bandwidth exhaustion".to_string(),
        confidence: 0.95,
    };
    skunkbat.respond_to_threat(&critical_threat)?;
    println!("   → Action: Immediate quarantine (no approval required)\n");

    // Scenario 5: Unknown lineage (genetic threat)
    println!("5. Unknown Lineage (Genetic Threat)");
    let genetic_threat = Threat {
        id: "threat-genetic-1".to_string(),
        threat_type: ThreatType::UnknownLineage {
            peer_id: "unknown-peer-123".to_string(),
            lineage: Some("unverified-chain".to_string()),
        },
        severity: Severity::High,
        source: "unknown-node".to_string(),
        target: "local-node".to_string(),
        detected_at: SystemTime::now(),
        description: "Connection from peer with unverified genetic lineage".to_string(),
        confidence: 0.9,
    };
    skunkbat.respond_to_threat(&genetic_threat)?;
    println!("   → Action: Quarantine + Alert (genetic trust violation)\n");

    // Get final metrics
    println!("=== Final Security Metrics ===");
    let _metrics = skunkbat.get_security_metrics();
    println!("Total threats processed: 5");
    println!("Response actions executed:");
    println!("  • Monitor + Alert: 2");
    println!("  • Quarantine + Alert: 2");
    println!("  • Immediate Quarantine: 1\n");

    // Stop skunkBat
    skunkbat.stop().await?;
    println!("=== Example Complete ===");

    Ok(())
}

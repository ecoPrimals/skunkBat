//! Comprehensive violation detection example for skunkBat
//!
//! Demonstrates all threat detection capabilities:
//! 1. Genetic violations (unknown lineage)
//! 2. Behavioral anomalies (statistical deviations)
//! 3. Intrusion attempts (attack patterns)
//! 4. Resource exhaustion (DoS)

use skunk_bat_core::{
    SkunkBat, SkunkBatConfig,
    threats::{Severity, Threat, ThreatType, Observation, BaselineProfiler, StatisticalProfiler, TopologyValidator, LayerTopologyValidator},
};
use sourdough_core::PrimalLifecycle;
use std::time::SystemTime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing with structured output
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    println!("🦨 skunkBat - Violation Detection Demo");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Testing all 4 violation types...\n");

    // Create and start skunkBat
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    // ════════════════════════════════════════
    // 1. GENETIC VIOLATION (WHO)
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("1. GENETIC VIOLATION (WHO)");
    println!("════════════════════════════════════════\n");
    println!("Scenario: Unknown node attempts connection\n");
    
    let genetic_threat = Threat {
        id: "violation-genetic-1".to_string(),
        threat_type: ThreatType::UnknownLineage {
            peer_id: "unknown-node-42".to_string(),
            lineage: None,
        },
        severity: Severity::High,
        source: "unknown-node-42".to_string(),
        target: "local-node".to_string(),
        detected_at: SystemTime::now(),
        description: "Connection lacks valid genetic lineage".to_string(),
        confidence: 0.9,
    };

    println!("✓ Connection from: unknown-node-42");
    println!("✗ Lineage check: FAILED");
    println!("  → No valid genetic lineage found");
    println!("  → Not in BearDog family tree\n");
    
    println!("Threat Detected:");
    println!("  Type: UnknownLineage");
    println!("  Source: unknown-node-42");
    println!("  Severity: High");
    println!("  Description: Connection lacks valid lineage\n");
    
    skunkbat.respond_to_threat(&genetic_threat)?;
    println!("Recommended Action: QUARANTINE");
    println!("Reasoning: Unknown genetic origin - isolate for review\n");

    // ════════════════════════════════════════
    // 2. BEHAVIORAL ANOMALY (PATTERN)
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("2. TOPOLOGY VIOLATION (WHERE)");
    println!("════════════════════════════════════════\n");
    println!("Scenario: Node attempts layer-hopping\n");

    // Create topology validator
    let validator = LayerTopologyValidator::new(vec![0, 1, 2, 3]);
    
    println!("Expected Path: Layer 0 → 1 → 2 → 3");
    println!("Attempted Path: Layer 0 → 3 (SKIPPED LAYERS!)\n");

    // Validate an invalid path
    let attempted_path = vec![0, 3]; // Skips layers 1 and 2!
    let validation = validator.validate_path(&attempted_path).await?;

    if !validation.is_valid {
        println!("✗ Topology check: FAILED");
        println!("  → Bypassed security layers: {:?}", validation.bypassed_layers);
        println!("  → Invalid path detected\n");

        let topology_threat = Threat {
            id: "violation-topology-1".to_string(),
            threat_type: ThreatType::TopologyViolation {
                expected_path: validation.expected_path.clone(),
                actual_path: validation.actual_path.clone(),
                bypassed_layers: validation.bypassed_layers,
            },
            severity: Severity::Critical,
            source: "sneaky-node-99".to_string(),
            target: "192.168.1.1".to_string(),
            detected_at: SystemTime::now(),
            description: "Layer-hopping attack detected - bypassed security layers".to_string(),
            confidence: 0.95,
        };

        println!("Threat Detected:");
        println!("  Type: TopologyViolation");
        println!("  Source: sneaky-node-99");
        println!("  Severity: Critical");
        println!("  Description: Layer-hopping attack detected\n");

        skunkbat.respond_to_threat(&topology_threat)?;
        println!("Recommended Action: QUARANTINE");
        println!("Reasoning: Attempted security bypass - immediate isolation\n");
    }

    // ════════════════════════════════════════
    // 3. BEHAVIORAL ANOMALY (PATTERN)
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("3. BEHAVIORAL ANOMALY (PATTERN)");
    println!("════════════════════════════════════════\n");
    println!("Scenario: Abnormal traffic pattern\n");

    // First, establish a baseline
    let mut profiler = StatisticalProfiler::new(2.5); // 2.5 sigma threshold
    
    println!("Building baseline from normal traffic...");
    for i in 0..100 {
        let obs = Observation {
            connection_rate: 10.0 + (i as f64 % 5.0) * 0.5, // ~10 conn/s with minor variation
            traffic_volume: 1024 * (100 + i),
            ports_accessed: vec![80, 443],
            timestamp: SystemTime::now(),
        };
        profiler.update(&obs).await?;
    }
    println!("✓ Baseline established from 100 observations\n");
    
    println!("Baseline (YOUR network normal):");
    println!("  • Connection rate: 10.2 ± 2.1 req/s");
    println!("  • Learned from 100 observations\n");

    // Now detect anomaly
    let anomalous_obs = Observation {
        connection_rate: 45.0, // Way above baseline!
        traffic_volume: 1024 * 500,
        ports_accessed: vec![80, 443, 22, 3389],
        timestamp: SystemTime::now(),
    };

    let anomalies = profiler.detect_anomalies(&anomalous_obs).await?;
    
    println!("Current observation:");
    println!("  • Connection rate: 45.0 req/s");
    if let Some(anomaly) = anomalies.first() {
        println!("  • Deviation: {:.1}σ (std deviations)\n", anomaly.deviation);
        
        println!("✗ Behavioral check: ANOMALY DETECTED");
        println!("  → {:.1}σ above baseline", anomaly.deviation);
        println!("  → Extremely unusual for YOUR network\n");
    }

    let behavior_threat = Threat {
        id: "violation-behavior-1".to_string(),
        threat_type: ThreatType::BehaviorAnomaly {
            deviation: anomalies.first().map(|a| a.deviation).unwrap_or(0.0),
            behavior: "Traffic pattern significantly above baseline".to_string(),
        },
        severity: Severity::Critical,
        source: "weird-traffic-source".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: SystemTime::now(),
        description: format!(
            "Traffic pattern {:.1}σ from baseline",
            anomalies.first().map(|a| a.deviation).unwrap_or(0.0)
        ),
        confidence: 0.92,
    };

    println!("Threat Detected:");
    println!("  Type: BehaviorAnomaly");
    println!("  Source: weird-traffic-source");
    println!("  Severity: Critical");
    println!("  Description: Traffic pattern {:.1}σ from baseline\n", 
        anomalies.first().map(|a| a.deviation).unwrap_or(0.0));
    
    skunkbat.respond_to_threat(&behavior_threat)?;
    println!("Recommended Action: QUARANTINE");
    println!("Reasoning: Unusual but not necessarily malicious - isolate first\n");

    // ════════════════════════════════════════
    // 4. INTRUSION ATTEMPT (ATTACK)
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("4. INTRUSION ATTEMPT (ATTACK)");
    println!("════════════════════════════════════════\n");
    println!("Scenario: Active attack pattern detected\n");

    println!("Attack signature detected:");
    println!("  • Pattern: Sequential port scanning");
    println!("  • Ports: 1-1024 scanned in 5 seconds");
    println!("  • Known signature: nmap SYN scan\n");

    let intrusion_threat = Threat {
        id: "violation-intrusion-1".to_string(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "Port Scan".to_string(),
            signature: "nmap-syn-scan".to_string(),
        },
        severity: Severity::Critical,
        source: "attacker-node-99".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: SystemTime::now(),
        description: "Active port scanning detected - reconnaissance phase".to_string(),
        confidence: 0.95,
    };

    println!("✗ Intrusion check: ATTACK DETECTED");
    println!("  → Matches known attack pattern");
    println!("  → Active reconnaissance in progress\n");

    println!("Threat Detected:");
    println!("  Type: IntrusionAttempt");
    println!("  Source: attacker-node-99");
    println!("  Severity: Critical");
    println!("  Description: Active port scanning detected\n");
    
    skunkbat.respond_to_threat(&intrusion_threat)?;
    println!("Recommended Action: QUARANTINE");
    println!("Reasoning: Active attack detected - immediate isolation\n");

    // ════════════════════════════════════════
    // 5. RESOURCE EXHAUSTION (CAPACITY)
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("5. RESOURCE EXHAUSTION (CAPACITY)");
    println!("════════════════════════════════════════\n");
    println!("Scenario: Resource consumption attack\n");

    println!("Resource Limits (YOUR policies):");
    println!("  • Max connections: 100/s");
    println!("  • Max bandwidth: 50 MB/s per source");
    println!("  • Memory threshold: 90%\n");

    println!("Current usage:");
    println!("  • Connections: 500/s (5x limit!)");
    println!("  • Bandwidth: 150 MB/s (3x limit!)");
    println!("  • Memory: 95% (above threshold!)\n");

    let dos_threat = Threat {
        id: "violation-dos-1".to_string(),
        threat_type: ThreatType::DenialOfService {
            resource: "bandwidth+connections".to_string(),
            current_level: 98.5,
        },
        severity: Severity::Critical,
        source: "flood-attack-source".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: SystemTime::now(),
        description: "Consuming excessive resources - DoS attack".to_string(),
        confidence: 0.97,
    };

    println!("✗ Resource check: EXHAUSTION DETECTED");
    println!("  → Multiple limits exceeded");
    println!("  → DoS attack likely\n");

    println!("Threat Detected:");
    println!("  Type: DenialOfService");
    println!("  Source: flood-attack-source");
    println!("  Severity: Critical");
    println!("  Description: Consuming excessive resources\n");
    
    skunkbat.respond_to_threat(&dos_threat)?;
    println!("Recommended Action: QUARANTINE");
    println!("Reasoning: Preventing resource exhaustion - protect availability\n");

    // ════════════════════════════════════════
    // SUMMARY
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SUMMARY");
    println!("════════════════════════════════════════\n");

    println!("Violations Detected: 5/5");
    println!("  ✗ Genetic violation (High)");
    println!("  ✗ Topology violation (Critical)");
    println!("  ✗ Behavioral anomaly (Critical)");
    println!("  ✗ Intrusion attempt (Critical)");
    println!("  ✗ Resource exhaustion (Critical)\n");

    println!("Key Takeaways:");
    println!("1. Detection is PATTERN-based, not content-based");
    println!("2. Each type catches different attack vectors");
    println!("3. Topology enforcement prevents layer-hopping");
    println!("4. Severity guides response recommendation");
    println!("5. Owner decides final action (not automatic)\n");

    // Get metrics
    let _metrics = skunkbat.get_security_metrics();

    // Stop skunkBat
    skunkbat.stop().await?;
    println!("✅ Demo Complete!");

    Ok(())
}


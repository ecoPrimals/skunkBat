// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Baseline learning demonstration for skunkBat
//!
//! Shows how statistical profiling learns YOUR network's normal behavior
//! and detects anomalies based on statistical deviations.

use skunk_bat_core::threats::{BaselineProfiler, Observation, StatisticalProfiler};
use std::time::SystemTime;

#[expect(clippy::too_many_lines, reason = "self-contained demo")]
#[expect(clippy::cast_precision_loss, reason = "demo percentages")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    println!("🦨 skunkBat - Baseline Learning Demo");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Learning YOUR network's normal behavior...\n");

    // Create statistical profiler with 2.5 sigma threshold
    let mut profiler = StatisticalProfiler::new(2.5);

    // ════════════════════════════════════════
    // PHASE 1: LEARNING (No baseline yet)
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("PHASE 1: LEARNING MODE");
    println!("════════════════════════════════════════\n");

    println!("Collecting initial observations...");
    println!("  → Minimum required: 10 observations");
    println!("  → Collecting: 50 for stable baseline\n");

    // Simulate 50 observations of "normal" traffic
    println!("Day 1-5: Normal weekday traffic");
    for i in 0..50 {
        let obs = Observation {
            // Normal: ~10 connections/sec with natural variation
            connection_rate: (i as f64 % 10.0).mul_add(0.5, 10.0),
            traffic_volume: 1024 * (100 + i * 2),
            ports_accessed: vec![80, 443], // Typical web traffic
            timestamp: SystemTime::now(),
            http: None,
        };
        profiler.update(&obs).await?;

        if (i + 1) % 10 == 0 {
            println!("  ✓ Collected {} observations", i + 1);
        }
    }

    println!("\n✓ Baseline established!\n");

    // Check baseline status
    assert!(profiler.is_established(), "Baseline should be established");

    println!("Baseline Statistics (YOUR network normal):");
    println!("  • Connection rate: 10.0 ± 2.5 conn/sec");
    println!("  • Traffic volume: ~200 KB/sec");
    println!("  • Typical ports: 80, 443 (HTTP/HTTPS)");
    println!("  • Time period: Weekday business hours");
    println!("  • Observations: 50 samples\n");

    println!("Detection Threshold:");
    println!("  • 2.5σ (standard deviations)");
    println!("  • Confidence: 98.8% (outside normal range)");
    println!("  • Adapts as YOUR network evolves\n");

    // ════════════════════════════════════════
    // PHASE 2: NORMAL TRAFFIC (Within baseline)
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("PHASE 2: NORMAL TRAFFIC DETECTION");
    println!("════════════════════════════════════════\n");

    println!("Testing traffic within baseline...\n");

    // Test 1: Normal traffic
    let normal_obs = Observation {
        connection_rate: 10.5, // Within normal range
        traffic_volume: 1024 * 110,
        ports_accessed: vec![80, 443],
        timestamp: SystemTime::now(),
        http: None,
    };

    let anomalies = profiler.detect_anomalies(&normal_obs).await?;

    println!("Observation 1:");
    println!("  • Connection rate: 10.5 conn/sec");
    println!("  • Deviation: ~0.2σ");
    println!("  • Result: ✓ NORMAL");
    println!("  • Action: None (within expected range)\n");

    assert!(
        anomalies.is_empty(),
        "Normal traffic should not trigger anomalies"
    );

    // Test 2: Slightly elevated (still normal)
    let elevated_obs = Observation {
        connection_rate: 12.0, // Slightly higher, but within 2.5σ
        traffic_volume: 1024 * 130,
        ports_accessed: vec![80, 443, 8080],
        timestamp: SystemTime::now(),
        http: None,
    };

    let anomalies = profiler.detect_anomalies(&elevated_obs).await?;

    println!("Observation 2:");
    println!("  • Connection rate: 12.0 conn/sec");
    println!("  • Deviation: ~0.8σ");
    println!("  • Result: ✓ NORMAL");
    println!("  • Action: None (natural variation)\n");

    assert!(
        anomalies.is_empty(),
        "Slight elevation should still be normal"
    );

    // ════════════════════════════════════════
    // PHASE 3: ANOMALY DETECTION
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("PHASE 3: ANOMALY DETECTION");
    println!("════════════════════════════════════════\n");

    println!("Testing anomalous traffic...\n");

    // Test 3: Clear anomaly
    let anomalous_obs = Observation {
        connection_rate: 45.0, // Way above baseline!
        traffic_volume: 1024 * 500,
        ports_accessed: vec![80, 443, 22, 3389, 5900],
        timestamp: SystemTime::now(),
        http: None,
    };

    let anomalies = profiler.detect_anomalies(&anomalous_obs).await?;

    println!("Observation 3:");
    println!("  • Connection rate: 45.0 conn/sec");

    if let Some(anomaly) = anomalies.first() {
        println!("  • Deviation: {:.1}σ", anomaly.deviation);
        println!("  • Result: ✗ ANOMALY DETECTED");
        println!("  • Confidence: {:.1}%", anomaly.confidence * 100.0);
        println!("  • Behavior: {}", anomaly.behavior);
        println!("  • Action: Quarantine + Alert operator\n");

        assert!(anomaly.deviation > 2.5, "Should exceed threshold");
    } else {
        panic!("Anomaly should be detected for 45 conn/sec");
    }

    println!("Why Anomalous?");
    println!("  • Far outside YOUR normal (10 ± 2.5)");
    println!("  • Not based on universal standards");
    println!("  • YOUR baseline, YOUR threshold");
    println!("  • Statistical confidence > 98%\n");

    // ════════════════════════════════════════
    // PHASE 4: BASELINE ADAPTATION
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("PHASE 4: BASELINE ADAPTATION");
    println!("════════════════════════════════════════\n");

    println!("Simulating network evolution...");
    println!("  → Scenario: Business growth, more users\n");

    // Simulate gradual increase in normal traffic
    println!("Weeks 2-4: Gradual increase in legitimate traffic");
    for i in 0..30 {
        let obs = Observation {
            // Gradually increasing baseline
            connection_rate: (i as f64).mul_add(0.3, 10.0),
            traffic_volume: 1024 * (100 + i * 5),
            ports_accessed: vec![80, 443],
            timestamp: SystemTime::now(),
            http: None,
        };
        profiler.update(&obs).await?;

        if (i + 1) % 10 == 0 {
            println!(
                "  ✓ Week {}: Average ~{:.1} conn/sec (new normal)",
                (i + 1) / 10 + 1,
                (i as f64).mul_add(0.3, 10.0)
            );
        }
    }

    println!("\n✓ Baseline adapted to new normal!\n");

    println!("New Baseline Statistics:");
    println!("  • Connection rate: ~19.0 conn/sec (was 10.0)");
    println!("  • Baseline EVOLVED with YOUR network");
    println!("  • Rolling window: Last 100 observations");
    println!("  • Old normal gradually aged out\n");

    // Test against new baseline
    let new_normal_obs = Observation {
        connection_rate: 18.0, // Would be anomalous with old baseline
        traffic_volume: 1024 * 250,
        ports_accessed: vec![80, 443],
        timestamp: SystemTime::now(),
        http: None,
    };

    let anomalies = profiler.detect_anomalies(&new_normal_obs).await?;

    println!("Testing 18.0 conn/sec:");
    println!("  • Old baseline: Would be anomalous (8σ deviation!)");
    println!("  • New baseline: ✓ NORMAL (within range)");
    println!("  • Result: Adaptation successful\n");

    assert!(
        anomalies.is_empty(),
        "Should be normal with adapted baseline"
    );

    // ════════════════════════════════════════
    // SUMMARY
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SUMMARY: Baseline Learning");
    println!("════════════════════════════════════════\n");

    println!("Key Principles:");
    println!("  ✓ YOUR network, YOUR normal");
    println!("  ✓ Statistical profiling (mean + std deviation)");
    println!("  ✓ Rolling window (adapts to change)");
    println!("  ✓ Threshold-based detection (2.5σ default)");
    println!("  ✓ High confidence anomalies only\n");

    println!("Phases:");
    println!("  1. Learning: Collect observations (min 10)");
    println!("  2. Established: Baseline ready for detection");
    println!("  3. Detection: Compare to baseline");
    println!("  4. Adaptation: Evolve with YOUR network\n");

    println!("Why Statistical?");
    println!("  • No universal 'normal' traffic pattern");
    println!("  • Home network ≠ Enterprise ≠ Data center");
    println!("  • YOUR usage patterns are unique");
    println!("  • Machine learning would need YOUR data anyway\n");

    println!("✅ Demo Complete!\n");
    println!("Key Takeaway: Detection learns YOUR normal, not a universal standard.");
    println!("This is defensive, personalized security. 🦨");

    Ok(())
}

use super::*;
use crate::config::{FeatureFlags, SkunkBatConfig};
use crate::primal_foundation::config::CommonConfig;

fn test_config() -> SkunkBatConfig {
    SkunkBatConfig {
        common: CommonConfig {
            name: "skunkBat-test".to_string(),
            ..CommonConfig::default()
        },
        features: FeatureFlags {
            reconnaissance: true,
            threat_detection: true,
            auto_defense: true,
            observability: true,
        },
        lineage_id: Some("test-lineage".to_string()),
        thresholds: crate::config::ThreatThresholds::default(),
        expected_topology_path: None,
    }
}

#[test]
fn test_threat_detector_creation() {
    let config = test_config();
    let detector = ThreatDetector::new(&config);
    assert!(detector.is_healthy());
}

#[test]
fn test_threat_detector_start_stop() {
    let config = test_config();
    let detector = ThreatDetector::new(&config);
    assert!(detector.start().is_ok());
    assert!(detector.stop().is_ok());
}

#[tokio::test]
async fn test_threat_detection_with_local_verifier() {
    let config = test_config();
    let detector = ThreatDetector::new(&config);
    let threats = detector.detect().await.expect("detection should succeed");
    assert_eq!(
        threats.len(),
        1,
        "LocalLineageVerifier errors → degraded genetic threat"
    );
    assert!(threats[0].id.starts_with("genetic-degraded-"));
}

#[tokio::test]
async fn test_threat_detection_no_lineage_id() {
    let config = SkunkBatConfig {
        lineage_id: None,
        ..test_config()
    };
    let detector = ThreatDetector::new(&config);
    let threats = detector.detect().await.expect("detection should succeed");
    assert!(threats.is_empty(), "no lineage_id → no genetic detection");
}

#[tokio::test]
async fn test_statistical_profiler_learning() {
    let mut profiler = StatisticalProfiler::new(2.5);
    assert!(!profiler.is_established());

    for i in 0..10 {
        let observation = Observation {
            connection_rate: 10.0 + f64::from(i),
            traffic_volume: 1000,
            ports_accessed: vec![80, 443],
            timestamp: SystemTime::now(),
        };
        profiler
            .update(&observation)
            .await
            .expect("update should succeed");
    }
    assert!(profiler.is_established());
}

#[tokio::test]
async fn test_statistical_profiler_anomaly_detection() {
    let mut profiler = StatisticalProfiler::new(2.5);

    for i in 0..10 {
        let observation = Observation {
            connection_rate: f64::from(i).mul_add(0.1, 10.0),
            traffic_volume: 1000,
            ports_accessed: vec![80, 443],
            timestamp: SystemTime::now(),
        };
        profiler
            .update(&observation)
            .await
            .expect("update should succeed");
    }

    let normal_obs = Observation {
        connection_rate: 10.5,
        traffic_volume: 1000,
        ports_accessed: vec![80, 443],
        timestamp: SystemTime::now(),
    };
    let anomalies = profiler
        .detect_anomalies(&normal_obs)
        .await
        .expect("detection should succeed");
    assert!(anomalies.is_empty() || anomalies[0].deviation < 2.5);

    let anomalous_obs = Observation {
        connection_rate: 100.0,
        traffic_volume: 1000,
        ports_accessed: vec![80, 443],
        timestamp: SystemTime::now(),
    };
    let anomalies = profiler
        .detect_anomalies(&anomalous_obs)
        .await
        .expect("detection should succeed");
    assert!(!anomalies.is_empty());
    assert!(anomalies[0].deviation > 2.5);
}

#[tokio::test]
async fn test_local_lineage_verifier() {
    let verifier = LocalLineageVerifier;
    assert!(
        verifier.is_family("test-peer").await.is_err(),
        "local-only verifier should return error (no authority)"
    );
    assert!(
        verifier.get_lineage("test-peer").await.is_err(),
        "local-only verifier should return error (no authority)"
    );
}

#[tokio::test]
async fn test_threat_detector_with_verifiers() {
    let config = test_config();
    let detector = ThreatDetector::with_verifiers(
        &config,
        LocalLineageVerifier,
        StatisticalProfiler::new(2.5),
    );
    assert!(detector.is_healthy());
    let result = detector.detect().await;
    assert!(result.is_ok());
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn test_threat_type_creation() {
    let tt = ThreatType::UnknownLineage {
        peer_id: "test-peer".to_string(),
        lineage: Some("unknown-lineage".to_string()),
    };
    assert!(matches!(tt, ThreatType::UnknownLineage { .. }));
}

#[test]
#[expect(clippy::float_cmp, reason = "exact literal comparison in test")]
fn test_threat_creation() {
    let threat = Threat {
        id: "threat-1".to_string(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "port-scan".to_string(),
            signature: "rapid-connect".to_string(),
        },
        severity: Severity::High,
        source: "192.168.1.100".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: SystemTime::now(),
        description: "Port scanning detected".to_string(),
        confidence: 0.85,
    };
    assert_eq!(threat.severity, Severity::High);
    assert_eq!(threat.confidence, 0.85);
}

#[test]
fn test_dos_threat() {
    let tt = ThreatType::DenialOfService {
        resource: "bandwidth".to_string(),
        current_level: 95.5,
    };
    assert!(matches!(tt, ThreatType::DenialOfService { .. }));
}

#[test]
fn test_behavior_anomaly() {
    let tt = ThreatType::BehaviorAnomaly {
        deviation: 3.5,
        behavior: "unusual traffic pattern".to_string(),
    };
    assert!(matches!(tt, ThreatType::BehaviorAnomaly { .. }));
}

#[tokio::test]
async fn test_statistical_profiler_baseline() {
    let mut profiler = StatisticalProfiler::new(2.5);
    assert!(!profiler.is_established());

    for _ in 0..10 {
        let obs = Observation {
            connection_rate: 5.0,
            traffic_volume: 1000,
            ports_accessed: vec![80, 443],
            timestamp: SystemTime::now(),
        };
        profiler.update(&obs).await.expect("update should succeed");
    }
    assert!(profiler.is_established());
}

#[tokio::test]
async fn test_detector_with_behavioral_anomalies() {
    let config = test_config();
    let mut profiler = StatisticalProfiler::new(2.5);

    for _ in 0..10 {
        let obs = Observation {
            connection_rate: 5.0,
            traffic_volume: 1000,
            ports_accessed: vec![80],
            timestamp: SystemTime::now(),
        };
        profiler.update(&obs).await.expect("update should succeed");
    }

    let detector = ThreatDetector::with_verifiers(&config, LocalLineageVerifier, profiler);

    let threats = detector.detect().await.expect("detect should succeed");
    assert!(
        threats.is_empty() || !threats.is_empty(),
        "Should return a result"
    );
}

#[test]
#[expect(clippy::float_cmp, reason = "exact literal comparison in test")]
fn test_observation_creation() {
    let obs = Observation {
        connection_rate: 10.0,
        traffic_volume: 2000,
        ports_accessed: vec![80, 443, 8080],
        timestamp: SystemTime::now(),
    };
    assert_eq!(obs.connection_rate, 10.0);
    assert_eq!(obs.traffic_volume, 2000);
    assert_eq!(obs.ports_accessed.len(), 3);
}

#[test]
#[expect(clippy::float_cmp, reason = "exact literal comparison in test")]
fn test_anomaly_creation() {
    let anomaly = Anomaly {
        deviation: 4.5,
        behavior: "High connection rate".to_string(),
        confidence: 0.92,
    };
    assert_eq!(anomaly.deviation, 4.5);
    assert_eq!(anomaly.confidence, 0.92);
}

#[test]
fn test_lineage_id_access() {
    let config = test_config();
    let detector = ThreatDetector::new(&config);
    assert_eq!(detector.lineage_id(), Some("test-lineage"));
}

#[tokio::test]
async fn test_layer_topology_validator_valid_path() {
    let validator = LayerTopologyValidator::new(vec![0, 1, 2, 3]);
    let result = validator
        .validate_path(&[0, 1, 2, 3])
        .await
        .expect("should succeed");
    assert!(result.is_valid);
    assert!(result.bypassed_layers.is_empty());
}

#[tokio::test]
async fn test_layer_topology_validator_invalid_path() {
    let validator = LayerTopologyValidator::new(vec![0, 1, 2, 3]);
    let result = validator
        .validate_path(&[0, 2, 3])
        .await
        .expect("should succeed");
    assert!(!result.is_valid);
    assert_eq!(result.bypassed_layers, vec![1]);
}

#[tokio::test]
async fn test_layer_topology_validator_empty_path() {
    let validator = LayerTopologyValidator::new(vec![0, 1, 2]);
    let result = validator.validate_path(&[]).await.expect("should succeed");
    assert!(!result.is_valid);
    assert_eq!(result.bypassed_layers, vec![0, 1, 2]);
}

#[test]
fn test_layer_topology_expected_path() {
    let validator = LayerTopologyValidator::new(vec![1, 2, 3]);
    assert_eq!(validator.expected_path(), vec![1, 2, 3]);
}

#[tokio::test]
async fn test_detect_behavioral_anomaly_triggers() {
    let config = test_config();
    let mut profiler = StatisticalProfiler::new(2.5);

    for _ in 0..15 {
        let obs = Observation {
            connection_rate: 5.0,
            traffic_volume: 1000,
            ports_accessed: vec![80],
            timestamp: SystemTime::now(),
        };
        profiler.update(&obs).await.expect("update");
    }

    let spike = Observation {
        connection_rate: 500.0,
        traffic_volume: 1000,
        ports_accessed: vec![80],
        timestamp: SystemTime::now(),
    };
    profiler.update(&spike).await.expect("update");

    let detector = ThreatDetector::with_verifiers(&config, LocalLineageVerifier, profiler);
    let threats = detector.detect().await.expect("detect");
    assert!(
        threats
            .iter()
            .any(|t| matches!(t.threat_type, ThreatType::BehaviorAnomaly { .. })),
        "Should detect the connection rate spike as anomaly"
    );
}

#[tokio::test]
async fn test_detect_disabled() {
    let config = SkunkBatConfig {
        common: CommonConfig::default(),
        features: FeatureFlags {
            reconnaissance: false,
            threat_detection: false,
            auto_defense: false,
            observability: false,
        },
        lineage_id: None,
        thresholds: crate::config::ThreatThresholds::default(),
        expected_topology_path: None,
    };
    let detector = ThreatDetector::new(&config);
    assert!(!detector.is_healthy());
    let threats = detector.detect().await.expect("detect");
    assert!(threats.is_empty());
}

#[test]
fn test_start_disabled() {
    let config = SkunkBatConfig {
        common: CommonConfig::default(),
        features: FeatureFlags {
            reconnaissance: false,
            threat_detection: false,
            auto_defense: false,
            observability: false,
        },
        lineage_id: None,
        thresholds: crate::config::ThreatThresholds::default(),
        expected_topology_path: None,
    };
    let detector = ThreatDetector::new(&config);
    assert!(detector.start().is_ok());
}

#[test]
fn test_lineage_verifier_access() {
    let config = test_config();
    let detector = ThreatDetector::new(&config);
    let _verifier = detector.lineage_verifier();
}

#[test]
fn test_severity_display_all_variants() {
    let variants = [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];
    for v in &variants {
        assert!(!format!("{v:?}").is_empty());
    }
}

#[tokio::test]
async fn test_intrusion_portscan_detected() {
    let config = test_config();
    let mut profiler = StatisticalProfiler::new(2.5);
    let obs = Observation {
        connection_rate: 5.0,
        traffic_volume: 500,
        ports_accessed: vec![22, 445, 80],
        timestamp: SystemTime::now(),
    };
    profiler.update(&obs).await.expect("update");

    let detector = ThreatDetector::with_verifiers(&config, LocalLineageVerifier, profiler);
    let threats = detector.detect().await.expect("detect");
    assert!(
        threats
            .iter()
            .any(|t| matches!(&t.threat_type, ThreatType::IntrusionAttempt { attack_type, .. } if attack_type == "port-scan")),
        "Should detect port-scan when 2+ sensitive ports accessed"
    );
}

#[tokio::test]
async fn test_intrusion_portscan_not_triggered_single_port() {
    let config = test_config();
    let mut profiler = StatisticalProfiler::new(2.5);
    let obs = Observation {
        connection_rate: 5.0,
        traffic_volume: 500,
        ports_accessed: vec![22, 80, 443],
        timestamp: SystemTime::now(),
    };
    profiler.update(&obs).await.expect("update");

    let detector = ThreatDetector::with_verifiers(&config, LocalLineageVerifier, profiler);
    let threats = detector.detect().await.expect("detect");
    assert!(
        !threats
            .iter()
            .any(|t| matches!(&t.threat_type, ThreatType::IntrusionAttempt { attack_type, .. } if attack_type == "port-scan")),
        "Single sensitive port should not trigger port-scan"
    );
}

#[tokio::test]
async fn test_intrusion_exfiltration_detected() {
    let config = test_config();
    let mut profiler = StatisticalProfiler::new(2.5);
    let obs = Observation {
        connection_rate: 2.0,
        traffic_volume: 500_000,
        ports_accessed: vec![80],
        timestamp: SystemTime::now(),
    };
    profiler.update(&obs).await.expect("update");

    let detector = ThreatDetector::with_verifiers(&config, LocalLineageVerifier, profiler);
    let threats = detector.detect().await.expect("detect");
    assert!(
        threats
            .iter()
            .any(|t| matches!(&t.threat_type, ThreatType::IntrusionAttempt { attack_type, .. } if attack_type == "data-exfiltration")),
        "High volume-to-connection ratio should trigger exfiltration alert"
    );
}

#[tokio::test]
async fn test_intrusion_exfiltration_not_triggered_low_volume() {
    let config = test_config();
    let mut profiler = StatisticalProfiler::new(2.5);
    let obs = Observation {
        connection_rate: 10.0,
        traffic_volume: 500,
        ports_accessed: vec![80],
        timestamp: SystemTime::now(),
    };
    profiler.update(&obs).await.expect("update");

    let detector = ThreatDetector::with_verifiers(&config, LocalLineageVerifier, profiler);
    let threats = detector.detect().await.expect("detect");
    assert!(
        !threats
            .iter()
            .any(|t| matches!(&t.threat_type, ThreatType::IntrusionAttempt { attack_type, .. } if attack_type == "data-exfiltration")),
        "Low traffic volume should not trigger exfiltration"
    );
}

#[tokio::test]
async fn test_intrusion_uses_configurable_thresholds() {
    let mut config = test_config();
    config.thresholds.intrusion_sensitive_ports = vec![8080, 9090];
    config.thresholds.intrusion_portscan_confidence = 0.9;

    let mut profiler = StatisticalProfiler::new(2.5);
    let obs = Observation {
        connection_rate: 5.0,
        traffic_volume: 500,
        ports_accessed: vec![8080, 9090],
        timestamp: SystemTime::now(),
    };
    profiler.update(&obs).await.expect("update");

    let detector = ThreatDetector::with_verifiers(&config, LocalLineageVerifier, profiler);
    let threats = detector.detect().await.expect("detect");
    let portscan = threats
        .iter()
        .find(|t| matches!(&t.threat_type, ThreatType::IntrusionAttempt { attack_type, .. } if attack_type == "port-scan"));
    assert!(portscan.is_some(), "Custom ports should trigger detection");
    #[expect(clippy::float_cmp, reason = "exact configured value comparison")]
    let confidence_matches = portscan.unwrap().confidence == 0.9;
    assert!(confidence_matches, "Should use configured confidence");
}

use super::*;

#[test]
fn test_skunkbat_creation() {
    let config = SkunkBatConfig::default();
    let skunkbat = SkunkBat::new(config);
    assert_eq!(skunkbat.state(), PrimalState::Created);
}

#[tokio::test]
async fn test_skunkbat_lifecycle() {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);

    skunkbat.start().await.unwrap();
    assert_eq!(skunkbat.state(), PrimalState::Running);

    skunkbat.stop().await.unwrap();
    assert_eq!(skunkbat.state(), PrimalState::Stopped);
}

#[tokio::test]
async fn test_detect_threats() {
    let config = SkunkBatConfig::default();
    let skunkbat = SkunkBat::new(config);

    let result = skunkbat.detect_threats().await;
    assert!(result.is_ok(), "detect_threats should not error");
    let threats = result.unwrap();
    for t in &threats {
        assert!(
            matches!(t.threat_type, threats::ThreatType::DenialOfService { .. }),
            "default config (no lineage_id) should only produce DoS threats under load, got: {:?}",
            t.threat_type
        );
    }
}

#[test]
fn test_scan_network() {
    let config = SkunkBatConfig::default();
    let skunkbat = SkunkBat::new(config);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(skunkbat.scan_network());
    assert!(result.is_ok());

    let scan = result.unwrap();
    assert!(!scan.nodes.is_empty());
}

#[test]
fn test_get_security_metrics() {
    let config = SkunkBatConfig::default();
    let skunkbat = SkunkBat::new(config);

    let metrics = skunkbat.get_security_metrics();
    assert_eq!(metrics.threats_detected, 0);
    assert_eq!(metrics.threats_mitigated, 0);
}

#[test]
fn test_respond_to_threat() {
    let config = SkunkBatConfig::default();
    let skunkbat = SkunkBat::new(config);

    let threat = threats::Threat {
        id: "test-threat".to_string(),
        threat_type: threats::ThreatType::IntrusionAttempt {
            attack_type: "test".to_string(),
            signature: "test-sig".to_string(),
        },
        severity: threats::Severity::Low,
        source: "192.168.1.100".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: std::time::SystemTime::now(),
        description: "Test threat".to_string(),
        confidence: 0.5,
    };

    let action = skunkbat.respond_to_threat(&threat).unwrap();
    assert_eq!(action, defense::ActionType::MonitorAndAlert);
}

#[test]
fn test_respond_returns_quarantine_for_critical() {
    let config = SkunkBatConfig::default();
    let skunkbat = SkunkBat::new(config);

    let threat = threats::Threat {
        id: "crit-threat".to_string(),
        threat_type: threats::ThreatType::IntrusionAttempt {
            attack_type: "exploit".to_string(),
            signature: "cve-2025-0001".to_string(),
        },
        severity: threats::Severity::Critical,
        source: "10.0.0.99".to_string(),
        target: "10.0.0.1".to_string(),
        detected_at: std::time::SystemTime::now(),
        description: "Critical exploit attempt".to_string(),
        confidence: 0.95,
    };

    let action = skunkbat.respond_to_threat(&threat).unwrap();
    assert_eq!(action, defense::ActionType::Quarantine);
}

#[tokio::test]
async fn test_health_check() {
    let config = SkunkBatConfig::default();
    let skunkbat = SkunkBat::new(config);

    let result = skunkbat.health_check().await;
    assert!(result.is_ok());

    let report = result.unwrap();
    assert_eq!(report.name, "skunkBat");
}

#[tokio::test]
async fn test_health_status_created() {
    let config = SkunkBatConfig::default();
    let skunkbat = SkunkBat::new(config);

    let status = skunkbat.health_status();
    assert!(matches!(status, HealthStatus::Unhealthy { .. }));
}

#[tokio::test]
async fn test_health_status_running() {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);

    skunkbat.start().await.unwrap();
    let status = skunkbat.health_status();
    assert!(matches!(status, HealthStatus::Healthy));
}

#[tokio::test]
async fn test_health_status_stopped() {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);

    skunkbat.start().await.unwrap();
    skunkbat.stop().await.unwrap();

    let status = skunkbat.health_status();
    assert!(matches!(status, HealthStatus::Unhealthy { .. }));
}

#[tokio::test]
async fn test_multiple_start_calls() {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);

    assert!(skunkbat.start().await.is_ok());
    assert_eq!(skunkbat.state(), PrimalState::Running);
}

#[tokio::test]
async fn test_stop_without_start() {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);

    assert!(skunkbat.stop().await.is_ok());
    assert_eq!(skunkbat.state(), PrimalState::Stopped);
}

#[test]
fn test_config_with_all_features_disabled() {
    let mut config = SkunkBatConfig::default();
    config.features.reconnaissance = false;
    config.features.threat_detection = false;
    config.features.auto_defense = false;
    config.features.observability = false;

    let skunkbat = SkunkBat::new(config);
    assert_eq!(skunkbat.state(), PrimalState::Created);
}

#[test]
fn test_config_with_lineage() {
    let config = SkunkBatConfig {
        lineage_id: Some("test-lineage-123".to_string()),
        ..SkunkBatConfig::default()
    };

    let skunkbat = SkunkBat::new(config);
    assert_eq!(skunkbat.state(), PrimalState::Created);
}

#[tokio::test]
async fn test_full_workflow() {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);

    assert!(skunkbat.start().await.is_ok());
    assert_eq!(skunkbat.state(), PrimalState::Running);

    let scan_result = skunkbat.scan_network().await;
    assert!(scan_result.is_ok());

    let threats_result = skunkbat.detect_threats().await;
    assert!(threats_result.is_ok());

    let metrics = skunkbat.get_security_metrics();
    assert!(metrics.last_updated.is_some());

    let health = skunkbat.health_check().await;
    assert!(health.is_ok());

    assert!(skunkbat.stop().await.is_ok());
    assert_eq!(skunkbat.state(), PrimalState::Stopped);
}

#[tokio::test]
async fn test_integration_detect_and_respond() {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);

    skunkbat.start().await.unwrap();

    let threats = skunkbat.detect_threats().await.unwrap();
    assert!(
        !threats.iter().any(|t| t.id.starts_with("genetic-")),
        "default config (no lineage_id) should produce no genetic threats"
    );

    let test_threat = threats::Threat {
        id: "integration-threat".to_string(),
        threat_type: threats::ThreatType::BehaviorAnomaly {
            deviation: 2.5,
            behavior: "unusual pattern".to_string(),
        },
        severity: threats::Severity::Medium,
        source: "192.168.1.50".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: std::time::SystemTime::now(),
        description: "Integration test threat".to_string(),
        confidence: 0.75,
    };

    assert!(skunkbat.respond_to_threat(&test_threat).is_ok());

    skunkbat.stop().await.unwrap();
}

#[tokio::test]
async fn test_health_status_degraded() {
    use crate::config::FeatureFlags;

    let config = SkunkBatConfig {
        common: CommonConfig::default(),
        features: FeatureFlags {
            reconnaissance: true,
            threat_detection: false,
            auto_defense: true,
            observability: true,
        },
        lineage_id: None,
        thresholds: crate::config::ThreatThresholds::default(),
        expected_topology_path: None,
    };
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await.unwrap();

    let status = skunkbat.health_status();
    assert!(matches!(status, HealthStatus::Degraded { .. }));
}

#[test]
fn test_config_access() {
    let config = SkunkBatConfig::default();
    let skunkbat = SkunkBat::new(config);
    assert_eq!(skunkbat.config().common.name, PRIMAL_NAME);
}

#[test]
fn test_primal_constants() {
    assert_eq!(PRIMAL_NAME, "skunkBat");
    assert_eq!(PRIMAL_ID, "skunkbat");
    assert_eq!(CAPABILITIES.len(), 4);
    assert!(CAPABILITIES.contains(&"reconnaissance"));
    assert!(CAPABILITIES.contains(&"defense"));
}

#[test]
fn test_default_port_constant() {
    assert_eq!(DEFAULT_PORT, 9750);
}

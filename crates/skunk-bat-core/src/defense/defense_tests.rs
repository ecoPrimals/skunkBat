// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

use super::*;
use crate::test_support::test_config;
use crate::threats::{Severity, Threat, ThreatType};

fn test_threat(severity: Severity, confidence: f64) -> Threat {
    Threat {
        id: "test-threat-1".to_string(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "test-attack".to_string(),
            signature: "test-sig".to_string(),
        },
        severity,
        source: "192.168.1.100".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: SystemTime::now(),
        description: "Test threat".to_string(),
        confidence,
    }
}

#[test]
fn test_defense_engine_creation() {
    let config = test_config();
    let engine = DefenseEngine::new(&config);
    assert!(engine.is_healthy());
}

#[test]
fn test_defense_engine_start_stop() {
    let config = test_config();
    let engine = DefenseEngine::new(&config);

    assert!(engine.start().is_ok());
    assert!(engine.stop().is_ok());
}

#[test]
fn test_respond_to_threat() {
    let config = test_config();
    let engine = DefenseEngine::new(&config);

    let threat = test_threat(Severity::Medium, 0.7);
    let result = engine.respond(&threat);
    assert!(result.is_ok());
}

#[test]
fn test_critical_threat_response() {
    let config = test_config();
    let engine = DefenseEngine::new(&config);
    let threat = test_threat(Severity::Critical, 0.95);
    let action = engine.determine_action(&threat);

    assert_eq!(action.action_type, ActionType::Quarantine);
    assert!(!action.requires_approval);
}

#[test]
fn test_high_severity_response() {
    let config = test_config();
    let engine = DefenseEngine::new(&config);
    let threat = test_threat(Severity::High, 0.8);
    let action = engine.determine_action(&threat);

    assert_eq!(action.action_type, ActionType::QuarantineAndAlert);
    assert!(!action.requires_approval);
}

#[test]
fn test_medium_severity_response() {
    let config = test_config();
    let engine = DefenseEngine::new(&config);
    let threat = test_threat(Severity::Medium, 0.6);
    let action = engine.determine_action(&threat);

    assert_eq!(action.action_type, ActionType::MonitorAndAlert);
    assert!(action.requires_approval);
}

#[test]
fn test_low_confidence_threat() {
    let config = test_config();
    let engine = DefenseEngine::new(&config);
    let threat = test_threat(Severity::Critical, 0.5);
    let action = engine.determine_action(&threat);

    assert_eq!(action.action_type, ActionType::MonitorAndAlert);
}

#[test]
fn test_disabled_defense() {
    let mut config = test_config();
    config.features.auto_defense = false;

    let engine = DefenseEngine::new(&config);
    assert!(!engine.is_healthy());

    let threat = test_threat(Severity::Critical, 0.95);
    let result = engine.respond(&threat);
    assert!(result.is_ok());
}

#[test]
fn test_action_type_equality() {
    assert_eq!(ActionType::Quarantine, ActionType::Quarantine);
    assert_ne!(ActionType::Quarantine, ActionType::Block);
}

#[test]
fn test_quarantine_record_creation() {
    let record = QuarantineRecord {
        source: "192.168.1.100".to_string(),
        started_at: SystemTime::now(),
        reason: "Suspicious activity".to_string(),
        threat_id: "threat-123".to_string(),
    };

    assert_eq!(record.source, "192.168.1.100");
    assert_eq!(record.threat_id, "threat-123");
}

#[test]
fn test_defense_action_variants() {
    let action1 = DefenseAction {
        action_type: ActionType::Quarantine,
        target: "test".to_string(),
        requires_approval: false,
        reason: "test".to_string(),
    };
    assert_eq!(action1.action_type, ActionType::Quarantine);

    let action2 = DefenseAction {
        action_type: ActionType::Block,
        target: "test".to_string(),
        requires_approval: false,
        reason: "test".to_string(),
    };
    assert_eq!(action2.action_type, ActionType::Block);
}

#[test]
fn test_block_action_response() {
    let threat = Threat {
        id: "test-block".to_string(),
        threat_type: crate::threats::ThreatType::IntrusionAttempt {
            attack_type: "port-scan".to_string(),
            signature: "rapid".to_string(),
        },
        severity: Severity::Critical,
        source: "192.168.1.200".to_string(),
        target: "192.168.1.1".to_string(),
        detected_at: SystemTime::now(),
        description: "Port scanning".to_string(),
        confidence: 0.95,
    };

    let config = test_config();
    let engine = DefenseEngine::new(&config);

    let action = DefenseAction {
        action_type: ActionType::Block,
        target: threat.source.clone(),
        requires_approval: false,
        reason: "High confidence attack".to_string(),
    };

    engine.execute_action(&action, &threat);
}

#[test]
fn test_disabled_defense_start() {
    let mut config = test_config();
    config.features.auto_defense = false;

    let engine = DefenseEngine::new(&config);
    assert!(engine.start().is_ok());
    assert!(engine.stop().is_ok());
}

#[test]
fn test_quarantine_lifecycle() {
    let config = test_config();
    let engine = DefenseEngine::new(&config);

    let threat = test_threat(Severity::High, 0.8);
    engine.respond(&threat).expect("respond should succeed");

    let snapshot = engine.quarantine_snapshot();
    assert!(!snapshot.is_empty(), "Should have quarantined the source");
    assert!(snapshot.contains_key(&threat.source));

    let record = &snapshot[&threat.source];
    assert_eq!(record.threat_id, threat.id);
}

#[test]
fn test_quarantine_and_alert() {
    let config = test_config();
    let engine = DefenseEngine::new(&config);

    let threat = Threat {
        id: "qa-test".to_string(),
        threat_type: crate::threats::ThreatType::UnknownLineage {
            peer_id: "unknown".to_string(),
            lineage: None,
        },
        severity: Severity::High,
        source: "10.0.0.50".to_string(),
        target: "local".to_string(),
        detected_at: SystemTime::now(),
        description: "Unknown lineage detected".to_string(),
        confidence: 0.8,
    };

    engine.respond(&threat).expect("respond should succeed");

    let action = engine.determine_action(&threat);
    assert_eq!(action.action_type, ActionType::QuarantineAndAlert);
}

#[test]
fn test_auto_response_and_quarantine_accessors() {
    let config = test_config();
    let engine = DefenseEngine::new(&config);
    assert!(engine.auto_response_enabled());

    let snapshot = engine.quarantine_snapshot();
    assert!(snapshot.is_empty());
}

#[test]
fn test_all_action_types_execute() {
    let config = test_config();
    let engine = DefenseEngine::new(&config);
    let threat = test_threat(Severity::Critical, 0.95);

    for action_type in [
        ActionType::Quarantine,
        ActionType::QuarantineAndAlert,
        ActionType::MonitorAndAlert,
        ActionType::Block,
    ] {
        let action = DefenseAction {
            action_type,
            target: "test-target".to_string(),
            requires_approval: false,
            reason: "test".to_string(),
        };
        engine.execute_action(&action, &threat);
    }
}

#[test]
fn quarantine_persistence_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config();
    config.common.data_dir = dir.path().to_string_lossy().into_owned();

    let engine = DefenseEngine::new(&config);
    engine.quarantine("10.0.0.1", "test threat", "threat-001");
    engine.quarantine("10.0.0.2", "second threat", "threat-002");

    assert!(engine.is_quarantined("10.0.0.1"));
    assert!(engine.is_quarantined("10.0.0.2"));

    let persist_file = dir.path().join("quarantine.json");
    assert!(persist_file.exists());

    let engine2 = DefenseEngine::new(&config);
    assert!(engine2.is_quarantined("10.0.0.1"));
    assert!(engine2.is_quarantined("10.0.0.2"));

    engine2.release("10.0.0.1");
    assert!(!engine2.is_quarantined("10.0.0.1"));
    assert!(engine2.is_quarantined("10.0.0.2"));

    let engine3 = DefenseEngine::new(&config);
    assert!(!engine3.is_quarantined("10.0.0.1"));
    assert!(engine3.is_quarantined("10.0.0.2"));
}

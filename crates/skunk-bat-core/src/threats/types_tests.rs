// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

use super::*;
use std::time::SystemTime;

#[test]
fn threat_serde_roundtrip() {
    let threat = Threat {
        id: "threat-001".to_owned(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "port-scan".to_owned(),
            signature: "nmap".to_owned(),
        },
        severity: Severity::High,
        source: "192.168.1.100".to_owned(),
        target: "192.168.1.1".to_owned(),
        detected_at: SystemTime::UNIX_EPOCH,
        description: "Port scan detected".to_owned(),
        confidence: 0.85,
    };

    let json = serde_json::to_string(&threat).unwrap();
    let parsed: Threat = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.id, "threat-001");
    assert_eq!(parsed.severity, Severity::High);
}

#[test]
fn severity_ordering() {
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn threat_type_unknown_lineage_serde() {
    let tt = ThreatType::UnknownLineage {
        peer_id: "peer-xyz".to_owned(),
        lineage: Some("family-a".to_owned()),
    };
    let json = serde_json::to_value(&tt).unwrap();
    assert!(json["UnknownLineage"]["peer_id"].is_string());
}

#[test]
fn threat_type_dos_serde() {
    let tt = ThreatType::DenialOfService {
        resource: "cpu".to_owned(),
        current_level: 0.95,
    };
    let json = serde_json::to_value(&tt).unwrap();
    let parsed: ThreatType = serde_json::from_value(json).unwrap();
    match parsed {
        ThreatType::DenialOfService {
            resource,
            current_level,
        } => {
            assert_eq!(resource, "cpu");
            assert!((current_level - 0.95).abs() < f64::EPSILON);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn threat_type_topology_violation_serde() {
    let tt = ThreatType::TopologyViolation {
        expected_path: vec![1, 2, 3],
        actual_path: vec![1, 3],
        bypassed_layers: vec![2],
    };
    let json = serde_json::to_string(&tt).unwrap();
    let parsed: ThreatType = serde_json::from_str(&json).unwrap();
    match parsed {
        ThreatType::TopologyViolation {
            bypassed_layers, ..
        } => assert_eq!(bypassed_layers, vec![2]),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn observation_serde_roundtrip() {
    let obs = Observation {
        connection_rate: 42.5,
        traffic_volume: 1_000_000,
        ports_accessed: vec![80, 443, 8080],
        timestamp: SystemTime::UNIX_EPOCH,
        http: None,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let parsed: Observation = serde_json::from_str(&json).unwrap();
    assert!((parsed.connection_rate - 42.5).abs() < f64::EPSILON);
    assert_eq!(parsed.ports_accessed.len(), 3);
}

#[test]
fn anomaly_serde_roundtrip() {
    let anomaly = Anomaly {
        deviation: 3.5,
        behavior: "spike".to_owned(),
        confidence: 0.9,
    };
    let json = serde_json::to_string(&anomaly).unwrap();
    let parsed: Anomaly = serde_json::from_str(&json).unwrap();
    assert!((parsed.deviation - 3.5).abs() < f64::EPSILON);
}

#[test]
fn path_validation_construction() {
    let pv = PathValidation {
        is_valid: false,
        expected_path: vec![1, 2, 3],
        actual_path: vec![1, 3],
        bypassed_layers: vec![2],
    };
    assert!(!pv.is_valid);
    assert_eq!(pv.bypassed_layers.len(), 1);
}

#[test]
fn severity_equality() {
    assert_eq!(Severity::Critical, Severity::Critical);
    assert_ne!(Severity::Low, Severity::High);
}

#[test]
fn severity_clone() {
    let s = Severity::High;
    let cloned = s;
    assert_eq!(s, cloned);
}

#[test]
fn threat_type_behavior_anomaly_serde() {
    let tt = ThreatType::BehaviorAnomaly {
        deviation: 4.2,
        behavior: "connection spike".to_owned(),
    };
    let json = serde_json::to_value(&tt).unwrap();
    let parsed: ThreatType = serde_json::from_value(json).unwrap();
    match parsed {
        ThreatType::BehaviorAnomaly {
            deviation,
            behavior,
        } => {
            assert!((deviation - 4.2).abs() < f64::EPSILON);
            assert_eq!(behavior, "connection spike");
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn threat_type_config_drift_serde() {
    let tt = ThreatType::ConfigurationDrift {
        component: "firewall".to_owned(),
        expected: "enabled".to_owned(),
        observed: "disabled".to_owned(),
    };
    let json = serde_json::to_string(&tt).unwrap();
    let parsed: ThreatType = serde_json::from_str(&json).unwrap();
    match parsed {
        ThreatType::ConfigurationDrift {
            component,
            expected,
            observed,
        } => {
            assert_eq!(component, "firewall");
            assert_eq!(expected, "enabled");
            assert_eq!(observed, "disabled");
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn threat_clone() {
    let threat = Threat {
        id: "t-clone".to_owned(),
        threat_type: ThreatType::IntrusionAttempt {
            attack_type: "scan".to_owned(),
            signature: "nmap".to_owned(),
        },
        severity: Severity::Medium,
        source: "10.0.0.1".to_owned(),
        target: "10.0.0.2".to_owned(),
        detected_at: SystemTime::UNIX_EPOCH,
        description: "test".to_owned(),
        confidence: 0.7,
    };
    let cloned = threat.clone();
    assert_eq!(cloned.id, threat.id);
    assert_eq!(cloned.severity, threat.severity);
}

#[test]
fn observation_empty_ports() {
    let obs = Observation {
        connection_rate: 0.0,
        traffic_volume: 0,
        ports_accessed: vec![],
        timestamp: SystemTime::UNIX_EPOCH,
        http: None,
    };
    let json = serde_json::to_string(&obs).unwrap();
    let parsed: Observation = serde_json::from_str(&json).unwrap();
    assert!(parsed.ports_accessed.is_empty());
}

#[test]
fn path_validation_valid_path() {
    let pv = PathValidation {
        is_valid: true,
        expected_path: vec![0, 1, 2, 3],
        actual_path: vec![0, 1, 2, 3],
        bypassed_layers: vec![],
    };
    assert!(pv.is_valid);
    assert!(pv.bypassed_layers.is_empty());
}

#[test]
fn all_severity_values_serialize() {
    for severity in [
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        let json = serde_json::to_string(&severity).unwrap();
        let parsed: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, severity);
    }
}

#[test]
fn threat_type_intrusion_debug() {
    let tt = ThreatType::IntrusionAttempt {
        attack_type: "brute_force".to_owned(),
        signature: "ssh-rapid".to_owned(),
    };
    let debug = format!("{tt:?}");
    assert!(debug.contains("IntrusionAttempt"));
    assert!(debug.contains("brute_force"));
}

#[test]
fn anomaly_confidence_range() {
    let low = Anomaly {
        deviation: 1.0,
        behavior: "normal".to_owned(),
        confidence: 0.0,
    };
    let high = Anomaly {
        deviation: 10.0,
        behavior: "extreme".to_owned(),
        confidence: 1.0,
    };
    assert!(low.confidence <= high.confidence);
}

#[test]
fn observation_large_ports_list() {
    let obs = Observation {
        connection_rate: 100.0,
        traffic_volume: 5_000_000,
        ports_accessed: (1..=100).collect(),
        timestamp: SystemTime::UNIX_EPOCH,
        http: None,
    };
    assert_eq!(obs.ports_accessed.len(), 100);
    let json = serde_json::to_string(&obs).unwrap();
    let parsed: Observation = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.ports_accessed.len(), 100);
}

#[test]
fn threat_unknown_lineage_none_lineage() {
    let tt = ThreatType::UnknownLineage {
        peer_id: "unknown-peer".to_owned(),
        lineage: None,
    };
    let json = serde_json::to_value(&tt).unwrap();
    assert!(json["UnknownLineage"]["lineage"].is_null());
}

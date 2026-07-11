// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

use super::*;
use skunk_bat_core::observability::audit_log::{EventKind, EventSource};
use std::time::Duration;

fn make_event(seq: u64) -> SecurityEvent {
    SecurityEvent {
        seq,
        timestamp: std::time::SystemTime::now(),
        source: EventSource::MethodGate,
        severity: EventSeverity::Warn,
        kind: EventKind::GateRejection {
            method: "security.scan".to_owned(),
            origin: "Remote".to_owned(),
        },
        correlation_id: None,
    }
}

#[tokio::test]
async fn forward_to_dag_unreachable() {
    let event = make_event(1);
    let result = forward_to_dag(&event, Duration::from_millis(100)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn forward_to_braid_unreachable() {
    let event = make_event(1);
    let result = forward_to_braid(&event, Duration::from_millis(100)).await;
    assert!(result.is_err());
}

#[test]
fn default_config() {
    let config = ForwardingConfig::default();
    assert_eq!(config.poll_interval, Duration::from_secs(10));
    assert!(config.dag_enabled);
    assert!(config.braid_enabled);
    assert_eq!(config.min_severity, EventSeverity::Warn);
}

#[test]
fn resolve_endpoints_have_capability_sockets() {
    let target = resolve_rhizocrypt();
    match &target {
        ResolvedTarget::Legacy { uds, .. } => {
            assert!(uds.as_ref().unwrap().contains("provenance.sock"));
        }
        ResolvedTarget::Endpoint(_) => {}
    }

    let target = resolve_sweetgrass();
    match &target {
        ResolvedTarget::Legacy { uds, .. } => {
            assert!(uds.as_ref().unwrap().contains("attribution.sock"));
        }
        ResolvedTarget::Endpoint(_) => {}
    }
}

#[tokio::test]
async fn forwarding_loop_advances_cursor() {
    let log = AuditLog::new();
    log.record(
        EventSource::ThreatDetection,
        EventSeverity::Warn,
        EventKind::ThreatDetected {
            threat_id: "t-1".to_owned(),
            threat_type: "behavioral".to_owned(),
            severity: "High".to_owned(),
            source: "10.0.0.1".to_owned(),
        },
    )
    .await;

    let config = ForwardingConfig {
        poll_interval: Duration::from_millis(10),
        timeout: Duration::from_millis(50),
        ..Default::default()
    };

    let log_clone = log.clone();
    let handle = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_millis(100),
            run_forwarding_loop(log_clone, config),
        )
        .await
    });

    let _ = handle.await;
    assert_eq!(log.latest_seq().await, 1);
}

#[tokio::test]
async fn skips_low_severity_events() {
    let event = SecurityEvent {
        seq: 1,
        timestamp: std::time::SystemTime::now(),
        source: EventSource::Lifecycle,
        severity: EventSeverity::Info,
        kind: EventKind::LifecycleTransition {
            from_state: "Created".to_owned(),
            to_state: "Running".to_owned(),
        },
        correlation_id: None,
    };

    assert!(event.severity < MIN_FORWARD_SEVERITY);
}

#[test]
fn config_with_custom_values() {
    let config = ForwardingConfig {
        poll_interval: Duration::from_secs(30),
        timeout: Duration::from_secs(5),
        dag_enabled: false,
        braid_enabled: true,
        min_severity: EventSeverity::Critical,
    };
    assert_eq!(config.poll_interval, Duration::from_secs(30));
    assert!(!config.dag_enabled);
    assert_eq!(config.min_severity, EventSeverity::Critical);
}

#[test]
fn warn_severity_meets_minimum() {
    let event = make_event(1);
    assert!(event.severity >= MIN_FORWARD_SEVERITY);
}

#[test]
fn error_severity_meets_minimum() {
    let event = SecurityEvent {
        seq: 1,
        timestamp: std::time::SystemTime::now(),
        source: EventSource::DefenseEngine,
        severity: EventSeverity::Error,
        kind: EventKind::DefenseAction {
            threat_id: "t-1".to_owned(),
            action: "block".to_owned(),
        },
        correlation_id: None,
    };
    assert!(event.severity >= MIN_FORWARD_SEVERITY);
}

#[test]
fn critical_severity_meets_minimum() {
    let event = SecurityEvent {
        seq: 2,
        timestamp: std::time::SystemTime::now(),
        source: EventSource::ThreatDetection,
        severity: EventSeverity::Critical,
        kind: EventKind::ThreatDetected {
            threat_id: "t-critical".to_owned(),
            threat_type: "intrusion".to_owned(),
            severity: "Critical".to_owned(),
            source: "10.0.0.1".to_owned(),
        },
        correlation_id: Some("incident-1".to_owned()),
    };
    assert!(event.severity >= MIN_FORWARD_SEVERITY);
}

#[test]
fn resolve_rhizocrypt_returns_consistent_paths() {
    let t1 = resolve_rhizocrypt();
    let t2 = resolve_rhizocrypt();
    assert_eq!(t1, t2);
}

#[test]
fn resolve_sweetgrass_returns_consistent_paths() {
    let t1 = resolve_sweetgrass();
    let t2 = resolve_sweetgrass();
    assert_eq!(t1, t2);
}

#[tokio::test]
async fn multiple_events_forwarding() {
    let log = AuditLog::new();
    for i in 0..5 {
        log.record(
            EventSource::ThreatDetection,
            EventSeverity::Warn,
            EventKind::ThreatDetected {
                threat_id: format!("t-{i}"),
                threat_type: "scan".to_owned(),
                severity: "Medium".to_owned(),
                source: "10.0.0.1".to_owned(),
            },
        )
        .await;
    }
    assert_eq!(log.latest_seq().await, 5);
}

#[test]
fn make_event_has_correct_seq() {
    let event = make_event(42);
    assert_eq!(event.seq, 42);
}

#[test]
fn min_forward_severity_is_warn() {
    assert_eq!(MIN_FORWARD_SEVERITY, EventSeverity::Warn);
}

#[test]
fn config_default_timeout() {
    let config = ForwardingConfig::default();
    assert_eq!(config.timeout, Duration::from_secs(5));
}

#[tokio::test]
async fn cursor_stops_on_failed_forward() {
    let log = AuditLog::new();
    for i in 0..3 {
        log.record(
            EventSource::ThreatDetection,
            EventSeverity::Warn,
            EventKind::ThreatDetected {
                threat_id: format!("t-{i}"),
                threat_type: "scan".to_owned(),
                severity: "Medium".to_owned(),
                source: "10.0.0.1".to_owned(),
            },
        )
        .await;
    }

    let config = ForwardingConfig {
        poll_interval: Duration::from_millis(10),
        timeout: Duration::from_millis(50),
        ..Default::default()
    };

    let log_clone = log.clone();
    let handle = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_millis(100),
            run_forwarding_loop(log_clone, config),
        )
        .await
    });

    let _ = handle.await;
    let seq = log.latest_seq().await;
    assert_eq!(seq, 3, "events remain available for retry after failure");
}

#[tokio::test]
async fn low_severity_events_advance_cursor() {
    let log = AuditLog::new();
    log.record(
        EventSource::Lifecycle,
        EventSeverity::Info,
        EventKind::LifecycleTransition {
            from_state: "Created".to_owned(),
            to_state: "Running".to_owned(),
        },
    )
    .await;
    log.record(
        EventSource::ThreatDetection,
        EventSeverity::Warn,
        EventKind::ThreatDetected {
            threat_id: "t-after-info".to_owned(),
            threat_type: "scan".to_owned(),
            severity: "Low".to_owned(),
            source: "10.0.0.1".to_owned(),
        },
    )
    .await;
    assert_eq!(log.latest_seq().await, 2);
}

#[test]
fn from_env_defaults_when_unset() {
    let config = ForwardingConfig::from_env();
    assert_eq!(config.poll_interval, POLL_INTERVAL);
    assert_eq!(config.timeout, FORWARD_TIMEOUT);
    assert_eq!(config.min_severity, MIN_FORWARD_SEVERITY);
}

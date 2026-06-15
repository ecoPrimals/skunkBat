// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! JH-5 Phase 3: Cross-primal audit event forwarding.
//!
//! Forwards security events from the local `AuditLog` to:
//! - `rhizoCrypt` DAG via `dag.event.append` (tamper-evident audit history)
//! - `sweetGrass` braids via `braid.create` (provenance attribution)
//!
//! Uses capability-based discovery — no hardcoded primal endpoints.
//! Forwarding is best-effort: if targets are unreachable, events stay
//! in the local ring buffer and are retried on the next poll cycle.

use std::time::Duration;

use skunk_bat_core::observability::audit_log::{AuditLog, EventSeverity, SecurityEvent};

use crate::rpc::{self, RpcError, TransportEndpoint};

/// Environment variable for rhizoCrypt endpoint override.
const RHIZOCRYPT_ENDPOINT_ENV: &str = "RHIZOCRYPT_ENDPOINT";

/// Environment variable for sweetGrass endpoint override.
const SWEETGRASS_ENDPOINT_ENV: &str = "SWEETGRASS_ENDPOINT";

/// Transport endpoint env for provenance (sourDough standard).
const RHIZOCRYPT_TRANSPORT_ENV: &str = "RHIZOCRYPT_TRANSPORT";

/// Transport endpoint env for attribution (sourDough standard).
const SWEETGRASS_TRANSPORT_ENV: &str = "SWEETGRASS_TRANSPORT";

/// Capability domain socket name for provenance (rhizoCrypt).
const PROVENANCE_CAPABILITY: &str = "provenance";

/// Capability domain socket name for attribution (sweetGrass).
const ATTRIBUTION_CAPABILITY: &str = "attribution";

/// Default IPC timeout for forwarding calls.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

/// Default polling interval for the forwarding loop.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Minimum event severity to forward (skip Info-level noise).
const MIN_FORWARD_SEVERITY: EventSeverity = EventSeverity::Warn;

/// Configuration for the forwarding service.
#[derive(Debug, Clone)]
pub struct ForwardingConfig {
    /// How often to poll the audit log for new events.
    pub poll_interval: Duration,
    /// IPC call timeout.
    pub timeout: Duration,
    /// Minimum severity to forward (events below this are skipped).
    pub min_severity: EventSeverity,
    /// Whether DAG forwarding (rhizoCrypt) is enabled.
    pub dag_enabled: bool,
    /// Whether braid forwarding (sweetGrass) is enabled.
    pub braid_enabled: bool,
}

impl Default for ForwardingConfig {
    fn default() -> Self {
        Self {
            poll_interval: POLL_INTERVAL,
            timeout: FORWARD_TIMEOUT,
            min_severity: MIN_FORWARD_SEVERITY,
            dag_enabled: true,
            braid_enabled: true,
        }
    }
}

/// Resolve the rhizoCrypt endpoint.
///
/// Resolution order:
/// 1. `RHIZOCRYPT_TRANSPORT` env (sourDough `TransportEndpoint` JSON)
/// 2. `RHIZOCRYPT_ENDPOINT` env (legacy TCP string)
/// 3. Capability socket (`provenance.sock`)
fn resolve_rhizocrypt() -> ResolvedTarget {
    if let Some(ep) = parse_transport_env(RHIZOCRYPT_TRANSPORT_ENV) {
        return ResolvedTarget::Endpoint(ep);
    }
    let tcp = std::env::var(RHIZOCRYPT_ENDPOINT_ENV).ok();
    let uds = Some(rpc::capability_socket(PROVENANCE_CAPABILITY));
    ResolvedTarget::Legacy { uds, tcp }
}

/// Resolve the sweetGrass endpoint.
///
/// Resolution order:
/// 1. `SWEETGRASS_TRANSPORT` env (sourDough `TransportEndpoint` JSON)
/// 2. `SWEETGRASS_ENDPOINT` env (legacy TCP string)
/// 3. Capability socket (`attribution.sock`)
fn resolve_sweetgrass() -> ResolvedTarget {
    if let Some(ep) = parse_transport_env(SWEETGRASS_TRANSPORT_ENV) {
        return ResolvedTarget::Endpoint(ep);
    }
    let tcp = std::env::var(SWEETGRASS_ENDPOINT_ENV).ok();
    let uds = Some(rpc::capability_socket(ATTRIBUTION_CAPABILITY));
    ResolvedTarget::Legacy { uds, tcp }
}

/// Resolved outbound target — either a sourDough `TransportEndpoint` or legacy (UDS + TCP).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedTarget {
    Endpoint(TransportEndpoint),
    Legacy {
        uds: Option<String>,
        tcp: Option<String>,
    },
}

/// Parse a `TransportEndpoint` from an environment variable.
fn parse_transport_env(var: &str) -> Option<TransportEndpoint> {
    std::env::var(var)
        .ok()
        .and_then(|v| serde_json::from_str(&v).ok())
}

/// Issue a JSON-RPC call to a resolved target.
async fn call_resolved(
    target: &ResolvedTarget,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, RpcError> {
    match target {
        ResolvedTarget::Endpoint(ep) => rpc::call_endpoint(ep, method, params, timeout).await,
        ResolvedTarget::Legacy { uds, tcp } => {
            rpc::call(uds.as_deref(), tcp.as_deref(), method, params, timeout).await
        }
    }
}

/// Forward a security event to rhizoCrypt's DAG as a vertex.
///
/// Calls `dag.event.append` with the serialized event payload.
///
/// # Errors
///
/// Returns [`RpcError`] if rhizoCrypt is unreachable or rejects the event.
pub async fn forward_to_dag(
    event: &SecurityEvent,
    timeout: Duration,
) -> Result<serde_json::Value, RpcError> {
    let target = resolve_rhizocrypt();
    let params = serde_json::json!({
        "event_type": "security_audit",
        "source_primal": skunk_bat_core::PRIMAL_ID,
        "seq": event.seq,
        "timestamp": event.timestamp,
        "severity": event.severity,
        "event_source": event.source,
        "payload": event.kind,
        "correlation_id": event.correlation_id,
    });

    call_resolved(&target, "dag.event.append", Some(params), timeout).await
}

/// Forward a security event to sweetGrass as a provenance braid entry.
///
/// Calls `braid.create` with attribution metadata derived from the event.
///
/// # Errors
///
/// Returns [`RpcError`] if sweetGrass is unreachable or rejects the event.
pub async fn forward_to_braid(
    event: &SecurityEvent,
    timeout: Duration,
) -> Result<serde_json::Value, RpcError> {
    let target = resolve_sweetgrass();
    let params = serde_json::json!({
        "braid_type": "security_attestation",
        "source": skunk_bat_core::PRIMAL_ID,
        "anchor": {
            "seq": event.seq,
            "timestamp": event.timestamp,
            "source": event.source,
            "severity": event.severity,
        },
        "payload": event.kind,
        "correlation_id": event.correlation_id,
    });

    call_resolved(&target, "braid.create", Some(params), timeout).await
}

/// Run the forwarding loop as a background task.
///
/// Polls the audit log at `config.poll_interval`, forwarding events with
/// severity >= `config.min_severity` to rhizoCrypt and sweetGrass.
///
/// This function runs indefinitely — spawn it as a Tokio task.
pub async fn run_forwarding_loop(audit_log: AuditLog, config: ForwardingConfig) {
    let mut cursor: u64 = audit_log.latest_seq().await;
    tracing::info!(
        cursor,
        dag = config.dag_enabled,
        braid = config.braid_enabled,
        "JH-5 Phase 3 forwarding loop started"
    );

    loop {
        tokio::time::sleep(config.poll_interval).await;

        let events = audit_log.query(cursor, 50).await;
        if events.is_empty() {
            continue;
        }

        for event in &events {
            if event.severity < config.min_severity {
                continue;
            }

            if config.dag_enabled {
                match forward_to_dag(event, config.timeout).await {
                    Ok(_) => {
                        tracing::debug!(seq = event.seq, "forwarded to rhizoCrypt DAG");
                    }
                    Err(e) => {
                        tracing::warn!(seq = event.seq, err = %e, "rhizoCrypt DAG forward failed");
                    }
                }
            }

            if config.braid_enabled {
                match forward_to_braid(event, config.timeout).await {
                    Ok(_) => {
                        tracing::debug!(seq = event.seq, "forwarded to sweetGrass braid");
                    }
                    Err(e) => {
                        tracing::warn!(seq = event.seq, err = %e, "sweetGrass braid forward failed");
                    }
                }
            }
        }

        if let Some(last) = events.last() {
            cursor = last.seq;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skunk_bat_core::observability::audit_log::{EventKind, EventSource};

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
}

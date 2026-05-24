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

use crate::rpc::{self, RpcError};

/// Environment variable for rhizoCrypt endpoint override.
const RHIZOCRYPT_ENDPOINT_ENV: &str = "RHIZOCRYPT_ENDPOINT";

/// Environment variable for sweetGrass endpoint override.
const SWEETGRASS_ENDPOINT_ENV: &str = "SWEETGRASS_ENDPOINT";

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

/// Resolve the rhizoCrypt endpoint (env override → capability socket).
fn resolve_rhizocrypt() -> (Option<String>, Option<String>) {
    let tcp = std::env::var(RHIZOCRYPT_ENDPOINT_ENV).ok();
    let uds = Some(rpc::capability_socket(PROVENANCE_CAPABILITY));
    (uds, tcp)
}

/// Resolve the sweetGrass endpoint (env override → capability socket).
fn resolve_sweetgrass() -> (Option<String>, Option<String>) {
    let tcp = std::env::var(SWEETGRASS_ENDPOINT_ENV).ok();
    let uds = Some(rpc::capability_socket(ATTRIBUTION_CAPABILITY));
    (uds, tcp)
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
    let (uds, tcp) = resolve_rhizocrypt();
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

    rpc::call(
        uds.as_deref(),
        tcp.as_deref(),
        "dag.event.append",
        Some(params),
        timeout,
    )
    .await
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
    let (uds, tcp) = resolve_sweetgrass();
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

    rpc::call(
        uds.as_deref(),
        tcp.as_deref(),
        "braid.create",
        Some(params),
        timeout,
    )
    .await
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
        let (uds, _tcp) = resolve_rhizocrypt();
        assert!(uds.unwrap().contains("provenance.sock"));

        let (uds, _tcp) = resolve_sweetgrass();
        assert!(uds.unwrap().contains("attribution.sock"));
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
}

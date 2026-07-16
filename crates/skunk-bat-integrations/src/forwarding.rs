// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! JH-5 Phase 3: Cross-primal audit event forwarding.
//!
//! Forwards security events from the local `AuditLog` to:
//! - **provenance** DAG via `dag.event.append` (tamper-evident audit history)
//! - **attribution** braids via `braid.create` (provenance attribution)
//!
//! Uses capability-based discovery — no hardcoded primal endpoints.
//! Forwarding is best-effort: if a target is unreachable the cursor
//! stops advancing at the last successfully forwarded event, so
//! unforwarded events are retried on the next poll cycle.

use std::time::Duration;

use skunk_bat_core::observability::audit_log::{AuditLog, EventSeverity, SecurityEvent};

use crate::rpc::{self, RpcError, TransportEndpoint};

use skunk_bat_core::env_keys;

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

impl ForwardingConfig {
    /// Build from environment variables, falling back to defaults.
    ///
    /// Reads: `SKUNKBAT_FORWARD_INTERVAL`, `SKUNKBAT_FORWARD_TIMEOUT`,
    /// `SKUNKBAT_FORWARD_MIN_SEVERITY`.
    #[must_use]
    pub fn from_env() -> Self {
        let poll_interval = std::env::var(env_keys::SKUNKBAT_FORWARD_INTERVAL)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map_or(POLL_INTERVAL, Duration::from_secs);

        let timeout = std::env::var(env_keys::SKUNKBAT_FORWARD_TIMEOUT)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map_or(FORWARD_TIMEOUT, Duration::from_secs);

        let min_severity = std::env::var(env_keys::SKUNKBAT_FORWARD_MIN_SEVERITY)
            .ok()
            .map_or(MIN_FORWARD_SEVERITY, |v| {
                match v.to_ascii_lowercase().as_str() {
                    "info" => EventSeverity::Info,
                    "error" | "critical" => EventSeverity::Error,
                    _ => MIN_FORWARD_SEVERITY,
                }
            });

        Self {
            poll_interval,
            timeout,
            min_severity,
            dag_enabled: true,
            braid_enabled: true,
        }
    }
}

/// Resolve the rhizoCrypt endpoint.
///
/// Resolution order:
/// 1. `RHIZOCRYPT_TRANSPORT` env (sourDough `TransportEndpoint` JSON)
/// 2. `RHIZOCRYPT_ENDPOINT` env → TCP
/// 3. Capability socket (`provenance.sock`) → UDS
fn resolve_rhizocrypt() -> Option<TransportEndpoint> {
    rpc::parse_transport_env(env_keys::RHIZOCRYPT_TRANSPORT)
        .or_else(|| {
            std::env::var(env_keys::RHIZOCRYPT_ENDPOINT)
                .ok()
                .and_then(|v| rpc::parse_tcp_host_port(&v))
        })
        .or_else(|| {
            let path = rpc::capability_socket(PROVENANCE_CAPABILITY);
            std::path::Path::new(&path)
                .exists()
                .then_some(TransportEndpoint::Uds { path })
        })
}

/// Resolve the sweetGrass endpoint.
///
/// Resolution order:
/// 1. `SWEETGRASS_TRANSPORT` env (sourDough `TransportEndpoint` JSON)
/// 2. `SWEETGRASS_ENDPOINT` env → TCP
/// 3. Capability socket (`attribution.sock`) → UDS
fn resolve_sweetgrass() -> Option<TransportEndpoint> {
    rpc::parse_transport_env(env_keys::SWEETGRASS_TRANSPORT)
        .or_else(|| {
            std::env::var(env_keys::SWEETGRASS_ENDPOINT)
                .ok()
                .and_then(|v| rpc::parse_tcp_host_port(&v))
        })
        .or_else(|| {
            let path = rpc::capability_socket(ATTRIBUTION_CAPABILITY);
            std::path::Path::new(&path)
                .exists()
                .then_some(TransportEndpoint::Uds { path })
        })
}

/// Issue a JSON-RPC call to a resolved endpoint.
async fn call_resolved(
    endpoint: Option<&TransportEndpoint>,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, RpcError> {
    let ep = endpoint
        .ok_or_else(|| RpcError::Io("no endpoint resolved for forwarding target".to_owned()))?;
    rpc::call_endpoint(ep, method, params, timeout).await
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

    call_resolved(target.as_ref(), "dag.event.append", Some(params), timeout).await
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

    call_resolved(target.as_ref(), "braid.create", Some(params), timeout).await
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

        let mut last_success_seq = cursor;

        for event in &events {
            if event.severity < config.min_severity {
                last_success_seq = event.seq;
                continue;
            }

            let mut event_ok = true;

            if config.dag_enabled {
                match forward_to_dag(event, config.timeout).await {
                    Ok(_) => {
                        tracing::debug!(seq = event.seq, "forwarded to provenance DAG");
                    }
                    Err(e) => {
                        tracing::warn!(seq = event.seq, err = %e, "provenance DAG forward failed");
                        event_ok = false;
                    }
                }
            }

            if config.braid_enabled {
                match forward_to_braid(event, config.timeout).await {
                    Ok(_) => {
                        tracing::debug!(seq = event.seq, "forwarded to attribution braid");
                    }
                    Err(e) => {
                        tracing::warn!(seq = event.seq, err = %e, "attribution braid forward failed");
                        event_ok = false;
                    }
                }
            }

            if event_ok {
                last_success_seq = event.seq;
            } else {
                break;
            }
        }

        cursor = last_success_seq;
    }
}

#[cfg(test)]
#[path = "forwarding_tests.rs"]
mod tests;

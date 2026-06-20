// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Audit log — bounded ring buffer of security-relevant events (JH-5).
//!
//! Captures structured security events from multiple sources:
//! - `MethodGate` rejections (unauthenticated RPC calls)
//! - Threat detections (behavioral, genetic, intrusion, `DoS`, topology)
//! - Defense actions (quarantine, alert, block)
//! - BTSP transport events (negotiate, session create, encryption failures)
//!
//! The log is a fixed-capacity ring buffer. When full, oldest events are
//! evicted. Events are queryable via `security.audit_log` RPC method for
//! downstream consumption by `rhizoCrypt` DAG and `sweetGrass` provenance braids.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Maximum events retained in the ring buffer.
const DEFAULT_CAPACITY: usize = 1024;

/// A security-relevant event in the audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// When the event occurred.
    pub timestamp: SystemTime,
    /// Event source (which subsystem generated it).
    pub source: EventSource,
    /// Event severity.
    pub severity: EventSeverity,
    /// Structured event payload.
    pub kind: EventKind,
    /// Optional correlation ID (links related events).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

/// Which subsystem produced the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    /// Pre-dispatch method gate.
    MethodGate,
    /// Threat detection pipeline.
    ThreatDetection,
    /// Defense engine action.
    DefenseEngine,
    /// BTSP transport layer.
    Transport,
    /// Startup/shutdown lifecycle.
    Lifecycle,
}

/// Event severity levels (aligned with syslog/tracing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventSeverity {
    /// Informational — normal operation.
    Info,
    /// Warning — potential issue, no immediate action.
    Warn,
    /// Error — security-relevant failure.
    Error,
    /// Critical — immediate action required.
    Critical,
}

/// Structured event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKind {
    /// Gate rejected an unauthenticated call to a protected method.
    GateRejection {
        /// The method that was rejected.
        method: String,
        /// Connection origin (Unix/Loopback/Remote).
        origin: String,
    },
    /// Gate allowed a call in permissive mode (warning-level).
    GatePermissiveAllow {
        /// The protected method that was allowed.
        method: String,
        /// Connection origin.
        origin: String,
    },
    /// Threat detected by the detection pipeline.
    ThreatDetected {
        /// Unique threat identifier.
        threat_id: String,
        /// Threat type classification.
        threat_type: String,
        /// Threat severity level.
        severity: String,
        /// Source of the threat.
        source: String,
    },
    /// Defense action taken in response to a threat.
    DefenseAction {
        /// The threat that triggered the action.
        threat_id: String,
        /// Action taken (quarantine, alert, block).
        action: String,
    },
    /// BTSP negotiate completed (success or failure).
    BtspNegotiate {
        /// Session identifier.
        session_id: String,
        /// Negotiated cipher suite.
        cipher: String,
        /// Whether negotiation succeeded.
        success: bool,
    },
    /// BTSP encrypted frame decryption failure.
    BtspDecryptFailure {
        /// Reason for the failure.
        reason: String,
    },
    /// Baseline profiler received a live observation.
    BaselineObservation {
        /// Connection rate from the observation.
        connection_rate: f64,
    },
    /// Primal started or stopped.
    LifecycleTransition {
        /// Previous state.
        from_state: String,
        /// New state.
        to_state: String,
    },
}

/// Thread-safe audit log with bounded ring buffer.
#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<RwLock<AuditLogInner>>,
}

struct AuditLogInner {
    events: VecDeque<SecurityEvent>,
    capacity: usize,
    next_seq: u64,
}

impl AuditLog {
    /// Create a new audit log with default capacity (1024 events).
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a new audit log with custom capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(AuditLogInner {
                events: VecDeque::with_capacity(capacity),
                capacity,
                next_seq: 1,
            })),
        }
    }

    /// Record a new security event.
    pub async fn record(&self, source: EventSource, severity: EventSeverity, kind: EventKind) {
        self.record_with_correlation(source, severity, kind, None)
            .await;
    }

    /// Record a new security event with a correlation ID.
    pub async fn record_with_correlation(
        &self,
        source: EventSource,
        severity: EventSeverity,
        kind: EventKind,
        correlation_id: Option<String>,
    ) {
        let mut inner = self.inner.write().await;
        let seq = inner.next_seq;
        inner.next_seq += 1;

        let event = SecurityEvent {
            seq,
            timestamp: SystemTime::now(),
            source,
            severity,
            kind,
            correlation_id,
        };

        if inner.events.len() >= inner.capacity {
            inner.events.pop_front();
        }
        inner.events.push_back(event);
    }

    /// Query events since a given sequence number.
    ///
    /// Returns up to `limit` events with `seq > since_seq`.
    pub async fn query(&self, since_seq: u64, limit: usize) -> Vec<SecurityEvent> {
        let inner = self.inner.read().await;
        inner
            .events
            .iter()
            .filter(|e| e.seq > since_seq)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get the latest sequence number (for cursor-based polling).
    pub async fn latest_seq(&self) -> u64 {
        let inner = self.inner.read().await;
        inner.next_seq.saturating_sub(1)
    }

    /// Total number of events currently in the buffer.
    pub async fn len(&self) -> usize {
        self.inner.read().await.events.len()
    }

    /// Whether the buffer is empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.events.is_empty()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_and_query() {
        let log = AuditLog::new();
        log.record(
            EventSource::MethodGate,
            EventSeverity::Warn,
            EventKind::GateRejection {
                method: "security.scan".to_owned(),
                origin: "Remote".to_owned(),
            },
        )
        .await;

        let events = log.query(0, 10).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[0].source, EventSource::MethodGate);
    }

    #[tokio::test]
    async fn query_with_cursor() {
        let log = AuditLog::new();
        for i in 0..5 {
            log.record(
                EventSource::ThreatDetection,
                EventSeverity::Error,
                EventKind::ThreatDetected {
                    threat_id: format!("t-{i}"),
                    threat_type: "intrusion".to_owned(),
                    severity: "High".to_owned(),
                    source: "10.0.0.1".to_owned(),
                },
            )
            .await;
        }

        let events = log.query(3, 10).await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, 4);
        assert_eq!(events[1].seq, 5);
    }

    #[tokio::test]
    async fn ring_buffer_eviction() {
        let log = AuditLog::with_capacity(3);
        for i in 0..5 {
            log.record(
                EventSource::Lifecycle,
                EventSeverity::Info,
                EventKind::LifecycleTransition {
                    from_state: format!("s{i}"),
                    to_state: format!("s{}", i + 1),
                },
            )
            .await;
        }

        assert_eq!(log.len().await, 3);
        let events = log.query(0, 10).await;
        assert_eq!(events[0].seq, 3);
        assert_eq!(events[2].seq, 5);
    }

    #[tokio::test]
    async fn latest_seq_tracking() {
        let log = AuditLog::new();
        assert_eq!(log.latest_seq().await, 0);

        log.record(
            EventSource::Transport,
            EventSeverity::Info,
            EventKind::BtspNegotiate {
                session_id: "s1".to_owned(),
                cipher: "chacha20-poly1305".to_owned(),
                success: true,
            },
        )
        .await;

        assert_eq!(log.latest_seq().await, 1);
    }

    #[tokio::test]
    async fn correlation_id() {
        let log = AuditLog::new();
        log.record_with_correlation(
            EventSource::DefenseEngine,
            EventSeverity::Warn,
            EventKind::DefenseAction {
                threat_id: "t-99".to_owned(),
                action: "quarantine".to_owned(),
            },
            Some("incident-42".to_owned()),
        )
        .await;

        let events = log.query(0, 10).await;
        assert_eq!(events[0].correlation_id.as_deref(), Some("incident-42"));
    }

    #[tokio::test]
    async fn event_serialization() {
        let event = SecurityEvent {
            seq: 1,
            timestamp: SystemTime::UNIX_EPOCH,
            source: EventSource::MethodGate,
            severity: EventSeverity::Critical,
            kind: EventKind::GateRejection {
                method: "security.detect".to_owned(),
                origin: "Remote".to_owned(),
            },
            correlation_id: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: SecurityEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.seq, 1);
        assert_eq!(parsed.source, EventSource::MethodGate);
        assert_eq!(parsed.severity, EventSeverity::Critical);
    }

    #[tokio::test]
    async fn empty_query_returns_empty() {
        let log = AuditLog::new();
        let events = log.query(0, 100).await;
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn is_empty_tracks_state() {
        let log = AuditLog::new();
        assert!(log.is_empty().await);

        log.record(
            EventSource::Lifecycle,
            EventSeverity::Info,
            EventKind::LifecycleTransition {
                from_state: "init".to_owned(),
                to_state: "running".to_owned(),
            },
        )
        .await;

        assert!(!log.is_empty().await);
    }

    #[tokio::test]
    async fn query_zero_limit_returns_empty() {
        let log = AuditLog::new();
        log.record(
            EventSource::Transport,
            EventSeverity::Info,
            EventKind::BtspNegotiate {
                session_id: "s1".to_owned(),
                cipher: "null".to_owned(),
                success: true,
            },
        )
        .await;

        let events = log.query(0, 0).await;
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn sequential_seq_numbers() {
        let log = AuditLog::new();
        for _ in 0..10 {
            log.record(
                EventSource::ThreatDetection,
                EventSeverity::Warn,
                EventKind::ThreatDetected {
                    threat_id: "t".to_owned(),
                    threat_type: "test".to_owned(),
                    severity: "Low".to_owned(),
                    source: "local".to_owned(),
                },
            )
            .await;
        }

        let events = log.query(0, 100).await;
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.seq, (i + 1) as u64);
        }
    }

    #[tokio::test]
    async fn cursor_beyond_latest_returns_empty() {
        let log = AuditLog::new();
        log.record(
            EventSource::Lifecycle,
            EventSeverity::Info,
            EventKind::LifecycleTransition {
                from_state: "a".to_owned(),
                to_state: "b".to_owned(),
            },
        )
        .await;

        let events = log.query(999, 100).await;
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn all_severity_levels_recordable() {
        let log = AuditLog::new();
        for severity in [
            EventSeverity::Info,
            EventSeverity::Warn,
            EventSeverity::Error,
            EventSeverity::Critical,
        ] {
            log.record(
                EventSource::DefenseEngine,
                severity,
                EventKind::DefenseAction {
                    threat_id: "t".to_owned(),
                    action: "test".to_owned(),
                },
            )
            .await;
        }
        assert_eq!(log.len().await, 4);
    }

    #[tokio::test]
    async fn all_event_sources_recordable() {
        let log = AuditLog::new();
        for source in [
            EventSource::MethodGate,
            EventSource::ThreatDetection,
            EventSource::DefenseEngine,
            EventSource::Transport,
            EventSource::Lifecycle,
        ] {
            log.record(
                source,
                EventSeverity::Info,
                EventKind::LifecycleTransition {
                    from_state: "x".to_owned(),
                    to_state: "y".to_owned(),
                },
            )
            .await;
        }
        assert_eq!(log.len().await, 5);
    }

    #[tokio::test]
    async fn correlation_id_none_by_default() {
        let log = AuditLog::new();
        log.record(
            EventSource::Lifecycle,
            EventSeverity::Info,
            EventKind::LifecycleTransition {
                from_state: "a".to_owned(),
                to_state: "b".to_owned(),
            },
        )
        .await;

        let events = log.query(0, 1).await;
        assert!(events[0].correlation_id.is_none());
    }

    #[tokio::test]
    async fn default_and_new_equivalent() {
        let log1 = AuditLog::new();
        let log2 = AuditLog::default();
        assert_eq!(log1.latest_seq().await, log2.latest_seq().await);
        assert_eq!(log1.len().await, log2.len().await);
    }

    #[tokio::test]
    async fn limit_caps_results() {
        let log = AuditLog::new();
        for _ in 0..20 {
            log.record(
                EventSource::Transport,
                EventSeverity::Info,
                EventKind::BtspNegotiate {
                    session_id: "s".to_owned(),
                    cipher: "null".to_owned(),
                    success: true,
                },
            )
            .await;
        }

        let events = log.query(0, 5).await;
        assert_eq!(events.len(), 5);
    }
}

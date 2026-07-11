// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Security observability for skunkBat.
//!
//! Provides security-focused metrics, traces, and logs.
//! The [`audit_log`] submodule implements the JH-5 audit trail — a bounded
//! ring buffer of structured security events queryable via RPC.

pub mod audit_log;

use crate::SkunkBatConfig;
use crate::error::SkunkBatError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// Security observer.
pub struct SecurityObserver {
    enabled: bool,
    metrics: Arc<SecurityMetricsInternal>,
}

impl SecurityObserver {
    /// Create a new security observer.
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        Self {
            enabled: config.features.observability,
            metrics: Arc::new(SecurityMetricsInternal::default()),
        }
    }

    /// Start security observer.
    ///
    /// # Errors
    ///
    /// Returns an error if the security observer fails to start.
    pub fn start(&self) -> Result<(), SkunkBatError> {
        if !self.enabled {
            tracing::info!("Security observer disabled by config");
            return Ok(());
        }
        tracing::debug!("Security observer starting");
        Ok(())
    }

    /// Stop security observer.
    ///
    /// # Errors
    ///
    /// Returns an error if the security observer fails to stop.
    pub fn stop(&self) -> Result<(), SkunkBatError> {
        tracing::debug!("Security observer stopping");
        Ok(())
    }

    /// Check if security observer is healthy.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.enabled
    }

    /// Get security metrics.
    #[must_use]
    pub fn get_metrics(&self) -> SecurityMetrics {
        SecurityMetrics {
            threats: ThreatMetrics {
                detected: self.metrics.threats_detected.load(Ordering::Relaxed),
                mitigated: self.metrics.threats_mitigated.load(Ordering::Relaxed),
            },
            scanning: ScanMetrics {
                performed: self.metrics.scans_performed.load(Ordering::Relaxed),
            },
            defense: DefenseMetrics {
                connections_quarantined: self
                    .metrics
                    .connections_quarantined
                    .load(Ordering::Relaxed),
                alerts_sent: self.metrics.alerts_sent.load(Ordering::Relaxed),
            },
            http: HttpMetrics {
                requests_screened: self.metrics.http_requests_screened.load(Ordering::Relaxed),
                allows: self.metrics.http_allows.load(Ordering::Relaxed),
                warns: self.metrics.http_warns.load(Ordering::Relaxed),
                blocks: self.metrics.http_blocks.load(Ordering::Relaxed),
            },
            last_updated: Some(SystemTime::now()),
        }
    }

    /// Record a threat detection.
    pub fn record_threat_detected(&self) {
        self.metrics
            .threats_detected
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a threat mitigation.
    pub fn record_threat_mitigated(&self) {
        self.metrics
            .threats_mitigated
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a scan performed.
    pub fn record_scan_performed(&self) {
        self.metrics.scans_performed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection quarantined.
    pub fn record_quarantine(&self) {
        self.metrics
            .connections_quarantined
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record an alert sent.
    pub fn record_alert(&self) {
        self.metrics.alerts_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an HTTP advisory verdict.
    pub fn record_http_advisory(&self, verdict: crate::Verdict) {
        match verdict {
            crate::Verdict::Allow => {
                self.metrics.http_allows.fetch_add(1, Ordering::Relaxed);
            }
            crate::Verdict::Warn => {
                self.metrics.http_warns.fetch_add(1, Ordering::Relaxed);
            }
            crate::Verdict::Block => {
                self.metrics.http_blocks.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.metrics
            .http_requests_screened
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Internal metrics storage (thread-safe).
#[derive(Default)]
struct SecurityMetricsInternal {
    /// Number of threats detected
    threats_detected: AtomicU64,
    /// Number of threats mitigated
    threats_mitigated: AtomicU64,
    /// Network scan count
    scans_performed: AtomicU64,
    /// Connections quarantined
    connections_quarantined: AtomicU64,
    /// Alerts sent to operator
    alerts_sent: AtomicU64,
    /// HTTP requests screened via advisory
    http_requests_screened: AtomicU64,
    /// HTTP advisories that returned Allow
    http_allows: AtomicU64,
    /// HTTP advisories that returned Warn
    http_warns: AtomicU64,
    /// HTTP advisories that returned Block
    http_blocks: AtomicU64,
}

/// Security metrics (public snapshot).
///
/// Organized by domain for structured observability. The flat counters
/// are still accessible for backwards-compatibility via `total_*` methods.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Threat detection metrics.
    pub threats: ThreatMetrics,
    /// Scanning / reconnaissance metrics.
    pub scanning: ScanMetrics,
    /// Defense response metrics.
    pub defense: DefenseMetrics,
    /// HTTP outer membrane advisory metrics.
    #[serde(default, skip_serializing_if = "HttpMetrics::is_empty")]
    pub http: HttpMetrics,
    /// Last update timestamp.
    pub last_updated: Option<SystemTime>,
}

/// Threat detection counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatMetrics {
    /// Total threats detected.
    pub detected: u64,
    /// Threats successfully mitigated.
    pub mitigated: u64,
}

/// Network scanning counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanMetrics {
    /// Total scans performed.
    pub performed: u64,
}

/// Active defense counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DefenseMetrics {
    /// Connections currently/historically quarantined.
    pub connections_quarantined: u64,
    /// Alerts sent to operator.
    pub alerts_sent: u64,
}

/// HTTP outer membrane advisory counters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpMetrics {
    /// Total HTTP requests screened via `security.advisory`.
    pub requests_screened: u64,
    /// Requests that passed advisory (Allow).
    pub allows: u64,
    /// Requests flagged as suspicious (Warn).
    pub warns: u64,
    /// Requests blocked (quarantined source).
    pub blocks: u64,
}

impl HttpMetrics {
    const fn is_empty(&self) -> bool {
        self.requests_screened == 0
    }
}

impl SecurityMetrics {
    /// Total threats detected (flat accessor).
    #[must_use]
    pub const fn threats_detected(&self) -> u64 {
        self.threats.detected
    }

    /// Total threats mitigated (flat accessor).
    #[must_use]
    pub const fn threats_mitigated(&self) -> u64 {
        self.threats.mitigated
    }

    /// Total scans performed (flat accessor).
    #[must_use]
    pub const fn scans_performed(&self) -> u64 {
        self.scanning.performed
    }

    /// Connections quarantined (flat accessor).
    #[must_use]
    pub const fn connections_quarantined(&self) -> u64 {
        self.defense.connections_quarantined
    }

    /// Alerts sent (flat accessor).
    #[must_use]
    pub const fn alerts_sent(&self) -> u64 {
        self.defense.alerts_sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_config;

    #[test]
    fn test_security_observer_creation() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);
        assert!(observer.is_healthy());
    }

    #[test]
    fn test_security_observer_start_stop() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        assert!(observer.start().is_ok());
        assert!(observer.stop().is_ok());
    }

    #[test]
    fn test_get_metrics() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        let metrics = observer.get_metrics();
        assert_eq!(metrics.threats.detected, 0);
        assert_eq!(metrics.threats.mitigated, 0);
        assert_eq!(metrics.scanning.performed, 0);
    }

    #[test]
    fn test_record_threat_detected() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_threat_detected();
        observer.record_threat_detected();

        let metrics = observer.get_metrics();
        assert_eq!(metrics.threats.detected, 2);
    }

    #[test]
    fn test_record_threat_mitigated() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_threat_mitigated();

        let metrics = observer.get_metrics();
        assert_eq!(metrics.threats.mitigated, 1);
    }

    #[test]
    fn test_record_scan_performed() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_scan_performed();
        observer.record_scan_performed();
        observer.record_scan_performed();

        let metrics = observer.get_metrics();
        assert_eq!(metrics.scanning.performed, 3);
    }

    #[test]
    fn test_record_quarantine() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_quarantine();

        let metrics = observer.get_metrics();
        assert_eq!(metrics.defense.connections_quarantined, 1);
    }

    #[test]
    fn test_record_alert() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_alert();
        observer.record_alert();

        let metrics = observer.get_metrics();
        assert_eq!(metrics.defense.alerts_sent, 2);
    }

    #[test]
    fn test_multiple_operations() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_threat_detected();
        observer.record_threat_detected();
        observer.record_threat_mitigated();
        observer.record_scan_performed();
        observer.record_quarantine();
        observer.record_alert();

        let metrics = observer.get_metrics();
        assert_eq!(metrics.threats.detected, 2);
        assert_eq!(metrics.threats.mitigated, 1);
        assert_eq!(metrics.scanning.performed, 1);
        assert_eq!(metrics.defense.connections_quarantined, 1);
        assert_eq!(metrics.defense.alerts_sent, 1);
    }

    #[test]
    fn test_disabled_observer() {
        let mut config = test_config();
        config.features.observability = false;

        let observer = SecurityObserver::new(&config);
        assert!(!observer.is_healthy());

        let metrics = observer.get_metrics();
        assert_eq!(metrics.threats.detected, 0);
    }

    #[test]
    fn test_metrics_timestamp() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        let metrics = observer.get_metrics();
        assert!(metrics.last_updated.is_some());
    }

    #[test]
    fn test_http_advisory_metrics() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_http_advisory(crate::Verdict::Allow);
        observer.record_http_advisory(crate::Verdict::Allow);
        observer.record_http_advisory(crate::Verdict::Warn);
        observer.record_http_advisory(crate::Verdict::Block);

        let metrics = observer.get_metrics();
        assert_eq!(metrics.http.requests_screened, 4);
        assert_eq!(metrics.http.allows, 2);
        assert_eq!(metrics.http.warns, 1);
        assert_eq!(metrics.http.blocks, 1);
    }

    #[test]
    fn test_http_metrics_empty_when_unused() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        let metrics = observer.get_metrics();
        assert!(metrics.http.is_empty());
        assert_eq!(metrics.http.requests_screened, 0);
    }
}

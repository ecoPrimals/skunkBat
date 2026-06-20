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
            threats_detected: self.metrics.threats_detected.load(Ordering::Relaxed),
            threats_mitigated: self.metrics.threats_mitigated.load(Ordering::Relaxed),
            scans_performed: self.metrics.scans_performed.load(Ordering::Relaxed),
            connections_quarantined: self.metrics.connections_quarantined.load(Ordering::Relaxed),
            alerts_sent: self.metrics.alerts_sent.load(Ordering::Relaxed),
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
}

/// Security metrics (public snapshot).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Number of threats detected
    pub threats_detected: u64,
    /// Number of threats mitigated
    pub threats_mitigated: u64,
    /// Network scan count
    pub scans_performed: u64,
    /// Connections quarantined
    pub connections_quarantined: u64,
    /// Alerts sent to operator
    pub alerts_sent: u64,
    /// Last update timestamp
    pub last_updated: Option<SystemTime>,
}

#[cfg(test)]
mod tests {
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
            lineage_id: None,
            thresholds: crate::config::ThreatThresholds::default(),
            expected_topology_path: None,
        }
    }

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
        assert_eq!(metrics.threats_detected, 0);
        assert_eq!(metrics.threats_mitigated, 0);
        assert_eq!(metrics.scans_performed, 0);
    }

    #[test]
    fn test_record_threat_detected() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_threat_detected();
        observer.record_threat_detected();

        let metrics = observer.get_metrics();
        assert_eq!(metrics.threats_detected, 2);
    }

    #[test]
    fn test_record_threat_mitigated() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_threat_mitigated();

        let metrics = observer.get_metrics();
        assert_eq!(metrics.threats_mitigated, 1);
    }

    #[test]
    fn test_record_scan_performed() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_scan_performed();
        observer.record_scan_performed();
        observer.record_scan_performed();

        let metrics = observer.get_metrics();
        assert_eq!(metrics.scans_performed, 3);
    }

    #[test]
    fn test_record_quarantine() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_quarantine();

        let metrics = observer.get_metrics();
        assert_eq!(metrics.connections_quarantined, 1);
    }

    #[test]
    fn test_record_alert() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        observer.record_alert();
        observer.record_alert();

        let metrics = observer.get_metrics();
        assert_eq!(metrics.alerts_sent, 2);
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
        assert_eq!(metrics.threats_detected, 2);
        assert_eq!(metrics.threats_mitigated, 1);
        assert_eq!(metrics.scans_performed, 1);
        assert_eq!(metrics.connections_quarantined, 1);
        assert_eq!(metrics.alerts_sent, 1);
    }

    #[test]
    fn test_disabled_observer() {
        let mut config = test_config();
        config.features.observability = false;

        let observer = SecurityObserver::new(&config);
        assert!(!observer.is_healthy());

        // Should still work, just not enabled
        let metrics = observer.get_metrics();
        assert_eq!(metrics.threats_detected, 0);
    }

    #[test]
    fn test_metrics_timestamp() {
        let config = test_config();
        let observer = SecurityObserver::new(&config);

        let metrics = observer.get_metrics();
        assert!(metrics.last_updated.is_some());
    }
}

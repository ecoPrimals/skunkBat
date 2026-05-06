// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! # skunkBat
//!
//! Reconnaissance & Automated Defense
//!
//! ## Overview
//!
//! skunkBat is a security-focused observability primal that provides:
//! - Reconnaissance (network scanning, topology mapping)
//! - Threat Detection (genetic analysis, anomaly detection)
//! - Automated Defense (threat response, quarantine)
//! - Security Observability (metrics, traces, logs)
//!
//! ## Philosophy
//!
//! > "Anti-surveillance by nature, but users should have full visibility for what they own."
//!
//! The difference:
//! - **Surveillance**: They watch YOU
//! - **Observability**: YOU watch your systems
//! - **Reconnaissance**: YOU watch for threats
//!
//! skunkBat monitors FOR defense, NOT for profit or tracking.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use skunk_bat_core::{SkunkBat, SkunkBatConfig};
//!
//! let config = SkunkBatConfig::default();
//! let mut skunkbat = SkunkBat::new(config);
//! skunkbat.start().await?;
//!
//! // Monitor for threats
//! let threats = skunkbat.detect_threats().await?;
//! for threat in threats {
//!     skunkbat.respond_to_threat(threat).await?;
//! }
//! ```

pub mod config;
pub mod defense;
pub mod error;
pub mod observability;
pub mod platform;
pub mod primal_foundation;
pub mod reconnaissance;
pub mod threats;
pub mod universal_adapter;

pub use primal_foundation::{
    CommonConfig, DependencyHealth, HealthReport, HealthStatus, PrimalError, PrimalHealth,
    PrimalLifecycle, PrimalResult, PrimalState, Timestamp,
};

/// skunkBat configuration.
pub use config::SkunkBatConfig;

/// skunkBat errors.
pub use error::SkunkBatError;

/// Primal self-knowledge — the single source of truth for identity and capabilities.
///
/// These are used by local discovery, capability-based integration clients,
/// dispatch, and IPC identity responses. No other primal names appear here.
pub const PRIMAL_NAME: &str = "skunkBat";

/// Binary/IPC name (lowercase, no punctuation — matches the `UniBin` binary name).
pub const PRIMAL_ID: &str = "skunkbat";

/// Capabilities this primal advertises for runtime discovery.
pub const CAPABILITIES: &[&str] = &[
    "reconnaissance",
    "threat-detection",
    "defense",
    "observability",
];

/// Reconnaissance capabilities.
pub use reconnaissance::ReconnaissanceEngine;

/// Threat detection capabilities.
pub use threats::ThreatDetector;

/// Automated defense capabilities.
pub use defense::DefenseEngine;

/// Security observability.
pub use observability::SecurityObserver;

/// The skunkBat primal.
///
/// Provides reconnaissance, threat detection, and automated defense
/// for the ecoPrimals ecosystem.
pub struct SkunkBat {
    config: SkunkBatConfig,
    state: PrimalState,
    reconnaissance: ReconnaissanceEngine,
    threat_detector: ThreatDetector,
    defense: DefenseEngine,
    observer: SecurityObserver,
}

impl SkunkBat {
    /// Create a new skunkBat instance.
    #[must_use]
    pub fn new(config: SkunkBatConfig) -> Self {
        Self {
            reconnaissance: ReconnaissanceEngine::new(&config),
            threat_detector: ThreatDetector::new(&config),
            defense: DefenseEngine::new(&config),
            observer: SecurityObserver::new(&config),
            config,
            state: PrimalState::Created,
        }
    }

    /// Detect threats in the system.
    ///
    /// Returns a list of detected threats.
    ///
    /// # Errors
    ///
    /// Returns an error if threat detection fails.
    #[must_use = "threats should be handled by respond_to_threat"]
    pub async fn detect_threats(&self) -> Result<Vec<threats::Threat>, SkunkBatError> {
        let threats = self.threat_detector.detect().await?;
        for _ in &threats {
            self.observer.record_threat_detected();
        }
        Ok(threats)
    }

    /// Respond to a detected threat.
    ///
    /// Automatically executes appropriate defense mechanisms.
    ///
    /// # Errors
    ///
    /// Returns an error if the threat response fails.
    pub fn respond_to_threat(&self, threat: &threats::Threat) -> Result<(), SkunkBatError> {
        let action = self.defense.respond(threat)?;
        self.observer.record_threat_mitigated();
        match action {
            defense::ActionType::Quarantine | defense::ActionType::QuarantineAndAlert => {
                self.observer.record_quarantine();
            }
            _ => {}
        }
        if matches!(
            action,
            defense::ActionType::QuarantineAndAlert | defense::ActionType::MonitorAndAlert
        ) {
            self.observer.record_alert();
        }
        Ok(())
    }

    /// Scan network topology.
    ///
    /// Returns reconnaissance data about the network.
    ///
    /// # Errors
    ///
    /// Returns an error if the network scan fails.
    #[must_use = "scan results should be analyzed for threats"]
    pub async fn scan_network(&self) -> Result<reconnaissance::NetworkScan, SkunkBatError> {
        let scan = self.reconnaissance.scan().await?;
        self.observer.record_scan_performed();
        Ok(scan)
    }

    /// Get security metrics.
    ///
    /// Returns observability data for security analysis.
    #[must_use]
    pub fn get_security_metrics(&self) -> observability::SecurityMetrics {
        self.observer.get_metrics()
    }

    /// Access the configuration.
    #[must_use]
    pub const fn config(&self) -> &SkunkBatConfig {
        &self.config
    }

    /// Access the current primal state.
    #[must_use]
    pub fn state(&self) -> PrimalState {
        <Self as PrimalLifecycle>::state(self)
    }
}

impl PrimalLifecycle for SkunkBat {
    fn state(&self) -> PrimalState {
        self.state
    }

    async fn start(&mut self) -> Result<(), PrimalError> {
        self.state = PrimalState::Starting;
        tracing::info!("skunkBat starting...");

        // Initialize reconnaissance engine
        self.reconnaissance
            .start()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;

        // Initialize threat detector
        self.threat_detector
            .start()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;

        // Initialize defense engine
        self.defense
            .start()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;

        // Initialize security observer
        self.observer
            .start()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;

        self.state = PrimalState::Running;
        tracing::info!("skunkBat running (reconnaissance active)");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), PrimalError> {
        self.state = PrimalState::Stopping;
        tracing::info!("skunkBat stopping...");

        // Stop all engines
        self.observer
            .stop()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;
        self.defense
            .stop()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;
        self.threat_detector
            .stop()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;
        self.reconnaissance
            .stop()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;

        self.state = PrimalState::Stopped;
        tracing::info!("skunkBat stopped");
        Ok(())
    }
}

impl PrimalHealth for SkunkBat {
    fn health_status(&self) -> HealthStatus {
        if self.state.is_running() {
            // Check sub-systems
            let recon_healthy = self.reconnaissance.is_healthy();
            let detector_healthy = self.threat_detector.is_healthy();
            let defense_healthy = self.defense.is_healthy();
            let observer_healthy = self.observer.is_healthy();

            if recon_healthy && detector_healthy && defense_healthy && observer_healthy {
                HealthStatus::Healthy
            } else {
                HealthStatus::Degraded {
                    reason: format!(
                        "recon:{recon_healthy} detector:{detector_healthy} defense:{defense_healthy} observer:{observer_healthy}"
                    ),
                }
            }
        } else {
            HealthStatus::Unhealthy {
                reason: format!("state: {}", self.state),
            }
        }
    }

    async fn health_check(&self) -> Result<HealthReport, PrimalError> {
        let mut report = HealthReport::new(&self.config.common.name, env!("CARGO_PKG_VERSION"))
            .with_status(self.health_status());

        for dep in self.dependency_health().await? {
            report = report.with_dependency(dep);
        }

        Ok(report)
    }

    async fn dependency_health(&self) -> Result<Vec<DependencyHealth>, PrimalError> {
        let mut deps = Vec::with_capacity(2);

        let lineage_status = if self.config.lineage_id.is_some() {
            DependencyHealth::healthy("lineage-verifier", "capability")
        } else {
            DependencyHealth::unhealthy(
                "lineage-verifier",
                "capability",
                "no lineage_id configured",
            )
        };
        deps.push(lineage_status);

        let observer_status = if self.observer.is_healthy() {
            DependencyHealth::healthy("security-observer", "internal")
        } else {
            DependencyHealth::unhealthy("security-observer", "internal", "disabled by config")
        };
        deps.push(observer_status);

        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
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

        // Start
        skunkbat.start().await.unwrap();
        assert_eq!(skunkbat.state(), PrimalState::Running);

        // Stop
        skunkbat.stop().await.unwrap();
        assert_eq!(skunkbat.state(), PrimalState::Stopped);
    }

    #[tokio::test]
    async fn test_detect_threats() {
        let config = SkunkBatConfig::default();
        let skunkbat = SkunkBat::new(config);

        let result = skunkbat.detect_threats().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_scan_network() {
        let config = SkunkBatConfig::default();
        let skunkbat = SkunkBat::new(config);

        // Use tokio runtime for async test
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

        let result = skunkbat.respond_to_threat(&threat);
        assert!(result.is_ok());
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

        // Stopping without starting should still work
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

        // Start the primal
        assert!(skunkbat.start().await.is_ok());
        assert_eq!(skunkbat.state(), PrimalState::Running);

        // Perform reconnaissance
        let scan_result = skunkbat.scan_network().await;
        assert!(scan_result.is_ok());

        // Check for threats
        let threats_result = skunkbat.detect_threats().await;
        assert!(threats_result.is_ok());

        // Get metrics
        let metrics = skunkbat.get_security_metrics();
        assert!(metrics.last_updated.is_some());

        // Check health
        let health = skunkbat.health_check().await;
        assert!(health.is_ok());

        // Stop the primal
        assert!(skunkbat.stop().await.is_ok());
        assert_eq!(skunkbat.state(), PrimalState::Stopped);
    }

    #[tokio::test]
    async fn test_integration_detect_and_respond() {
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);

        skunkbat.start().await.unwrap();

        // Detect threats (should be empty initially)
        let threats = skunkbat.detect_threats().await.unwrap();
        assert!(threats.is_empty());

        // If we had a threat, respond to it
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
}

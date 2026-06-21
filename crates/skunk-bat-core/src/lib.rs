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
//! for threat in &threats {
//!     skunkbat.respond_to_threat(threat)?;
//! }
//! ```

pub mod config;
pub mod defense;
pub mod env_keys;
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

/// Default TCP port for JSON-RPC (Tier 5 fallback only).
pub const DEFAULT_PORT: u16 = 9750;

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

/// Audit log (JH-5 security event trail).
pub use observability::audit_log::AuditLog;

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
    audit_log: AuditLog,
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
            audit_log: AuditLog::new(),
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

    /// Access the audit log for event recording and querying (JH-5).
    #[must_use]
    pub const fn audit_log(&self) -> &AuditLog {
        &self.audit_log
    }

    /// Respond to a detected threat.
    ///
    /// Automatically executes appropriate defense mechanisms.
    ///
    /// # Errors
    ///
    /// Returns an error if the threat response fails.
    pub fn respond_to_threat(
        &self,
        threat: &threats::Threat,
    ) -> Result<defense::ActionType, SkunkBatError> {
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
        Ok(action)
    }

    /// Feed a live network observation into the threat detector's profiler.
    ///
    /// # Errors
    ///
    /// Returns an error if the profiler update fails.
    pub async fn observe(
        &self,
        observation: &threats::types::Observation,
    ) -> Result<(), SkunkBatError> {
        self.threat_detector.observe(observation).await
    }

    /// Record a connection's layer traversal path for topology validation.
    ///
    /// The path is consumed on the next `detect_threats()` call. If no
    /// `expected_topology_path` is configured, this is a no-op.
    pub fn record_connection_path(&self, path: Vec<u8>) {
        self.threat_detector.record_connection_path(path);
    }

    /// Check if a source address is currently quarantined.
    #[must_use]
    pub fn is_quarantined(&self, source: &str) -> bool {
        self.defense.is_quarantined(source)
    }

    /// Defense engine status snapshot for IPC.
    #[must_use]
    pub fn defense_status(&self) -> serde_json::Value {
        let quarantine = self.defense.quarantine_snapshot();
        let entries: Vec<serde_json::Value> = quarantine
            .iter()
            .map(|(source, record)| {
                serde_json::json!({
                    "source": source,
                    "reason": record.reason,
                    "threat_id": record.threat_id,
                })
            })
            .collect();
        serde_json::json!({
            "enabled": self.config.features.auto_defense,
            "auto_response": self.defense.auto_response_enabled(),
            "quarantined_count": quarantine.len(),
            "quarantined": entries,
        })
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

        self.reconnaissance
            .start()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;

        self.threat_detector
            .start()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;

        self.defense
            .start()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;

        self.observer
            .start()
            .map_err(|e| PrimalError::lifecycle(e.to_string()))?;

        self.state = PrimalState::Running;
        self.audit_log
            .record(
                observability::audit_log::EventSource::Lifecycle,
                observability::audit_log::EventSeverity::Info,
                observability::audit_log::EventKind::LifecycleTransition {
                    from_state: "Starting".to_owned(),
                    to_state: "Running".to_owned(),
                },
            )
            .await;
        tracing::info!("skunkBat running (reconnaissance active)");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), PrimalError> {
        self.state = PrimalState::Stopping;
        tracing::info!("skunkBat stopping...");

        self.audit_log
            .record(
                observability::audit_log::EventSource::Lifecycle,
                observability::audit_log::EventSeverity::Info,
                observability::audit_log::EventKind::LifecycleTransition {
                    from_state: "Running".to_owned(),
                    to_state: "Stopping".to_owned(),
                },
            )
            .await;

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
#[path = "lib_tests.rs"]
mod tests;

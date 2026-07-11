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

#[cfg(test)]
pub(crate) mod test_support;

pub use primal_foundation::{
    CommonConfig, DependencyHealth, HealthReport, HealthStatus, PrimalError, PrimalHealth,
    PrimalLifecycle, PrimalResult, PrimalState, Timestamp,
};

/// skunkBat configuration.
pub use config::SkunkBatConfig;

/// skunkBat errors.
pub use error::SkunkBatError;

/// Advisory verdict for the Tower HTTP Gateway integration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdvisoryVerdict {
    /// Security verdict: allow, warn, or block.
    pub verdict: Verdict,
    /// Human-readable reason for the verdict.
    pub reason: String,
    /// Source address that was checked.
    pub source: String,
    /// Associated threat IDs (if any).
    pub threat_ids: Vec<String>,
    /// Anomalies detected during advisory check (empty if none).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anomalies: Vec<threats::types::Anomaly>,
}

/// Security advisory verdict level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No security concern — route normally.
    Allow,
    /// Suspicious but not blocked — log and proceed with caution.
    Warn,
    /// Quarantined or actively hostile — recommend rejection.
    Block,
}

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
            audit_log: AuditLog::with_capacity(config.thresholds.audit_log_capacity),
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
    #[must_use = "defense action should be logged or inspected"]
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

    /// Manually quarantine a source address.
    pub fn quarantine(&self, source: &str, reason: &str, threat_id: &str) {
        self.defense.quarantine(source, reason, threat_id);
    }

    /// Release a source address from quarantine. Returns `true` if it was quarantined.
    pub fn release_quarantine(&self, source: &str) -> bool {
        self.defense.release(source)
    }

    /// Evaluate a threat and return the recommended action without executing it.
    #[must_use]
    pub fn evaluate_threat(&self, threat: &threats::Threat) -> defense::DefenseAction {
        self.defense.evaluate(threat)
    }

    /// Query the baseline profiler's current statistics.
    #[must_use]
    pub async fn baseline_stats(&self) -> Option<threats::types::BaselineStats> {
        self.threat_detector.baseline_stats().await
    }

    /// Check an observation against the baseline for anomalies (read-only).
    ///
    /// # Errors
    ///
    /// Returns an error if anomaly detection fails.
    pub async fn check_anomalies(
        &self,
        observation: &threats::types::Observation,
    ) -> Result<Vec<threats::types::Anomaly>, SkunkBatError> {
        self.threat_detector.check_anomalies(observation).await
    }

    /// Reset the baseline profiler. If `reseed` is true, re-seeds with defaults.
    pub async fn reset_baseline(&self, reseed: bool) {
        self.threat_detector.reset_baseline(reseed).await;
    }

    /// Check if a source address is currently quarantined.
    #[must_use]
    pub fn is_quarantined(&self, source: &str) -> bool {
        self.defense.is_quarantined(source)
    }

    /// Advisory security check for inbound connection metadata.
    ///
    /// Used by the Tower HTTP Gateway to get a security verdict before
    /// routing a request. Returns a structured advisory with verdict and
    /// reasoning. Does NOT enforce — the gateway decides what to do.
    #[must_use]
    pub fn advisory_check(&self, source: &str) -> AdvisoryVerdict {
        self.advisory_check_http(source, None)
    }

    /// Advisory check with optional HTTP telemetry (outer membrane).
    ///
    /// When `http` is `Some`, runs behavioral anomaly detection on the HTTP
    /// dimensions. Returns `Verdict::Warn` if anomalies are detected but the
    /// source is not quarantined.
    #[must_use]
    pub fn advisory_check_http(
        &self,
        source: &str,
        http: Option<&threats::types::HttpObservation>,
    ) -> AdvisoryVerdict {
        if self.defense.is_quarantined(source) {
            return AdvisoryVerdict {
                verdict: Verdict::Block,
                reason: "source is quarantined".to_owned(),
                source: source.to_owned(),
                threat_ids: self
                    .defense
                    .quarantine_snapshot()
                    .get(source)
                    .map(|r| vec![r.threat_id.clone()])
                    .unwrap_or_default(),
                anomalies: Vec::new(),
            };
        }

        if !self.defense.is_healthy() {
            return AdvisoryVerdict {
                verdict: Verdict::Allow,
                reason: "defense engine disabled — no advisory".to_owned(),
                source: source.to_owned(),
                threat_ids: Vec::new(),
                anomalies: Vec::new(),
            };
        }

        if let Some(http_obs) = http {
            let observation = threats::types::Observation {
                connection_rate: 0.0,
                traffic_volume: 0,
                ports_accessed: Vec::new(),
                timestamp: std::time::SystemTime::now(),
                http: Some(http_obs.clone()),
            };

            let profiler = self.threat_detector.baseline_profiler_handle();
            let http_anomalies: Vec<_> = profiler
                .check_anomalies_sync(&observation)
                .unwrap_or_default()
                .into_iter()
                .filter(|a| a.behavior.contains("HTTP"))
                .collect();

            if !http_anomalies.is_empty() {
                self.observer.record_http_advisory(Verdict::Warn);
                return AdvisoryVerdict {
                    verdict: Verdict::Warn,
                    reason: format!(
                        "{} HTTP anomal{} detected for source",
                        http_anomalies.len(),
                        if http_anomalies.len() == 1 {
                            "y"
                        } else {
                            "ies"
                        }
                    ),
                    source: source.to_owned(),
                    threat_ids: Vec::new(),
                    anomalies: http_anomalies,
                };
            }
            self.observer.record_http_advisory(Verdict::Allow);
        }

        AdvisoryVerdict {
            verdict: Verdict::Allow,
            reason: "no threats detected for source".to_owned(),
            source: source.to_owned(),
            threat_ids: Vec::new(),
            anomalies: Vec::new(),
        }
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

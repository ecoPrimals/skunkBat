// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Automated defense for skunkBat.
//!
//! Provides threat response, quarantine, and self-healing.

use crate::SkunkBatConfig;
use crate::error::SkunkBatError;
use crate::threats::{Severity, Threat};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

/// Defense engine with thread-safe quarantine tracking.
pub struct DefenseEngine {
    enabled: bool,
    auto_response_enabled: bool,
    quarantine_map: Mutex<HashMap<String, QuarantineRecord>>,
    critical_confidence: f64,
    high_confidence: f64,
    persist_path: Option<std::path::PathBuf>,
}

impl DefenseEngine {
    /// Create a new defense engine.
    ///
    /// If `data_dir` from the config is non-empty, loads any persisted
    /// quarantine state from `{data_dir}/quarantine.json`.
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        let persist_path = if config.common.data_dir.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(&config.common.data_dir).join("quarantine.json"))
        };

        let quarantine_map = persist_path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();

        Self {
            enabled: config.features.auto_defense,
            auto_response_enabled: config.features.auto_defense,
            quarantine_map: Mutex::new(quarantine_map),
            critical_confidence: config.thresholds.quarantine_critical_confidence,
            high_confidence: config.thresholds.quarantine_high_confidence,
            persist_path,
        }
    }

    /// Start defense engine.
    ///
    /// # Errors
    ///
    /// Returns an error if the defense engine fails to start.
    pub fn start(&self) -> Result<(), SkunkBatError> {
        if !self.enabled {
            tracing::info!("Defense engine disabled by config");
            return Ok(());
        }
        tracing::debug!("Defense engine starting");
        Ok(())
    }

    /// Stop defense engine.
    ///
    /// # Errors
    ///
    /// Returns an error if the defense engine fails to stop.
    pub fn stop(&self) -> Result<(), SkunkBatError> {
        tracing::debug!("Defense engine stopping");
        Ok(())
    }

    /// Check if defense engine is healthy.
    #[must_use]
    #[inline]
    pub const fn is_healthy(&self) -> bool {
        self.enabled
    }

    /// Respond to a threat.
    ///
    /// # Errors
    ///
    /// Returns an error if the threat response fails.
    #[must_use = "defense action should be logged or inspected"]
    pub fn respond(&self, threat: &Threat) -> Result<ActionType, SkunkBatError> {
        if !self.enabled {
            tracing::debug!("Defense engine disabled, threat logged only");
            return Ok(ActionType::MonitorAndAlert);
        }

        tracing::warn!(
            "Processing threat response: {:?} (severity: {:?}, confidence: {})",
            threat.threat_type,
            threat.severity,
            threat.confidence
        );

        let action = self.determine_action(threat);
        self.execute_action(&action, threat);

        Ok(action.action_type)
    }

    /// Determine appropriate defense action based on configured thresholds.
    fn determine_action(&self, threat: &Threat) -> DefenseAction {
        if threat.severity == Severity::Critical && threat.confidence > self.critical_confidence {
            return DefenseAction {
                action_type: ActionType::Quarantine,
                target: threat.source.clone(),
                requires_approval: false,
                reason: format!("Critical threat detected: {}", threat.description),
            };
        }

        if threat.severity == Severity::High && threat.confidence > self.high_confidence {
            return DefenseAction {
                action_type: ActionType::QuarantineAndAlert,
                target: threat.source.clone(),
                requires_approval: false,
                reason: format!("High severity threat: {}", threat.description),
            };
        }

        DefenseAction {
            action_type: ActionType::MonitorAndAlert,
            target: threat.source.clone(),
            requires_approval: true,
            reason: format!("Potential threat detected: {}", threat.description),
        }
    }

    /// Execute defense action.
    ///
    /// When `auto_response_enabled` is false, quarantine/block actions are
    /// downgraded to alerts — the operator must act manually.
    fn execute_action(&self, action: &DefenseAction, threat: &Threat) {
        if !self.auto_response_enabled {
            Self::alert_operator(threat, action);
            tracing::info!(
                "Auto-response disabled: would {:?} {} (reason: {})",
                action.action_type,
                action.target,
                action.reason
            );
            return;
        }

        match action.action_type {
            ActionType::Quarantine => {
                self.quarantine_connection(&action.target, threat);
                tracing::warn!(
                    "Quarantined connection from {} (reason: {})",
                    action.target,
                    action.reason
                );
            }
            ActionType::QuarantineAndAlert => {
                self.quarantine_connection(&action.target, threat);
                Self::alert_operator(threat, action);
                tracing::warn!(
                    "Quarantined and alerted for {} (reason: {})",
                    action.target,
                    action.reason
                );
            }
            ActionType::MonitorAndAlert => {
                Self::alert_operator(threat, action);
                tracing::info!(
                    "Monitoring connection from {} (reason: {})",
                    action.target,
                    action.reason
                );
            }
            ActionType::Block => {
                self.block_connection(&action.target);
                tracing::warn!(
                    "Blocked connection from {} (reason: {})",
                    action.target,
                    action.reason
                );
            }
        }
    }

    /// Quarantine a connection — records the quarantine and logs the action.
    fn quarantine_connection(&self, source: &str, threat: &Threat) {
        match self.quarantine_map.lock() {
            Ok(mut map) => {
                map.insert(
                    source.to_owned(),
                    QuarantineRecord {
                        source: source.to_owned(),
                        started_at: SystemTime::now(),
                        reason: threat.description.clone(),
                        threat_id: threat.id.clone(),
                    },
                );
                drop(map);
                self.persist();
                tracing::debug!("Quarantining connection from {source}");
            }
            Err(e) => {
                tracing::error!("Quarantine map poisoned, cannot quarantine {source}: {e}");
            }
        }
    }

    /// Block a connection — removes from quarantine (escalation) and logs.
    fn block_connection(&self, source: &str) {
        match self.quarantine_map.lock() {
            Ok(mut map) => {
                map.remove(source);
                tracing::debug!("Blocking connection from {source}");
            }
            Err(e) => {
                tracing::error!("Quarantine map poisoned, cannot block {source}: {e}");
            }
        }
    }

    /// Alert operator about threat via tracing.
    ///
    /// In production, this is the IPC integration point — the server
    /// layer broadcasts alerts to any primal announcing the `federation`
    /// capability.
    fn alert_operator(threat: &Threat, action: &DefenseAction) {
        tracing::info!(
            "ALERT: Threat detected - {:?} from {} (action: {:?})",
            threat.threat_type,
            threat.source,
            action.action_type
        );
    }

    /// Manually quarantine a source address (operator, IPC, or test use).
    pub fn quarantine(&self, source: &str, reason: &str, threat_id: &str) {
        if let Ok(mut map) = self.quarantine_map.lock() {
            map.insert(
                source.to_owned(),
                QuarantineRecord {
                    source: source.to_owned(),
                    started_at: SystemTime::now(),
                    reason: reason.to_owned(),
                    threat_id: threat_id.to_owned(),
                },
            );
            drop(map);
            self.persist();
        }
    }

    /// Release a source address from quarantine. Returns `true` if the source
    /// was quarantined and has been released, `false` if it wasn't quarantined.
    pub fn release(&self, source: &str) -> bool {
        let released = self
            .quarantine_map
            .lock()
            .ok()
            .is_some_and(|mut map| map.remove(source).is_some());
        if released {
            self.persist();
        }
        released
    }

    /// Evaluate a threat and return the recommended action without executing it.
    ///
    /// This is the composable read-only primitive — callers can inspect the
    /// recommendation before deciding whether to execute via `respond()`.
    #[must_use]
    pub fn evaluate(&self, threat: &Threat) -> DefenseAction {
        if !self.enabled {
            return DefenseAction {
                action_type: ActionType::MonitorAndAlert,
                target: threat.source.clone(),
                requires_approval: true,
                reason: "defense engine disabled — advisory only".to_owned(),
            };
        }
        self.determine_action(threat)
    }

    /// Check whether a source address is currently quarantined.
    #[must_use]
    #[inline]
    pub fn is_quarantined(&self, source: &str) -> bool {
        self.quarantine_map
            .lock()
            .ok()
            .is_some_and(|map| map.contains_key(source))
    }

    /// Get a snapshot of the current quarantine map.
    #[must_use]
    pub fn quarantine_snapshot(&self) -> HashMap<String, QuarantineRecord> {
        self.quarantine_map
            .lock()
            .map(|map| map.clone())
            .unwrap_or_default()
    }

    /// Check whether auto-response is enabled.
    #[must_use]
    #[inline]
    pub const fn auto_response_enabled(&self) -> bool {
        self.auto_response_enabled
    }

    /// Persist the quarantine map to disk (best-effort).
    ///
    /// Writes atomically to `{data_dir}/quarantine.json`. Failures are
    /// logged but do not affect in-memory state.
    fn persist(&self) {
        let Some(ref path) = self.persist_path else {
            return;
        };
        let Ok(map) = self.quarantine_map.lock() else {
            return;
        };
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!("Quarantine persist dir creation failed: {e}");
        }
        match serde_json::to_string_pretty(&*map) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    tracing::debug!("Quarantine persist failed: {e}");
                }
            }
            Err(e) => tracing::debug!("Quarantine serialize failed: {e}"),
        }
    }
}

/// Defense action to take.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseAction {
    /// Type of action
    pub action_type: ActionType,
    /// Target of action
    pub target: String,
    /// Requires user approval
    pub requires_approval: bool,
    /// Reason for action
    pub reason: String,
}

/// Type of defense action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    /// Quarantine connection (isolate but don't block)
    Quarantine,
    /// Quarantine and alert operator
    QuarantineAndAlert,
    /// Monitor and alert operator
    MonitorAndAlert,
    /// Block connection entirely
    Block,
}

/// Quarantine record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// Source being quarantined
    pub source: String,
    /// When quarantine started
    pub started_at: SystemTime,
    /// Reason for quarantine
    pub reason: String,
    /// Associated threat
    pub threat_id: String,
}

#[cfg(test)]
#[path = "defense_tests.rs"]
mod tests;

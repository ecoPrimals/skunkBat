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
}

impl DefenseEngine {
    /// Create a new defense engine.
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        Self {
            enabled: config.features.auto_defense,
            auto_response_enabled: config.features.auto_defense,
            quarantine_map: Mutex::new(HashMap::new()),
            critical_confidence: config.thresholds.quarantine_critical_confidence,
            high_confidence: config.thresholds.quarantine_high_confidence,
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
        }
    }

    /// Release a source address from quarantine. Returns `true` if the source
    /// was quarantined and has been released, `false` if it wasn't quarantined.
    pub fn release(&self, source: &str) -> bool {
        self.quarantine_map
            .lock()
            .map(|mut map| map.remove(source).is_some())
            .unwrap_or(false)
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
    pub fn is_quarantined(&self, source: &str) -> bool {
        self.quarantine_map
            .lock()
            .map(|map| map.contains_key(source))
            .unwrap_or(false)
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
    pub const fn auto_response_enabled(&self) -> bool {
        self.auto_response_enabled
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
mod tests {
    use super::*;
    use crate::config::{FeatureFlags, SkunkBatConfig};
    use crate::primal_foundation::config::CommonConfig;
    use crate::threats::{Severity, Threat, ThreatType};

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

    fn test_threat(severity: Severity, confidence: f64) -> Threat {
        Threat {
            id: "test-threat-1".to_string(),
            threat_type: ThreatType::IntrusionAttempt {
                attack_type: "test-attack".to_string(),
                signature: "test-sig".to_string(),
            },
            severity,
            source: "192.168.1.100".to_string(),
            target: "192.168.1.1".to_string(),
            detected_at: SystemTime::now(),
            description: "Test threat".to_string(),
            confidence,
        }
    }

    #[test]
    fn test_defense_engine_creation() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        assert!(engine.is_healthy());
    }

    #[test]
    fn test_defense_engine_start_stop() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);

        assert!(engine.start().is_ok());
        assert!(engine.stop().is_ok());
    }

    #[test]
    fn test_respond_to_threat() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);

        let threat = test_threat(Severity::Medium, 0.7);
        let result = engine.respond(&threat);
        assert!(result.is_ok());
    }

    #[test]
    fn test_critical_threat_response() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::Critical, 0.95);
        let action = engine.determine_action(&threat);

        assert_eq!(action.action_type, ActionType::Quarantine);
        assert!(!action.requires_approval);
    }

    #[test]
    fn test_high_severity_response() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::High, 0.8);
        let action = engine.determine_action(&threat);

        assert_eq!(action.action_type, ActionType::QuarantineAndAlert);
        assert!(!action.requires_approval);
    }

    #[test]
    fn test_medium_severity_response() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::Medium, 0.6);
        let action = engine.determine_action(&threat);

        assert_eq!(action.action_type, ActionType::MonitorAndAlert);
        assert!(action.requires_approval);
    }

    #[test]
    fn test_low_confidence_threat() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::Critical, 0.5);
        let action = engine.determine_action(&threat);

        assert_eq!(action.action_type, ActionType::MonitorAndAlert);
    }

    #[test]
    fn test_disabled_defense() {
        let mut config = test_config();
        config.features.auto_defense = false;

        let engine = DefenseEngine::new(&config);
        assert!(!engine.is_healthy());

        let threat = test_threat(Severity::Critical, 0.95);
        let result = engine.respond(&threat);
        assert!(result.is_ok()); // Should not error, just log
    }

    #[test]
    fn test_action_type_equality() {
        assert_eq!(ActionType::Quarantine, ActionType::Quarantine);
        assert_ne!(ActionType::Quarantine, ActionType::Block);
    }

    #[test]
    fn test_quarantine_record_creation() {
        let record = QuarantineRecord {
            source: "192.168.1.100".to_string(),
            started_at: SystemTime::now(),
            reason: "Suspicious activity".to_string(),
            threat_id: "threat-123".to_string(),
        };

        assert_eq!(record.source, "192.168.1.100");
        assert_eq!(record.threat_id, "threat-123");
    }

    #[test]
    fn test_defense_action_variants() {
        let action1 = DefenseAction {
            action_type: ActionType::Quarantine,
            target: "test".to_string(),
            requires_approval: false,
            reason: "test".to_string(),
        };
        assert_eq!(action1.action_type, ActionType::Quarantine);

        let action2 = DefenseAction {
            action_type: ActionType::Block,
            target: "test".to_string(),
            requires_approval: false,
            reason: "test".to_string(),
        };
        assert_eq!(action2.action_type, ActionType::Block);
    }

    #[test]
    fn test_block_action_response() {
        let threat = Threat {
            id: "test-block".to_string(),
            threat_type: crate::threats::ThreatType::IntrusionAttempt {
                attack_type: "port-scan".to_string(),
                signature: "rapid".to_string(),
            },
            severity: Severity::Critical,
            source: "192.168.1.200".to_string(),
            target: "192.168.1.1".to_string(),
            detected_at: SystemTime::now(),
            description: "Port scanning".to_string(),
            confidence: 0.95,
        };

        let config = test_config();
        let engine = DefenseEngine::new(&config);

        // Test block action can be executed
        let action = DefenseAction {
            action_type: ActionType::Block,
            target: threat.source.clone(),
            requires_approval: false,
            reason: "High confidence attack".to_string(),
        };

        engine.execute_action(&action, &threat);
    }

    #[test]
    fn test_disabled_defense_start() {
        let mut config = test_config();
        config.features.auto_defense = false;

        let engine = DefenseEngine::new(&config);
        assert!(engine.start().is_ok());
        assert!(engine.stop().is_ok());
    }

    #[test]
    fn test_quarantine_lifecycle() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);

        let threat = test_threat(Severity::High, 0.8);
        engine.respond(&threat).expect("respond should succeed");

        let snapshot = engine.quarantine_snapshot();
        assert!(!snapshot.is_empty(), "Should have quarantined the source");
        assert!(snapshot.contains_key(&threat.source));

        let record = &snapshot[&threat.source];
        assert_eq!(record.threat_id, threat.id);
    }

    #[test]
    fn test_quarantine_and_alert() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);

        let threat = Threat {
            id: "qa-test".to_string(),
            threat_type: crate::threats::ThreatType::UnknownLineage {
                peer_id: "unknown".to_string(),
                lineage: None,
            },
            severity: Severity::High,
            source: "10.0.0.50".to_string(),
            target: "local".to_string(),
            detected_at: SystemTime::now(),
            description: "Unknown lineage detected".to_string(),
            confidence: 0.8,
        };

        engine.respond(&threat).expect("respond should succeed");

        let action = engine.determine_action(&threat);
        assert_eq!(action.action_type, ActionType::QuarantineAndAlert);
    }

    #[test]
    fn test_auto_response_and_quarantine_accessors() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        assert!(engine.auto_response_enabled());

        let snapshot = engine.quarantine_snapshot();
        assert!(snapshot.is_empty());
    }

    #[test]
    fn test_all_action_types_execute() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::Critical, 0.95);

        for action_type in [
            ActionType::Quarantine,
            ActionType::QuarantineAndAlert,
            ActionType::MonitorAndAlert,
            ActionType::Block,
        ] {
            let action = DefenseAction {
                action_type,
                target: "test-target".to_string(),
                requires_approval: false,
                reason: "test".to_string(),
            };
            engine.execute_action(&action, &threat);
        }
    }
}

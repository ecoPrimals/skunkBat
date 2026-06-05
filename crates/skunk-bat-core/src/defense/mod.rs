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

/// Confidence threshold for automatic quarantine of critical threats.
const CRITICAL_CONFIDENCE_THRESHOLD: f64 = 0.9;

/// Confidence threshold for automatic quarantine of high-severity threats.
const HIGH_CONFIDENCE_THRESHOLD: f64 = 0.7;

/// Number of repeat quarantines before escalating to block.
const ESCALATION_THRESHOLD: u32 = 3;

/// Defense engine with thread-safe quarantine tracking.
pub struct DefenseEngine {
    enabled: bool,
    auto_response_enabled: bool,
    quarantine_map: Mutex<HashMap<String, QuarantineRecord>>,
    escalation_counts: Mutex<HashMap<String, u32>>,
}

impl DefenseEngine {
    /// Create a new defense engine.
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        Self {
            enabled: config.features.auto_defense,
            auto_response_enabled: true,
            quarantine_map: Mutex::new(HashMap::new()),
            escalation_counts: Mutex::new(HashMap::new()),
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
    /// Implements graduated escalation: repeated threats from the same source
    /// escalate through Monitor → Quarantine → Block.
    ///
    /// # Errors
    ///
    /// Returns an error if the threat response fails.
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

        let escalation_count = self.increment_escalation(&threat.source);
        let action = self.determine_action(threat, escalation_count);
        self.execute_action(&action, threat);

        Ok(action.action_type)
    }

    fn increment_escalation(&self, source: &str) -> u32 {
        self.escalation_counts.lock().map_or(1, |mut counts| {
            let count = counts.entry(source.to_owned()).or_insert(0);
            *count += 1;
            *count
        })
    }

    /// Get the escalation count for a source.
    #[must_use]
    pub fn escalation_count(&self, source: &str) -> u32 {
        self.escalation_counts
            .lock()
            .ok()
            .and_then(|c| c.get(source).copied())
            .unwrap_or(0)
    }

    /// Determine appropriate defense action with escalation awareness.
    fn determine_action(&self, threat: &Threat, escalation_count: u32) -> DefenseAction {
        if escalation_count >= ESCALATION_THRESHOLD {
            return DefenseAction {
                action_type: ActionType::Block,
                target: threat.source.clone(),
                requires_approval: false,
                reason: format!(
                    "Escalated to block after {} repeated threats: {}",
                    escalation_count, threat.description
                ),
            };
        }

        if threat.severity == Severity::Critical
            && threat.confidence > CRITICAL_CONFIDENCE_THRESHOLD
        {
            return DefenseAction {
                action_type: ActionType::Quarantine,
                target: threat.source.clone(),
                requires_approval: false,
                reason: format!("Critical threat detected: {}", threat.description),
            };
        }

        if threat.severity == Severity::High && threat.confidence > HIGH_CONFIDENCE_THRESHOLD {
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
            requires_approval: self.auto_response_enabled,
            reason: format!("Potential threat detected: {}", threat.description),
        }
    }

    /// Execute defense action.
    fn execute_action(&self, action: &DefenseAction, threat: &Threat) {
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
                self.alert_operator(threat, action);
                tracing::warn!(
                    "Quarantined and alerted for {} (reason: {})",
                    action.target,
                    action.reason
                );
            }
            ActionType::MonitorAndAlert => {
                self.alert_operator(threat, action);
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
        if let Ok(mut map) = self.quarantine_map.lock() {
            map.insert(
                source.to_owned(),
                QuarantineRecord {
                    source: source.to_owned(),
                    started_at: SystemTime::now(),
                    reason: threat.description.clone(),
                    threat_id: threat.id.clone(),
                },
            );
        }
        tracing::debug!("Quarantining connection from {source}");
    }

    /// Block a connection — removes from quarantine (escalation) and logs.
    fn block_connection(&self, source: &str) {
        if let Ok(mut map) = self.quarantine_map.lock() {
            map.remove(source);
        }
        tracing::debug!("Blocking connection from {source}");
    }

    /// Alert operator about threat via tracing.
    ///
    /// In production, this is the IPC integration point — the server
    /// layer broadcasts alerts to any primal announcing the `federation`
    /// capability.
    fn alert_operator(&self, threat: &Threat, action: &DefenseAction) {
        let _ = &self.auto_response_enabled; // future: gate alert on auto-response policy
        tracing::info!(
            "ALERT: Threat detected - {:?} from {} (action: {:?})",
            threat.threat_type,
            threat.source,
            action.action_type
        );
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
        let action = engine.determine_action(&threat, 1);

        assert_eq!(action.action_type, ActionType::Quarantine);
        assert!(!action.requires_approval);
    }

    #[test]
    fn test_high_severity_response() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::High, 0.8);
        let action = engine.determine_action(&threat, 1);

        assert_eq!(action.action_type, ActionType::QuarantineAndAlert);
        assert!(!action.requires_approval);
    }

    #[test]
    fn test_medium_severity_response() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::Medium, 0.6);
        let action = engine.determine_action(&threat, 1);

        assert_eq!(action.action_type, ActionType::MonitorAndAlert);
    }

    #[test]
    fn test_low_confidence_threat() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::Critical, 0.5);
        let action = engine.determine_action(&threat, 1);

        assert_eq!(action.action_type, ActionType::MonitorAndAlert);
    }

    #[test]
    fn test_escalation_to_block() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::High, 0.8);

        for _ in 0..ESCALATION_THRESHOLD {
            engine.respond(&threat).unwrap();
        }

        assert_eq!(
            engine.escalation_count(&threat.source),
            ESCALATION_THRESHOLD
        );
        let action = engine.determine_action(&threat, ESCALATION_THRESHOLD);
        assert_eq!(action.action_type, ActionType::Block);
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

        let action = engine.determine_action(&threat, 1);
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

    #[test]
    fn test_multiple_sources_independent_escalation() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);

        let mut threat_a = test_threat(Severity::High, 0.8);
        threat_a.source = "10.0.0.1".to_string();
        let mut threat_b = test_threat(Severity::High, 0.8);
        threat_b.source = "10.0.0.2".to_string();

        engine.respond(&threat_a).unwrap();
        engine.respond(&threat_a).unwrap();
        engine.respond(&threat_b).unwrap();

        assert_eq!(engine.escalation_count("10.0.0.1"), 2);
        assert_eq!(engine.escalation_count("10.0.0.2"), 1);
    }

    #[test]
    fn test_block_clears_quarantine_entry() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::High, 0.8);

        engine.quarantine_connection(&threat.source, &threat);
        assert!(!engine.quarantine_snapshot().is_empty());

        engine.block_connection(&threat.source);
        assert!(engine.quarantine_snapshot().is_empty());
    }

    #[test]
    fn test_escalation_count_unknown_source() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        assert_eq!(engine.escalation_count("never-seen"), 0);
    }

    #[test]
    fn test_critical_low_confidence_stays_monitor() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::Critical, 0.3);
        let action = engine.determine_action(&threat, 1);
        assert_eq!(action.action_type, ActionType::MonitorAndAlert);
    }

    #[test]
    fn test_high_low_confidence_stays_monitor() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::High, 0.5);
        let action = engine.determine_action(&threat, 1);
        assert_eq!(action.action_type, ActionType::MonitorAndAlert);
    }

    #[test]
    fn test_low_severity_always_monitor() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::Low, 0.99);
        let action = engine.determine_action(&threat, 1);
        assert_eq!(action.action_type, ActionType::MonitorAndAlert);
    }

    #[test]
    fn test_escalation_at_exact_threshold() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::Low, 0.3);
        let action = engine.determine_action(&threat, ESCALATION_THRESHOLD);
        assert_eq!(action.action_type, ActionType::Block);
    }

    #[test]
    fn test_escalation_above_threshold() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::Low, 0.1);
        let action = engine.determine_action(&threat, ESCALATION_THRESHOLD + 5);
        assert_eq!(action.action_type, ActionType::Block);
    }

    #[test]
    fn test_multiple_quarantine_entries() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);

        let mut threat_1 = test_threat(Severity::High, 0.8);
        threat_1.source = "10.0.0.1".to_string();
        let mut threat_2 = test_threat(Severity::High, 0.8);
        threat_2.source = "10.0.0.2".to_string();
        let mut threat_3 = test_threat(Severity::High, 0.8);
        threat_3.source = "10.0.0.3".to_string();

        engine.respond(&threat_1).unwrap();
        engine.respond(&threat_2).unwrap();
        engine.respond(&threat_3).unwrap();

        let snapshot = engine.quarantine_snapshot();
        assert_eq!(snapshot.len(), 3);
    }

    #[test]
    fn test_respond_returns_action_type() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);

        let threat = test_threat(Severity::Critical, 0.95);
        let action_type = engine.respond(&threat).unwrap();
        assert_eq!(action_type, ActionType::Quarantine);
    }

    #[test]
    fn test_medium_confidence_boundary() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::High, HIGH_CONFIDENCE_THRESHOLD + 0.01);
        let action = engine.determine_action(&threat, 1);
        assert_eq!(action.action_type, ActionType::QuarantineAndAlert);
    }

    #[test]
    fn test_critical_confidence_boundary() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);
        let threat = test_threat(Severity::Critical, CRITICAL_CONFIDENCE_THRESHOLD + 0.01);
        let action = engine.determine_action(&threat, 1);
        assert_eq!(action.action_type, ActionType::Quarantine);
    }

    #[test]
    fn test_quarantine_overwrites_same_source() {
        let config = test_config();
        let engine = DefenseEngine::new(&config);

        let mut threat_1 = test_threat(Severity::High, 0.8);
        threat_1.id = "first".to_string();
        let mut threat_2 = test_threat(Severity::High, 0.8);
        threat_2.id = "second".to_string();

        engine.respond(&threat_1).unwrap();
        engine.respond(&threat_2).unwrap();

        let snapshot = engine.quarantine_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[&threat_2.source].threat_id, "second");
    }

    #[test]
    fn test_defense_action_debug_format() {
        let action = DefenseAction {
            action_type: ActionType::Block,
            target: "attacker".to_string(),
            requires_approval: true,
            reason: "malicious".to_string(),
        };
        let debug = format!("{action:?}");
        assert!(debug.contains("Block"));
        assert!(debug.contains("attacker"));
    }

    #[test]
    fn test_action_type_serialize_roundtrip() {
        for action_type in [
            ActionType::Quarantine,
            ActionType::QuarantineAndAlert,
            ActionType::MonitorAndAlert,
            ActionType::Block,
        ] {
            let json = serde_json::to_string(&action_type).unwrap();
            let back: ActionType = serde_json::from_str(&json).unwrap();
            assert_eq!(action_type, back);
        }
    }

    #[test]
    fn test_quarantine_record_serialize() {
        let record = QuarantineRecord {
            source: "10.0.0.1".to_string(),
            started_at: SystemTime::UNIX_EPOCH,
            reason: "port scan".to_string(),
            threat_id: "threat-1".to_string(),
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["source"], "10.0.0.1");
        assert_eq!(json["threat_id"], "threat-1");
    }
}

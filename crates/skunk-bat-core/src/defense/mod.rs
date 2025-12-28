//! Automated defense for skunkBat.
//!
//! Provides threat response, quarantine, and self-healing.

use crate::SkunkBatConfig;
use crate::error::SkunkBatError;
use crate::threats::{Severity, Threat};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

/// Defense engine.
pub struct DefenseEngine {
    enabled: bool,
    #[allow(dead_code)]
    auto_response_enabled: bool,
    #[allow(dead_code)]
    quarantine_map: HashMap<String, QuarantineRecord>,
}

impl DefenseEngine {
    /// Create a new defense engine.
    #[must_use]
    pub fn new(config: &SkunkBatConfig) -> Self {
        Self {
            enabled: config.features.auto_defense,
            auto_response_enabled: true, // Can be configurable
            quarantine_map: HashMap::new(),
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
    pub fn is_healthy(&self) -> bool {
        self.enabled
    }

    /// Respond to a threat.
    ///
    /// # Errors
    ///
    /// Returns an error if the threat response fails.
    pub fn respond(&self, threat: &Threat) -> Result<(), SkunkBatError> {
        if !self.enabled {
            tracing::debug!("Defense engine disabled, threat logged only");
            return Ok(());
        }

        tracing::warn!(
            "Processing threat response: {:?} (severity: {:?}, confidence: {})",
            threat.threat_type,
            threat.severity,
            threat.confidence
        );

        // Determine appropriate response based on threat
        let action = Self::determine_action(threat);

        // Execute defense action
        self.execute_action(&action, threat)?;

        Ok(())
    }

    /// Determine appropriate defense action.
    fn determine_action(threat: &Threat) -> DefenseAction {
        // Critical threats: immediate quarantine
        if threat.severity == Severity::Critical && threat.confidence > 0.9 {
            return DefenseAction {
                action_type: ActionType::Quarantine,
                target: threat.source.clone(),
                requires_approval: false,
                reason: format!("Critical threat detected: {}", threat.description),
            };
        }

        // High severity: quarantine with alert
        if threat.severity == Severity::High && threat.confidence > 0.7 {
            return DefenseAction {
                action_type: ActionType::QuarantineAndAlert,
                target: threat.source.clone(),
                requires_approval: false,
                reason: format!("High severity threat: {}", threat.description),
            };
        }

        // Medium/Low: monitor and alert
        DefenseAction {
            action_type: ActionType::MonitorAndAlert,
            target: threat.source.clone(),
            requires_approval: true,
            reason: format!("Potential threat detected: {}", threat.description),
        }
    }

    /// Execute defense action.
    #[allow(clippy::unnecessary_wraps)]
    fn execute_action(&self, action: &DefenseAction, threat: &Threat) -> Result<(), SkunkBatError> {
        match action.action_type {
            ActionType::Quarantine => {
                self.quarantine_connection(&action.target);
                tracing::warn!(
                    "Quarantined connection from {} (reason: {})",
                    action.target,
                    action.reason
                );
            }
            ActionType::QuarantineAndAlert => {
                self.quarantine_connection(&action.target);
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

        Ok(())
    }

    /// Quarantine a connection.
    ///
    /// # Integration Point
    /// This method should be extended by the network layer to:
    /// - Rate limit traffic from the source
    /// - Restrict capabilities of quarantined connections
    /// - Log all activity for analysis
    /// - Maintain quarantine state for operator review
    #[allow(clippy::unused_self)]
    fn quarantine_connection(&self, source: &str) {
        // Integration contract: Network layer implements isolation here
        tracing::debug!("Quarantining connection from {source}");
    }

    /// Block a connection.
    ///
    /// # Integration Point
    /// This method should be extended by the network layer to:
    /// - Close existing connections from the source
    /// - Reject new connection attempts
    /// - Add source to block list
    /// - Log block event for audit
    #[allow(clippy::unused_self)]
    fn block_connection(&self, source: &str) {
        // Integration contract: Network layer implements blocking here
        tracing::debug!("Blocking connection from {source}");
    }

    /// Alert operator about threat.
    ///
    /// # Integration Point
    /// This method should be extended to integrate with:
    /// - **Songbird**: Send real-time alert notifications
    /// - **petalTongue**: Update security dashboard visualization
    /// - **rhizoCrypt**: Log to encrypted audit trail
    #[allow(clippy::unused_self)]
    fn alert_operator(&self, threat: &Threat, action: &DefenseAction) {
        // Integration contract: Notification system implements delivery here
        tracing::info!(
            "ALERT: Threat detected - {:?} from {} (action: {:?})",
            threat.threat_type,
            threat.source,
            action.action_type
        );
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
    use crate::threats::{Severity, Threat, ThreatType};
    use sourdough_core::config::CommonConfig;

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
        let threat = test_threat(Severity::Critical, 0.95);
        let action = DefenseEngine::determine_action(&threat);

        assert_eq!(action.action_type, ActionType::Quarantine);
        assert!(!action.requires_approval);
    }

    #[test]
    fn test_high_severity_response() {
        let threat = test_threat(Severity::High, 0.8);
        let action = DefenseEngine::determine_action(&threat);

        assert_eq!(action.action_type, ActionType::QuarantineAndAlert);
        assert!(!action.requires_approval);
    }

    #[test]
    fn test_medium_severity_response() {
        let threat = test_threat(Severity::Medium, 0.6);
        let action = DefenseEngine::determine_action(&threat);

        assert_eq!(action.action_type, ActionType::MonitorAndAlert);
        assert!(action.requires_approval);
    }

    #[test]
    fn test_low_confidence_threat() {
        let threat = test_threat(Severity::Critical, 0.5);
        let action = DefenseEngine::determine_action(&threat);

        // Low confidence, even critical, should require approval
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
        
        assert!(engine.execute_action(&action, &threat).is_ok());
    }
    
    #[test]
    fn test_disabled_defense_start() {
        let mut config = test_config();
        config.features.auto_defense = false;
        
        let engine = DefenseEngine::new(&config);
        assert!(engine.start().is_ok());
        assert!(engine.stop().is_ok());
    }
}

//! Integration tests for skunkBat with songbird
//!
//! Tests alert delivery and metrics broadcasting integration

#[cfg(test)]
mod songbird_integration {
    use skunk_bat_core::{
        threats::{Severity, Threat, ThreatType},
        SkunkBat, SkunkBatConfig,
    };
    use sourdough_core::PrimalLifecycle;
    use std::time::SystemTime;

    #[tokio::test]
    #[ignore] // Enable when songbird integration is ready
    async fn test_threat_alert_delivery() {
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.unwrap();

        // TODO: Test alert delivery via songbird
        // - Create high severity threat
        // - Trigger response
        // - Verify songbird receives alert message

        let threat = Threat {
            id: "test-threat-1".to_string(),
            threat_type: ThreatType::IntrusionAttempt {
                attack_type: "brute-force".to_string(),
                signature: "multiple-failed-auth".to_string(),
            },
            severity: Severity::High,
            source: "192.168.1.100".to_string(),
            target: "192.168.1.1".to_string(),
            detected_at: SystemTime::now(),
            description: "Test threat for integration".to_string(),
            confidence: 0.9,
        };

        skunkbat.respond_to_threat(&threat).unwrap();

        // Verify alert was sent via songbird
        
        skunkbat.stop().await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Enable when songbird integration is ready
    async fn test_metrics_broadcasting() {
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.unwrap();

        // TODO: Test metrics broadcasting via songbird
        // - Perform operations (scan, detect, respond)
        // - Verify metrics are broadcast via songbird
        // - Verify other primals can receive metrics

        let _scan = skunkbat.scan_network().await.unwrap();
        let _threats = skunkbat.detect_threats().await.unwrap();
        let metrics = skunkbat.get_security_metrics();

        // Verify metrics were broadcast
        assert!(metrics.last_updated.is_some());

        skunkbat.stop().await.unwrap();
    }

    #[tokio::test]
    #[ignore] // Enable when songbird integration is ready
    async fn test_security_event_stream() {
        let config = SkunkBatConfig::default();
        let mut skunkbat = SkunkBat::new(config);
        skunkbat.start().await.unwrap();

        // TODO: Test continuous security event streaming
        // - Subscribe to skunkBat security events via songbird
        // - Perform reconnaissance and threat detection
        // - Verify events are streamed in real-time

        skunkbat.stop().await.unwrap();
    }
}


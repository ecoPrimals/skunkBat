# skunkBat Observability Specification

**Version:** 0.2.13  
**Status:** Implemented  
**Author:** ecoPrimals Project  
**Date:** December 27, 2025  
**License:** AGPL-3.0  

---

## Abstract

skunkBat observability provides **security-focused visibility** into reconnaissance, threat detection, and defense operations. All observability is designed for YOUR understanding and control, not external surveillance.

**Core Principle:** Observability for debugging and protection, not surveillance for control.

---

## 1. Observability Philosophy

### 1.1 Observability vs. Surveillance

**Observability (What We Do):**
- ✅ YOU observe YOUR systems
- ✅ Metrics for YOUR security posture
- ✅ Logs for YOUR debugging
- ✅ Traces for YOUR understanding
- ✅ Dashboards for YOUR visibility

**Surveillance (What We DON'T Do):**
- ❌ External monitoring of your actions
- ❌ Behavioral profiling
- ❌ Data extraction for others
- ❌ Hidden telemetry
- ❌ Cloud-only metrics

### 1.2 Local by Default

**Principle:** All observability data stays on YOUR node unless YOU choose to federate.

```rust
/// Security observability manager
pub struct SecurityObserver {
    /// Metrics collector (local)
    metrics: MetricsCollector,
    
    /// Log storage (local)
    logs: LogStorage,
    
    /// Trace collector (local)
    traces: TraceCollector,
    
    /// Dashboard (local UI)
    dashboard: Dashboard,
    
    /// Federation (opt-in)
    federation: Option<FederatedObservability>,
}
```

---

## 2. Metrics

### 2.1 Security Metrics

```rust
/// Security metrics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Reconnaissance metrics
    pub reconnaissance: ReconMetrics,
    
    /// Threat detection metrics
    pub threats: ThreatMetrics,
    
    /// Defense metrics
    pub defense: DefenseMetrics,
    
    /// System health
    pub health: HealthMetrics,
    
    /// Timestamp
    pub timestamp: Timestamp,
}

/// Reconnaissance metrics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconMetrics {
    /// Total assets discovered
    pub assets_discovered: u64,
    
    /// Scans performed (last 24h)
    pub scans_performed: u64,
    
    /// Network topology complexity
    pub topology_nodes: u64,
    pub topology_edges: u64,
    
    /// Average scan duration
    pub avg_scan_duration: Duration,
}

/// Threat detection metrics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatMetrics {
    /// Threats detected (by severity)
    pub detected_by_severity: HashMap<Severity, u64>,
    
    /// Threats by type
    pub detected_by_type: HashMap<ThreatType, u64>,
    
    /// False positive rate
    pub false_positive_rate: f64,
    
    /// Detection latency (threat → detection)
    pub avg_detection_latency: Duration,
}

/// Defense metrics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefenseMetrics {
    /// Active quarantines
    pub active_quarantines: u64,
    
    /// Active blocks
    pub active_blocks: u64,
    
    /// Defense actions taken (24h)
    pub actions_taken: HashMap<ActionType, u64>,
    
    /// Self-healing actions (24h)
    pub healing_actions: u64,
}
```

### 2.2 Metrics Collection

```rust
impl SecurityObserver {
    /// Collect current metrics
    pub fn collect_metrics(&self) -> SecurityMetrics {
        SecurityMetrics {
            reconnaissance: self.collect_recon_metrics(),
            threats: self.collect_threat_metrics(),
            defense: self.collect_defense_metrics(),
            health: self.collect_health_metrics(),
            timestamp: Timestamp::now(),
        }
    }
    
    /// Export metrics (Prometheus format)
    pub fn export_prometheus(&self) -> String {
        let metrics = self.collect_metrics();
        
        format!(
            r#"# HELP skunkbat_assets_discovered Total assets discovered
# TYPE skunkbat_assets_discovered gauge
skunkbat_assets_discovered {{}}
# HELP skunkbat_threats_detected Threats detected by severity
# TYPE skunkbat_threats_detected counter
skunkbat_threats_detected{{severity="low"}} {}
skunkbat_threats_detected{{severity="medium"}} {}
skunkbat_threats_detected{{severity="high"}} {}
skunkbat_threats_detected{{severity="critical"}} {}
"#,
            metrics.reconnaissance.assets_discovered,
            metrics.threats.detected_by_severity.get(&Severity::Low).unwrap_or(&0),
            metrics.threats.detected_by_severity.get(&Severity::Medium).unwrap_or(&0),
            metrics.threats.detected_by_severity.get(&Severity::High).unwrap_or(&0),
            metrics.threats.detected_by_severity.get(&Severity::Critical).unwrap_or(&0),
        )
    }
}
```

---

## 3. Logging

### 3.1 Structured Logging

```rust
/// Security event log
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Event timestamp
    pub timestamp: Timestamp,
    
    /// Event type
    pub event_type: SecurityEventType,
    
    /// Severity
    pub severity: LogSeverity,
    
    /// Component that logged event
    pub component: Component,
    
    /// Event data
    pub data: serde_json::Value,
    
    /// Cryptographic signature (audit trail)
    pub signature: Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SecurityEventType {
    /// Reconnaissance events
    ScanStarted,
    ScanCompleted,
    AssetDiscovered,
    TopologyUpdated,
    
    /// Threat detection events
    ThreatDetected,
    FalsePositive,
    ThreatEscalated,
    
    /// Defense events
    QuarantineApplied,
    QuarantineReleased,
    BlockApplied,
    BlockRemoved,
    HealingPerformed,
    
    /// User interactions
    UserApproved,
    UserRejected,
    UserOverride,
}
```

### 3.2 Audit Logging

```rust
/// Audit logger (cryptographically signed)
pub struct AuditLogger {
    /// Log storage
    storage: LogStorage,
    
    /// Crypto signer
    signer: CryptoSigner,
}

impl AuditLogger {
    /// Log security event
    pub async fn log_event(
        &self,
        event_type: SecurityEventType,
        severity: LogSeverity,
        data: impl Serialize,
    ) -> Result<(), ObservabilityError> {
        let event = SecurityEvent {
            timestamp: Timestamp::now(),
            event_type,
            severity,
            component: self.component(),
            data: serde_json::to_value(data)?,
            signature: self.signer.sign(&serialize(&event))?,
        };
        
        self.storage.store(event).await?;
        
        Ok(())
    }
}
```

---

## 4. Integration with BiomeOS

```rust
/// BiomeOS health reporter
pub struct BiomeOsHealthReporter {
    /// BiomeOS client
    biomeos: BiomeOsClient,
    
    /// Metrics collector
    metrics: MetricsCollector,
}

impl BiomeOsHealthReporter {
    /// Report health to BiomeOS
    pub async fn report_health(&self) -> Result<(), ObservabilityError> {
        let health = HealthReport {
            service: "skunkbat".to_string(),
            status: self.compute_health_status(),
            metrics: self.metrics.collect(),
            timestamp: Timestamp::now(),
        };
        
        self.biomeos.report_health(health).await?;
        
        Ok(())
    }
}
```

---

## Appendix: Configuration Example

```yaml
# observability.yaml
observability:
  enabled: true
  
  # Metrics
  metrics:
    enabled: true
    collection_interval: 60s
    retention: 7d
    export_formats: [prometheus, json]
  
  # Logging
  logging:
    enabled: true
    level: info  # debug, info, warn, error
    structured: true
    audit_signing: true
    retention: 30d
  
  # BiomeOS integration
  biomeos:
    enabled: true
    health_report_interval: 60s
```

---

**Status:** Initial draft complete. All 4 specifications created.

**Next:** Implementation following specifications.


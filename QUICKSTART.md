# skunkBat Quick Start Guide

**Date:** December 27, 2025  
**Version:** 0.1.0  
**Status:** Ready for Integration

---

## Overview

skunkBat is the reconnaissance and automated defense primal for the ecoPrimals ecosystem. This guide will help you get started with skunkBat quickly.

### What is skunkBat?

skunkBat provides:
- **Reconnaissance:** Network scanning and topology mapping for YOUR systems
- **Threat Detection:** Multi-layer security analysis (genetic, behavioral, signature-based)
- **Automated Defense:** Intelligent response to detected threats
- **Security Observability:** Real-time metrics and monitoring

### Core Principles

✅ **Reconnaissance, NOT Surveillance** - Scans only your owned networks  
✅ **Defense, NOT Offense** - Protective actions only, never attacks  
✅ **Local by Default** - Data stays on your node  
✅ **Transparent** - Open source, auditable operations  
✅ **User Authority** - You retain ultimate control  

---

## Installation

### Prerequisites

- Rust 1.75+ (stable)
- Tokio runtime for async operations
- sourdough-core (ecoPrimals foundation)

### Add to Cargo.toml

```toml
[dependencies]
skunk-bat-core = { path = "../skunkBat/crates/skunk-bat-core" }
sourdough-core = { path = "../sourDough/crates/sourdough-core" }
tokio = { version = "1", features = ["full"] }
```

---

## Basic Usage

### 1. Create and Start skunkBat

```rust
use skunk_bat_core::{SkunkBat, SkunkBatConfig};
use sourdough_core::{PrimalLifecycle, PrimalHealth};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = SkunkBatConfig::default();
    
    // Create skunkBat instance
    let mut skunkbat = SkunkBat::new(config);
    
    // Start the primal
    skunkbat.start().await?;
    
    // ... use skunkBat ...
    
    // Stop when done
    skunkbat.stop().await?;
    
    Ok(())
}
```

### 2. Perform Reconnaissance

```rust
// Scan your network
let scan = skunkbat.scan_network()?;

println!("Discovered {} nodes", scan.nodes.len());
for node in &scan.nodes {
    println!("  • {} ({}): {:?}", 
        node.id, node.node_type, node.status);
}
```

### 3. Detect Threats

```rust
// Check for security threats
let threats = skunkbat.detect_threats()?;

if threats.is_empty() {
    println!("✓ No threats detected");
} else {
    println!("⚠ {} threat(s) detected!", threats.len());
    for threat in &threats {
        println!("  • {:?} from {} (severity: {:?})",
            threat.threat_type,
            threat.source,
            threat.severity
        );
    }
}
```

### 4. Respond to Threats

```rust
// Automatically respond to detected threats
for threat in threats {
    skunkbat.respond_to_threat(&threat)?;
}

// skunkBat will:
// - Quarantine critical threats immediately
// - Alert you for high severity threats
// - Monitor and report medium/low threats
```

### 5. Monitor Security Metrics

```rust
// Get current security metrics
let metrics = skunkbat.get_security_metrics();

println!("Security Metrics:");
println!("  Threats detected: {}", metrics.threats_detected);
println!("  Threats mitigated: {}", metrics.threats_mitigated);
println!("  Scans performed: {}", metrics.scans_performed);
println!("  Quarantines active: {}", metrics.connections_quarantined);
println!("  Alerts sent: {}", metrics.alerts_sent);
```

### 6. Check Health Status

```rust
// Check if skunkBat is healthy
let health = skunkbat.health_check().await?;
println!("Health: {:?}", health.status);
```

---

## Configuration

### Basic Configuration

```rust
use skunk_bat_core::config::{SkunkBatConfig, FeatureFlags};
use sourdough_core::config::CommonConfig;

let config = SkunkBatConfig {
    common: CommonConfig {
        name: "my-skunkbat".to_string(),
        ..CommonConfig::default()
    },
    features: FeatureFlags {
        reconnaissance: true,      // Enable network scanning
        threat_detection: true,    // Enable threat detection
        auto_defense: true,        // Enable automated responses
        observability: true,       // Enable metrics
    },
    lineage_id: None,  // Optional: for family-only monitoring
};

let skunkbat = SkunkBat::new(config);
```

### Family-Only Monitoring

```rust
let mut config = SkunkBatConfig::default();
config.lineage_id = Some("my-family-lineage".to_string());

// Now skunkBat will:
// - Verify genetic lineage via beardog (when integrated)
// - Flag connections from unknown lineages as threats
// - Only share intelligence within family (opt-in)
```

### Disable Features

```rust
let mut config = SkunkBatConfig::default();
config.features.auto_defense = false;  // Disable automated responses

// Now skunkBat will detect threats but not respond automatically
```

---

## Examples

### Run Provided Examples

```bash
# Basic usage demonstration
cargo run --example basic_usage

# Threat response scenarios
cargo run --example threat_response

# Continuous monitoring loop
cargo run --example monitoring_loop
```

### Example: Continuous Monitoring

```rust
use skunk_bat_core::{SkunkBat, SkunkBatConfig};
use sourdough_core::{PrimalLifecycle, PrimalHealth};
use tokio::time::{interval, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    let mut timer = interval(Duration::from_secs(30));

    loop {
        timer.tick().await;

        // Scan network
        let scan = skunkbat.scan_network()?;
        println!("✓ Scanned {} nodes", scan.nodes.len());

        // Detect and respond to threats
        let threats = skunkbat.detect_threats()?;
        for threat in threats {
            println!("⚠ Threat: {:?}", threat.threat_type);
            skunkbat.respond_to_threat(&threat)?;
        }

        // Report metrics
        let metrics = skunkbat.get_security_metrics();
        println!("📊 Metrics: {} detected, {} mitigated",
            metrics.threats_detected,
            metrics.threats_mitigated
        );
    }
}
```

---

## Integration with ecoPrimals

### Capability Discovery (toadstool)

```rust
// When integrated with toadstool:
// - skunkBat registers its capabilities
// - Discovers other primals automatically
// - Maps network topology via capability announcements

// Currently stub implementation, full integration pending
```

### Genetic Trust (beardog)

```rust
// When integrated with beardog:
// - Verifies lineage of connecting nodes
// - Detects unknown/untrusted genetic chains
// - Enables family-only monitoring

let mut config = SkunkBatConfig::default();
config.lineage_id = Some("verified-family-id".to_string());
```

### Alert Delivery (songbird)

```rust
// When integrated with songbird:
// - Threat alerts broadcast via songbird
// - Security metrics published
// - Real-time event streaming

// Currently logs to tracing, full integration pending
```

### Security Dashboard (petalTongue)

```rust
// When integrated with petalTongue:
// - Real-time security dashboard
// - Visual threat representation
// - Interactive metrics display

// Integration point ready, implementation pending
```

### Audit Trail (rhizoCrypt)

```rust
// When integrated with rhizoCrypt:
// - All security events logged to DAG
// - Cryptographically signed audit trail
// - Immutable security history

// Integration point ready, implementation pending
```

---

## API Reference

### Core API

```rust
// Lifecycle
async fn start(&mut self) -> Result<(), PrimalError>
async fn stop(&mut self) -> Result<(), PrimalError>
fn state(&self) -> PrimalState

// Reconnaissance
fn scan_network(&self) -> Result<NetworkScan, SkunkBatError>

// Threat Detection
fn detect_threats(&self) -> Result<Vec<Threat>, SkunkBatError>

// Defense
fn respond_to_threat(&self, threat: &Threat) -> Result<(), SkunkBatError>

// Observability
fn get_security_metrics(&self) -> SecurityMetrics

// Health
async fn health_check(&self) -> Result<HealthReport, PrimalError>
fn health_status(&self) -> HealthStatus
```

### Types

```rust
// Network Scan
pub struct NetworkScan {
    pub nodes: Vec<Node>,
    pub topology: Vec<Connection>,
    pub scan_time: Option<SystemTime>,
    pub scope: NetworkScope,
}

// Threat
pub struct Threat {
    pub id: String,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub source: String,
    pub target: String,
    pub detected_at: SystemTime,
    pub description: String,
    pub confidence: f64,
}

// Security Metrics
pub struct SecurityMetrics {
    pub threats_detected: u64,
    pub threats_mitigated: u64,
    pub scans_performed: u64,
    pub connections_quarantined: u64,
    pub alerts_sent: u64,
    pub last_updated: Option<SystemTime>,
}
```

---

## Testing

### Run Tests

```bash
# Run all tests
cargo test --workspace

# Run with coverage
cargo llvm-cov --workspace

# Run specific test module
cargo test --test integration_beardog
```

### Integration Tests

Currently marked as `#[ignore]` until integrations are ready:

```bash
# When ready, enable integration tests:
cargo test --ignored  # Run ignored tests
```

---

## Troubleshooting

### skunkBat won't start

```rust
// Check configuration
let config = SkunkBatConfig::default();
let mut skunkbat = SkunkBat::new(config);

match skunkbat.start().await {
    Ok(_) => println!("Started successfully"),
    Err(e) => eprintln!("Failed to start: {}", e),
}
```

### No nodes discovered

```rust
// Verify reconnaissance is enabled
let mut config = SkunkBatConfig::default();
assert!(config.features.reconnaissance);

// Check scan result
let scan = skunkbat.scan_network()?;
println!("Discovered {} nodes", scan.nodes.len());

// Note: Current implementation returns local node only
// Full discovery requires toadstool integration
```

### Threats not detected

```rust
// Verify threat detection is enabled
assert!(config.features.threat_detection);

// Check if baseline is established
// (behavioral anomaly detection requires learning period)

// Verify lineage configuration for genetic threats
config.lineage_id = Some("your-lineage".to_string());
```

---

## Performance Considerations

### Scan Frequency

```rust
// Balance security vs. performance
let scan_interval = Duration::from_secs(30);  // Good balance
// Too frequent: < 10s may impact performance
// Too infrequent: > 60s may miss threats
```

### Memory Usage

skunkBat is designed to be lightweight:
- No permanent data storage by default
- 24-hour retention for reconnaissance data
- Atomic operations for metrics (minimal overhead)

### Threading

All operations are async-compatible:
```rust
// Safe to use with Tokio runtime
tokio::spawn(async move {
    let threats = skunkbat.detect_threats()?;
    // Process threats...
});
```

---

## Best Practices

### 1. Always Check Health

```rust
loop {
    // Perform operations...
    
    if matches!(skunkbat.health_status(), HealthStatus::Unhealthy { .. }) {
        eprintln!("skunkBat is unhealthy!");
        // Take corrective action
    }
}
```

### 2. Handle Errors Gracefully

```rust
match skunkbat.detect_threats() {
    Ok(threats) => { /* Handle threats */ },
    Err(e) => {
        tracing::error!("Threat detection failed: {}", e);
        // Continue operating, retry later
    }
}
```

### 3. Monitor Metrics

```rust
let metrics = skunkbat.get_security_metrics();
if metrics.threats_detected > 100 {
    // Investigate potential attack
}
```

### 4. Respect User Authority

```rust
// For high-confidence threats, respond automatically
if threat.severity == Severity::Critical && threat.confidence > 0.9 {
    skunkbat.respond_to_threat(&threat)?;
} else {
    // For uncertain threats, alert user for approval
    println!("Potential threat detected. Respond? [y/n]");
    // Wait for user decision...
}
```

---

## Next Steps

1. **Run Examples:** Try the provided examples to understand the API
2. **Read Specifications:** Review `specs/` directory for detailed design
3. **Review Ethics:** Read `RECONNAISSANCE_NOT_SURVEILLANCE.md` for principles
4. **Integrate:** Prepare for integration with other primals
5. **Contribute:** Help implement integration points

---

## Resources

- **Documentation:** See `/home/eastgate/Development/ecoPrimals/phase2/skunkBat/`
- **Specifications:** `specs/` directory
- **Examples:** `examples/` directory
- **Tests:** `tests/` directory
- **Implementation Report:** `IMPLEMENTATION_COMPLETE.md`
- **Ethics Framework:** `RECONNAISSANCE_NOT_SURVEILLANCE.md`

---

## Support

For questions or issues:
1. Check the specifications in `specs/`
2. Review test cases for usage examples
3. Consult the implementation report
4. Refer to ecoPrimals ecosystem documentation

---

**Status:** Ready for Integration 🚀  
**Version:** 0.1.0  
**License:** AGPL-3.0

*Generated: December 27, 2025*  
*ecoPrimals Project*


# 🦨 skunkBat
## Defensive Network Security for Sovereign Computing

**Status**: Production Ready ✅  
**Version**: Phase 2 Complete  
**Coverage**: 87.37% (Core: 90-100%)

---

## What is skunkBat?

skunkBat is a **defensive network security primal** that protects sovereign computing environments through:

- **5 Types of Threat Detection**: Genetic, Topology, Behavioral, Intrusion, Resource
- **Graduated Defense Response**: Monitor → Quarantine → Block (user authority preserved)
- **Statistical Baseline Profiling**: Learns YOUR network's normal, not universal standards
- **Zero-Coupling Architecture**: Trait-based integration with ecosystem primals
- **Privacy by Architecture**: Metadata-only, no content inspection possible

### Philosophy

**Defensive, Not Offensive**: skunkBat protects networks, doesn't attack  
**Reconnaissance, Not Surveillance**: Monitors patterns, not user behavior  
**User Authority**: Owner approves major actions  
**Sovereignty First**: Local-by-default, user-controlled data

---

## Quick Start

### Run Showcase Demos

```bash
# Start with local capabilities
cd showcase/00-local-primal
./RUN_ALL_LOCAL.sh

# Or run individual demos
cd 01-hello-skunkbat && ./demo.sh
cd 02-violation-detection && ./demo.sh
```

### Basic Usage

```rust
use skunk_bat_core::{SkunkBat, SkunkBatConfig};
use sourdough_core::PrimalLifecycle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize skunkBat
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    
    // Start protection
    skunkbat.start().await?;
    
    // Scan network
    skunkbat.scan_network().await?;
    
    // Detect threats
    let threats = skunkbat.detect_threats().await?;
    
    // Respond to threats
    for threat in threats {
        skunkbat.respond_to_threat(&threat)?;
    }
    
    // Get metrics
    let metrics = skunkbat.get_security_metrics();
    
    Ok(())
}
```

---

## Features

### Threat Detection (5 Types)

| Type | Detects | Response |
|------|---------|----------|
| **Genetic** | Unknown lineage (via Beardog) | Quarantine |
| **Topology** | Layer-hopping, path bypass | Quarantine |
| **Behavioral** | Statistical anomalies | Graduated |
| **Intrusion** | Attack signatures | Quarantine/Block |
| **Resource** | DoS, exhaustion | Rate limit |

### Defense Actions

- **Monitor + Alert**: Low severity, requires approval
- **Quarantine**: Isolate connection, alert operator
- **Block**: Deny access (operator decision)

### Ecosystem Integration

- 🐻 **Beardog**: Genetic lineage verification (WHO)
- 🍄 **Toadstool**: Capability-based discovery (WHERE)
- 🐦 **Songbird**: Federated threat intelligence (COORDINATION)
- 🏠 **Nestgate**: Protected application platform (HOME)

---

## Documentation

### Getting Started
- `START_HERE.md` - Quick orientation
- `QUICKSTART.md` - Fast setup guide
- `showcase/00_START_HERE.md` - Demo walkthrough

### Specifications
- `specs/RECONNAISSANCE_SPEC.md` - Network intelligence
- `specs/THREAT_DETECTION_SPEC.md` - Threat identification
- `specs/AUTO_DEFENSE_SPEC.md` - Defense mechanisms
- `specs/OBSERVABILITY_SPEC.md` - Metrics and monitoring

### Production
- `PRODUCTION_READINESS.md` - Deployment guide
- `GAPS_FOUND_DURING_SHOWCASE.md` - Known issues (1 resolved, 2 acknowledged)
- `DOCUMENTATION_INDEX.md` - Complete doc index

### Archives
- `archive/` - Session reports and historical documentation

---

## Project Structure

```
skunkBat/
├── crates/
│   ├── skunk-bat-core/        # Core threat detection & defense
│   └── skunk-bat-integrations/ # Ecosystem integrations
├── examples/                   # 10 working examples (zero mocks!)
│   ├── basic_usage.rs
│   ├── violation_detection.rs  # All 5 threat types
│   ├── defense_actions.rs
│   ├── baseline_learning.rs
│   ├── local_federation.rs
│   ├── defensive_vs_surveillance.rs
│   ├── beardog_integration.rs
│   ├── toadstool_integration.rs
│   ├── songbird_integration.rs
│   └── nestgate_protection.rs  # Grand finale!
├── showcase/                   # Interactive demonstrations
│   ├── 00-local-primal/        # Level 0: Local capabilities (6 demos)
│   ├── 01-ecosystem-integration/ # Level 1: Inter-primal (4 demos)
│   ├── 02-federation-mesh/     # Level 2: Multi-node
│   └── 03-production/          # Level 3: Deployment
├── tests/                      # Integration & chaos tests
└── specs/                      # Technical specifications
```

---

## Build & Test

```bash
# Build
cargo build --release

# Run tests
cargo test

# Run examples
cargo run --example basic_usage
cargo run --example violation_detection

# With ecosystem integrations
cargo build --features beardog-integration
cargo build --features full  # All integrations

# Code quality
cargo clippy --all-targets
cargo fmt --check
```

---

## Configuration

### Environment Variables
```bash
# Required
export SKUNKBAT_ID=your-instance-id

# Optional
export SKUNKBAT_ADDRESS=your-address
export SKUNKBAT_OWNED_NETWORKS=192.168.1.0/24
export TOADSTOOL_DISCOVERY_ENDPOINT=http://toadstool.local:3000
```

### Feature Flags
```toml
[features]
default = []
beardog-integration = ["beardog-genetics"]
toadstool-integration = []
songbird-integration = []
full = ["beardog-integration", "toadstool-integration", "songbird-integration"]
```

---

## Status

### Completed ✅
- [x] Core threat detection (5 types)
- [x] Defense orchestration
- [x] Statistical baseline profiling
- [x] Security observability
- [x] Multi-instance federation
- [x] Ecosystem integrations (trait-based)
- [x] Comprehensive showcase (10 demos)
- [x] Production readiness

### Metrics
- **Test Coverage**: 87.37% overall, 90-100% core modules
- **Examples**: 10 working demos
- **Code Quality**: Zero compiler errors, zero critical warnings
- **Mocks**: 0 (All real production code)
- **Documentation**: Comprehensive

---

## Ethics & Philosophy

### What skunkBat Monitors
✅ Connection metadata (source, destination, rate)  
✅ Cryptographic proofs (lineage verification)  
✅ Network topology (layer traversal)  
✅ Statistical patterns (deviations from YOUR baseline)  
✅ Resource consumption (impact on YOUR system)

### What skunkBat Does NOT Monitor
❌ Packet payloads or content  
❌ User data or personal information  
❌ Browsing history or activity  
❌ Application usage  
❌ Individual user behavior

**Architectural Guarantee**: The code literally cannot access packet contents or user data. This isn't a promise - it's architectural impossibility.

See `RECONNAISSANCE_NOT_SURVEILLANCE.md` and `ETHICS_REVIEW_SUMMARY.md` for details.

---

## Contributing

skunkBat follows modern idiomatic Rust practices:
- Async/await patterns
- Trait-based abstractions (zero coupling)
- Comprehensive error handling
- Feature gates for optional dependencies
- 87%+ test coverage target

See archived session reports in `archive/` for development methodology.

---

## License

Part of the ecoPrimals ecosystem - sovereignty-first, privacy-preserving, user-controlled computing.

---

## Support

- **Documentation**: See `docs/` and `specs/`
- **Examples**: See `examples/` (all working, zero mocks!)
- **Showcase**: Run `showcase/00-local-primal/RUN_ALL_LOCAL.sh`
- **Issues**: See `GAPS_FOUND_DURING_SHOWCASE.md`

---

🦨 **Defensive by architecture. Sovereign by design. Human dignity by default.**

**skunkBat: Network security that respects privacy, preserves sovereignty, and maintains user authority.**

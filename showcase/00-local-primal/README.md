# 🦨 Level 0: Local Primal Capabilities
## Master the fundamentals in 45 minutes

**Goal**: Understand what skunkBat can do standalone, before ecosystem integration  
**Prerequisites**: None - start here if new to skunkBat  
**Time**: 6 demos × 5-10 minutes = 45-60 minutes

---

## 🎯 What You'll Learn

By completing this level, you'll understand:
- ✅ How skunkBat initializes and discovers itself
- ✅ All 5 types of threat detection (genetic, topology, behavioral, intrusion, resource)
- ✅ All 3 defense actions (quarantine, rate-limit, block)
- ✅ Statistical baseline profiling for anomaly detection
- ✅ Real-time security metrics and observability
- ✅ Zero-knowledge bootstrap (discovers identity from system)

---

## 📚 Demo Progression

### 🟢 Demo 01: Hello skunkBat (5 min)
**File**: `01-hello-skunkbat/demo.sh`

Your first security scan. See skunkBat initialize, scan, and report.

```bash
cd 01-hello-skunkbat && ./demo.sh
```

**What it shows**:
- Self-knowledge principle (only knows itself by default)
- Local-first design
- Basic reconnaissance scan
- Health monitoring

**Key Insight**: skunkBat starts with ZERO assumptions about the network!

---

### 🟢 Demo 02: Violation Detection (10 min)
**File**: `02-violation-detection/demo.sh`

See all 5 threat detection mechanisms in action with real scenarios.

```bash
cd 02-violation-detection && ./demo.sh
```

**What it shows**:
- 🧬 **Genetic threats** - Unknown lineage detection
- 📊 **Behavioral anomalies** - Statistical deviation detection
- 🔍 **Signature threats** - Known attack pattern matching
- 💥 **DoS attempts** - Resource exhaustion detection

**Key Insight**: Multi-layered detection catches different threat classes!

---

### 🟡 Demo 03: Defense Actions (10 min)
**File**: `03-defense-actions/demo.sh`

Watch skunkBat quarantine, rate-limit, and block threats.

```bash
cd 03-defense-actions && ./demo.sh
```

**What it shows**:
- 🔒 **Quarantine** - Isolate suspicious connection (non-blocking)
- ⏱️ **Rate Limit** - Slow down potential threats
- 🛑 **Block** - Stop confirmed malicious traffic
- 👤 **User Approval** - Sovereignty-first decision making

**Architecture**:
```
Threat Severity → Defense Action
─────────────────────────────────
Critical (>0.9)  → Quarantine immediately
High (>0.7)      → Quarantine + Alert
Medium (<0.7)    → Monitor + Alert (requires approval)
Low              → Log only
```

**Key Insight**: Defense is graduated and respects user authority!

---

### 🟡 Demo 04: Baseline Learning (10 min)
**File**: `04-baseline-learning/demo.sh`

See statistical profiling learn normal behavior and detect anomalies.

```bash
cd 04-baseline-learning && ./demo.sh
```

**What it shows**:
- 📈 **Baseline establishment** - 10+ observations to learn normal
- 📉 **Statistical analysis** - Mean, std dev, z-score calculation
- ⚠️ **Anomaly detection** - Deviation beyond threshold (2.5σ)
- 🎯 **Confidence scoring** - How confident we are in detection

**Example Scenario**:
```
Normal traffic:  5 connections/sec (baseline)
Anomaly traffic: 100 connections/sec (20x deviation!)
Result: HIGH confidence anomaly detected
```

**Key Insight**: Behavioral analysis catches zero-day threats!

---

### 🟡 Demo 05: Local Federation (10 min)
**File**: `05-local-federation/demo.sh`

Two skunkBat instances coordinating threat intelligence locally.

```bash
cd 05-local-federation && ./demo.sh
```

**What it shows**:
- 🔗 **Peer coordination** - Two instances sharing intel
- 📡 **Threat broadcast** - Propagate detections to peers
- 🤝 **Consensus actions** - Coordinated defense responses
- 🔒 **Trust boundaries** - Only trusted peers accepted

**Key Insight**: Federation starts local — same patterns scale to mesh!

---

### 🔵 Demo 06: Defensive vs Surveillance (10 min)
**File**: `06-defensive-vs-surveillance/demo.sh`

Architectural proof that skunkBat is defensive, not surveillance.

```bash
cd 06-defensive-vs-surveillance && ./demo.sh
```

**What it shows**:
- 🛡️ **Defensive** - Monitors YOUR perimeter, not others'
- 🚫 **Not surveillance** - Cannot inspect content by design
- 👤 **User authority** - Owner approves all major actions
- 🏛️ **Sovereignty** - Data stays local, no call-home

**Key Insight**: Privacy is architectural, not policy — skunkBat structurally cannot surveil!

---

## 🏃 Run All Demos

### Sequential Execution
```bash
# From this directory (00-local-primal/)
./RUN_ALL_LOCAL.sh
```

**Expected Time**: ~45-60 minutes for all demos

**What happens**:
- Each demo runs automatically
- Outputs are logged to `logs/demo-{name}.log`
- Final summary shows completion status
- Pauses between demos for review

### Individual Execution
```bash
# Run any single demo
cd 02-violation-detection && ./demo.sh

# Or with debug logging
RUST_LOG=debug ./demo.sh
```

---

## 📊 Architecture Overview

### Local-Only Mode
```
┌──────────────────────────────────┐
│         Your Machine             │
│                                  │
│  ┌────────────────────────────┐  │
│  │      skunkBat              │  │
│  │                            │  │
│  │  ┌──────────────────────┐  │  │
│  │  │ Reconnaissance       │  │  │
│  │  │ (LocalDiscovery)     │  │  │
│  │  └──────────────────────┘  │  │
│  │                            │  │
│  │  ┌──────────────────────┐  │  │
│  │  │ Threat Detection     │  │  │
│  │  │ (4 mechanisms)       │  │  │
│  │  └──────────────────────┘  │  │
│  │                            │  │
│  │  ┌──────────────────────┐  │  │
│  │  │ Defense Engine       │  │  │
│  │  │ (3 action types)     │  │  │
│  │  └──────────────────────┘  │  │
│  │                            │  │
│  │  ┌──────────────────────┐  │  │
│  │  │ Security Observer    │  │  │
│  │  │ (Metrics + Logs)     │  │  │
│  │  └──────────────────────┘  │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘

No external dependencies!
Everything runs locally.
```

---

## ✅ Completion Checklist

After completing Level 0, you should be able to:

- [ ] Explain the "self-knowledge principle"
- [ ] List all 5 threat detection types
- [ ] Describe all 3 defense actions
- [ ] Understand baseline learning process
- [ ] Read security metrics dashboard
- [ ] Explain zero-knowledge bootstrap
- [ ] Run any demo independently
- [ ] Modify demo parameters

---

## 🎓 Learning Outcomes

### Technical Skills
- ✅ Security observability concepts
- ✅ Threat detection methodologies
- ✅ Defense action strategies
- ✅ Statistical anomaly detection
- ✅ Metrics interpretation
- ✅ Configuration management

### Architecture Understanding
- ✅ Local-first design pattern
- ✅ Trait-based dependency injection
- ✅ Zero-knowledge principles
- ✅ Sovereignty-first operations
- ✅ Graceful degradation

---

## ➡️ What's Next?

### Live Ecosystem Integration

Levels 1–3 (ecosystem integration, federation mesh, production ops) are now
exercised through live compositions in the delta springs. See:

- `examples/beardog_integration.rs` — BearDog lineage verification
- `examples/toadstool_integration.rs` — ToadStool primal discovery
- `examples/songbird_integration.rs` — Songbird federation
- `examples/local_federation.rs` — Multi-instance coordination
- `tests/` — Integration and chaos tests

---

## 🔬 Experimentation Ideas

### Customize These Demos

1. **Change Threat Thresholds**
   - Edit config to require higher confidence
   - See how detection rate changes

2. **Adjust Baseline Parameters**
   - Change `observations_required` from 10 → 20
   - See impact on anomaly detection

3. **Enable All Features**
   - Turn on all detection types
   - Watch comprehensive threat analysis

4. **Simulate Network Scenarios**
   - Add port scanning behavior
   - Trigger DoS detection
   - Test rate limiting

---

## 📖 Additional Resources

### Documentation
- **Specifications**: `../../specs/`
  - `RECONNAISSANCE_SPEC.md` - Discovery design
  - `THREAT_DETECTION_SPEC.md` - Detection algorithms
  - `AUTO_DEFENSE_SPEC.md` - Defense strategies
  - `OBSERVABILITY_SPEC.md` - Metrics architecture

### Examples
- **Code Examples**: `../../examples/`
  - `basic_usage.rs` - Simple initialization
  - `threat_response.rs` - Defense scenarios
  - `monitoring_loop.rs` - Continuous operation

### Source Code
- **Core Implementation**: `../../crates/skunk-bat-core/src/`
  - `reconnaissance/mod.rs` - Discovery engine
  - `threats/mod.rs` - Detection engine
  - `defense/mod.rs` - Defense engine
  - `observability/mod.rs` - Metrics collection

---

## 🆘 Troubleshooting

### Demo Won't Run
```bash
# Check if skunkBat builds
cd ../../
cargo build --release

# Try the example directly
cargo run --example basic_usage
```

### Permission Denied
```bash
# Make demo executable
chmod +x demo.sh

# Or run with bash
bash demo.sh
```

### Compilation Errors
```bash
# Clean and rebuild
cargo clean
cargo build --release
```

---

**Ready to become a skunkBat expert?** Start with `01-hello-skunkbat/` and progress through all 6 demos! 🦨

**Estimated Time**: 45-60 minutes  
**Difficulty**: Beginner to Intermediate  
**Reward**: Complete understanding of skunkBat's local capabilities

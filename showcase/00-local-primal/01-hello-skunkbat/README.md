# Demo 01: Hello skunkBat

**Duration**: 5 minutes  
**Difficulty**: Beginner  
**Prerequisites**: None

---

## 🎯 What This Demo Shows

- skunkBat initialization
- Local network reconnaissance
- Self-knowledge principle (only knows itself by default)
- Basic health monitoring

---

## 🚀 Run the Demo

```bash
./demo.sh
```

---

## 📋 Expected Output

```
🦨 skunkBat - Hello World Demo
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Step 1: Initialize skunkBat...
✓ Configuration loaded
✓ Engines initialized
✓ skunkBat ready

Step 2: Start reconnaissance...
✓ Local network scan started
✓ Primal discovery active

Step 3: Scan results...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Discovered Nodes: 1
  • local-skunkbat
    Type: skunkBat
    Status: Healthy
    Capabilities: reconnaissance, threat-detection, defense

Discovered Connections: 0
  (No external connections - this is expected!)

Threat Assessment: CLEAR
  No threats detected

Defense Status: MONITORING
  All engines operational

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Demo Complete!

Key Takeaway:
skunkBat by default only knows about ITSELF.
It doesn't discover other nodes without explicit
integration (Toadstool for discovery).

This is the "self-knowledge" principle:
- No hardcoded other primals
- Local by default
- Discovers ecosystem at runtime (when integrated)
```

---

## 🔍 What's Happening

### Step 1: Initialization
```rust
// skunkBat creates default configuration
let config = Config::builder()
    .reconnaissance_enabled(true)
    .threat_detection_enabled(true)
    .defense_enabled(false)  // Just monitoring for this demo
    .build()?;

let mut skunkbat = SkunkBat::new(config);
skunkbat.start().await?;
```

### Step 2: Reconnaissance
```rust
// Scan local network
let scan = skunkbat.scan_network().await?;

// With default LocalPrimalDiscovery, only returns local node
// To discover more, you'd inject ToadstoolDiscovery trait
```

### Step 3: Results
The scan returns:
- **1 node**: `local-skunkbat` (itself)
- **0 connections**: No external connections
- **0 threats**: Clean state

---

## 🎓 Learning Points

### 1. Self-Knowledge Principle
skunkBat only knows about itself by default:
- No hardcoded list of other primals
- No automatic network scanning
- Discovery requires explicit integration

**Why?** Sovereignty - you control what skunkBat can see.

### 2. Local-First Design
Default implementations are local-only:
```rust
pub struct LocalPrimalDiscovery;

impl PrimalDiscovery for LocalPrimalDiscovery {
    async fn discover_local(&self) -> Result<Vec<Node>> {
        Ok(vec![Node::local()])  // Only returns self
    }
}
```

### 3. Runtime Integration
To discover other primals, you inject a trait:
```rust
// With Toadstool integration
let discovery = ToadstoolDiscovery::new(toadstool_client);
let recon = ReconnaissanceEngine::with_discovery(
    &config,
    Box::new(discovery),  // Now can discover ecosystem
    Box::new(SimpleTopologyMapper),
);
```

---

## 🔬 Experiment Ideas

### Modify the Demo

1. **Enable Defense Mode**
   ```bash
   # Edit demo script, change:
   defense_enabled: false
   # To:
   defense_enabled: true
   ```

2. **Change Log Level**
   ```bash
   RUST_LOG=debug ./demo.sh
   ```

3. **Run Multiple Times**
   ```bash
   # Should be identical each time (deterministic)
   for i in {1..5}; do ./demo.sh; done
   ```

---

## 📊 Demo Implementation

This demo runs:
```bash
cargo run --example basic_usage
```

Which uses `examples/basic_usage.rs` from the main codebase.

**Current State**: ✅ Working (uses existing example)

---

## ➡️ Next Demo

**Continue to**: `../02-violation-detection/` to see all 4 threat detection types

---

**Key Takeaway**: skunkBat starts with self-knowledge only. Discovery requires integration - this is sovereignty by design! 🦨


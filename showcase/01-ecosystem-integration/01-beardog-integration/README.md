# Demo 01: Beardog Integration (Genetic Trust)

**Duration**: 10 minutes  
**Difficulty**: Intermediate  
**Prerequisites**: Level 0 complete

---

## 🎯 What This Demo Shows

Integration with Beardog for cryptographic lineage verification (WHO).

---

## 🚀 Run the Demo

```bash
./demo.sh
```

---

## 📋 Expected Output

```
🦨 + 🐻 skunkBat + Beardog Integration Demo
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Scenario: Node attempts connection to YOUR network

Step 1: Connection received
  Source: node-abc123
  IP: 192.168.1.50
  Requested service: data-access

Step 2: skunkBat requests lineage verification
  → Querying Beardog...

Step 3: Beardog response
  ✓ Valid genetic lineage found!
  
  Lineage Chain:
    └─ BearDog Root (genesis)
       └─ YourTower (your-tower-id)
          └─ node-abc123 (requesting node)
  
  Trust: FAMILY (verified descendant)

Step 4: skunkBat decision
  ✓ Connection APPROVED
  Reason: Valid family lineage verified by Beardog

Step 5: Audit log
  ✓ Logged to local audit trail
  ✓ Shared with federation (if enabled)

═══════════════════════════════════════════
COMPARISON: With vs Without Beardog
═══════════════════════════════════════════

WITHOUT Beardog (stub):
  • Local-only verification
  • No cryptographic proof
  • Trust = "maybe?"

WITH Beardog (real):
  • Cryptographic lineage chain
  • Genetic trust verification
  • Trust = "proven family"

✅ Demo Complete!
```

---

## 🔍 What's Happening

### Integration Architecture

```rust
// skunkBat uses Beardog via trait
pub trait LineageVerifier {
    async fn is_family(&self, peer_id: &str) -> Result<bool>;
    async fn get_lineage(&self, peer_id: &str) -> Result<Option<String>>;
}

// Real Beardog implementation
pub struct BeardogLineageVerifier {
    beardog_client: BeardogClient,
}

impl LineageVerifier for BeardogLineageVerifier {
    async fn is_family(&self, peer_id: &str) -> Result<bool> {
        // Query Beardog for cryptographic lineage proof
        let lineage = self.beardog_client
            .verify_lineage(peer_id)
            .await?;
        
        Ok(lineage.is_valid_descendant())
    }
}
```

---

## 🎓 Learning Points

### 1. Genetic Trust vs Behavioral Trust

**Genetic (Beardog)**:
- Cryptographic proof of identity
- Based on lineage chain
- Can't be faked or impersonated

**Behavioral (traditional)**:
- Based on past actions
- Requires long observation period
- Can be gamed or spoofed

### 2. Trait-Based Integration

skunkBat uses traits for all external dependencies:
- `LineageVerifier` for Beardog
- `PrimalDiscovery` for Toadstool
- `ThreatBroadcaster` for Songbird

This means:
- ✅ Stub implementations for testing
- ✅ Real implementations for production
- ✅ Easy to swap or upgrade
- ✅ No hard dependencies

### 3. Self-Knowledge Principle

Notice what skunkBat does NOT know:
- ❌ How to find Beardog
- ❌ How Beardog works internally
- ❌ Beardog's storage or crypto details

skunkBat only knows:
- ✅ The trait interface
- ✅ What questions to ask
- ✅ How to interpret answers

---

## 🔬 Experiment Ideas

1. **Test Invalid Lineage**
   - Modify demo to use unknown peer ID
   - See how skunkBat handles rejection

2. **Compare Performance**
   - Stub vs real Beardog verification
   - Measure latency impact

3. **Federation Scenarios**
   - Multiple towers with different lineages
   - Cross-federation trust decisions

---

## 📊 Current State

**Implementation Status**: ⚠️ Stub (uses `LocalLineageVerifier`)

To connect to real Beardog:
```bash
# 1. Add Beardog client dependency
cd crates/skunk-bat-core
cargo add beardog-client

# 2. Implement BeardogLineageVerifier
# 3. Inject at runtime
```

---

## ➡️ Next Demo

**Continue to**: `../02-toadstool-integration/` to see primal discovery 🦨


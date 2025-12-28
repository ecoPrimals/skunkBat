# Demo 03: Defense Actions

**Duration**: 10 minutes  
**Difficulty**: Beginner  
**Prerequisites**: 02-violation-detection

---

## 🎯 What This Demo Shows

User-approved defense responses:
- **Monitor + Alert** (Low severity, requires approval)
- **Quarantine + Alert** (High severity, automatic)
- **Immediate Quarantine** (Critical, no approval needed)
- **Block** (Operator decision, explicit)

### Key Philosophy

**Owner Authority**: skunkBat suggests, YOU decide.

---

## 🚀 Run the Demo

```bash
./demo.sh
```

---

## 📋 Expected Output

```
🦨 skunkBat - Defense Actions Demo
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. MONITOR + ALERT (Low Severity)
   ✓ Connection allowed to continue
   → Logged for analysis
   → Requires operator approval for escalation

2. QUARANTINE + ALERT (High Severity)
   ✓ Connection isolated (not blocked)
   → Traffic rate-limited automatically
   → Operator alerted for review
   → Can be released if verified legitimate

3. IMMEDIATE QUARANTINE (Critical)
   ✓ No approval required (critical threat)
   → Quarantine executed instantly
   → Service availability protected
   → Operator can review and release

4. BLOCK (Operator Decision)
   Note: Available but rarely used automatically
   → Quarantine is preferred (reversible)
   → Block requires explicit operator decision

SUMMARY:
  Defense Philosophy:
    ✓ Graduated response
    ✓ User authority
    ✓ Reversible first
    ✓ Context-aware
    ✓ Audit logged
```

---

## 🔍 What's Happening

### Graduated Response System

```rust
fn determine_action(threat: &Threat) -> DefenseAction {
    // Critical: Immediate quarantine (no approval)
    if threat.severity == Severity::Critical && threat.confidence > 0.9 {
        return DefenseAction {
            action_type: ActionType::Quarantine,
            requires_approval: false,
        };
    }
    
    // High: Quarantine with alert
    if threat.severity == Severity::High && threat.confidence > 0.7 {
        return DefenseAction {
            action_type: ActionType::QuarantineAndAlert,
            requires_approval: false,
        };
    }
    
    // Medium/Low: Monitor and alert
    DefenseAction {
        action_type: ActionType::MonitorAndAlert,
        requires_approval: true, // Owner decides
    }
}
```

---

## 🎓 Learning Points

### 1. Action Hierarchy

- **Monitor** → Observe, don't interfere
- **Quarantine** → Isolate, but allow review  
- **Block** → Permanent denial (operator decision)

### 2. Why Quarantine Before Block?

**Reversibility**:
- False positives happen
- Legitimate unusual traffic exists
- Owner should review before permanent action

**Example**:
- Quarantine: "Isolate and notify me"
- Block: "I've reviewed, permanently deny"

### 3. Approval Workflow

```rust
pub struct DefenseAction {
    action_type: ActionType,
    requires_approval: bool, // Owner authority
    reason: String,          // Transparency
}
```

**When approval required:**
- Low confidence threats
- Medium severity
- Ambiguous patterns

**When automatic:**
- Critical severity + high confidence
- Service availability at risk
- Still reversible (quarantine, not block)

### 4. No "Rate Limit" Action?

**Gap Identified**: README originally mentioned "Rate Limit" as a separate action type.

**Current Implementation**: Rate limiting is part of **Quarantine**:

```rust
ActionType::Quarantine => {
    // Quarantine includes:
    // - Rate limiting traffic
    // - Restricting capabilities
    // - Logging activity
    self.quarantine_connection(&target);
}
```

**Why Combined**:
- Rate limiting IS a form of quarantine
- Simpler action model
- Same operator workflow

---

## 🔬 Experiment Ideas

1. **Adjust Confidence Thresholds**
   - Change `confidence > 0.9` to `> 0.8`
   - See how response sensitivity changes

2. **Test False Positive Recovery**
   - Quarantine a "threat"
   - Simulate operator review
   - Release from quarantine

3. **Simulate Escalation**
   - Start with Monitor
   - Same source repeats behavior
   - Escalate to Quarantine → Block

---

## 📊 Demo Implementation

This demo uses:
- `examples/defense_actions.rs` (**NEW**: comprehensive demo)
- Real `DefenseEngine` with actual action execution
- Production `determine_action()` logic
- Live threat response workflow

**Current State**: ✅ **PRODUCTION READY** (no mocks, real code)

---

## ➡️ Next Demo

**Continue to**: `../04-baseline-learning/` to see statistical profiling 🦨


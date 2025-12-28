# Violation Detection - How skunkBat Senses Threats

**Defensive reconnaissance through pattern recognition, not surveillance**

---

## Philosophy: Sense vs Surveil

### What skunkBat DOES (Defensive Sensing)
```
✅ Monitors YOUR network perimeter
✅ Detects violations of YOUR policies
✅ Learns YOUR normal patterns (baseline)
✅ Alerts YOU to deviations
✅ Requires YOUR authorization to act
✅ Logs for YOUR review
```

### What skunkBat DOES NOT DO (Surveillance)
```
❌ Monitor user behavior/content
❌ Profile individuals
❌ Track browsing/activity
❌ Persist personal data
❌ Report to external authorities
❌ Make moral judgments
```

**Key Difference:** skunkBat watches **connections and patterns**, not **people and content**.

---

## Four Violation Types

### 1. Genetic Violations (Who)
**Question:** "Is this entity who they claim to be?"

```rust
// Beardog verifies cryptographic lineage
pub async fn detect_genetic_violation(
    connection: &Connection,
    lineage_verifier: &dyn LineageVerifier,
) -> Result<Option<Threat>> {
    // Check genetic lineage
    let is_family = lineage_verifier
        .is_family(&connection.source_id)
        .await?;
    
    if !is_family {
        // Not in trusted lineage = genetic violation
        return Ok(Some(Threat {
            threat_type: ThreatType::GeneticViolation,
            source: connection.source_id.clone(),
            severity: Severity::High,
            description: format!(
                "Connection from {} lacks valid genetic lineage",
                connection.source_id
            ),
        }));
    }
    
    // Check if lineage has been revoked
    let lineage = lineage_verifier
        .get_lineage(&connection.source_id)
        .await?;
    
    if let Some(l) = lineage {
        if l.is_revoked() {
            return Ok(Some(Threat {
                threat_type: ThreatType::GeneticRevocation,
                source: connection.source_id.clone(),
                severity: Severity::Critical,
                description: format!(
                    "Connection from revoked lineage: {:?}",
                    l.revocation_reason
                ),
            }));
        }
    }
    
    Ok(None)
}
```

**Defensive Nature:**
- Checks identity, not behavior
- Binary decision: valid lineage or not
- No profiling of individuals
- No persistent tracking

**Demonstrates:** "Who are you?" not "What are you doing?"

---

### 2. Topology Violations (Where)
**Question:** "Are you accessing through the correct path?"

```rust
// Validates connection follows required topology layers
pub async fn detect_topology_violation(
    connection: &Connection,
    topology_mapper: &dyn TopologyMapper,
) -> Result<Option<Threat>> {
    // Get required path for this connection
    let required_path = topology_mapper
        .get_required_path(
            connection.from_layer,
            connection.to_layer
        ).await?;
    
    // Validate actual path matches required path
    let actual_path = topology_mapper
        .trace_connection_path(connection)
        .await?;
    
    if actual_path != required_path {
        // Layer-hopping detected!
        return Ok(Some(Threat {
            threat_type: ThreatType::TopologyViolation,
            source: connection.source_id.clone(),
            severity: Severity::Critical,
            description: format!(
                "Layer-hopping: {} attempted to bypass security layers\n\
                 Required: {:?}\n\
                 Actual: {:?}",
                connection.source_id,
                required_path,
                actual_path
            ),
        }));
    }
    
    Ok(None)
}
```

**Defensive Nature:**
- Validates path structure, not content
- Architectural boundary enforcement
- No inspection of payloads
- Binary: correct path or not

**Demonstrates:** "Did you enter through the front door?" not "What are you carrying?"

---

### 3. Behavioral Anomalies (Pattern)
**Question:** "Is this behavior normal for YOUR network?"

```rust
// Statistical baseline profiler
pub struct StatisticalProfiler {
    baseline: NetworkBaseline,
    threshold: f64,  // Std deviations
}

pub async fn detect_behavioral_anomaly(
    observation: &Observation,
    profiler: &dyn BaselineProfiler,
) -> Result<Vec<Threat>> {
    let mut threats = Vec::new();
    
    // Only check if baseline is established
    if !profiler.is_established() {
        // Still learning normal patterns
        profiler.update(observation).await?;
        return Ok(threats);
    }
    
    // Detect anomalies against YOUR baseline
    let anomalies = profiler
        .detect_anomalies(observation)
        .await?;
    
    for anomaly in anomalies {
        threats.push(Threat {
            threat_type: ThreatType::BehaviorAnomaly {
                behavior: anomaly.behavior.clone(),
                deviation: anomaly.deviation,
            },
            source: observation.source.clone(),
            severity: match anomaly.deviation {
                d if d > 5.0 => Severity::Critical,
                d if d > 3.0 => Severity::High,
                d if d > 2.0 => Severity::Medium,
                _ => Severity::Low,
            },
            description: format!(
                "Abnormal {}: {:.2}σ deviation from baseline",
                anomaly.behavior,
                anomaly.deviation
            ),
        });
    }
    
    Ok(threats)
}
```

**Defensive Nature:**
- Learns YOUR network's normal (not universal "normal")
- Detects deviations from YOUR baseline
- Statistical, not content-based
- Ephemeral (baseline can be reset)

**Demonstrates:** "This is unusual for YOUR network" not "This is bad behavior universally"

---

### 4. Resource Exhaustion (Capacity)
**Question:** "Are you consuming excessive resources?"

```rust
// DoS detection
pub async fn detect_resource_exhaustion(
    connection: &Connection,
    metrics: &SystemMetrics,
) -> Result<Option<Threat>> {
    let mut issues = Vec::new();
    
    // Check connection rate
    if connection.rate > metrics.max_connection_rate {
        issues.push(format!(
            "Excessive connection rate: {} req/s (limit: {})",
            connection.rate,
            metrics.max_connection_rate
        ));
    }
    
    // Check bandwidth consumption
    if connection.bandwidth > metrics.max_bandwidth_per_source {
        issues.push(format!(
            "Excessive bandwidth: {} MB/s (limit: {})",
            connection.bandwidth,
            metrics.max_bandwidth_per_source
        ));
    }
    
    // Check CPU/memory impact
    let load = check_system_load();
    if load > 0.9 {
        issues.push(format!(
            "High system load: {:.1}% (threshold: 90%)",
            load * 100.0
        ));
    }
    
    if !issues.empty() {
        return Ok(Some(Threat {
            threat_type: ThreatType::ResourceExhaustion,
            source: connection.source_id.clone(),
            severity: Severity::High,
            description: format!(
                "Resource exhaustion from {}:\n{}",
                connection.source_id,
                issues.join("\n")
            ),
        }));
    }
    
    Ok(None)
}
```

**Defensive Nature:**
- Protects YOUR resources
- Quantitative thresholds (YOUR policies)
- No judgment of intent
- Responds to impact, not motivation

**Demonstrates:** "You're consuming too much of MY resources" not "You're a bad actor"

---

## Complete Detection Flow

```rust
/// Comprehensive threat detection
pub async fn detect_all_violations(
    scan: &NetworkScan,
    engines: &DetectionEngines,
) -> Result<Vec<Threat>> {
    let mut all_threats = Vec::new();
    
    for connection in &scan.connections {
        // 1. Genetic check (WHO)
        if let Some(threat) = detect_genetic_violation(
            connection,
            &engines.lineage_verifier
        ).await? {
            all_threats.push(threat);
            // Genetic violation is critical - skip further checks
            continue;
        }
        
        // 2. Topology check (WHERE)
        if let Some(threat) = detect_topology_violation(
            connection,
            &engines.topology_mapper
        ).await? {
            all_threats.push(threat);
            // Topology violation is critical - skip further checks
            continue;
        }
        
        // 3. Behavioral check (PATTERN)
        let behavioral_threats = detect_behavioral_anomaly(
            &connection.to_observation(),
            &engines.baseline_profiler
        ).await?;
        all_threats.extend(behavioral_threats);
        
        // 4. Resource check (CAPACITY)
        if let Some(threat) = detect_resource_exhaustion(
            connection,
            &engines.system_metrics
        ).await? {
            all_threats.push(threat);
        }
    }
    
    Ok(all_threats)
}
```

---

## Why This Is NOT Surveillance

### 1. No Content Inspection
```rust
// What we DON'T look at:
❌ Packet payloads
❌ User data
❌ Message content
❌ File contents
❌ Browsing history
❌ Personal information

// What we DO look at:
✅ Connection metadata (source, destination, rate)
✅ Cryptographic proofs (lineage)
✅ Topology paths (layer traversal)
✅ Statistical patterns (deviations)
✅ Resource consumption (impact)
```

### 2. No Persistent Profiling
```rust
// Baseline is:
✅ Network-level patterns (aggregate)
✅ Ephemeral (can be reset)
✅ Local (YOUR network only)
✅ Statistical (anonymous)
✅ Defensive (protect resources)

// Baseline is NOT:
❌ Individual behavior tracking
❌ Permanent user profiles
❌ Cross-network correlation
❌ Identity-linked data
❌ Behavioral prediction
```

### 3. No Moral Judgment
```rust
// Detection is binary/quantitative:
✅ Valid lineage or not
✅ Correct path or not
✅ Within statistical bounds or not
✅ Under resource limits or not

// Detection is NOT subjective:
❌ "Good" vs "bad" behavior
❌ "Acceptable" vs "unacceptable" content
❌ "Normal" vs "deviant" users
❌ Moral/ethical judgments
```

### 4. User Authority Required
```rust
// Detection only alerts owner
// Owner decides response:
pub enum OwnerDecision {
    Allow,              // False positive, ignore
    Monitor,            // Watch but don't act
    Quarantine,         // Isolate for review
    Block,              // Deny access
}

// skunkBat suggests, owner decides
```

---

## Demonstration Examples

### Example 1: Genetic Violation

```bash
cargo run --example showcase_genetic_violation

# Output:
# ✓ Connection from family@network - Valid lineage
# ✗ Connection from unknown@external - GENETIC VIOLATION
#   → Threat detected: No valid lineage
#   → Severity: High
#   → Recommended action: Quarantine
#   → Awaiting owner decision...
```

### Example 2: Topology Violation

```bash
cargo run --example showcase_topology_violation

# Output:
# ✓ Layer 0 → Layer 1 - Valid path
# ✓ Layer 1 → Layer 2 - Valid path
# ✗ Layer 0 → Layer 3 - TOPOLOGY VIOLATION
#   → Attempted layer-hopping (bypassed Layers 1 & 2)
#   → Threat detected: Invalid path
#   → Severity: Critical
#   → Recommended action: Block
#   → Awaiting owner decision...
```

### Example 3: Behavioral Anomaly

```bash
cargo run --example showcase_behavioral_anomaly

# Output:
# Learning baseline... (100 observations)
# Baseline established:
#   - Normal connection rate: 10.2 ± 2.1 req/s
#   - Normal bandwidth: 5.3 ± 1.2 MB/s
#
# ✓ Connection at 11.5 req/s - Within baseline (0.6σ)
# ✗ Connection at 25.0 req/s - BEHAVIORAL ANOMALY
#   → Deviation: 7.0σ from baseline
#   → Severity: Critical
#   → Recommended action: Rate limit
#   → Awaiting owner decision...
```

---

## Gap Analysis

### Current State ✅
- Genetic verification trait defined
- Topology validation trait defined
- Behavioral profiler trait defined
- Resource monitoring framework

### Missing (Gaps) ⚠️
- [ ] Beardog client integration (stubbed)
- [ ] Songbird topology client (stubbed)
- [ ] Persistent baseline storage
- [ ] Statistical profiler tuning
- [ ] Resource metrics collection (partial)

### Evolution Path →
1. Integrate real Beardog for lineage
2. Integrate real Songbird for topology
3. Implement baseline persistence (optional)
4. Tune anomaly detection thresholds
5. Complete resource metrics

**See:** `showcase/99-gaps-analysis/` for details

---

## Running the Demonstrations

```bash
# Individual demonstrations
cd showcase/01-violation-detection
cargo run --example genetic_violation
cargo run --example topology_violation
cargo run --example behavioral_anomaly
cargo run --example resource_exhaustion

# All demonstrations
./run_all_violations.sh
```

---

**Key Takeaway:** skunkBat detects violations through **defensive pattern recognition** (what's unusual for YOUR network) not **offensive surveillance** (watching people's behavior for judgment).

🦨 Sense violations • Don't surveil people • Defend YOUR resources 🛡️


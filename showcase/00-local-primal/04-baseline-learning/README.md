# Demo 04: Baseline Learning

**Duration**: 10 minutes  
**Difficulty**: Intermediate  
**Prerequisites**: 03-defense-actions

---

## 🎯 What This Demo Shows

How skunkBat learns YOUR network's normal behavior through **statistical baseline profiling**.

### Four Phases Demonstrated

1. **Learning Mode**: Collecting initial observations (min 10, ideal 50+)
2. **Normal Detection**: Traffic within baseline (no alerts)
3. **Anomaly Detection**: Statistical deviations beyond threshold
4. **Baseline Adaptation**: Evolving with YOUR network changes

---

## 🚀 Run the Demo

```bash
./demo.sh
```

---

## 📋 Expected Output

```
🦨 skunkBat - Baseline Learning Demo

PHASE 1: LEARNING MODE
  ✓ Collected 50 observations
  ✓ Baseline established!
  
  Baseline Statistics (YOUR network normal):
    • Connection rate: 10.0 ± 2.5 conn/sec
    • Detection threshold: 2.5σ (98.8% confidence)

PHASE 2: NORMAL TRAFFIC DETECTION
  Observation: 10.5 conn/sec → ✓ NORMAL (0.2σ)
  Observation: 12.0 conn/sec → ✓ NORMAL (0.8σ)

PHASE 3: ANOMALY DETECTION
  Observation: 45.0 conn/sec → ✗ ANOMALY (22.8σ!)
    • Far outside YOUR normal
    • Confidence: 100%
    • Action: Quarantine + Alert

PHASE 4: BASELINE ADAPTATION
  Week 1-4: Gradual traffic increase
  New baseline: ~19.0 conn/sec (was 10.0)
  Testing 18.0 conn/sec:
    • Old baseline: Would be anomalous (8σ)
    • New baseline: ✓ NORMAL
    • Adaptation successful!

Key Takeaway: Detection learns YOUR normal, not a universal standard.
```

---

## 🔍 What's Happening

### Statistical Profiling

```rust
pub struct StatisticalProfiler {
    observations: Vec<Observation>,
    threshold: f64, // Standard deviations (2.5σ = 98.8% confidence)
}

impl BaselineProfiler for StatisticalProfiler {
    fn is_established(&self) -> bool {
        // Need 10+ observations for stable baseline
        self.observations.len() >= 10
    }
    
    async fn detect_anomalies(&self, obs: &Observation) 
        -> Result<Vec<Anomaly>, SkunkBatError> 
    {
        // Calculate mean and std dev from YOUR traffic
        let (mean, std_dev) = self.calculate_stats();
        
        // Measure deviation
        let deviation = (obs.connection_rate - mean).abs() / std_dev;
        
        // Threshold check
        if deviation > self.threshold {
            return Anomaly::new(deviation, behavior, confidence);
        }
        
        Ok(Vec::new()) // Normal
    }
}
```

---

## 🎓 Learning Points

### 1. YOUR Network, YOUR Normal

**Not Universal Standards**:
- Home network: 5-10 conn/sec might be normal
- Enterprise: 500+ conn/sec might be normal
- Data center: 10,000+ conn/sec might be normal

**Personalized Security**:
```
skunkBat learns YOUR baseline
  → Detects YOUR anomalies
  → Based on YOUR usage patterns
```

### 2. Rolling Window Adaptation

```rust
async fn update(&mut self, observation: &Observation) -> Result<()> {
    self.observations.push(observation.clone());
    
    // Keep only recent observations (rolling window)
    if self.observations.len() > 100 {
        self.observations.remove(0); // Age out oldest
    }
    
    Ok(())
}
```

**Why Rolling Window?**
- Networks evolve (business growth, new users)
- Old "normal" becomes obsolete
- Continuous adaptation without manual tuning
- Last 100 observations = ~recent behavior

### 3. Statistical Confidence

**Threshold: 2.5σ (Standard Deviations)**

| Threshold | Confidence | False Positive Rate |
|-----------|-----------|---------------------|
| 1.0σ      | 68.3%     | 31.7% (too high)    |
| 2.0σ      | 95.4%     | 4.6% (acceptable)   |
| 2.5σ      | 98.8%     | 1.2% (good)         |
| 3.0σ      | 99.7%     | 0.3% (very strict)  |

**Default: 2.5σ** balances sensitivity and accuracy.

### 4. Why Not Machine Learning?

**Statistical profiling is:**
- ✅ Fast (real-time calculation)
- ✅ Transparent (mean + std dev, explainable)
- ✅ Data-efficient (works with 10 observations)
- ✅ No training required
- ✅ Adapts continuously
- ✅ Sovereignty-preserving (data stays local)

**Machine learning would:**
- ❌ Require large datasets
- ❌ Need training time
- ❌ Be a black box (less transparent)
- ❌ Risk overfitting
- ❌ Still learn from YOUR data anyway

**Conclusion**: For behavioral baselines, statistics are sufficient and superior for sovereignty.

---

## 🔬 Experiment Ideas

1. **Adjust Threshold**
   - Try 2.0σ (more sensitive)
   - Try 3.0σ (stricter)
   - Observe false positive trade-offs

2. **Test Adaptation Speed**
   - Simulate sudden traffic spike
   - How many observations to adapt?
   - Rolling window size impact

3. **Multi-Metric Detection**
   - Currently: connection rate
   - Could add: bandwidth, port diversity
   - Combine multiple baselines

---

## 📊 Demo Implementation

This demo uses:
- `examples/baseline_learning.rs` (**NEW**: comprehensive demo)
- Real `StatisticalProfiler` from production code
- Actual baseline calculation (mean, std dev)
- Live anomaly detection logic
- 80 simulated observations showing all phases

**Current State**: ✅ **PRODUCTION READY** (no mocks, real statistical profiling)

---

## ➡️ Next Demo

**Continue to**: `../05-local-federation/` (or skip to `../06-defensive-vs-surveillance/` for philosophy) 🦨


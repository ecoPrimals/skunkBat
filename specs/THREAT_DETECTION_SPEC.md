# skunkBat Threat Detection Specification

**Version:** 0.2.0-dev  
**Status:** Core implemented; thymic selection and bond-type classification in design  
**Author:** ecoPrimals Project  
**Date:** April 2026 (evolved from December 2025 draft)  
**License:** AGPL-3.0-or-later  

---

## Abstract

skunkBat threat detection identifies security threats to YOUR systems using defensive analysis techniques. Unlike surveillance systems that profile people, threat detection focuses on **network behavior patterns that indicate attacks against YOUR infrastructure**.

**Core Approach:** Genetic trust (via BearDog lineage) + behavioral anomaly detection + known attack signatures.

---

## 1. Threat Model

### 1.1 Threats We Detect

**Network-Based Threats (Defensive):**
- ✅ Unknown lineage connections (genetic threats via BearDog)
- ✅ Port scanning attempts (reconnaissance attacks against YOU)
- ✅ Brute-force authentication attacks (against YOUR services)
- ✅ Denial-of-service patterns (resource exhaustion on YOUR systems)
- ✅ Anomalous traffic patterns (unusual behavior on YOUR network)
- ✅ Configuration drift (unexpected changes to YOUR systems)

**What We DON'T Detect (Offensive):**
- ❌ User behavior profiling
- ❌ Content-based threats (we don't inspect payload)
- ❌ "Pre-crime" prediction
- ❌ Thought patterns or intentions

### 1.2 Threat Classification

```rust
/// Threat detected on YOUR network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Threat {
    /// Unique threat identifier
    pub id: ThreatId,
    
    /// Threat type
    pub threat_type: ThreatType,
    
    /// Severity level
    pub severity: Severity,
    
    /// Source of threat (network address, asset)
    pub source: ThreatSource,
    
    /// Target of threat (YOUR system)
    pub target: ThreatTarget,
    
    /// Detection timestamp
    pub detected_at: Timestamp,
    
    /// Evidence (reconnaissance data)
    pub evidence: Vec<Evidence>,
    
    /// Recommended response
    pub recommended_action: DefenseAction,
    
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
}

/// Threat types (all defensive)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ThreatType {
    /// Unknown genetic lineage (not family)
    UnknownLineage {
        peer_id: Did,
        lineage: Option<LineageChain>,
    },
    
    /// Behavior anomaly (unusual pattern)
    BehaviorAnomaly {
        baseline: BaselineProfile,
        observed: ObservedBehavior,
        deviation: f64,
    },
    
    /// Intrusion attempt (attack signature matched)
    IntrusionAttempt {
        attack_type: AttackType,
        signature: Signature,
    },
    
    /// Denial of service (resource exhaustion)
    DenialOfService {
        resource: Resource,
        threshold: f64,
        current: f64,
    },
    
    /// Configuration drift (unexpected change)
    ConfigurationDrift {
        expected: Configuration,
        observed: Configuration,
        drift: DriftAnalysis,
    },
}
```

---

## 2. Detection Architecture

### 2.1 Genetic Threat Analysis (via BearDog)

**Principle:** Trust is determined by genetic lineage, not behavior.

```rust
/// Genetic threat analyzer using BearDog lineage
pub struct GeneticThreatAnalyzer {
    /// BearDog client (lineage verification)
    beardog: BeardogClient,
    
    /// Trust policy (family vs. stranger)
    trust_policy: TrustPolicy,
    
    /// Lineage cache (performance)
    cache: LineageCache,
}

impl GeneticThreatAnalyzer {
    /// Analyze connection for genetic threats
    pub async fn analyze_connection(
        &self,
        connection: &Connection,
    ) -> Result<Option<Threat>, ThreatError> {
        // Extract peer DID
        let peer_did = connection.peer_did()
            .ok_or(ThreatError::NoDid)?;
        
        // Verify lineage via BearDog
        match self.beardog.verify_lineage(peer_did).await {
            Ok(lineage) if self.trust_policy.is_family(&lineage) => {
                // Family connection - trusted
                Ok(None)
            }
            Ok(lineage) => {
                // Stranger connection - potential threat
                Ok(Some(Threat {
                    threat_type: ThreatType::UnknownLineage {
                        peer_id: peer_did.clone(),
                        lineage: Some(lineage),
                    },
                    severity: Severity::Medium,
                    source: ThreatSource::PeerId(peer_did),
                    recommended_action: DefenseAction::Quarantine,
                    confidence: 0.9,
                    // ...
                }))
            }
            Err(e) => {
                // Cannot verify lineage - treat as threat
                Ok(Some(Threat {
                    threat_type: ThreatType::UnknownLineage {
                        peer_id: peer_did.clone(),
                        lineage: None,
                    },
                    severity: Severity::High,
                    source: ThreatSource::PeerId(peer_did),
                    recommended_action: DefenseAction::Block,
                    confidence: 0.95,
                    // ...
                }))
            }
        }
    }
}
```

**Key Points:**
- Genetic trust = cryptographic (lineage chain verification)
- Family nodes = trusted by default (opt-in federation)
- Stranger nodes = flagged for review (can be manually allowed)
- No behavioral profiling (trust is structural, not behavioral)

### 2.2 Anomaly Detection (Behavioral Patterns)

**Principle:** Detect unusual patterns that deviate from YOUR normal baseline.

```rust
/// Anomaly detector for YOUR network
pub struct AnomalyDetector {
    /// Baseline profile (what's "normal" for YOUR network)
    baseline: BaselineProfile,
    
    /// Statistical analyzer
    analyzer: StatisticalAnalyzer,
    
    /// Threshold configuration
    thresholds: AnomalyThresholds,
}

impl AnomalyDetector {
    /// Detect anomalies in network behavior
    pub async fn detect_anomalies(
        &self,
        behavior: &ObservedBehavior,
    ) -> Result<Vec<Threat>, ThreatError> {
        let mut threats = Vec::new();
        
        // Analyze traffic volume
        if let Some(deviation) = self.analyze_traffic_volume(behavior).await? {
            if deviation > self.thresholds.traffic_volume {
                threats.push(Threat {
                    threat_type: ThreatType::BehaviorAnomaly {
                        baseline: self.baseline.clone(),
                        observed: behavior.clone(),
                        deviation,
                    },
                    severity: Self::classify_severity(deviation),
                    // ...
                });
            }
        }
        
        // Analyze connection patterns
        if let Some(anomaly) = self.analyze_connection_patterns(behavior).await? {
            threats.push(self.create_anomaly_threat(anomaly));
        }
        
        // Analyze port usage
        if let Some(anomaly) = self.analyze_port_usage(behavior).await? {
            threats.push(self.create_anomaly_threat(anomaly));
        }
        
        Ok(threats)
    }
    
    /// Build baseline profile from historical data
    pub async fn build_baseline(
        &mut self,
        historical_data: Vec<ObservedBehavior>,
    ) -> Result<(), ThreatError> {
        self.baseline = self.analyzer.compute_baseline(historical_data).await?;
        Ok(())
    }
}
```

**Baseline Profiling:**
- Learn what's "normal" for YOUR network
- Statistical analysis (mean, standard deviation, percentiles)
- Time-series patterns (daily, weekly cycles)
- Dynamic updating (adapt to legitimate changes)

**Privacy Preservation:**
- Metadata-only analysis (no content inspection)
- Aggregate patterns (not individual behavior)
- Network-level (not user-level)

---

## 3. Threat Intelligence

### 3.1 Local Threat Database

```rust
/// Local threat intelligence database
pub struct ThreatIntelDatabase {
    /// Known attack signatures
    signatures: SignatureDatabase,
    
    /// Historical threats (for YOUR network)
    history: ThreatHistory,
    
    /// False positive tracking
    false_positives: FalsePositiveTracker,
}
```

### 3.2 Federated Threat Intelligence (Opt-In)

**Principle:** Share threat signatures with family (not raw data).

```rust
/// Federated threat intelligence (opt-in, family-only)
pub struct FederatedThreatIntel {
    /// BearDog client (family verification)
    beardog: BeardogClient,
    
    /// Threat signature sharing (no raw data)
    sharing: ThreatSignatureSharing,
    
    /// Federation policy
    policy: FederationPolicy,
}

impl FederatedThreatIntel {
    /// Share threat signature with family
    pub async fn share_threat(
        &self,
        threat: &Threat,
    ) -> Result<(), ThreatError> {
        // Verify federation enabled
        if !self.policy.federation_enabled {
            return Ok(()); // Not sharing
        }
        
        // Create signature (no identifying data)
        let signature = ThreatSignature {
            pattern: threat.fingerprint(), // Hash
            severity: threat.severity,
            threat_type: threat.threat_type.classify(),
            timestamp: Timestamp::now(),
            // NO source IP, NO target info, NO raw data
        };
        
        // Share with family only
        self.sharing.share_with_family(signature).await?;
        
        Ok(())
    }
}
```

**What Gets Shared:**
- ✅ Threat pattern fingerprints (hashes)
- ✅ Severity and type
- ✅ Timestamps
- ❌ NO source IPs
- ❌ NO target information
- ❌ NO raw packet data
- ❌ NO identifying information

---

## 4. Integration with Reconnaissance

```rust
/// Threat detector integrated with reconnaissance
pub struct IntegratedThreatDetector {
    /// Reconnaissance engine (network scanning)
    recon: ReconnaissanceEngine,
    
    /// Genetic analyzer (BearDog lineage)
    genetic: GeneticThreatAnalyzer,
    
    /// Anomaly detector (behavioral patterns)
    anomaly: AnomalyDetector,
    
    /// Signature matcher (known attacks)
    signature: SignatureMatcher,
}

impl IntegratedThreatDetector {
    /// Continuous threat detection loop
    pub async fn detect_threats(&self) -> Result<Vec<Threat>, ThreatError> {
        // Get reconnaissance data
        let topology = self.recon.get_topology().await?;
        let assets = self.recon.list_assets().await?;
        
        let mut threats = Vec::new();
        
        // Genetic threat analysis (via BearDog)
        for asset in &assets {
            if let Some(threat) = self.genetic.analyze_asset(asset).await? {
                threats.push(threat);
            }
        }
        
        // Anomaly detection (behavioral patterns)
        let behavior = self.observe_behavior(&topology).await?;
        threats.extend(self.anomaly.detect_anomalies(&behavior).await?);
        
        // Signature matching (known attacks)
        threats.extend(self.signature.match_signatures(&behavior).await?);
        
        Ok(threats)
    }
}
```

---

## 5. Testing & Validation

### 5.1 Test Threat Scenarios

```rust
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_unknown_lineage_detection() {
        let detector = create_test_detector();
        let stranger = create_stranger_connection();
        
        let threats = detector.detect_threats_from_connection(&stranger).await.unwrap();
        
        assert_eq!(threats.len(), 1);
        assert!(matches!(
            threats[0].threat_type,
            ThreatType::UnknownLineage { .. }
        ));
    }
    
    #[tokio::test]
    async fn test_anomaly_detection() {
        let mut detector = create_test_detector();
        
        // Build baseline
        detector.build_baseline(create_normal_traffic()).await.unwrap();
        
        // Test anomalous traffic
        let anomalous = create_anomalous_traffic();
        let threats = detector.detect_anomalies(&anomalous).await.unwrap();
        
        assert!(!threats.is_empty());
    }
}
```

---

## Appendix: Configuration Example

```yaml
# threat-detection.yaml
threat_detection:
  enabled: true
  
  # Genetic threat analysis (via BearDog)
  genetic:
    enabled: true
    trust_policy:
      family_trusted: true
      stranger_action: quarantine
  
  # Anomaly detection
  anomaly:
    enabled: true
    baseline:
      learning_period: 7d
      update_frequency: 1h
    thresholds:
      traffic_volume: 2.5  # Standard deviations
      connection_rate: 3.0
      port_scanning: 2.0
  
  # Federated intelligence (opt-in)
  federation:
    enabled: false  # Opt-in
    family_only: true
    share_signatures: true  # Signatures only, not raw data
```

---

## 6. Thymic Selection Model (PLANNED)

> **Status: DESIGN PHASE** — not yet implemented. See `THYMIC_SELECTION_SPEC.md`
> for the full specification.

### 6.1 Biological Analogy

The thymus trains T-cells to distinguish **self** from **non-self** through
two selection phases. skunkBat applies the same principle: instead of
maintaining a database of known attacks (signature-based), it learns what
**self** looks like and flags everything else.

**Positive selection** — Can a detector probe read BearDog's identity system?
Probes are tested against `btsp.server.verify` and `genetic.verify_lineage`
responses. Probes that cannot parse identity presentations are useless and
are eliminated.

**Negative selection** — Does a detector probe react to verified family
members (covalent bonds)? Probes that flag self are dangerous (autoimmune
risk) and are eliminated. The family roster is built from observed
`genetic.verify_lineage` results and locally cached identities.

**What survives** — Probes that can read the identity system AND do not
react to self. These mature detectors are deployed and will react to any
entity that fails to present valid lineage.

### 6.2 Advantages Over Signature-Based Detection

- Zero-day attacks are detectable — they have no valid lineage
- No signature database to maintain — self-knowledge is the only database
- Novel threats are the default case — everything unknown is non-self
- False positives are trained out via negative selection

### 6.3 Continuous Training Loop

The detector population is regenerated periodically as the network evolves:
new family members join (lineage expansion), members leave (revocation),
behavioral baselines drift. Each regeneration cycle produces fresh detectors
calibrated to the current self-model.

---

## 7. Bond-Type Threat Classification (PLANNED)

> **Status: DESIGN PHASE** — maps the ecosystem bonding model to immune
> categories for threat assessment.

The chemistry bonding model from `ECOSYSTEM_ARCHITECTURE.md` maps to
immunological categories that determine skunkBat's default response:

| Bond Type | Immune Analog | Default Response |
|-----------|---------------|------------------|
| **Covalent** (family seed) | Self — your own cells | Never flag. Autoimmune if attacked. |
| **Ionic** (contract) | Commensal — known beneficial non-self | Tolerate within contract bounds. Monitor for violation. |
| **Metallic** (sub-specialized) | Organ-specific tolerance | Permit within role scope (compute-only, storage-only). |
| **Weak** (pre-trust) | Unknown antigen | Default suspicion. Challenge, probe, verify before trust. |

The Pixel 8a onboarding pattern (weak -> covalent after BearDog verification)
is the canonical example: unknown entity is challenged, lineage is verified
cryptographically, trust escalates. skunkBat monitors the entire transition
and flags anomalies at each stage.

---

**Status:** Core threat detection (sections 1-5) implemented and tested.
Thymic selection (section 6) and bond-type classification (section 7) are
in design phase — see `THYMIC_SELECTION_SPEC.md` and
`COMPOSABLE_PRIMITIVES_SPEC.md` for full specifications.


# skunkBat Automated Defense Specification

**Version:** 0.2.16  
**Status:** Implemented  
**Author:** ecoPrimals Project  
**Date:** December 27, 2025  
**License:** AGPL-3.0  

---

## Abstract

skunkBat automated defense provides **defensive responses to detected threats** while maintaining user sovereignty. Defense mechanisms protect YOUR systems without attacking others, always with transparency and user control.

**Core Principle:** Automate suggestions, not decisions. The user retains ultimate authority.

---

> **Implementation Note (v0.2.16):** The core defense engine is implemented with
> four action types: `MonitorAndAlert`, `Quarantine`, `QuarantineAndAlert`, `Block`.
> Quarantine thresholds are configurable via `ThreatThresholds`. Auto-response
> gating, quarantine tracking, and dispatch-level enforcement are live.
> **Wave 123**: MethodGate enforces origin-based trust (UDS/loopback bypass),
> bearer token extraction from `_auth.token`, BTSP session elevation, quarantine
> host matching with port stripping, and `defense.status` protected.
> Rate limiting (§2.2), self-healing (§2.4), user approval workflow (§4.2),
> and auto-approve timeouts are design-phase — tracked for future evolution.

---

## 1. Defense Philosophy

### 1.1 Defense, Not Offense

**What We Do (Defensive):**
- ✅ Quarantine suspicious connections (to YOUR systems)
- ✅ Rate-limit anomalous traffic (YOUR resources)
- ✅ Block known-bad actors (YOUR protection)
- ✅ Alert operator (YOU) for review
- ✅ Audit all actions (YOUR oversight)

**What We DON'T Do (Offensive):**
- ❌ Attack back (no offensive actions)
- ❌ Scan attackers (no reconnaissance of others)
- ❌ Censor content (no filtering)
- ❌ Report to authorities (no snitching)
- ❌ Make moral judgments (no thought police)

### 1.2 User Authority

**Principle:** skunkBat suggests, user decides.

```rust
/// Defense action with user approval
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefenseAction {
    /// Recommended action
    pub action: ActionType,
    
    /// Requires user approval?
    pub requires_approval: bool,
    
    /// Auto-approve after timeout?
    pub auto_approve_after: Option<Duration>,
    
    /// User decision (if approved)
    pub user_decision: Option<UserDecision>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UserDecision {
    /// User approved action
    Approved { approved_at: Timestamp },
    
    /// User rejected action
    Rejected { rejected_at: Timestamp, reason: Option<String> },
    
    /// User modified action
    Modified { original: ActionType, modified: ActionType },
    
    /// Auto-approved (timeout)
    AutoApproved { timeout_at: Timestamp },
}
```

---

## 2. Defense Mechanisms

### 2.1 Quarantine (Isolation)

**Purpose:** Isolate suspicious connections without blocking entirely.

```rust
/// Quarantine mechanism
pub struct QuarantineEngine {
    /// Quarantine rules
    rules: QuarantineRules,
    
    /// Active quarantines
    active: RwLock<HashMap<ConnectionId, Quarantine>>,
    
    /// User notification
    notifier: UserNotifier,
}

impl QuarantineEngine {
    /// Quarantine a connection
    pub async fn quarantine(
        &self,
        threat: &Threat,
        connection: &Connection,
    ) -> Result<QuarantineId, DefenseError> {
        // Create quarantine
        let quarantine = Quarantine {
            id: QuarantineId::new(),
            connection_id: connection.id(),
            threat_id: threat.id,
            reason: format!("Threat detected: {}", threat.threat_type),
            quarantined_at: Timestamp::now(),
            expires_at: Timestamp::now() + self.rules.default_quarantine_duration,
            status: QuarantineStatus::Active,
        };
        
        // Apply quarantine (rate-limit to 1% bandwidth)
        self.apply_quarantine(&quarantine).await?;
        
        // Store quarantine
        self.active.write().await.insert(connection.id(), quarantine.clone());
        
        // Notify user
        self.notifier.notify_quarantine(&quarantine).await?;
        
        Ok(quarantine.id)
    }
    
    /// Release from quarantine (user decision)
    pub async fn release(
        &self,
        quarantine_id: QuarantineId,
        reason: String,
    ) -> Result<(), DefenseError> {
        // Find quarantine
        let mut active = self.active.write().await;
        let quarantine = active.values_mut()
            .find(|q| q.id == quarantine_id)
            .ok_or(DefenseError::QuarantineNotFound)?;
        
        // Update status
        quarantine.status = QuarantineStatus::Released { reason, by: "user".to_string() };
        
        // Remove quarantine constraints
        self.remove_quarantine(quarantine).await?;
        
        Ok(())
    }
}
```

**Quarantine vs. Block:**
- **Quarantine:** Isolate but allow minimal traffic (can recover if false positive)
- **Block:** Complete denial (more severe, requires stronger evidence)

### 2.2 Rate Limiting

**Purpose:** Throttle suspicious traffic without complete blocking.

```rust
/// Rate limiter for threat mitigation
pub struct ThreatRateLimiter {
    /// Rate limit rules
    rules: RateLimitRules,
    
    /// Active limits
    limits: RwLock<HashMap<ConnectionId, RateLimit>>,
}

impl ThreatRateLimiter {
    /// Apply rate limit to connection
    pub async fn apply_rate_limit(
        &self,
        threat: &Threat,
        connection: &Connection,
    ) -> Result<(), DefenseError> {
        // Determine rate limit based on threat severity
        let limit = match threat.severity {
            Severity::Low => self.rules.low_severity_limit,
            Severity::Medium => self.rules.medium_severity_limit,
            Severity::High => self.rules.high_severity_limit,
            Severity::Critical => self.rules.critical_severity_limit,
        };
        
        // Apply rate limit
        let rate_limit = RateLimit {
            connection_id: connection.id(),
            max_packets_per_second: limit,
            applied_at: Timestamp::now(),
            expires_at: Timestamp::now() + self.rules.default_duration,
        };
        
        self.limits.write().await.insert(connection.id(), rate_limit);
        
        Ok(())
    }
}
```

### 2.3 Blocking (Last Resort)

**Purpose:** Complete denial for confirmed threats.

```rust
/// Block engine (last resort)
pub struct BlockEngine {
    /// Block rules
    rules: BlockRules,
    
    /// Active blocks
    blocks: RwLock<HashMap<BlockTarget, Block>>,
    
    /// Audit log (all blocks logged)
    audit: AuditLogger,
}

impl BlockEngine {
    /// Block a threat source
    pub async fn block(
        &self,
        threat: &Threat,
        target: BlockTarget,
    ) -> Result<BlockId, DefenseError> {
        // Require high confidence for blocks
        if threat.confidence < self.rules.min_confidence_for_block {
            return Err(DefenseError::InsufficientConfidence {
                required: self.rules.min_confidence_for_block,
                actual: threat.confidence,
            });
        }
        
        // Create block
        let block = Block {
            id: BlockId::new(),
            target,
            threat_id: threat.id,
            reason: format!("High-confidence threat: {}", threat.threat_type),
            blocked_at: Timestamp::now(),
            expires_at: Timestamp::now() + self.rules.default_block_duration,
            user_approved: false, // Pending user review
        };
        
        // Log to audit (cryptographically signed)
        self.audit.log_block(&block).await?;
        
        // Apply block
        self.apply_block(&block).await?;
        
        // Store block
        self.blocks.write().await.insert(target, block.clone());
        
        Ok(block.id)
    }
}
```

### 2.4 Self-Healing

**Purpose:** Automatic recovery from attacks.

```rust
/// Self-healing mechanisms
pub struct SelfHealingEngine {
    /// Healing strategies
    strategies: Vec<Box<dyn HealingStrategy>>,
    
    /// Health monitor
    monitor: HealthMonitor,
}

impl SelfHealingEngine {
    /// Detect and heal from attacks
    pub async fn heal(&self) -> Result<Vec<HealingAction>, DefenseError> {
        let mut actions = Vec::new();
        
        // Check system health
        let health = self.monitor.check_health().await?;
        
        // Apply healing strategies
        for strategy in &self.strategies {
            if let Some(action) = strategy.can_heal(&health).await? {
                // Apply healing
                strategy.heal(&health).await?;
                actions.push(action);
            }
        }
        
        Ok(actions)
    }
}

/// Example healing strategy: Restart crashed services
pub struct ServiceRestartStrategy {
    /// Service manager
    services: ServiceManager,
}

impl HealingStrategy for ServiceRestartStrategy {
    async fn can_heal(&self, health: &HealthStatus) -> Result<Option<HealingAction>, DefenseError> {
        // Check for crashed services
        if let Some(crashed) = health.find_crashed_service() {
            Ok(Some(HealingAction::RestartService { service: crashed }))
        } else {
            Ok(None)
        }
    }
    
    async fn heal(&self, health: &HealthStatus) -> Result<(), DefenseError> {
        if let Some(crashed) = health.find_crashed_service() {
            self.services.restart(&crashed).await?;
        }
        Ok(())
    }
}
```

---

## 3. Integration with Threat Detection

```rust
/// Automated defense orchestrator
pub struct DefenseOrchestrator {
    /// Threat detector
    detector: ThreatDetector,
    
    /// Defense engines
    quarantine: QuarantineEngine,
    rate_limiter: ThreatRateLimiter,
    blocker: BlockEngine,
    healer: SelfHealingEngine,
    
    /// User notification
    notifier: UserNotifier,
    
    /// Policy engine
    policy: DefensePolicy,
}

impl DefenseOrchestrator {
    /// Respond to detected threat
    pub async fn respond_to_threat(
        &self,
        threat: Threat,
    ) -> Result<DefenseResponse, DefenseError> {
        // Determine appropriate response based on policy
        let action = self.policy.determine_action(&threat).await?;
        
        // Execute defense action
        match action.action {
            ActionType::Quarantine => {
                let id = self.quarantine.quarantine(&threat, &action.target).await?;
                Ok(DefenseResponse::Quarantined { id })
            }
            ActionType::RateLimit => {
                self.rate_limiter.apply_rate_limit(&threat, &action.target).await?;
                Ok(DefenseResponse::RateLimited)
            }
            ActionType::Block => {
                let id = self.blocker.block(&threat, action.target).await?;
                Ok(DefenseResponse::Blocked { id })
            }
            ActionType::Alert => {
                self.notifier.alert_user(&threat).await?;
                Ok(DefenseResponse::AlertSent)
            }
            ActionType::None => {
                Ok(DefenseResponse::NoActionNeeded)
            }
        }
    }
}
```

---

## 4. User Control & Transparency

### 4.1 Defense Dashboard

**User Interface Elements:**
- Active threats (real-time)
- Defense actions taken (audit log)
- Quarantined connections (review/release)
- Blocked entities (review/unblock)
- Self-healing actions (history)

### 4.2 Approval Workflow

```rust
/// User approval for defense actions
pub struct ApprovalWorkflow {
    /// Pending approvals
    pending: RwLock<Vec<PendingApproval>>,
    
    /// Approval timeout
    timeout: Duration,
}

impl ApprovalWorkflow {
    /// Request user approval
    pub async fn request_approval(
        &self,
        action: DefenseAction,
    ) -> Result<ApprovalId, DefenseError> {
        let approval = PendingApproval {
            id: ApprovalId::new(),
            action,
            requested_at: Timestamp::now(),
            expires_at: Timestamp::now() + self.timeout,
            status: ApprovalStatus::Pending,
        };
        
        self.pending.write().await.push(approval.clone());
        
        Ok(approval.id)
    }
    
    /// User approves action
    pub async fn approve(
        &self,
        approval_id: ApprovalId,
    ) -> Result<DefenseAction, DefenseError> {
        let mut pending = self.pending.write().await;
        let approval = pending.iter_mut()
            .find(|a| a.id == approval_id)
            .ok_or(DefenseError::ApprovalNotFound)?;
        
        approval.status = ApprovalStatus::Approved;
        
        Ok(approval.action.clone())
    }
}
```

---

## 5. Audit & Compliance

```rust
/// Defense audit logger (all actions logged)
pub struct DefenseAuditLogger {
    /// Audit log storage
    storage: AuditStorage,
    
    /// Cryptographic signer
    signer: CryptoSigner,
}

impl DefenseAuditLogger {
    /// Log defense action (cryptographically signed)
    pub async fn log_action(
        &self,
        action: &DefenseAction,
        result: &DefenseResponse,
    ) -> Result<(), DefenseError> {
        let entry = AuditEntry {
            timestamp: Timestamp::now(),
            action: action.clone(),
            result: result.clone(),
            signature: self.signer.sign(&serialize(action, result))?,
        };
        
        self.storage.store(entry).await?;
        
        Ok(())
    }
}
```

---

## Appendix: Configuration Example

```yaml
# auto-defense.yaml
auto_defense:
  enabled: true
  
  # Defense policy
  policy:
    # Require user approval for blocks?
    require_approval_for_blocks: true
    
    # Auto-approve after timeout?
    auto_approve_timeout: 5m
    
    # Minimum confidence for automated actions
    min_confidence:
      quarantine: 0.7
      rate_limit: 0.8
      block: 0.9
  
  # Quarantine settings
  quarantine:
    enabled: true
    default_duration: 1h
    max_concurrent: 100
    rate_limit_percent: 1  # 1% of normal bandwidth
  
  # Rate limiting
  rate_limit:
    enabled: true
    limits:
      low_severity: 1000   # packets/sec
      medium_severity: 100
      high_severity: 10
      critical_severity: 1
  
  # Blocking (last resort)
  block:
    enabled: true
    default_duration: 24h
    min_confidence: 0.9
    require_user_approval: true
  
  # Self-healing
  self_healing:
    enabled: true
    strategies:
      - restart_crashed_services
      - clear_resource_exhaustion
      - reset_failed_connections
```

---

**Status:** Initial draft complete.

**Next:** OBSERVABILITY_SPEC.md (monitoring and visibility)


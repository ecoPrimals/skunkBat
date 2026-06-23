# skunkBat Reconnaissance Specification

**Version:** 0.2.15  
**Status:** Implemented  
**Author:** ecoPrimals Project  
**Date:** December 27, 2025  
**License:** AGPL-3.0  

---

## Abstract

skunkBat reconnaissance provides **defensive network intelligence** for the ecoPrimals ecosystem. Unlike surveillance systems that watch people without consent, reconnaissance watches **YOUR systems FOR YOU** to defend against threats while respecting sovereignty and privacy.

**Core Distinction:** Reconnaissance is about visibility for protection, not extraction for control.

---

## 1. Core Principles

### 1.1 Reconnaissance, Not Surveillance

**The Distinction:**
- **Surveillance:** THEY watch YOU (asymmetric power, no consent)
- **Reconnaissance:** YOU watch YOUR systems (symmetric power, explicit consent)

**Implementation:**
- Scan only networks/systems the user explicitly owns
- Never profile individuals or their behavior
- Defensive posture only (detect threats TO you, not FROM you)
- Local by default (no central collection)

### 1.2 Sovereignty First

**Principle:** The user owns all reconnaissance data and controls its use.

**Implementation:**
- Data stays on user's node by default
- Federation is opt-in and family-only (via BearDog lineage)
- Export in open formats (JSON, CSV, YAML)
- Delete on demand (no permanent retention without consent)

### 1.3 Transparency Always

**Principle:** Reconnaissance operations must be observable and explainable.

**Implementation:**
- Open source (AGPL 3.0)
- Clear logging of all scans
- Auditable operations (cryptographically signed logs)
- Documented algorithms (no blackboxes)

### 1.4 Ephemeral by Design

**Principle:** Forget by default, remember only what's necessary.

**Implementation:**
- Default retention: 24 hours
- Auto-pruning of old data
- Configurable TTL (user choice)
- No permanent databases without explicit consent

---

## 2. Reconnaissance Scope

### 2.1 What We Scan

**Owned Networks:**
```rust
pub struct NetworkScope {
    /// Networks explicitly owned by user
    owned_networks: Vec<NetworkId>,
    
    /// Systems user manages
    managed_systems: Vec<SystemId>,
    
    /// Explicitly excluded (privacy zones)
    excluded: Vec<NetworkId>,
}
```

**Scanning Targets:**
- ✅ Network topology (YOUR network)
- ✅ Open ports (YOUR systems)
- ✅ Active connections (YOUR nodes)
- ✅ Resource usage (YOUR processes)
- ✅ Traffic patterns (YOUR bandwidth)

**Not Scanned:**
- ❌ Other people's networks
- ❌ Communications content
- ❌ Personal data or files
- ❌ Browsing history
- ❌ Application usage patterns

### 2.2 Asset Discovery

**Purpose:** Inventory YOUR systems for security management.

```rust
/// Asset discovered on YOUR network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Asset {
    /// Unique identifier (local to your network)
    pub id: AssetId,
    
    /// Asset type (server, workstation, IoT device, etc.)
    pub asset_type: AssetType,
    
    /// Network location (IP, MAC, etc.)
    pub location: NetworkLocation,
    
    /// Discovered services
    pub services: Vec<Service>,
    
    /// Operating system fingerprint
    pub os_fingerprint: Option<OsFingerprint>,
    
    /// Last seen timestamp
    pub last_seen: Timestamp,
    
    /// Genetic lineage (if ecoPrimals node via BearDog)
    pub lineage: Option<Lineage>,
}
```

**Discovery Methods:**
1. **Active Scanning:** Probe YOUR network for active hosts
2. **Passive Listening:** Monitor YOUR traffic for asset activity
3. **Integration Queries:** Ask Songbird for ecoPrimals topology
4. **Manual Registration:** User adds known assets

### 2.3 Topology Mapping

**Purpose:** Understand YOUR network structure for security analysis.

```rust
/// Network topology of YOUR infrastructure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkTopology {
    /// Discovered nodes (YOUR assets)
    pub nodes: Vec<Asset>,
    
    /// Connections between nodes (YOUR traffic)
    pub edges: Vec<Connection>,
    
    /// Network segments (YOUR VLANs/subnets)
    pub segments: Vec<NetworkSegment>,
    
    /// Critical paths (YOUR important routes)
    pub critical_paths: Vec<Path>,
    
    /// Discovery timestamp
    pub discovered_at: Timestamp,
    
    /// Time-to-live (ephemeral)
    pub expires_at: Timestamp,
}
```

**Topology Elements:**
- **Nodes:** Devices on YOUR network
- **Edges:** Connections between YOUR devices
- **Segments:** Logical groupings (VLANs, subnets)
- **Gateways:** Entry/exit points to YOUR network
- **Critical Paths:** Important routes requiring monitoring

---

## 3. Architecture

### 3.1 Component Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                  skunkBat Reconnaissance Service                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │   Scanner    │  │   Analyzer   │  │   Data Manager        │ │
│  │              │  │              │  │                       │ │
│  │ - Active     │  │ - Topology   │  │ - Local Storage      │ │
│  │ - Passive    │  │ - Patterns   │  │ - TTL Management     │ │
│  │ - Integrated │  │ - Anomalies  │  │ - Export/Import      │ │
│  └──────┬───────┘  └──────┬───────┘  └───────┬───────────────┘ │
│         │                 │                   │                 │
│         ▼                 ▼                   ▼                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    Integration Layer                        │ │
│  │  • BearDog (lineage verification)                          │ │
│  │  • Songbird (topology discovery)                           │ │
│  │  • BiomeOS (health reporting)                              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Scanner Component

**Responsibilities:**
- Active network scanning (YOUR networks only)
- Passive traffic monitoring (YOUR traffic only)
- Integration with discovery services (Songbird)
- Rate limiting and politeness (avoid network disruption)

**Scanner Types:**

```rust
/// Active scanner for YOUR network
pub struct ActiveScanner {
    /// Networks to scan (owned only)
    scope: NetworkScope,
    
    /// Scanning techniques
    techniques: Vec<ScanTechnique>,
    
    /// Rate limiter (politeness)
    rate_limit: RateLimit,
    
    /// Consent verification
    consent: ConsentVerifier,
}

/// Passive listener for YOUR traffic
pub struct PassiveListener {
    /// Interfaces to monitor (owned only)
    interfaces: Vec<NetworkInterface>,
    
    /// Capture filters (privacy-preserving)
    filters: CaptureFilters,
    
    /// Packet analyzer (metadata only, no content)
    analyzer: PacketAnalyzer,
}

/// Integration with Songbird topology
pub struct IntegrationScanner {
    /// Songbird client (capability-based)
    songbird: SongbirdClient,
    
    /// Topology query patterns
    queries: Vec<TopologyQuery>,
    
    /// Cache (performance)
    cache: TopologyCache,
}
```

### 3.3 Analyzer Component

**Responsibilities:**
- Build topology graph from scan results
- Identify patterns (normal vs. anomalous)
- Detect configuration drift
- Generate security insights

```rust
/// Topology analyzer
pub struct TopologyAnalyzer {
    /// Graph builder
    graph_builder: GraphBuilder,
    
    /// Pattern detector
    pattern_detector: PatternDetector,
    
    /// Baseline (what's "normal" for YOUR network)
    baseline: BaselineProfile,
    
    /// Anomaly detector
    anomaly_detector: AnomalyDetector,
}

impl TopologyAnalyzer {
    /// Build topology graph from scan results
    pub async fn build_topology(
        &self,
        scan_results: Vec<ScanResult>,
    ) -> Result<NetworkTopology, ReconError> {
        // Construct graph of YOUR network
        let graph = self.graph_builder.build(scan_results).await?;
        
        // Identify critical paths
        let critical_paths = self.identify_critical_paths(&graph).await?;
        
        // Detect anomalies (compared to baseline)
        let anomalies = self.anomaly_detector.detect(&graph, &self.baseline).await?;
        
        Ok(NetworkTopology {
            nodes: graph.nodes,
            edges: graph.edges,
            critical_paths,
            anomalies,
            discovered_at: Timestamp::now(),
            expires_at: Timestamp::now() + TTL_24H,
        })
    }
}
```

### 3.4 Data Manager Component

**Responsibilities:**
- Local storage (default)
- TTL management (ephemeral)
- Export/import (open formats)
- Encryption at rest

```rust
/// Data manager for reconnaissance results
pub struct ReconDataManager {
    /// Local storage backend
    storage: LocalStorage,
    
    /// TTL manager (auto-pruning)
    ttl_manager: TtlManager,
    
    /// Encryption (at rest)
    encryption: EncryptionProvider,
    
    /// Export formats
    exporters: Vec<Box<dyn Exporter>>,
}

impl ReconDataManager {
    /// Store scan results (ephemeral by default)
    pub async fn store(
        &self,
        topology: NetworkTopology,
        ttl: Duration,
    ) -> Result<StorageId, ReconError> {
        // Encrypt before storage
        let encrypted = self.encryption.encrypt(&topology).await?;
        
        // Store locally with TTL
        let id = self.storage.store(encrypted, ttl).await?;
        
        // Schedule auto-deletion
        self.ttl_manager.schedule_deletion(id, ttl).await?;
        
        Ok(id)
    }
    
    /// Export in open format
    pub async fn export(
        &self,
        id: StorageId,
        format: ExportFormat,
    ) -> Result<Vec<u8>, ReconError> {
        // Retrieve and decrypt
        let topology = self.storage.retrieve(id).await?;
        let decrypted = self.encryption.decrypt(&topology).await?;
        
        // Export in requested format
        let exporter = self.find_exporter(format)?;
        exporter.export(&decrypted).await
    }
}
```

---

## 4. Integration Specifications

### 4.1 BearDog Integration (Lineage Verification)

**Purpose:** Identify family vs. stranger nodes via genetic lineage.

```rust
/// BearDog integration for lineage-based trust
pub struct LineageVerifier {
    /// BearDog client (capability-based discovery)
    beardog: BeardogClient,
    
    /// Lineage cache (performance)
    cache: LineageCache,
    
    /// Trust policy
    policy: TrustPolicy,
}

impl LineageVerifier {
    /// Verify if asset is part of genetic family
    pub async fn is_family(&self, asset: &Asset) -> Result<bool, ReconError> {
        // Check if asset has DID
        let did = asset.did().ok_or(ReconError::NoDid)?;
        
        // Query BearDog for lineage
        let lineage = self.beardog.verify_lineage(did).await?;
        
        // Check against trust policy
        Ok(self.policy.is_trusted(&lineage))
    }
    
    /// Get full lineage chain
    pub async fn get_lineage_chain(
        &self,
        asset: &Asset,
    ) -> Result<LineageChain, ReconError> {
        let did = asset.did().ok_or(ReconError::NoDid)?;
        self.beardog.get_lineage_chain(did).await
            .map_err(|e| ReconError::LineageQuery(e))
    }
}
```

**Use Cases:**
1. **Asset Classification:** Family vs. stranger devices
2. **Trust Boundaries:** Different reconnaissance policies for family vs. unknown
3. **Threat Detection:** Unknown lineage = potential threat (see THREAT_DETECTION_SPEC.md)

### 4.2 Songbird Integration (Topology Discovery)

**Purpose:** Discover ecoPrimals topology via capability-based discovery.

```rust
/// Songbird integration for primal topology
pub struct PrimalTopologyDiscovery {
    /// Songbird client (4-tier discovery)
    songbird: SongbirdClient,
    
    /// Capability queries
    queries: CapabilityQueries,
    
    /// Topology cache
    cache: TopologyCache,
}

impl PrimalTopologyDiscovery {
    /// Discover ecoPrimals on YOUR network
    pub async fn discover_primals(&self) -> Result<Vec<PrimalNode>, ReconError> {
        // Query Songbird for topology
        let topology = self.songbird.query_topology().await?;
        
        // Filter for YOUR network only
        let local_primals = topology.nodes
            .into_iter()
            .filter(|node| self.is_local(node))
            .collect();
        
        Ok(local_primals)
    }
    
    /// Map primal capabilities
    pub async fn map_capabilities(
        &self,
        primal: &PrimalNode,
    ) -> Result<CapabilityMap, ReconError> {
        // Query what capabilities primal provides
        self.queries.query_capabilities(primal.id()).await
            .map_err(|e| ReconError::CapabilityQuery(e))
    }
}
```

**Use Cases:**
1. **Ecosystem Visibility:** Know what primals are running on YOUR network
2. **Capability Mapping:** Understand what services are available
3. **Integration Points:** Identify how primals interact

### 4.3 BiomeOS Integration (Health Reporting)

**Purpose:** Report reconnaissance status to orchestration layer.

```rust
/// BiomeOS integration for health reporting
pub struct HealthReporter {
    /// BiomeOS client
    biomeos: BiomeOsClient,
    
    /// Health status
    health: HealthStatus,
    
    /// Metrics collector
    metrics: MetricsCollector,
}

impl HealthReporter {
    /// Report reconnaissance health
    pub async fn report_health(&self) -> Result<(), ReconError> {
        let report = HealthReport {
            status: self.health.status(),
            metrics: self.metrics.collect(),
            timestamp: Timestamp::now(),
        };
        
        self.biomeos.report_health("skunkbat-recon", report).await
            .map_err(|e| ReconError::HealthReport(e))
    }
    
    /// Report scan statistics
    pub async fn report_stats(&self, stats: ScanStats) -> Result<(), ReconError> {
        self.biomeos.report_metrics("skunkbat-recon", stats.to_metrics()).await
            .map_err(|e| ReconError::MetricsReport(e))
    }
}
```

---

## 5. API Specification

### 5.1 Reconnaissance API

```rust
/// Reconnaissance service API
pub trait ReconnaissanceService {
    /// Start reconnaissance scan
    async fn start_scan(&self, scope: NetworkScope) -> Result<ScanId, ReconError>;
    
    /// Get scan status
    async fn get_scan_status(&self, scan_id: ScanId) -> Result<ScanStatus, ReconError>;
    
    /// Get scan results
    async fn get_scan_results(&self, scan_id: ScanId) -> Result<NetworkTopology, ReconError>;
    
    /// List all assets
    async fn list_assets(&self) -> Result<Vec<Asset>, ReconError>;
    
    /// Get asset details
    async fn get_asset(&self, asset_id: AssetId) -> Result<Asset, ReconError>;
    
    /// Get network topology
    async fn get_topology(&self) -> Result<NetworkTopology, ReconError>;
    
    /// Export reconnaissance data
    async fn export_data(
        &self,
        format: ExportFormat,
    ) -> Result<Vec<u8>, ReconError>;
    
    /// Delete old data (manual pruning)
    async fn prune_data(&self, older_than: Duration) -> Result<u32, ReconError>;
}
```

### 5.2 REST API Endpoints

```yaml
paths:
  /reconnaissance/scan:
    post:
      summary: Start reconnaissance scan
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/NetworkScope'
      responses:
        200:
          description: Scan started
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ScanId'
  
  /reconnaissance/scan/{scan_id}:
    get:
      summary: Get scan status
      parameters:
        - name: scan_id
          in: path
          required: true
          schema:
            type: string
      responses:
        200:
          description: Scan status
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ScanStatus'
  
  /reconnaissance/assets:
    get:
      summary: List discovered assets
      responses:
        200:
          description: Asset list
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Asset'
  
  /reconnaissance/topology:
    get:
      summary: Get network topology
      responses:
        200:
          description: Network topology
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NetworkTopology'
  
  /reconnaissance/export:
    get:
      summary: Export reconnaissance data
      parameters:
        - name: format
          in: query
          schema:
            type: string
            enum: [json, yaml, csv]
      responses:
        200:
          description: Exported data
          content:
            application/octet-stream:
              schema:
                type: string
                format: binary
```

---

## 6. Data Privacy & Sovereignty

### 6.1 Privacy-Preserving Reconnaissance

**Principles:**
1. **Metadata Only:** Scan network metadata, not content
2. **No Deep Inspection:** Packet headers only (no payload analysis)
3. **Aggregate Statistics:** Individual flows → aggregate patterns
4. **Consent Required:** User must explicitly enable scanning

**Implementation:**

```rust
/// Privacy-preserving packet capture
pub struct PrivacyPreservingCapture {
    /// Capture metadata only (no payload)
    capture_mode: CaptureMode::MetadataOnly,
    
    /// Anonymization (IP address hashing)
    anonymizer: IpAnonymizer,
    
    /// Aggregation (flows → statistics)
    aggregator: FlowAggregator,
}

impl PrivacyPreservingCapture {
    /// Capture packet metadata (no content)
    pub async fn capture(&self, packet: RawPacket) -> PacketMetadata {
        PacketMetadata {
            // Network layer (anonymized)
            src_ip: self.anonymizer.anonymize(packet.src_ip),
            dst_ip: self.anonymizer.anonymize(packet.dst_ip),
            protocol: packet.protocol,
            
            // Transport layer (metadata only)
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            
            // Timestamp and size
            timestamp: packet.timestamp,
            size: packet.size,
            
            // NO PAYLOAD CAPTURE
            // NO CONTENT INSPECTION
        }
    }
}
```

### 6.2 Data Sovereignty Guarantees

**Guarantees:**
1. **Local Storage:** Data on YOUR node (not cloud)
2. **Ephemeral by Default:** Auto-delete after TTL
3. **User Ownership:** YOU own all reconnaissance data
4. **Export Freedom:** Open formats (JSON, YAML, CSV)
5. **Delete Anytime:** On-demand data deletion

**Compliance:**

```rust
/// Sovereignty compliance manager
pub struct SovereigntyCompliance {
    /// Verify data stays local
    pub fn verify_local_storage(&self) -> bool {
        // Ensure no cloud uploads
        !self.has_cloud_backend()
    }
    
    /// Verify TTL enforcement
    pub fn verify_ephemeral(&self) -> bool {
        // Ensure auto-pruning enabled
        self.ttl_manager.is_enabled()
    }
    
    /// Verify export capability
    pub fn verify_export_freedom(&self) -> bool {
        // Ensure open format export
        self.exporters.supports_open_formats()
    }
    
    /// Verify deletion capability
    pub fn verify_delete_freedom(&self) -> bool {
        // Ensure on-demand deletion
        self.data_manager.supports_deletion()
    }
}
```

---

## 7. Performance Considerations

### 7.1 Politeness & Rate Limiting

**Principle:** Reconnaissance must not disrupt YOUR network.

```rust
/// Polite scanner with rate limiting
pub struct PoliteScanner {
    /// Maximum packets per second
    rate_limit: RateLimit,
    
    /// Backoff on congestion
    backoff: ExponentialBackoff,
    
    /// Scan scheduling (off-peak hours)
    scheduler: ScanScheduler,
}

impl PoliteScanner {
    /// Scan with rate limiting
    pub async fn scan_politely(
        &self,
        targets: Vec<Target>,
    ) -> Result<Vec<ScanResult>, ReconError> {
        let mut results = Vec::new();
        
        for target in targets {
            // Rate limit
            self.rate_limit.wait().await;
            
            // Scan target
            match self.scan_target(target).await {
                Ok(result) => results.push(result),
                Err(e) if e.is_congestion() => {
                    // Backoff on congestion
                    self.backoff.wait().await;
                }
                Err(e) => return Err(e),
            }
        }
        
        Ok(results)
    }
}
```

### 7.2 Caching & Optimization

**Strategy:**
- Cache topology results (avoid redundant scans)
- Incremental updates (detect changes only)
- Lazy evaluation (scan on demand)

```rust
/// Topology cache for performance
pub struct TopologyCache {
    /// Cached topology
    cache: RwLock<Option<NetworkTopology>>,
    
    /// Cache TTL
    cache_ttl: Duration,
    
    /// Last update timestamp
    last_update: Timestamp,
}

impl TopologyCache {
    /// Get cached topology (if fresh)
    pub async fn get(&self) -> Option<NetworkTopology> {
        let cache = self.cache.read().await;
        
        if self.is_fresh() {
            cache.clone()
        } else {
            None
        }
    }
    
    /// Update cache
    pub async fn update(&self, topology: NetworkTopology) {
        let mut cache = self.cache.write().await;
        *cache = Some(topology);
        self.last_update = Timestamp::now();
    }
}
```

---

## 8. Security Considerations

### 8.1 Reconnaissance as Attack Surface

**Threat:** Reconnaissance tools can be abused for offensive scanning.

**Mitigation:**
1. **Scope Enforcement:** Only scan networks in NetworkScope (user-configured)
2. **Consent Verification:** Require explicit user authorization
3. **Audit Logging:** Log all scan operations (cryptographically signed)
4. **Rate Limiting:** Prevent abuse via excessive scanning

```rust
/// Secure reconnaissance enforcer
pub struct SecureReconEnforcer {
    /// User-configured scope (whitelist only)
    scope: NetworkScope,
    
    /// Consent verification
    consent: ConsentVerifier,
    
    /// Audit logger (signed logs)
    audit_log: AuditLogger,
    
    /// Rate limiter (abuse prevention)
    rate_limit: RateLimit,
}

impl SecureReconEnforcer {
    /// Enforce secure reconnaissance
    pub async fn enforce_scan(
        &self,
        target: Target,
    ) -> Result<(), ReconError> {
        // Verify target in scope
        if !self.scope.contains(&target) {
            self.audit_log.log_violation("out_of_scope", &target).await?;
            return Err(ReconError::OutOfScope(target));
        }
        
        // Verify consent
        if !self.consent.has_consent(&target).await? {
            self.audit_log.log_violation("no_consent", &target).await?;
            return Err(ReconError::NoConsent(target));
        }
        
        // Rate limit check
        if !self.rate_limit.allow().await {
            self.audit_log.log_violation("rate_limited", &target).await?;
            return Err(ReconError::RateLimited);
        }
        
        // Log authorized scan
        self.audit_log.log_scan("authorized", &target).await?;
        
        Ok(())
    }
}
```

### 8.2 Data Protection

**Threat:** Reconnaissance data could be stolen or leaked.

**Mitigation:**
1. **Encryption at Rest:** Encrypt all stored data
2. **Access Control:** Owner-only access
3. **Secure Deletion:** Overwrite data on deletion
4. **No Backups to Cloud:** Local only

---

## 9. Testing Strategy

### 9.1 Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_topology_discovery() {
        let scanner = create_test_scanner();
        let topology = scanner.discover_topology().await.unwrap();
        
        assert!(!topology.nodes.is_empty());
        assert!(topology.expires_at > Timestamp::now());
    }
    
    #[tokio::test]
    async fn test_scope_enforcement() {
        let enforcer = create_test_enforcer();
        let out_of_scope = Target::new("192.168.99.1");
        
        let result = enforcer.enforce_scan(out_of_scope).await;
        assert!(matches!(result, Err(ReconError::OutOfScope(_))));
    }
    
    #[tokio::test]
    async fn test_ephemeral_storage() {
        let storage = create_test_storage();
        let topology = create_test_topology();
        
        let id = storage.store(topology, Duration::hours(1)).await.unwrap();
        
        // Fast-forward time
        tokio::time::advance(Duration::hours(2)).await;
        
        // Should be auto-deleted
        let result = storage.retrieve(id).await;
        assert!(matches!(result, Err(StorageError::Expired)));
    }
}
```

### 9.2 Integration Tests

**Test Scenarios:**
1. BearDog lineage verification integration
2. Songbird topology discovery integration
3. BiomeOS health reporting integration
4. End-to-end reconnaissance flow

### 9.3 Security Tests

**Test Scenarios:**
1. Out-of-scope scan prevention
2. Consent verification enforcement
3. Rate limiting effectiveness
4. Data encryption validation
5. Secure deletion verification

---

## 10. Roadmap

### Phase 1: Foundation (Weeks 1-2)
- [ ] Basic network scanner (active + passive)
- [ ] Asset discovery and inventory
- [ ] Topology graph construction
- [ ] Local storage with TTL

### Phase 2: Integration (Weeks 3-4)
- [ ] BearDog lineage integration
- [ ] Songbird topology integration
- [ ] BiomeOS health reporting
- [ ] Scope enforcement and consent

### Phase 3: Advanced Features (Weeks 5-6)
- [ ] Pattern analysis (baseline profiling)
- [ ] Anomaly detection
- [ ] Performance optimization (caching)
- [ ] Export in multiple formats

### Phase 4: Hardening (Weeks 7-8)
- [ ] Security audit and penetration testing
- [ ] Comprehensive test suite (90% coverage)
- [ ] Documentation and examples
- [ ] Production deployment readiness

---

## 11. Related Specifications

- **THREAT_DETECTION_SPEC.md:** How reconnaissance feeds threat detection
- **AUTO_DEFENSE_SPEC.md:** How reconnaissance enables defensive responses
- **OBSERVABILITY_SPEC.md:** How reconnaissance data is made observable
- **RECONNAISSANCE_NOT_SURVEILLANCE.md:** Ethical framework and principles

---

## Appendix A: Glossary

**Asset:** A device or system on YOUR network (server, workstation, IoT device, etc.)

**Lineage:** Genetic ancestry chain via BearDog (determines family vs. stranger)

**Reconnaissance:** Watching YOUR systems FOR YOU (defensive intelligence)

**Scope:** The networks and systems you explicitly own and scan

**Surveillance:** Watching others without consent (what we DON'T do)

**Topology:** The structure and connections of YOUR network

**TTL:** Time-to-live (how long data is kept before auto-deletion)

---

## Appendix B: Configuration Example

```yaml
# skunkbat-reconnaissance.yaml
reconnaissance:
  # Enable reconnaissance
  enabled: true
  
  # Networks to scan (YOUR networks only)
  scope:
    owned_networks:
      - "192.168.1.0/24"    # Home network
      - "10.0.0.0/16"       # Lab network
    excluded:
      - "192.168.1.100"     # Privacy zone (don't scan)
  
  # Scanning configuration
  scanning:
    # Scan techniques
    techniques:
      - active_port_scan
      - passive_listening
      - songbird_integration
    
    # Rate limiting (politeness)
    rate_limit:
      max_packets_per_second: 100
      backoff_on_congestion: true
    
    # Scan schedule (off-peak hours)
    schedule:
      enabled: true
      cron: "0 2 * * *"  # 2 AM daily
  
  # Data management
  data:
    # Local storage
    storage:
      backend: local
      path: /var/lib/skunkbat/recon
      encryption: true
    
    # Ephemeral by design
    retention:
      default_ttl: 24h
      max_ttl: 7d
      auto_prune: true
    
    # Export formats
    export:
      formats: [json, yaml, csv]
  
  # Integration
  integration:
    # BearDog lineage verification
    beardog:
      enabled: true
      discovery: auto  # 4-tier discovery
    
    # Songbird topology discovery
    songbird:
      enabled: true
      discovery: auto
    
    # BiomeOS health reporting
    biomeos:
      enabled: true
      report_interval: 60s
  
  # Security
  security:
    # Consent verification
    consent:
      required: true
      verification_method: explicit
    
    # Audit logging
    audit:
      enabled: true
      log_path: /var/log/skunkbat/recon-audit.log
      signing: true  # Cryptographically signed logs
```

---

**End of Reconnaissance Specification**

**Next:** See THREAT_DETECTION_SPEC.md for how reconnaissance data feeds threat analysis.


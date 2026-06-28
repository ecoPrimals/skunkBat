<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# skunkBat Composable Primitives Specification

**Version:** 0.2.17 (Design Phase — only `baseline.observe` shipped)
**Status:** Design — method surface not yet exposed over IPC
**Date:** April 2026
**License:** AGPL-3.0-or-later

---

## Abstract

skunkBat is not a single-purpose security tool. It is a collection of
aligned primitives — statistical baseline profiling, metadata analysis,
graduated response, lineage challenge, and health sensing — that are
independently useful as standalone capabilities and compose with every
other primal in the ecosystem.

This specification decomposes skunkBat into its primitive domains, defines
the IPC method surface for each, and describes composition patterns with
other primals and springs.

---

## 1. Primitive Decomposition

### 1.1 The Five Primitive Domains

| Domain | What It Actually Is | Security Framing | General Framing |
|--------|--------------------|--------------------|-----------------|
| `baseline` | Rolling-window statistical anomaly detector | Behavioral threat detection | Time-series pattern analysis |
| `metadata` | Connection metadata extraction and classification | Traffic fingerprinting | Observable telemetry analysis |
| `response` | Progressive state machine with escalation | Graduated defense | Resource management workflow |
| `lineage` | Identity challenge via BearDog delegation | Genetic threat verification | Trust boundary arbitration |
| `health` | System load, network state, resource utilization | DoS detection inputs | Cross-platform system sensing |

The key insight: **baseline profiling is a statistics primitive**, not a
security primitive. Graduated response is a state-machine primitive.
Separated from the "security" framing, they compose with everything.

### 1.2 Self-Knowledge

skunkBat follows the ecosystem niche pattern. All identity, capabilities,
and scheduling hints are centralized:

| Constant / Function | Value |
|---------------------|-------|
| `PRIMAL_ID` | `"skunkbat"` |
| `CAPABILITIES` | All exposed methods (see IPC table below) |
| `CONSUMED_CAPABILITIES` | `btsp.session.verify`, `lineage.verify`, `lineage.list`, `capabilities.list`, `discovery.find_by_capability`, `federation.broadcast` |

---

## 2. IPC Method Table

All methods follow `{domain}.{operation}` per the Semantic Method Naming
Standard.

### 2.1 Baseline Domain

| Method | What It Does | Standalone Use |
|--------|-------------|----------------|
| `baseline.observe` | Record a metric observation into the rolling window | Any time-series from any primal |
| `baseline.query` | Retrieve current baseline statistics (mean, sigma, percentiles) | Dashboard, monitoring |
| `baseline.anomaly` | Check a value against the baseline, return deviation | Alerting for any metric |
| `baseline.reset` | Clear the rolling window and start fresh | After known topology changes |

### 2.2 Metadata Domain

| Method | What It Does | Standalone Use |
|--------|-------------|----------------|
| `metadata.classify` | Classify a connection's metadata pattern | Traffic analysis |
| `metadata.fingerprint` | Generate a metadata fingerprint for a connection | Deduplication, matching |

### 2.3 Response Domain

| Method | What It Does | Standalone Use |
|--------|-------------|----------------|
| `response.evaluate` | Given evidence, recommend a response level | Any decision-support workflow |
| `response.escalate` | Move an entity to a higher response level | Resource management |
| `response.deescalate` | Move an entity to a lower response level | Recovery after incident |
| `response.status` | Query current response level for an entity | Dashboard, audit |

### 2.4 Lineage Domain

| Method | What It Does | Standalone Use |
|--------|-------------|----------------|
| `lineage.challenge` | Challenge an entity to present lineage proof | Trust boundary gates |
| `lineage.verify` | Verify a presented lineage proof (delegates to BearDog `genetic.verify_lineage`: `our_family_id`, `peer_family_id`, `lineage_proof`, `lineage_seed`) | Any trust decision |

### 2.5 Health Domain

| Method | What It Does | Standalone Use |
|--------|-------------|----------------|
| `health.system` | Current system load (CPU, memory) | Monitoring, scheduling |
| `health.network` | Network connection summary | Dashboard |
| `health.resource` | Resource utilization breakdown | Capacity planning |
| `health.check` | Service health (status, version, uptime) | Standard health probe |

### 2.6 Standard Methods

| Method | What It Does |
|--------|-------------|
| `capability.list` | List all capabilities with per-method cost and dependency hints |
| `identity.get` | Return primal identity, version, bond type |

---

## 3. Standalone Patterns

These patterns use skunkBat primitives alone — no other primals required.

### 3.1 General-Purpose Anomaly Detection

Any primal or spring can feed metrics into `baseline.observe` and poll
`baseline.anomaly`. The baseline profiler learns "normal" for any
time-series and flags deviations. Not security-specific at all.

```
baseline.observe { domain: "compile_time", value: 142.0 }
baseline.observe { domain: "compile_time", value: 138.0 }
... (learning phase)
baseline.anomaly { domain: "compile_time", value: 14200.0 }
  → { deviation: 8.2, sigma: 17.3, assessment: "critical" }
```

### 3.2 Graduated Response as Workflow Engine

The response state machine works for any progressive action sequence,
not just security escalation:

- Resource scaling: Monitor -> Provision -> Scale -> Throttle -> Shed
- User onboarding: Observe -> Welcome -> Enable -> Trust -> Full-Access
- Experiment gating: Draft -> Review -> Approved -> Running -> Complete

### 3.3 Cross-Platform Health Sensing

`health.system` provides real system load via `/proc/loadavg` (Linux) or
`uptime` (fallback). Any primal can call it for scheduling decisions
without implementing platform detection itself.

---

## 4. Cross-Primal Composition Patterns

### 4.1 skunkBat + BearDog: Thymic Detection

The core composition. BearDog provides genetic identity (MHC). skunkBat
provides self/non-self discrimination (thymic selection). See
`THYMIC_SELECTION_SPEC.md`.

```
lineage.challenge { peer_id }
  → BearDog btsp.server.verify { session_token, client_ephemeral_pub, response, preferred_cipher }
    → { verified: true, session_id, cipher }  // self
    → { verified: false, error }              // non-self → escalate
  → BearDog genetic.verify_lineage { our_family_id, peer_family_id, lineage_proof, lineage_seed }
    → { valid: true, depth, generation }      // deep lineage confirmed
    → { valid: false, reason }                // lineage broken → block
```

### 4.2 skunkBat + coralReef: Compiler Sensing

Shader compilation has observable metadata patterns: compile time
distributions, input/output size ratios, instruction mix fingerprints.
skunkBat learns "normal compilation" and flags anomalies.

```
baseline.observe { domain: "shader_compile", value: compile_time_ms }
baseline.observe { domain: "shader_ratio", value: output_bytes / input_bytes }
baseline.anomaly { domain: "shader_compile", value: 100x_normal }
  → { deviation: 6.1, pattern: "resource_exhaustion" }
response.evaluate → Throttle (rate-limit compilation requests)
```

Detects compiler abuse — pathological shaders submitted to exhaust GPU
compile resources.

### 4.3 skunkBat + ToadStool: Compute Resource Guardian

ToadStool dispatches workloads. skunkBat profiles normal compute patterns.

```
baseline.observe { domain: "gpu_util", value: utilization_pct }
baseline.observe { domain: "dispatch_rate", value: dispatches_per_sec }
baseline.anomaly { domain: "gpu_util", value: 100.0 for 2_hours }
  → { pattern: "unscheduled_compute" }
response.evaluate → Warn (alert biomeOS)
```

Catches cryptomining, runaway workloads, hardware failures.

### 4.4 skunkBat + Songbird: Federation Health Monitor

```
baseline.observe { domain: "peer_msg_rate", value: messages_per_sec }
baseline.observe { domain: "peer_latency", value: avg_latency_ms }
baseline.anomaly { domain: "peer_msg_rate", value: 50x_normal }
  → { deviation: 12.0, pattern: "flood_or_spoof" }
response.evaluate → Quarantine (isolate peer)
```

### 4.5 skunkBat + rhizoCrypt: DAG Session Anomaly Monitoring

```
baseline.observe { domain: "vertex_rate", value: vertices_per_min }
baseline.observe { domain: "agent_count", value: unique_agents }
baseline.anomaly { domain: "vertex_rate", value: 10x_spike }
  → { deviation: 8.2, source: "unknown_agent" }
response.evaluate → Quarantine (isolate session for review)
```

Detects unauthorized DAG modifications, automation errors, injected vertices.

### 4.6 skunkBat + NestGate: Storage Exfiltration Detection

```
baseline.observe { domain: "storage_get_rate", value: gets_per_sec }
baseline.observe { domain: "bytes_out", value: total_bytes }
baseline.anomaly { domain: "storage_get_rate", value: bulk_sequential }
  → { pattern: "bulk_exfiltration" }
response.evaluate → Quarantine (pause gets, alert owner)
```

### 4.7 skunkBat + LoamSpine: Ledger Integrity Sentinel

```
baseline.observe { domain: "commit_rate", value: commits_per_hour }
baseline.anomaly { domain: "commit_rate", value: 1000x_normal }
  → { pattern: "ledger_flood" }
response.evaluate → Block (with user authority)
```

### 4.8 skunkBat + sweetGrass: Anomaly Markers in Braids

When skunkBat detects an anomaly during a provenance-tracked session,
the anomaly assessment becomes metadata in sweetGrass attribution braids.

```
sweetGrass: provenance.create_braid {
    session_id,
    anomaly_markers: [skunkbat_assessment]
}
```

### 4.9 skunkBat + Squirrel: AI Behavior Profiling

```
baseline.observe { domain: "inference_rate", value: requests_per_min }
baseline.observe { domain: "token_volume", value: avg_tokens }
baseline.anomaly { domain: "inference_rate", value: 100x_normal }
  → { pattern: "api_abuse" }
response.evaluate → Throttle
```

### 4.10 skunkBat + petalTongue: Anomaly Dashboards

petalTongue renders skunkBat's baseline and anomaly data as live
visualizations. The `baseline.query` method provides the data;
petalTongue provides the rendering.

### 4.11 skunkBat + biomeOS: Alert Routing

biomeOS receives `response.evaluate` outputs and coordinates ecosystem-wide
response via the Neural API. skunkBat suggests; biomeOS orchestrates.

---

## 5. What skunkBat Does NOT Do

| Concern | Who Handles It | skunkBat's Role |
|---------|---------------|-----------------|
| Cryptography | BearDog | Consumes lineage verification |
| Networking | Songbird | Monitors federation metadata |
| Storage | NestGate | Monitors access patterns |
| Compute dispatch | ToadStool | Monitors resource patterns |
| Shader compilation | coralReef | Monitors compilation patterns |
| GPU kernels | barraCuda | Monitors kernel execution patterns |
| Permanence | LoamSpine | Monitors commit patterns |
| Attribution | sweetGrass | Provides anomaly markers for braids |
| Ephemeral state | rhizoCrypt | Monitors DAG session patterns |
| AI inference | Squirrel | Monitors inference patterns |
| Visualization | petalTongue | Provides anomaly data for dashboards |
| Orchestration | biomeOS | Receives alerts, coordinates response |
| **Content inspection** | **Nobody** | **Architecturally impossible** |

skunkBat observes metadata from every primal composition but never touches
content. It is the immune system watching vital signs without reading mail.

---

**Status:** Design phase. The primitive decomposition reflects both
implemented capabilities (baseline profiling, health sensing, graduated
response) and planned IPC surface (method table). Implementation of the
full IPC method surface depends on biomeOS capability registration and
the Neural API routing layer.

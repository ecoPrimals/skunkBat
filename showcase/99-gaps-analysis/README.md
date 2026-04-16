<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Implementation Gaps Analysis

**Current state vs what's needed for complete skunkBat deployment.**

*Updated: April 2026*

---

## Current State

### Build Health

| Metric | Value |
|--------|-------|
| Tests | 171 passing / 0 failures / 15 ignored (external-primal-gated) |
| Coverage | 89.6% line (cargo-llvm-cov; CI gate: 85%) |
| Clippy | CLEAN — pedantic + nursery, `-D warnings`, zero warnings |
| Format | CLEAN — `cargo fmt --check` |
| Docs | CLEAN — `cargo doc --no-deps`, zero warnings |
| Deny | CLEAN — `cargo deny check` (advisory/ban/license/source) |
| Unsafe | `forbid(unsafe_code)` workspace-wide |
| Max file | 867 lines (`btsp.rs`); limit 1000 |
| Edition | 2024 |

### What's Implemented (Production Code)

**Core Architecture:**
- Trait-based dependency injection (sourdough-core `PrimalLifecycle`)
- Async/await throughout on Tokio
- Zero unsafe code, `forbid(unsafe_code)`
- All `#[allow]` migrated to `#[expect(reason)]`
- Named constants for all thresholds (no magic numbers)
- Cross-platform implementations (`proc_uid`, `check_system_load`)

**JSON-RPC 2.0 Server (from scratch):**
- Single requests with standard error codes (-32700 through -32603)
- **Batch requests** (JSON array dispatch)
- **Notifications** (id-less requests produce no response, per spec §4.1)
- Newline-delimited framing on TCP and UDS
- BTSP Phase 1 socket naming + Phase 2 BearDog-delegated handshake (aligned with BearDog v0.9.0)
- Wire Standard L2 (`capabilities.list`) and L3 (`identity.get`)
- Capability symlinks (`security.sock`)

**Threat Detection (5 types):**
- Genetic (lineage) — trait + local stub + BearDog delegation
- Topology (layer-hopping) — trait + simple mapper
- Behavioral (statistical anomaly) — `StatisticalProfiler` with rolling baselines
- Intrusion (signatures) — framework + pattern matching
- Resource (DoS/exhaustion) — real `check_system_load` on Linux + fallback

**Defense Engine:**
- Graduated response: Monitor / Quarantine / Block
- Severity assessment with named confidence thresholds
- User-approval workflow structure

**Observability:**
- Metrics collection, structured logging, health checks, audit logging

**Integrations (JSON-RPC clients):**
- `RpcClient` — full JSON-RPC 2.0 client with BTSP handshake
- `DiscoveryClient` — capability-based ToadStool discovery
- `FederationClient` — Songbird federation broadcast

**Showcase:**
- 12 working examples (`cargo run --example ...`)
- 4-tier interactive demo suite (22 demos with `demo.sh` scripts)

---

## Remaining Gaps

These are **integration-layer** gaps — the local architecture is sound, and
all internal traits are implemented. What remains is connecting to live
ecosystem primals.

### CRITICAL — Blocks real deployment

| Gap | Status | Notes |
|-----|--------|-------|
| **BearDog live integration** | BTSP handshake aligned with v0.9.0, integration test wired | Need live `crypto.sock` peer for E2E validation |
| **Network layer defense execution** | Actions logged, not enforced | Need OS/firewall abstraction |

### HIGH — Significantly limits functionality

| Gap | Status | Notes |
|-----|--------|-------|
| **ToadStool live discovery** | Client written, `#[ignore]`-gated tests | Blocked on ToadStool availability |
| **Songbird live federation** | Client written, `#[ignore]`-gated tests | Blocked on Songbird availability |
| **User approval workflow** | `requires_approval` field exists | Need notification + response channel |
| **Topology path validation** | Mapper trait + stub | Need real topology data source |

### MEDIUM — Enhances features

| Gap | Status | Notes |
|-----|--------|-------|
| **Federation threat sharing** | Conceptual | Needs intel format + pub/sub |
| **NestGate data protection** | Not started | Specific to NestGate deployments |
| **Multiple baseline windows** | Single rolling window works | Hour/day/week windows |
| **Baseline persistence** | Ephemeral (by design) | Optional save/restore |
| **Coordinated mesh blocking** | Conceptual | Needs federation consensus |

### LOW — Future polish

| Gap | Status | Notes |
|-----|--------|-------|
| **Configurable per-deployment thresholds** | Constants, not yet runtime-configurable | Config struct evolution |
| **Bandwidth monitoring** | Not started | Per-connection tracking |

---

## Key Insight

Most gaps are **ecosystem integration points** that require peer primals
(BearDog, ToadStool, Songbird) to be running. The core architecture, IPC
server, and local threat/defense logic are complete and tested.

The `#[ignore]`-gated integration tests are ready to light up as each
peer primal comes online.

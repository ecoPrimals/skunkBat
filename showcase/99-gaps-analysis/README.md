<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# Implementation Gaps Analysis

**Current state vs what's needed for complete skunkBat deployment.**

*Updated: May 5, 2026*

---

## Current State

### Build Health

| Metric | Value |
|--------|-------|
| Tests | 338 passing / 0 failures / 15 ignored (external-primal-gated) |
| Coverage | 90%+ function (cargo-llvm-cov); crypto 100%, behavioral 100%, threats ~98% |
| Clippy | CLEAN — pedantic + nursery, `-D warnings`, zero warnings |
| Format | CLEAN — `cargo fmt --check` |
| Docs | CLEAN — `cargo doc --no-deps`, zero warnings |
| Deny | CLEAN — `cargo deny check` (advisory/ban/license/source); `async-trait` banned |
| Unsafe | `forbid(unsafe_code)` workspace-wide |
| async-trait | **ELIMINATED** — 14→0, native RPITIT + generics, dep removed + banned |
| sourdough-core | **INTERNALIZED** — zero cross-repo path deps, `primal_foundation` module |
| Max file | 790 lines (`negotiate.rs`); limit 1000; 43 source files |
| Edition | 2024 |

### What's Implemented (Production Code)

**Core Architecture:**
- Trait-based dependency injection (`PrimalLifecycle` via `primal_foundation`)
- Async/await throughout on Tokio
- Zero unsafe code, `forbid(unsafe_code)`
- All `#[allow]` migrated to `#[expect(reason)]`
- Named constants for all thresholds (no magic numbers)
- Cross-platform implementations (`platform::proc_uid`, `check_system_load`)
- Crate-level self-knowledge constants (`PRIMAL_NAME`, `PRIMAL_ID`, `CAPABILITIES`)
- Config-driven TCP bind address via `SKUNKBAT_LISTEN_ADDR` env var (no hardcoded `"0.0.0.0"`)

**JSON-RPC 2.0 Server (from scratch):**
- Single requests with standard error codes (-32700 through -32603)
- **Batch requests** (JSON array dispatch)
- **Notifications** (id-less requests produce no response, per spec §4.1)
- Newline-delimited framing on TCP and UDS
- BTSP Phase 1 socket naming + Phase 2 BearDog-delegated handshake + Phase 3 `btsp.negotiate` with encrypted `ChaCha20-Poly1305` frame upgrade (handshake key plumbed, AEAD loop wired)
- Wire Standard L2 (`capabilities.list`) and L3 (`identity.get`)
- Capability symlinks (`security.sock`)
- **Self-registration** with discovery (`ipc.register`) — standalone-safe probe on startup

**Threat Detection (5 types):**
- Genetic (lineage) — real verifier call + `RuntimeVerifier` enum dispatch + conservative deny fallback
- Topology (layer-hopping) — trait + simple mapper
- Behavioral (statistical anomaly) — `StatisticalProfiler` with rolling baselines
- Intrusion (signatures) — framework + pattern matching
- Resource (DoS/exhaustion) — real `check_system_load` on Linux + fallback

**Defense Engine:**
- Graduated response: Monitor / Quarantine / Block
- Severity assessment with named confidence thresholds
- User-approval workflow structure

**Observability:**
- Metrics collection wired to live operations (detect → `record_threat_detected`, respond → `record_threat_mitigated` + `record_quarantine` + `record_alert`, scan → `record_scan_performed`)
- Structured logging, health checks, audit logging

**Integrations (JSON-RPC clients):**
- `RpcClient` — full JSON-RPC 2.0 client with BTSP handshake
- `RemoteLineageVerifier` — BearDog lineage verification (`lineage.verify`, `lineage.list`)
- `DiscoveryClient` — capability-based ToadStool discovery
- `FederationClient` — Songbird federation broadcast

**Showcase:**
- 12 working examples (`cargo run --example ...`)
- 4-tier interactive demo suite (21 demos with `demo.sh` scripts)

---

## Remaining Gaps

These are **integration-layer** gaps — the local architecture is sound, and
all internal traits are implemented. What remains is connecting to live
ecosystem primals.

### CRITICAL — Blocks real deployment

| Gap | Status | Notes |
|-----|--------|-------|
| **BearDog live integration** | `RemoteLineageVerifier` complete, BTSP handshake aligned with v0.9.0 | Need BearDog to expose `lineage.list` + `btsp.session.verify` IPC |
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
| **Neural API registration** | **DONE** | `ipc.register` on startup with 6 capabilities; standalone-safe |
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

### plasmidBin Publishing

| Item | Status | Notes |
|------|--------|-------|
| **sources.toml entry** | DONE | `private = true` (`needs_sibling` removed — standalone) |
| **manifest.toml** | DONE | Binary, arch, capabilities updated |
| **checksums.toml** | READY | Awaiting harvest pipeline execution |
| **CI release workflow** | DONE | `ci.yml` release job: musl-static x86_64 + aarch64 on tag push |
| **sourDough sibling in CI** | **REMOVED** | No longer needed — build is standalone |
| **Tag + GitHub Release** | PENDING | First `v0.2.0` tag needed to trigger release pipeline |

---

## Key Insight

Most gaps are **ecosystem integration points** that require peer primals
(BearDog, ToadStool, Songbird) to be running. The core architecture, IPC
server, and local threat/defense logic are complete and tested.

The `#[ignore]`-gated integration tests are ready to light up as each
peer primal comes online.

# skunkBat — Handoff Blurb

**Role**: Defensive network security primal (Tower Atomic — perimeter defense, WAN anomaly detection)
**Version**: 0.2.18
**Date**: Jul 4, 2026
**Wave**: 132c

---

## At a Glance

| Metric | Value |
|--------|-------|
| Tests | 539 passing (0 failed) |
| Clippy | 0 warnings (pedantic + nursery, `-D warnings`) |
| Max file | 728 lines production (test files exempt from 800L cap) |
| IPC methods | 29 (Tower HTTP advisory + 6 composable primitives) |
| Unsafe code | `forbid(unsafe_code)` workspace-wide |
| Edition | 2024 |
| License | AGPL-3.0-or-later (scyBorg triple-copyleft) |
| TODOs in prod | 0 |
| Production unwrap/expect | 0 |

## What's Implemented

- **6-category threat detection**: genetic (lineage), behavioral (statistical), intrusion (signature), resource (exhaustion), topology (layer-hop), configuration drift
- **BTSP Phase 1/2/3**: socket naming, BearDog-delegated handshake (TCP + UDS), `btsp.negotiate` with ChaCha20-Poly1305 AEAD encrypted framing
- **riboCipher Tier 1**: signal-first routing (`0xEC` clear signal + protocol type byte)
- **JH-5 audit log**: 1024-event ring buffer with cursor-based forwarding to provenance/attribution DAGs
- **Federation broadcast**: monitors audit log for `ThreatDetected` events, broadcasts via Songbird
- **MethodGate**: pre-dispatch capability gate (enforced/permissive modes)
- **Defense attestation**: `ActionType`-specific audit events at `Warn` severity
- **Wire Standard L2/L3**: `capabilities.list` + `identity.get`
- **WAN timeouts**: BTSP provider_call (10s) + handshake (30s)
- **Configurable thresholds**: all detection constants via `ThreatThresholds`
- **Capability-based discovery**: no primal names hardcoded in routing

## What's Implemented (Wave 120)

- **Live observation feed**: `baseline.observe` IPC method feeds live traffic into `StatisticalProfiler` via `RwLock`
- **6-category detection LIVE**: genetic, behavioral, intrusion, resource, topology, configuration drift — all wired into `detect()`
- **Defense enforcement**: quarantined sources rejected at dispatch gate; health probes exempt
- **`defense.status` IPC method**: returns engine status, auto-response flag, quarantine snapshot
- **Transport topology wiring**: `record_connection_path()` called from BTSP handshake layer
- **riboCipher probe response**: probes receive ack payload + close (TCP + UDS)
- **BTSP session cleanup**: evict on disconnect + periodic TTL sweep (1h TTL, 5m interval)
- **Auto-response policy**: driven from config (no hardcoded `true`)
- **Quarantine thresholds configurable**: critical (0.9) and high (0.7) moved to `ThreatThresholds`
- **RuntimeVerifier probe**: startup log of verifier availability
- **`hmac-plain` removed from btsp.capabilities**: only advertises implemented ciphers

## What's Implemented (Wave 123 — MethodGate Enforcement Validation)

- **Origin-based trust**: UDS and loopback callers bypass enforcement; only remote callers need tokens
- **Bearer token extraction**: `_auth.token` in JSON-RPC params wired into `CallerContext` per-request
- **BTSP session elevation**: successful handshake auto-sets `btsp:{session_id}` bearer token
- **`defense.status` protected**: moved from public to protected (exposes quarantine state)
- **Quarantine health exemption fix**: bare `"health"` now exempt alongside `"health.*"` prefix
- **Quarantine host matching fix**: port stripped from `source_addr` before quarantine lookup
- **Manual quarantine API**: `SkunkBat::quarantine()` for operator/test injection
- **26 new enforcement tests**: origin trust, quarantine block/exempt/audit, token extraction, BTSP auth, permissive audit, enforced unknown-method rejection, parse variants

## What's Implemented (Wave 124 — Method Wiring)

- **`method_gate.status` IPC method** (public): reports enforcement mode, origin trust policy (UDS/loopback bypass, remote token-required), public methods list, public prefixes, token extraction format, BTSP elevation status — enables cross-gate security posture probes
- **`threat.report` IPC method** (protected): structured report with threat count, threat summaries (id/type/severity/source/confidence), full security metrics, and defense posture in one call — the single endpoint for cross-gate threat intelligence
- **8 new tests**: gate status introspection, public accessibility, permissive/enforced modes, threat report structure, protection level, local origin bypass

## What's Not Wired (Library-Ready)

These modules exist as complete library APIs but are not wired into the server binary:

| Module | Status | Notes |
|--------|--------|-------|
| `RuntimeVerifier` injection | Probed at startup | Needs `SkunkBat` generic refactor to inject into `ThreatDetector` |
| `ToadStool` discovery | Library-ready | `CapabilityPrimalDiscovery` for mesh scanning |
| `NestGate` content protection | Library-ready | `ContentProtector` for content integrity |
| `UniversalAdapter` | Experimental | Capability-based adapter pattern |
| `MeshRelay` transport | Stub | Returns error; transport path not implemented |

## Method Gap Audit (Wave 128)

### IPC Methods — 28 dispatched (+ `capability.list` alias), all tested

| Method | Status | Notes |
|--------|--------|-------|
| `health.*` (3) | **Complete** | Full health triad |
| `security.scan` | **Partial** | Self-only discovery; `LocalDiscovery` returns one node, empty topology |
| `security.detect` | **Partial** | 6 categories run; genetic/topology need runtime providers |
| `security.advisory` | **Complete** | Tower HTTP Gateway verdict (quarantine + defense engine check) |
| `security.respond` | **Partial** | Real policy engine; quarantine in-memory only |
| `security.metrics` | **Partial** | Flat 5 counters; not spec's nested observability model |
| `security.audit_log` | **Complete** | JH-5 ring buffer with cursor-based polling |
| `baseline.observe` | **Partial** | Works when called; no transport auto-feed |
| `baseline.query` | **Complete** | Profiler stats across all dimensions |
| `baseline.anomaly` | **Complete** | Read-only anomaly check |
| `baseline.reset` | **Complete** | Reset with optional re-seed |
| `defense.status` | **Complete** | |
| `defense.quarantine` | **Complete** | Manual quarantine via IPC + audit |
| `defense.release` | **Complete** | Release from quarantine via IPC + audit |
| `response.evaluate` | **Complete** | Read-only action recommendation |
| `method_gate.status` | **Complete** | Cross-gate posture introspection |
| `threat.report` | **Partial** | Aggregates detect+metrics+defense; inherits detect limits |
| `lifecycle.*` (3) | **Complete** | |
| `capabilities.list` | **Complete** | Wire Standard L2/L3 |
| `identity.get` | **Complete** | Wire Standard L2 |
| `auth.*` (3) | **Complete** | Token presence + gate mode |
| `btsp.*` (2) | **Complete** | Phase 3 handshake + cipher negotiation |

### Composable Primitive Domains

| Domain | Spec methods | Status |
|--------|-------------|--------|
| `baseline` | `query`, `anomaly`, `reset` | **Shipped (v0.2.17)** |
| `defense` | `quarantine`, `release` | **Shipped (v0.2.17)** |
| `response` | `evaluate` | **Shipped (v0.2.17)** |
| `response` | `escalate`, `deescalate`, `status` | Not shipped (workflow primitives) |
| `metadata` | `classify`, `fingerprint` | Not shipped |
| `lineage` | `challenge`, `verify` | Not shipped (consumes BearDog, does not expose) |
| `health` | `system`, `network`, `resource` | Not shipped (load sensing internal only) |

### Integration Wiring Gaps

| Module | Status | Impact |
|--------|--------|--------|
| `RuntimeVerifier` → `ThreatDetector` | Probed only | Genetic detection degraded without BearDog injection |
| `ToadStool` → `ReconnaissanceEngine` | Library-ready | `security.scan` cannot discover mesh primals |
| `NestGate` content protection | Library-ready | No `content.*` IPC |
| `MeshRelay` transport | Stub | Returns error; needs Songbird mesh API |

### Blocked on Upstream

| Gap | Blocker |
|-----|---------|
| Token signature/HMAC validation | BearDog ionic token spec |
| RuntimeVerifier injection | SkunkBat generic refactor (structural) |
| riboCipher Tiers 2/3 (Mito/Nuclear) | Upstream crypto spec |
| Thymic selection (entire spec) | BearDog + runtime verifier prerequisite |
| OS firewall integration | nftables binding (design phase) |

### Fixed in Wave 128

- **Registration honesty**: narrowed from 6 capabilities (including `metadata`, `response`, `lineage` with no IPC) to 10 actually-served domains
- **`capabilities.list` completeness**: `provided_capabilities` now lists all 10 domains (was 3)
- **`announce_payload` method list**: now uses dispatch table directly (was stale 18-method hardcoded list)
- **Composable primitives shipped (v0.2.17)**: `baseline.{query,anomaly,reset}`, `defense.{quarantine,release}`, `response.evaluate` — 6 new IPC methods with full test coverage

## Cascade Status

Both remotes at parity:
- `forgejo` (git.primals.eco:2222)
- `origin` (GitHub)

## Dependencies

Pure Rust. No C bindings, no FFI, no system libraries beyond std.
Key deps: `tokio`, `chacha20poly1305`, `hkdf`, `sha2`, `serde`/`serde_json`, `tracing`, `clap`, `bytes`, `base64`.

## For Upstream Overwatch

- Registration honest — only advertises domains with live IPC methods
- `capabilities.list` self-consistent with dispatch table
- All 6 original known gaps resolved (profiler, topology, sessions, probe, defense, auto-response)
- Zero known P0 debt remaining (Wave 128 registration honesty was the last)
- All detection constants configurable
- All production error paths surfaced (no silent drops)
- No hardcoded primal names in routing

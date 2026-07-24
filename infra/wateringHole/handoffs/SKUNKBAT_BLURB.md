# skunkBat — Handoff Blurb

**Role**: Defensive network security primal (Tower Atomic — perimeter defense, WAN anomaly detection)
**Version**: 0.2.18
**Date**: Jul 24, 2026
**Wave**: 150x

---

## At a Glance

| Metric | Value |
|--------|-------|
| Tests | 586 passing (0 failed, 4 crates) |
| Clippy | 0 warnings (pedantic + nursery, `-D warnings`) |
| Max file | 700 lines production (test files exempt from 800L cap) |
| IPC methods | 30 (28 application + 2 transport) |
| Unsafe code | `forbid(unsafe_code)` workspace-wide |
| Edition | 2024 |
| License | AGPL-3.0-or-later (scyBorg triple-copyleft) |
| TODOs in prod | 0 |
| Production unwrap/expect | 0 |
| Cross-arch | `x86_64-pc-windows-gnu` check passes clean |
| Dependencies | 12 workspace deps, all pure Rust, zero C FFI |

## Workspace

| Crate | Role | Type |
|-------|------|------|
| `skunk-bat-core` | Threat detection (7 types), defense, observability, universal adapter | library |
| `skunk-bat-integrations` | JSON-RPC client, BearDog lineage, ToadStool discovery, Songbird federation | library |
| `skunk-bat-server` | UniBin server (TCP + UDS + BTSP), 30 IPC methods | binary |
| `skunky-ingest` | Live Caddy log tailer → `baseline.observe` with Cloudflare analytics stub | binary |

## What's Implemented

- **7-category threat detection**: genetic (lineage), behavioral (statistical), intrusion (signature), resource (exhaustion), topology (layer-hop), configuration drift, process spawn anomaly (crash-loop)
- **HTTP anomaly detection**: `HttpObservation` model, HTTP-dimension profiling, `advisory_check_http()` for Tower HTTP Gateway
- **BTSP Phase 1/2/3**: socket naming, BearDog-delegated handshake (TCP + UDS), `btsp.negotiate` with ChaCha20-Poly1305 AEAD encrypted framing, bond-type cipher enforcement (Covalent/Metallic/Ionic), server-side cipher floor (`SKUNKBAT_CIPHER_FLOOR`), protocol version `1.0`
- **riboCipher Tier 1**: signal-first routing (`0xEC` clear signal + protocol type byte)
- **JH-5 audit log**: 1024-event ring buffer with cursor-based forwarding to provenance/attribution DAGs
- **Federation broadcast**: monitors audit log for `ThreatDetected` events, broadcasts via Songbird
- **MethodGate**: pre-dispatch capability gate (enforced/permissive modes) with origin-based trust
- **Wire Standard L2/L3**: `capabilities.list` + `identity.get`
- **Live observation feed**: `baseline.observe` IPC + `skunky-ingest` Caddy log tailer
- **Conditional baseline**: `SKUNKBAT_SKIP_SYNTHETIC_BASELINE` for live-traffic-only profiling
- **Cross-architecture (Phase 2)**: `TransportEndpoint` trait dispatch in all high-level IPC; `#[cfg]` only in low-level UDS accept/signal primitives; Windows cross-check clean
- **All timeouts env-configurable**: provider call, handshake, federation poll/batch, content, session TTL/sweep, forwarding, registration
- **Zero `#[allow]` in production**: all suppressions use `#[expect(reason)]` with documented justification
- **Generic `SkunkBat<L>`**: lineage verifier trait-generic; `RuntimeVerifier` injected at server startup
- **Capability-based discovery**: no primal names hardcoded in routing

## Method Status (30 dispatched)

| Method | Status |
|--------|--------|
| `health.*` (3) | Complete |
| `security.scan` | Partial — self-only discovery |
| `security.detect` | Partial — genetic/topology need runtime providers |
| `security.advisory` | Complete — Tower HTTP Gateway verdict |
| `security.respond` | Partial — quarantine persisted to JSON |
| `security.metrics` | Complete — nested model |
| `security.audit_log` | Complete |
| `baseline.*` (4) | Complete — observe, query, anomaly, reset |
| `defense.*` (3) | Complete — status, quarantine, release |
| `response.evaluate` | Complete |
| `method_gate.status` | Complete |
| `threat.report` | Partial — inherits detect limits |
| `capabilities.list` | Complete |
| `identity.get` | Complete |
| `lifecycle.*` (3) | Complete |
| `auth.*` (3) | Complete (beta) |
| `btsp.*` (2) | Complete |

**25 Complete, 4 Partial** (all functional, partial = scope limits documented).

## Not Wired (Library-Ready)

| Module | Status | Notes |
|--------|--------|-------|
| `ToadStool` discovery | Library-ready | `CapabilityPrimalDiscovery` for mesh scanning |
| `NestGate` content protection | Library-ready | `ContentProtector` for content integrity |
| `UniversalAdapter` | Experimental | Capability-based adapter pattern |
| `MeshRelay` transport | Stub | Returns typed error; needs Songbird mesh API |
| `HmacPlain` cipher | Protocol placeholder | Recognized, not implemented on wire |
| Cloudflare analytics | Stub | `CfConfig` + `poll_analytics` placeholder; awaiting CF credentials |
| riboCipher Tiers 2/3 | Rejected | Fail-closed with tracing; awaiting upstream spec |

## Blocked on Upstream

| Gap | Blocker |
|-----|---------|
| Token signature/HMAC validation | BearDog ionic token spec |
| riboCipher Tiers 2/3 (Mito/Nuclear) | Upstream crypto spec |
| Thymic selection (entire spec) | BearDog + runtime verifier prerequisite |
| OS firewall integration | nftables binding (design phase) |
| Cloudflare analytics wiring | CF credentials from deployment team |

## Wave History

See `CHANGELOG.md` for complete wave-by-wave implementation history.
Key milestones: Wave 120 (live detection), 123 (MethodGate enforcement), 124 (method wiring),
128 (composable primitives + registration honesty), 132c (Tower HTTP advisory), 136a (HTTP
anomaly detection), 136b (skunky-ingest), 137b (conditional baseline + CF groundwork),
141a (cross-architecture Phase 1), 142b (Phase 2 TransportEndpoint abstraction + deep debt sweep),
149b (dispatch safety — unreachable!() → METHOD_NOT_FOUND errors), 150t (Tower Atomic bond-type
cipher enforcement, platform consolidation, deep debt alloc reduction), 150w (deep debt — error
surfacing, timeout unification, named constants), 150x (process spawn anomaly detection, cipher
floor policy, unreachable!() elimination, BTSP handshake deduplication, BindMode typed error).

## Cascade Status

Both remotes at parity:
- `forgejo` (git.primals.eco:2222)
- `origin` (GitHub)

## For Upstream Overwatch

- Registration honest — only advertises domains with live IPC methods
- `capabilities.list` self-consistent with dispatch table
- All detection constants env-configurable
- All production error paths surfaced (no silent drops)
- No hardcoded primal names in routing
- Zero `TODO`/`FIXME`/`HACK` in production code
- Zero `#[allow]` in production — all `#[expect(reason)]` with justification
- Zero production `unwrap()`/`expect()`, zero `unsafe`
- Zero `unreachable!()` in production (all evolved to proper error returns)
- Zero `clippy::too_many_lines` suppressions (BTSP handshake deduplicated)
- `BindMode` typed error (`BindModeParseError`) — no `String` error types
- Cross-platform: Windows cross-check clean, musl static targets configured
- Dimensional posture: GREEN — all dimensions clear (Wave 150x audit)

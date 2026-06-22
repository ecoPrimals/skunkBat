# skunkBat — Handoff Blurb

**Role**: Defensive network security primal (Tower Atomic — perimeter defense, WAN anomaly detection)
**Version**: 0.2.14
**Date**: Jun 22, 2026
**Wave**: 123

---

## At a Glance

| Metric | Value |
|--------|-------|
| Tests | 510 passing (0 failed) |
| Clippy | 0 warnings (pedantic + nursery, `-D warnings`) |
| Max file | 728 lines (all under 800L cap) |
| IPC methods | 20 (all Stable tier, incl. `baseline.observe`, `defense.status`) |
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

## What's Not Wired (Library-Ready)

These modules exist as complete library APIs but are not wired into the server binary:

| Module | Status | Notes |
|--------|--------|-------|
| `RuntimeVerifier` injection | Probed at startup | Needs `SkunkBat` generic refactor to inject into `ThreatDetector` |
| `ToadStool` discovery | Library-ready | `CapabilityPrimalDiscovery` for mesh scanning |
| `NestGate` content protection | Library-ready | `ContentProtector` for content integrity |
| `UniversalAdapter` | Experimental | Capability-based adapter pattern |
| `MeshRelay` transport | Stub | Returns error; transport path not implemented |

## Known Gaps (for upstream teams)

1. **RuntimeVerifier injection**: server probes for BearDog at startup but can't inject it into `ThreatDetector` without making `SkunkBat` generic (structural refactor, blocked on BearDog BTSP).
2. **Defense actions in-memory only**: Quarantine/block update a `HashMap`, reject at dispatch gate, and emit traces — no OS firewall/nftables integration yet.
3. **riboCipher Tiers 2/3**: Mito (`0xED`) and Nuclear (`0xEE`) signals logged and rejected — not implemented (needs upstream crypto spec).
4. **MeshRelay transport**: `TransportEndpoint::MeshRelay` returns error stub — needs Songbird mesh API for relay protocol.
5. **Auth gate token signature validation**: bearer token extraction and BTSP elevation wired (Wave 123); signature/HMAC verification pending (blocked on BearDog ionic token spec).
6. **ToadStool discovery**: library-ready but `ReconnaissanceEngine` still uses `LocalDiscovery` at runtime.

## Cascade Status

Both remotes at parity:
- `forgejo` (git.primals.eco:2222)
- `origin` (GitHub)

## Dependencies

Pure Rust. No C bindings, no FFI, no system libraries beyond std.
Key deps: `tokio`, `chacha20poly1305`, `hkdf`, `sha2`, `serde`/`serde_json`, `tracing`, `clap`, `bytes`, `base64`.

## For Upstream Overwatch

- All 6 original known gaps resolved (profiler, topology, sessions, probe, defense, auto-response)
- Zero known P0 debt remaining
- All detection constants configurable
- All production error paths surfaced (no silent drops)
- No hardcoded primal names in routing
- Registration uses `env_keys` constants
- Federation cursor stops on failure (retry semantics)
- Forwarding cursor stops on failure (retry semantics)

# skunkBat — Handoff Blurb

**Role**: Defensive network security primal (Tower Atomic — perimeter defense, WAN anomaly detection)
**Version**: 0.2.11
**Date**: Jun 20, 2026
**Wave**: 120

---

## At a Glance

| Metric | Value |
|--------|-------|
| Tests | 470 passing (0 failed) |
| Clippy | 0 warnings (pedantic + nursery, `-D warnings`) |
| Max file | 728 lines (all under 800L cap) |
| IPC methods | 19 (all Stable tier, incl. `baseline.observe`) |
| Unsafe code | `forbid(unsafe_code)` workspace-wide |
| Edition | 2024 |
| License | AGPL-3.0-or-later (scyBorg triple-copyleft) |
| TODOs in prod | 0 |
| Production unwrap/expect | 0 |

## What's Implemented

- **5-category threat detection**: genetic (lineage), behavioral (statistical), intrusion (signature), resource (exhaustion), topology (layer-hop)
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
- **5-category detection LIVE**: genetic, behavioral, intrusion, resource, topology — all wired into `detect()`
- **Defense enforcement**: quarantined sources rejected at dispatch gate; health probes exempt
- **riboCipher probe response**: probes receive ack payload + close (TCP + UDS)
- **BTSP session cleanup**: evict on disconnect + periodic TTL sweep (1h TTL, 5m interval)
- **Auto-response policy**: driven from config (no hardcoded `true`)
- **RuntimeVerifier probe**: startup log of verifier availability

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
4. **Topology path source**: `record_connection_path()` API exists but transport layer doesn't emit paths yet (needs BTSP handshake metadata or mesh routing context).
5. **ConfigurationDrift detection**: `ThreatType::ConfigurationDrift` defined but no detection category implemented.

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

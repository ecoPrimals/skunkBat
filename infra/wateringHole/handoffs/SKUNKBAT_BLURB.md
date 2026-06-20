# skunkBat — Handoff Blurb

**Role**: Defensive network security primal (Tower Atomic — perimeter defense, WAN anomaly detection)
**Version**: 0.2.10
**Date**: Jun 20, 2026
**Wave**: 119

---

## At a Glance

| Metric | Value |
|--------|-------|
| Tests | 470 passing (0 failed) |
| Clippy | 0 warnings (pedantic + nursery, `-D warnings`) |
| Max file | 728 lines (all under 800L cap) |
| IPC methods | 18 (all Stable tier) |
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

## What's Not Wired (Library-Ready)

These modules exist as complete library APIs but are not wired into the server binary:

| Module | Status | Notes |
|--------|--------|-------|
| `RuntimeVerifier` | Library-ready | Probes for remote lineage provider; server uses `LocalLineageVerifier` |
| `ToadStool` discovery | Library-ready | `CapabilityPrimalDiscovery` for mesh scanning |
| `NestGate` content protection | Library-ready | `ContentProtector` for content integrity |
| `UniversalAdapter` | Experimental | Capability-based adapter pattern |
| `MeshRelay` transport | Stub | Returns error; transport path not implemented |

## Known Gaps (for upstream teams)

1. **Profiler not fed live data**: `StatisticalProfiler` seeded at startup with static baseline. Nothing feeds live network observations in production — detection runs on stale seed data.
2. **Topology detection not wired**: Documented as 5th category but `detect()` only runs 4 (genetic, behavioral, intrusion, resource). `LayerTopologyValidator` exists but unused.
3. **Defense actions are in-memory only**: Quarantine/block update a `HashMap` and emit traces — no firewall/IPC/connection teardown integration.
4. **BTSP session cleanup**: `SessionRegistry::remove()` exists but never called on disconnect. No TTL task.
5. **riboCipher Tiers 2/3**: Mito (`0xED`) and Nuclear (`0xEE`) signals logged and rejected — not implemented.
6. **Probe response**: `0x00` probe logged but no response sent back.

## Cascade Status

Both remotes at parity:
- `forgejo` (git.primals.eco:2222)
- `origin` (GitHub)

## Dependencies

Pure Rust. No C bindings, no FFI, no system libraries beyond std.
Key deps: `tokio`, `chacha20poly1305`, `hkdf`, `sha2`, `serde`/`serde_json`, `tracing`, `clap`, `bytes`, `base64`.

## For Upstream Overwatch

- Zero known P0/P1 debt remaining
- All detection constants configurable
- All production error paths surfaced (no silent drops)
- No hardcoded primal names in routing
- Registration uses `env_keys` constants
- Federation cursor stops on failure (retry semantics)
- Forwarding cursor stops on failure (retry semantics)

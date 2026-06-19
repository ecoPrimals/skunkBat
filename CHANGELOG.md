# Changelog

All notable changes to skunkBat are documented here.

## [Unreleased]

### Added

- **riboCipher Tier 1** — `classify_connection()` reads `0xEC` clear signal + 
  protocol type byte, routing to NDJSON, BTSP, or probe. Legacy `{` peek falls
  back with deprecation warning. Tiers 2/3 (`0xED`/`0xEE`) log + reject.
- **`ThreatThresholds`** — all detection constants configurable on
  `SkunkBatConfig.thresholds` (sigma, DoS, genetic, intrusion ports/volume/ratio)
- **Intrusion detection** — `detect_intrusions()` with port-scan (2+ sensitive
  ports) and data-exfiltration (traffic-to-connection ratio) heuristics
- **Chaos tests wired** — `tests/chaos_testing.rs` registered in `Cargo.toml`
  (9 passing: rapid lifecycle, concurrent load, degradation, recovery)

### Changed

- `dispatch.rs` refactored: tests extracted to `dispatch_tests.rs` (862→430L
  production code), `id` passed by value to sub-dispatchers (fewer clones)
- `method_gate.check()` takes `&serde_json::Value` (clone only on rejection path)
- `lifecycle.status` returns actual primal state (was hardcoded "running")
- `detect_genetic_threats` reports degraded threat on verifier error (was silent)
- Discovery: hardcoded primal names (`songbird.sock`, `biomeos.sock`) removed —
  capability-based `DISCOVERY_SOCKET`/`NEURAL_API_SOCKET` env convention only
- Trace labels evolved from primal names to capabilities (`provenance`, `attribution`)
- Baseline port sweep patterns decoupled from ecosystem-specific ports
- `Timestamp::now()` uses non-panicking fallback (was `.expect()`)
- Silent error drops in BTSP (handshake, negotiate, HKDF) now log warnings
- NestGate `integrity_sweep` tracks and logs RPC failures (was silent skip)
- Example code updated: `beardog_integration.rs` uses `RemoteLineageVerifier`,
  `songbird_integration.rs` uses real `SkunkBatConfig` fields
- `lib.rs` quick-start doc fixed (removed `.await` on sync `respond_to_threat`)
- XDG socket dir resolution centralized in `resolve_socket_dir()`
- Background tasks (registration, forwarding) aborted on graceful shutdown

### Fixed

- `clippy::too_many_lines` in dispatch (extracted sub-dispatchers)
- `clippy::significant_drop_tightening` in dispatch (scoped `RwLock` guards)
- `defense_actions` example `too_many_lines` lint
- File count in docs (49→50 after `dispatch_tests.rs` extraction)

## [0.2.0] — 2026-05-17

### Added

- **BTSP Phase 3** — `btsp.negotiate` cipher negotiation with ChaCha20-Poly1305
  AEAD encrypted framing (auto-upgrade from NDJSON)
- **JH-0 MethodGate** — pre-dispatch capability authorization gate with
  `Permissive` (default) and `Enforced` modes (`SKUNKBAT_AUTH_MODE`)
- **JH-5 Audit Log** (Phases 1–3) — structured security event trail with
  ring buffer, cursor-based RPC polling (`security.audit_log`), and cross-primal
  forwarding to rhizoCrypt DAG + sweetGrass braids
- **NestGate content protection** — `ContentProtector` for CAS integrity
  verification via `content.*` IPC
- **BearDog live lineage** — `RemoteLineageVerifier` with graceful degradation,
  mock-server integration tests proving end-to-end wiring
- **`btsp.capabilities`** — advertises BTSP protocol version, supported ciphers,
  key derivation method
- **`--bind` flag** (PG-55) — CLI bind address override, secure-by-default
  `127.0.0.1` (was `0.0.0.0`)
- **Baseline learning** (PG-57) — multi-dimensional statistical profiler with
  auto-seeding (connection rate, traffic volume, port diversity)
- **Auth introspection** — `auth.check`, `auth.mode`, `auth.peer_info` methods
- **Forwarding service** — background task forwards Warn+ events to rhizoCrypt
  (`dag.event.append`) and sweetGrass (`braid.create`) via capability-based IPC
- **Wire Standard L3** — `capabilities.list` includes `protocol`, `transport`,
  `count`, BTSP capability section
- **Stability tiers** — all 18 methods annotated as Stable
- **Composition readiness docs** — degradation behavior, downstream pairing

### Changed

- `server.rs` split into focused modules (server, dispatch, transport, method_gate)
- `Result<_, String>` evolved to typed `TransportError` / `RpcError` enums
- `async-trait` eliminated (RPITIT)
- Tokio dependency trimmed to `sync`-only in `skunk-bat-core`
- Health reporting expanded with `dependency_health` (lineage verifier + observer)
- Federation broadcaster propagates errors (was silently swallowing)
- `deny.toml` adds explicit `ring` ban (ecoBin parity)

### Fixed

- BufReader post-negotiate corruption (leftover bytes into encrypted frame loop)
- `btsp.negotiate` inside batch arrays properly rejected (transport upgrade is
  incompatible with batch semantics)
- Threat IDs use clean microsecond epoch format (was Debug-formatted SystemTime)
- Stale showcase references, capability name drift
- Unfulfilled lint expectation in example code

### Security

- Default bind changed from `0.0.0.0` to `127.0.0.1` (secure-by-default)
- MethodGate enforced mode rejects protected methods with `-32001`
- Audit log records all gate rejections and permissive-allows
- Encrypted frame decryption failures logged to audit trail

## [0.1.0] — 2025-12-01

Initial release. BTSP Phase 1/2, basic threat detection, defense orchestration.

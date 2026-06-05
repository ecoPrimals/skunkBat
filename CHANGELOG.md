# Changelog

All notable changes to skunkBat are documented here.

## [0.2.4] — 2026-06-05

### Added

- **`--no-tcp` flag** — port-free UDS-only deployment mode for Tower Atomic compliance
- **`--socket` passthrough** — launcher-injected paths now reach the UDS listener
  directly (e.g. `--socket /run/membrane/skunkbat.sock --no-tcp`)
- Standalone capability symlink (`security.sock → skunkbat.sock`) when using
  `--socket` without `BtspConfig`

### Changed

- `serve_uds()` accepts `socket_override` parameter — no longer ignores `--socket` flag
- `serve()` accepts `no_tcp` parameter — full 4-mode deployment matrix
  (TCP+UDS, TCP-only, UDS-only, error)
- Deployment modes: UDS-only (port-free), TCP-only (legacy), TCP+UDS (default)

## [0.2.3] — 2026-06-05

### Added

- **`config/capability_registry.toml`** — machine-readable capability declaration
  per Wave 78 ecosystem standard (biomeOS dispatch compatibility)
- **Test scale sprint**: 391 → 500 tests across defense escalation edge cases,
  audit log coverage, topology validation, behavioral profiler boundaries,
  reconnaissance serialization, and dispatch auth methods
- `defense.status` classified as Public in MethodGate (health probe accessible
  without auth for gate deployment)

### Changed

- File count: 52 source files, max 670 lines/file
- Zero `#[allow]` in production (Wave 78 compliant, only `#[expect]` with reasons)

## [0.2.2] — 2026-06-04

### Added

- **`defense.status` method** — dedicated health probe for gate deployment; returns
  defense engine health, threat detection status, auto-response mode, quarantine count,
  and aggregated metrics (threats_detected, threats_mitigated, scans_performed)
- Delegate accessors on `SkunkBat`: `defense_healthy()`, `threat_detection_healthy()`,
  `auto_response_enabled()`, `defense_quarantine_snapshot()`
- `test_defense_status_responds` — validates gate health probe contract

### Changed

- Extracted dispatch tests to `dispatch_tests.rs` (391L production → 391L, tests in 453L sibling)
- File count: 52 source files, max 670 lines/file

## [0.2.1] — 2026-06-03

### Added

- **5-category threat pipeline complete** — intrusion detection (port-scan metadata),
  topology validation (layer-bypass via `TopologyValidator`), all wired into `detect()`
- **Defense escalation** — Block reachable via graduated escalation (3 repeated threats
  from same source auto-escalate Monitor → Quarantine → Block)
- **BTSP bond-type enforcement** — `handle_negotiate` validates cipher meets bond minimum
  (Covalent=null, Metallic≥hmac, Ionic=chacha20); rejects with `cipher_below_bond_minimum`
- **`test_escalation_to_block`** — coverage for the new escalation path

### Changed

- `LocalLineageVerifier` returns `Err` (no authority) instead of `Ok(false)`
- `RemoteLineageVerifier` returns `Err` when provider is unreachable (not `Ok(false)`)
- Genetic detection correctly skips in degraded mode (no false Critical alarms)
- `ThreatDetector` now generic over 3 axes: `LineageVerifier`, `BaselineProfiler`, `TopologyValidator`
- `DefenseEngine::determine_action` is instance method (escalation-aware)
- `negotiate.rs` tests extracted to `negotiate_tests.rs` (826L → 479L production)
- `threats/mod.rs` tests extracted to `mod_tests.rs` (851L → 452L production)
- All source files under 800L (max 791)

### Fixed

- Perpetual false Critical genetic threat in standalone mode (LocalLineageVerifier `Ok(false)` semantics)
- `BondType` and `minimum_cipher()` dead-code annotations removed (now active)

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
- **Stability tiers** — all 17 methods annotated as Stable
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

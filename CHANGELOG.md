# Changelog

All notable changes to skunkBat are documented here.

## [0.2.9] — 2026-06-10

### Changed

- **Zero-port standard compliance** — TCP binding is now OFF by default.
  `skunkbat server` runs UDS-only (port-free). TCP activates only when:
  - `--port <N>` is explicitly passed (Tier 5 fallback), OR
  - `PRIMAL_BIND_MODE=fallback` env var is set, OR
  - `TRANSPORT_ENDPOINT` specifies TCP
- Resolves `SKUNKBAT-TCP-9750` audit item from Wave 107.
- Added `PRIMAL_BIND_MODE` env key (`uds-only` default, `fallback` enables TCP).
- `--port` is now `Option<u16>` (not always present in CLI args).

## [0.2.8] — 2026-06-09

### Changed

- **Zero `Box<dyn Error>` in production** — replaced all trait-object error
  handling with typed enums:
  - `main.rs`: `ServerError` (thiserror-derived)
  - `ipc/mod.rs` + `transport/mod.rs`: `TransportError` (now includes `Task` variant)
- **`TRANSPORT_ENDPOINT` fully wired** — server reads env var at startup,
  overrides CLI flags. All integration clients (beardog, toadstool, songbird,
  forwarding) prefer `*_TRANSPORT` env vars (sourDough JSON format) over legacy
  TCP endpoint strings.
- **Integration transport evolution** — `RemoteLineageVerifier`, `DiscoveryClient`,
  and `FederationClient` now accept `LINEAGE_TRANSPORT`, `DISCOVERY_TRANSPORT`,
  `FEDERATION_TRANSPORT` env vars (JSON `TransportEndpoint` format). Resolution
  priority: TransportEndpoint > legacy TCP > capability socket.
- **Forwarding transport evolution** — `forward_to_dag()` / `forward_to_braid()`
  resolve via `ResolvedTarget` enum, preferring `RHIZOCRYPT_TRANSPORT` /
  `SWEETGRASS_TRANSPORT` env vars.
- **One-shot DRY** — extracted `started_instance()` helper for one-shot commands.

## [0.2.7] — 2026-06-08

### Added

- **`TransportEndpoint` type** — wire-compatible with sourDough's canonical
  `TransportEndpoint` enum (serde-tagged JSON: `uds`, `tcp`, `mesh_relay`).
  Supports `TRANSPORT_ENDPOINT` env var for launcher-injected transport.
- **`call_endpoint()`** — dispatches JSON-RPC calls via resolved
  `TransportEndpoint`, unifying the UDS/TCP call paths under a single type.
- **`TRANSPORT_ENDPOINT` env key** — declared in `env_keys` for ecosystem-wide
  transport injection (Wave 100 Transport Evolution Trigger compliance).

### Changed

- **`dispatch()` refactored** — extracted `authorize()` and `dispatch_detect()`
  helpers to comply with `clippy::too_many_lines` (nursery, 100L threshold).
- **`handle_negotiate()` refactored** — extracted `parse_negotiate_params()` for
  cleaner parameter validation flow.

## [0.2.6] — 2026-06-05

### Changed

- **`--socket` implies `--no-tcp`** — providing `--socket /path` now defaults
  to UDS-only (port-free) mode, matching the ecosystem deployment convention
  used by bearDog, songBird, and other primals. Add explicit `--port` to
  re-enable TCP alongside UDS.
- Resolves Wave 79b gate-crossing blurb: `skunkbat server --socket
  /run/membrane/skunkbat.sock` now starts port-free without needing `--no-tcp`.

## [0.2.5] — 2026-06-05

### Changed

- **Runtime transport metadata** — `identity.get` and `capabilities.list` now
  reflect actual active transports from `--no-tcp`/`--no-uds` flags rather than
  hardcoding `["uds", "tcp"]`
- **Lock contention reduction** — dispatch audit recording clones `AuditLog`
  (Arc-backed) and drops `RwLockReadGuard<SkunkBat>` before async `.record()`
  calls, eliminating unnecessary lock-hold across await points
- **Capabilities response dedup** — `capabilities_response()` constructs the
  methods Vec once and reuses it for both `capabilities` and `methods` fields
- Migrated last two `#[allow(dead_code)]` to target-conditional
  `#[cfg_attr(not(test), expect(dead_code))]` — zero `#[allow]` in production

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

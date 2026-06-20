# Changelog

All notable changes to skunkBat are documented here.

## [Unreleased]

### Added

- **Live observation feed** — `baseline.observe` IPC method + `ThreatDetector::observe()`
  wraps profiler in `RwLock` so live traffic observations update the rolling window;
  anomaly detection now uses current data instead of frozen startup baseline
- **Topology detection (5th category)** — `detect_topology_threats()` wired into
  `detect()` via `LayerTopologyValidator`; configurable `expected_topology_path` on
  `SkunkBatConfig`; `record_connection_path()` API for transport layer integration
- **Defense enforcement** — quarantined sources rejected at dispatch gate with
  `PERMISSION_DENIED`; health probes exempt; `CallerContext` carries `source_addr`
  from TCP transport
- **riboCipher probe response** — probes now receive `{"primal":"skunkbat","status":"alive"}`
  ack + close (TCP and UDS); discovery agents no longer hang until timeout
- **BTSP session cleanup** — `handle_connection` evicts sessions on disconnect;
  periodic TTL sweep (1h TTL, 5m interval) prevents unbounded `HashMap` growth;
  `SessionRegistry::sweep_expired()` added; `remove()`/`created_at` dead_code removed
- **Auto-response policy** — `auto_response_enabled` driven from `config.features.auto_defense`
  (was hardcoded `true`); `execute_action()` downgrades quarantine/block to alert when disabled
- **Quarantine query** — `DefenseEngine::is_quarantined()` and `SkunkBat::is_quarantined()`
  for pre-dispatch enforcement
- **RuntimeVerifier probe** — server logs verifier availability at startup (remote/local);
  structural injection deferred (requires `SkunkBat` generic refactor + BearDog BTSP)
- **`BaselineObservation` audit event** — audit log records live observation feeds

### Changed

- `baseline_profiler` wrapped in `tokio::sync::RwLock` for interior mutability
- `detect_intrusions`/`detect_behavioral_anomalies` acquire profiler read lock
  and drop it before building threat responses
- `alert_operator` refactored to associated function (no `&self`)

---

## [0.2.10]

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
- **Federation broadcast loop** — `run_federation_loop()` monitors audit log
  for `ThreatDetected` events and broadcasts via Songbird `federation.broadcast`;
  spawned at server startup alongside forwarding loop
- **BTSP WAN timeouts** — `provider_call` (10s) and `perform_server_handshake`
  (30s) wrapped in `tokio::time::timeout` to prevent indefinite hangs from
  slow/malicious peers or stalled BearDog providers

### Changed

- `dispatch.rs` refactored: tests extracted to `dispatch_tests.rs` (862→430L
  production code), `id` passed by value to sub-dispatchers (fewer clones)
- `threats/mod.rs` smart refactored: 899→160L orchestrator + `detection.rs`
  (246L) + tests extracted to `threats_tests.rs`; deleted 619L orphan `mod_tests.rs`
- `negotiate.rs` smart refactored: 826→484L, tests extracted to
  `negotiate_tests.rs` via `#[path]`; deleted 351L orphan duplicate
- `method_gate.check()` takes `&serde_json::Value` (clone only on rejection path)
- `lifecycle.status` returns actual primal state (was hardcoded "running")
- `detect_genetic_threats` reports degraded threat on verifier error (was silent)
- Discovery: hardcoded primal names (`songbird.sock`, `biomeos.sock`) removed —
  capability-based `DISCOVERY_SOCKET`/`NEURAL_API_SOCKET` env convention only
- Registration uses `env_keys::DISCOVERY_SOCKET` constant (was string literal)
- Trace labels evolved from primal names to capabilities (`provenance`, `attribution`)
- Baseline `normal_baseline_with_port()` accepts runtime port (was hardcoded 9750);
  `ThreatDetector::new` passes `config.common.listen_port`
- `Timestamp::now()` uses non-panicking fallback (was `.expect()`)
- Silent error drops in BTSP (handshake, negotiate, HKDF) now log warnings
- UDS setup failures (dir creation, stale socket removal) surfaced with `tracing::warn`
- Defense `quarantine_map` mutex poison now logged at error (was silent skip)
- NestGate `integrity_sweep` tracks and logs RPC failures (was silent skip)
- `serve_uds` refactored: setup extracted to `setup_uds_listener()`, resolving
  `clippy::too_many_lines`
- `hmac-plain` cipher: recognized in protocol but excluded from `select_best_cipher`
  (not implemented on wire — was silently negotiated then ignored)
- Example code updated: `beardog_integration.rs` uses `RemoteLineageVerifier`,
  `songbird_integration.rs` uses real `SkunkBatConfig` fields
- `lib.rs` quick-start doc fixed (removed `.await` on sync `respond_to_threat`)
- XDG socket dir resolution centralized in `resolve_socket_dir()`
- Background tasks (registration, forwarding, federation) aborted on graceful
  shutdown via `BackgroundTasks::abort_all()`
- `respond_to_threat()` returns `Result<ActionType, E>` (was `Result<(), E>`)
  so callers can log/attest the specific defense action taken
- Defense audit events emitted at `EventSeverity::Warn` with actual `ActionType`
  (was `Info` with generic `"responded"`) — now flows through JH-5 forwarding
  pipeline to provenance DAG and attribution braids

### Fixed

- `clippy::too_many_lines` in dispatch (extracted sub-dispatchers)
- `clippy::too_many_lines` in `serve_uds` (extracted setup)
- `clippy::significant_drop_tightening` in dispatch (scoped `RwLock` guards)
- `defense_actions` example `too_many_lines` lint
- **Forwarding cursor bug** — cursor now only advances past successfully
  forwarded events; previously advanced on failure, silently dropping events
- **Federation cursor bug** — cursor now stops advancing on broadcast failure,
  matching forwarding loop retry semantics
- Deleted 970 lines of orphan test files (`mod_tests.rs`, `negotiate_tests.rs`)
  that were never compiled — replaced with `#[path]` references

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

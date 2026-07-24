# Changelog

All notable changes to skunkBat are documented here.

## [Unreleased]

### Added

- **Server-side cipher floor policy** (Wave 150x pen-test response): New
  `SKUNKBAT_CIPHER_FLOOR` env var sets server minimum cipher regardless of
  client `bond_type`. Prevents cipher-downgrade attacks where clients omit
  `bond_type` to negotiate null. `select_best_cipher_with_floor()` inner
  function enables safe unit testing without env mutation. 6 new tests.
- **`BindMode` typed error**: Replaced `type Err = String` with
  `BindModeParseError` (thiserror-derived) for idiomatic Rust error handling.
- **Process spawn-rate anomaly detection** (Wave 150x): New 7th threat category
  `ProcessSpawnAnomaly` detecting crash-loop services via `/proc/stat` fork
  counter rate tracking. `SpawnRateTracker` in `platform.rs` samples total
  forks since boot and computes spawns/second. Configurable threshold
  (`spawn_rate_threshold`, default 50.0 forks/sec) + confidence
  (`spawn_rate_confidence`, default 0.85). Env-overridable via
  `SKUNKBAT_SPAWN_RATE_THRESHOLD`. Flows through existing `security.detect` +
  `threat.report` IPC methods. Windows-safe (returns 0.0 on non-Linux).
  Motivated by Wave 150x crash-loop divergence (29,081 systemd restarts undetected).
- **Deep debt sweep** (Wave 150w): Fix 2 silently dropped `Result`s (quarantine
  dir creation, probe flush). Unify integration timeout to shared
  `rpc::integration_timeout_ms()` (5000ms). Extract 6 magic numbers to named
  constants (audit pagination, BTSP seed min, HTTPS port, federation defaults).
  Tighten `pub` visibility (`system_load_normalized` → `pub(crate)`,
  `normal_baseline` → `#[cfg(test)]`).
- **Tower Atomic bond-type cipher enforcement** (Wave 150t): `BondType`
  (Covalent/Metallic/Ionic) evolved from test-only to production usage in
  `select_best_cipher()`. Ionic bonds reject null cipher, Metallic requires
  HMAC minimum. `btsp.negotiate` accepts optional `bond_type` param from
  songBird enrollment flow. `BTSP_PROTOCOL_VERSION` constant (`1.0`) in
  negotiate + capabilities responses. `fallback` field in negotiate response.
  `btsp.capabilities` now advertises `bond_types` and `fallback` behavior.
  `cipher_strength()` ordering function for typed cipher comparison.
- **Platform consolidation**: `system_load_normalized()` extracted to
  `platform.rs`, consolidating inline `#[cfg(target_os)]` from `detection.rs`.
  Platform-specific code now single module alongside `proc_uid()`.
- **`skunky-ingest` binary crate** (Wave 136b): Live Caddy JSON access log tailer
  feeding per-source-IP HTTP metrics into `baseline.observe` via TCP JSON-RPC.
  Per-window aggregation of connection rate, traffic volume, request rate, error
  rates (4xx/5xx), path/method diversity, latency. Crash-safe cursor tracking.
  `thiserror`-based typed errors. riboCipher NDJSON signal prefix on connect.
- **Cloudflare analytics stub** (Wave 137b): `cloudflare.rs` module with `CfConfig`
  and `poll_analytics` placeholder. CLI flags `--cf-api-token`, `--cf-zone-id`,
  `--cf-poll-secs` for future outer-membrane data flow.
- **HTTP anomaly detection** (Wave 136a): `HttpObservation` struct, HTTP-dimension
  statistical profiling (`request_rate`, `path_diversity`, `error_rate_4xx`),
  `advisory_check_http()` for Tower HTTP Gateway with HTTP-specific anomaly filtering.
  `HttpMetrics` in `SecurityObserver`.
- **Conditional synthetic baseline** (Wave 137b): `SKUNKBAT_SKIP_SYNTHETIC_BASELINE`
  env var. When live data flows via `skunky-ingest`, start with empty profiler that
  learns from traffic. Fixed `StatisticalProfiler::reset` port consistency.
- **Cross-architecture adoption** (Wave 141a): `#[cfg(unix)]`/`#[cfg(not(unix))]`
  guards on UDS transport (`provider_call`), Unix signals (`SIGTERM`), registration
  callsites, capability symlinks. Windows cross-check passes clean.
  musl static build aliases in `.cargo/config.toml` (`build-x64`, `build-arm64`).
- **Phase 2: TransportEndpoint abstraction** (Wave 142b): Evolved all IPC dispatch
  from `#[cfg]`-gated raw UDS to `TransportEndpoint` trait dispatch. Registration
  (`self_register`, `neural_announce`) now resolve `TransportEndpoint` (UDS, TCP,
  or `TransportEndpoint` JSON from env). BTSP `provider_call` dispatches via
  `call_endpoint`. `CapabilityClient` holds `Option<TransportEndpoint>` internally.
  Eliminated legacy `ResolvedTarget` enum, `rpc::call()`, and `ContentProtector`
  raw `uds_path`/`tcp_endpoint` fields. New env key: `BTSP_PROVIDER_TRANSPORT`.
  All integration constructors take `&str` (zero-copy). Every platform is first-class.
- **4 new env keys**: `SKUNKBAT_FEDERATION_POLL_SECS`, `SKUNKBAT_FEDERATION_BATCH_SIZE`,
  `SKUNKBAT_CONTENT_TIMEOUT`, `SKUNKBAT_HANDSHAKE_DEADLINE` — hardcoded timeouts
  evolved to env-configurable.

### Changed

- **`CapabilityClient` consolidation**: Extracted shared transport logic (endpoint,
  UDS, timeout, RPC dispatch) into `rpc::CapabilityClient`. All three integration
  clients (`RemoteLineageVerifier`, `DiscoveryClient`, `FederationClient`) now
  delegate transport to this shared struct, eliminating ~120 lines of duplication.
- **Quarantine persistence**: `DefenseEngine` now persists quarantine state to
  `{data_dir}/quarantine.json` on mutation and loads on startup. Round-trip tested.
  `SKUNKBAT_DATA_DIR` env var controls the persist path.
- **Nested security metrics**: `SecurityMetrics` evolved from flat counters to
  structured `{ threats, scanning, defense }` sub-domains. IPC responses
  (`security.metrics`, `security.scan`, `threat.report`) emit the nested model.
  Flat accessors retained for backwards-compatible reads.
- **Dispatch security split**: Moved security-domain handlers (`security.*`,
  `threat.report`, `baseline.observe`, `security.advisory`) from `dispatch.rs`
  (659L → 421L) to `dispatch_security.rs` (290L). Shared `parse_threat_params`
  helper eliminates duplicated threat deserialization.
- **`SkunkBatConfig::from_env()`**: Production config hydration from environment.
  Reads `SKUNKBAT_LINEAGE_ID` and `SKUNKBAT_TOPOLOGY_PATH`. Server startup
  uses `from_env()` instead of `default()`.
- **Integration timeout externalization**: `SKUNKBAT_INTEGRATION_TIMEOUT_MS`
  env var controls bearDog, songBird, and toadStool RPC timeouts (default 3–5s).
- **Test fixture consolidation**: Extracted 4 duplicated `test_config()` functions
  into `test_support` module with `test_config()` and `test_config_with_lineage()`.
- **Generic `SkunkBat<L: LineageVerifier>`**: Core struct generic over lineage verifier
  trait. `RuntimeVerifier` injected at server startup via `with_verifier()`. One-shot
  CLI commands use default local verifier.
- **Test extraction**: ~1,500 lines of inline tests extracted to dedicated `_tests.rs`
  files across 5 modules (defense, behavioral, types, forwarding, method_gate, btsp).
- **`skunky-ingest` error evolution**: `Box<dyn Error>` → `thiserror` `IngestError` enum.
  `expect()` calls in RPC client replaced with `let-else` error propagation.
- **Session sweep metrics**: `SessionRegistry::len()` wired into production sweep logging.
- **`BondType` annotation refinement**: `#[allow(dead_code)]` → `#[cfg_attr(not(test), allow)]`.
- **Toadstool cross-platform**: UDS discovery loop restructured inside `#[cfg(unix)]`
  block, eliminating cross-platform unused variable warnings.
- **Caddy latency wiring**: `duration` field wired into aggregator `IpBucket` for
  latency tracking via `mul_add`. False `dead_code` on `host` field removed.
- **Platform UID**: Magic number `1000` → named `DEFAULT_USER_UID` constant.
- **`pentest_attack_patterns()`** gated behind `#[cfg(test)]`.
- **Dispatch safety** (Wave 149b): Replaced 4 production `unreachable!()` in
  sub-dispatch functions with proper `METHOD_NOT_FOUND` JSON-RPC error responses.
  Server can no longer panic from method list mismatch.
- **Clippy lint evolution** (Wave 143b): Resolved `useless_conversion`,
  `duration_suboptimal_units`. `#[expect(dead_code)]` evolved to
  `#[cfg_attr(not(test), expect(dead_code))]` for items used from tests.
- **Deep debt sweep** (Wave 142b–150t): All production `#[allow]` evolved to
  `#[expect(reason)]` with documented justification. Dead fields removed from
  `skunky-ingest` `RpcResponse`. Announce payload cost/latency hints extracted
  to named constant modules. `ConfigDiff.diff()` returns `(&'static str, String, String)`
  eliminating field-name allocations. `BtspHandshakeConfig.family_id` annotation updated
  for Tower Atomic bond-type resolution.

## [0.2.18] — 2026-07-04 (Wave 132c: Tower HTTP Gateway advisory)

### Added

- **`security.advisory` IPC method**: Advisory verdict for inbound requests from
  the Tower HTTP Gateway. Checks quarantine list + defense engine state. Returns
  structured `AdvisoryVerdict` with `verdict` (allow/warn/block), `reason`, `source`,
  and `threat_ids`. Public (no auth required — mesh peers call it).
- **`AdvisoryVerdict` + `Verdict` types** in `skunk-bat-core` — serializable structured
  response for gateway integration.
- **6 new tests**: 2 core-level advisory tests + 4 dispatch-level integration tests
  (clean source, quarantined source, missing param, public access enforcement).

### Changed

- **Method count**: 28 → 29 IPC methods (27 application + 2 transport).
- **`security.advisory` in `PUBLIC_METHODS`**: accessible without auth token (mesh
  peers call this during request routing).
- **Registration threshold**: `announce_payload_methods_complete` now asserts ≥29.

## [0.2.17] — 2026-07-04 (Wave 128: Composable Primitives & Config Evolution)

### Added

- **6 composable primitive IPC methods** from `COMPOSABLE_PRIMITIVES_SPEC.md`:
  - `baseline.query` (public) — profiler statistics across all dimensions
  - `baseline.anomaly` (public) — read-only anomaly check against baseline
  - `baseline.reset` (protected) — reset profiler with optional re-seed
  - `defense.quarantine` (protected) — manual quarantine with audit trail
  - `defense.release` (protected) — release from quarantine with audit trail
  - `response.evaluate` (protected) — read-only action recommendation
- **`dispatch_composable.rs`** — smart split: composable handlers in dedicated module
- **`DefenseEngine::release()`** — remove source from quarantine map
- **`DefenseEngine::evaluate()`** — read-only action recommendation without execution
- **`StatisticalProfiler::query_stats()`** — dimension-level baseline statistics
- **`StatisticalProfiler::reset()`** — clear observations with optional re-seed
- **`StatisticalProfiler::with_config()`** — configurable rolling window and min observations
- **`BaselineStats` / `DimensionStats`** types for structured profiler statistics
- **`BaselineProfiler` trait extensions** — `query_stats()` and `reset()` with default impls
- **3 new `ThreatThresholds` fields** — `behavioral_rolling_window`, `behavioral_min_observations`,
  `audit_log_capacity` externalize previously hardcoded constants
- **14 new tests** for composable IPC methods (quarantine/release lifecycle, evaluate,
  query/anomaly/reset, protection classification, established-state verification)
- **`#[must_use]` on `DefenseEngine::respond()`**

### Changed

- `StatisticalProfiler` now uses configurable `rolling_window` and `min_observations`
  instead of hardcoded `ROLLING_WINDOW = 100` and `>= 10`
- `AuditLog` capacity wired from `ThreatThresholds::audit_log_capacity` (was hardcoded 1024)
- `capabilities.list` `provided_capabilities` now includes `response`, `defense.{quarantine,release}`,
  `baseline.{query,anomaly,reset}` domains
- Registration `CAPABILITIES` includes `response` domain
- **Typed transport errors**: `serve_tcp`, `serve_uds`, and `serve` return
  `Result<_, TransportError>` instead of `Box<dyn Error>`. Removed dead `Ipc` variant
  from `ServerError`.
- **Test module split**: `dispatch_tests.rs` (1011L) → 3 domain-focused modules:
  `dispatch_tests.rs` (393L), `dispatch_tests_gate.rs` (301L),
  `dispatch_tests_composable.rs` (382L).
- **`#[inline]` hot-path annotations**: `DefenseEngine::{is_quarantined, is_healthy,
  auto_response_enabled}`, `MethodGate::{check, mode}`, `classify_method`,
  `EnforcementMode::as_str`.
- **Externalized server timeouts**: `SESSION_TTL`, `SESSION_SWEEP_INTERVAL`,
  `REGISTRATION_TIMEOUT`, `FORWARD_TIMEOUT`, `FORWARD_INTERVAL`,
  `FORWARD_MIN_SEVERITY` — all now read from env with sensible defaults.
  New `ForwardingConfig::from_env()` constructor.
- **6 new `env_keys`**: `SKUNKBAT_SESSION_TTL`, `SKUNKBAT_SESSION_SWEEP`,
  `SKUNKBAT_FORWARD_INTERVAL`, `SKUNKBAT_FORWARD_TIMEOUT`,
  `SKUNKBAT_FORWARD_MIN_SEVERITY`, `SKUNKBAT_REGISTRATION_TIMEOUT`.

---

## [0.2.16] — Wave 128: Method Gap Audit & Registration Honesty

### Fixed

- **Registration honesty**: narrowed advertised capabilities from 6 (including
  `metadata`, `response`, `lineage` with no IPC methods) to 9 actually-served domains
- **`capabilities.list` completeness**: `provided_capabilities` now lists all 9
  shipped domains with their methods (was only 3: security, health, btsp)
- **`announce_payload` stale method list**: replaced hardcoded 18-method list with
  `all_methods()` sourced from dispatch table (now 23 methods)
- **Clippy `needless_collect`**: replaced `collect()` + `.len()` / `.is_empty()` with
  `.count()` / `!.any()` in threat tests
- **Unfulfilled `#[expect]`**: removed stale `too_many_lines` on `defense_actions` example

### Changed

- CONTEXT.md method table now shows implementation completeness per method
  (14 Complete, 8 Partial with documented scope limits)
- CONTEXT.md documents all composable primitive gaps from `COMPOSABLE_PRIMITIVES_SPEC.md`
- Handoff blurb restructured with full method gap audit, integration wiring gaps,
  and upstream blockers

---

## [0.2.15] — Wave 124: Method Wiring

### Added

- **`method_gate.status` IPC method** (public) — returns enforcement mode, origin trust
  policy, public methods/prefixes, token extraction format, BTSP elevation status;
  enables cross-gate security posture probes
- **`threat.report` IPC method** (protected) — structured report combining threat
  detection results, full security metrics, and defense posture in one call; the single
  endpoint for cross-gate threat intelligence
- **8 new tests** — gate status introspection (posture, mode, public accessibility),
  threat report structure/metrics/defense fields, protection levels, local origin bypass

### Test Count

518 tests passing (was 510).

---

## [0.2.14] — Wave 123: MethodGate Enforcement Validation

### Added

- **Origin-based trust** — UDS and loopback callers bypass MethodGate enforcement;
  only remote callers require a bearer token under `Enforced` mode
- **Bearer token extraction** — `_auth.token` field in JSON-RPC params wired into
  `CallerContext` per-request (connection-level BTSP token takes precedence)
- **BTSP session elevation** — successful BTSP handshake sets `btsp:{session_id}`
  bearer token on the connection, allowing BTSP-authenticated remotes to pass gate
- **Manual quarantine API** — `SkunkBat::quarantine()` and `DefenseEngine::quarantine()`
  for operator-triggered or test quarantine injection
- **`EnforcementMode::parse()`** — testable string parser extracted from `from_env()`
- **26 new tests** — origin trust (UDS, loopback, remote), quarantine enforcement
  (block, health exemption, audit logging), bearer token extraction (`_auth.token`,
  connection precedence), BTSP session auth, permissive audit logging, enforced-mode
  unknown method rejection, `EnforcementMode::parse()` variants

### Changed

- **`defense.status` moved to Protected** — quarantine state exposure requires
  authentication for remote callers
- **Quarantine health exemption** — bare `"health"` now exempt alongside `"health.*"`
  prefix (consistency fix)
- **Quarantine host matching** — dispatch strips port from `source_addr` before
  quarantine lookup (fix: `10.0.0.5:4321` → `10.0.0.5`)

### Test Count

510 tests passing (was 484).

---

## [0.2.13]

### Added

- **`defense.status` IPC method** — returns defense engine status snapshot (enabled,
  auto_response, quarantine list); was advertised in PUBLIC_METHODS but never dispatched
- **Transport topology wiring** — `record_connection_path()` now called from BTSP
  handshake in TCP transport layer; topology paths encoded as layer-traversal bytes
  (0=UDS, 1=loopback, 2=remote, 2+3=remote+BTSP)

### Changed

- Quarantine confidence thresholds (`0.9` critical, `0.7` high) moved from hardcoded
  constants to `ThreatThresholds` fields (`quarantine_critical_confidence`,
  `quarantine_high_confidence`); `determine_action()` now uses configurable values
- `hmac-plain` cipher removed from `btsp.capabilities` response (was advertised but
  never implemented on wire; only `chacha20-poly1305` and `null` are functional)
- Redundant `transport/sys.rs` shim removed; `config.rs` calls
  `skunk_bat_core::platform::proc_uid()` directly
- Duplicate `proc_uid()` wrapper in `rpc.rs` consolidated to `skunk_bat_core::platform`
- Tautological test assertion fixed (`threats.is_empty() || !threats.is_empty()` → meaningful
  assertion on genetic threat count)
- Flaky tests fixed: `test_detect_threats`, `test_integration_detect_and_respond`,
  `test_threat_detection_with_local_verifier`, `test_threat_detection_no_lineage_id` now
  filter by threat category instead of asserting total count (system load varies at CI)
- Docs updated from "5 threat types" to "6" across README, CONTEXT, sporeprint,
  THYMIC_SELECTION_SPEC, and capability_registry.toml
- `capability_registry.toml` version bumped, `baseline.observe` domain added,
  consumed primals replaced with consumed capabilities (no hardcoded primal names)
- README updated to v0.2.13 (was 0.2.0), 20 IPC methods, 484+ tests

---

## [0.2.12]

### Added

- **Configuration drift detection (6th category)** — `detect_configuration_drift()`
  compares startup `ConfigSnapshot` against live state; monitors features, lineage_id,
  topology_configured, and threshold fingerprint; emits `ConfigurationDrift` threats
- **`ConfigSnapshot`** — captures security-relevant config at construction for
  drift comparison; serde-serializable with diff support
- **`DEFAULT_PORT` constant** — consolidated from duplicate definitions in
  `main.rs` and `baseline.rs` to single `skunk_bat_core::DEFAULT_PORT`
- **`ThreatThresholds` expansion** — added `degraded_genetic_confidence` (0.5),
  `topology_confidence` (0.9), `drift_confidence` (0.85); replaces hardcoded literals

### Changed

- `RemoteLineageVerifier` returns `Err` on RPC failure (was `Ok(false)`, which
  caused false Critical genetic alerts instead of correct Medium/degraded)
- `lib.rs` tests extracted to `lib_tests.rs` (377L → 377L + 280L, was 662L)
- Non-Linux resource detection logs warning when load unavailable

---

## [0.2.11]

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

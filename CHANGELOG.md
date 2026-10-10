# skunkBat — Evolution Record

The changelog is sorted by capability surface, not by date.
Each section tells the arc: what emerged, what it replaced, what it became.
The date-sorted session history lives in `CHANGELOG_ARCHIVE.md`.

`H(data|epitope) < H(data|date) < H(data)`

---

## Transport — riboCipher, BTSP, Frame Crypto

The wire protocol evolved from raw JSON-RPC over UDS to a three-tier
cryptographic transport with session keys, cipher negotiation, and
bond-type enforcement.

- **riboCipher Tier 1** (Wave 136): `0xEC` clear signal + protocol type byte
  routing to NDJSON, BTSP, or probe. Legacy `{` peek falls back with deprecation.
  Tiers 2/3 (`0xED`/`0xEE`) log + reject.
- **BTSP Phase 1–3** (0.1.0 → 0.2.0): Challenge-response authentication →
  cipher negotiation → ChaCha20-Poly1305 AEAD encrypted framing.
  `btsp.negotiate` auto-upgrades from NDJSON. `btsp.capabilities` advertises
  protocol version, ciphers, key derivation, bond types.
- **Bond-type cipher enforcement** (Wave 150t): `BondType` (Covalent/Metallic/Ionic)
  from test-only to production. Ionic rejects null cipher, Metallic requires HMAC.
  `SKUNKBAT_CIPHER_FLOOR` env sets server minimum regardless of client.
- **Frame crypto extraction** (Wave 155b): `SessionKeys`, `derive_session_keys`,
  `encrypt_frame`, `decrypt_frame` from `negotiate.rs` → `frame.rs` (571→447 lines).
- **BTSP ClientHello** (Wave 151b): Consumer-side 4-step handshake for bearDog strict mode.
  HMAC-SHA256 challenge-response on UDS and TCP. Auto-detects strict mode + seed.
- **TransportEndpoint abstraction** (Wave 142b): All IPC dispatch evolved from
  `#[cfg]`-gated raw UDS to `TransportEndpoint` trait. UDS, TCP, and env-JSON
  first-class. Eliminated `ResolvedTarget`, `rpc::call()`, raw path fields.
- **Session cleanup**: Evict on disconnect, periodic TTL sweep (1h TTL, 5m interval).

## Detection — Threats, Anomalies, Topology

Six threat categories, each with statistical profiling against a learned baseline.

- **Baseline learning** (0.2.0): Multi-dimensional statistical profiler with
  auto-seeding. `baseline.observe` IPC for live traffic observation.
  Conditional synthetic baseline (`SKUNKBAT_SKIP_SYNTHETIC_BASELINE`).
- **Intrusion detection** (0.2.10): Port-scan (2+ sensitive ports) and
  data-exfiltration (traffic-to-connection ratio) heuristics.
- **Process spawn anomaly** (Wave 150x): `/proc/stat` fork counter rate tracking.
  Detects crash-loop services (motivated by 29,081 undetected systemd restarts).
- **Connectivity anomaly** (Wave 155d): Sliding window outbound RPC probe results.
  9th threat category for infrastructure layer failures. Motivated by golgiBody
  peptidoglycan incident (silent iptables DROP).
- **HTTP anomaly** (Wave 136a): Per-source-IP statistical profiling of request rate,
  path diversity, error rates. Advisory check for Tower HTTP Gateway.
- **Topology detection** (0.2.11): `LayerTopologyValidator`, configurable
  `expected_topology_path`, connection path recording.
- **`ThreatThresholds`** (0.2.10): All detection constants configurable on
  `SkunkBatConfig.thresholds`. No more magic numbers.

## Defense — Quarantine, Gates, Response

Quarantine lifecycle from detection through automated enforcement.

- **MethodGate** (0.2.0): Pre-dispatch capability authorization. Permissive (default)
  and Enforced modes (`SKUNKBAT_AUTH_MODE`). Gate rejections → audit trail.
- **Quarantine enforcement** (0.2.11): Quarantined sources rejected at dispatch gate
  with `PERMISSION_DENIED`. Health probes exempt. Persistence to JSON on mutation.
- **Auto-response policy**: `auto_response_enabled` from config (was hardcoded `true`).
  Quarantine/block downgrades to alert when disabled.
- **ConfigurationDrift detection** (0.2.12): `ConfigSnapshot` captures security
  config at construction, diffs against runtime. Serde-serializable.
- **Dispatch safety** (Wave 149b): 4 production `unreachable!()` → proper
  `METHOD_NOT_FOUND` responses. Server can no longer panic from method mismatch.

## Observation — skunky-ingest, Caddy Bridge, Fleet

The observation pipeline: Caddy access logs → behavioral profiling → fleet
routing → dashboard visualization.

- **skunky-ingest** (Wave 136b): Live Caddy JSON log tailer. Per-window aggregation
  of connection rate, traffic, request rate, error rates, path/method diversity, latency.
  Crash-safe cursor tracking. `thiserror`-based typed errors.
- **Caddy bridge** (Wave 150+): Fleet IP injection into Caddyfile for posture-aware
  routing. Negative selection (self-IPs protected). Sourdough restore across restarts.
  **Wave 172**: Vacuole fix — writes snippet files, Caddyfile no longer modified.
- **Dashboard writer**: Replaces `bloom_live.py`. Writes `dashboard.json`,
  `state.json`, `epitope_caddy.json`.
- **Cloudflare analytics stub** (Wave 137b): `CfConfig` + `poll_analytics` placeholder.

## Federation — Capabilities, Discovery, Audit

Cross-primal coordination through capability-based IPC.

- **CapabilityClient** consolidation: Shared transport logic for lineage verification,
  discovery, and federation. `RemoteLineageVerifier` with graceful degradation.
- **Audit log** (0.2.0): Structured security event trail with ring buffer,
  cursor-based polling, cross-primal forwarding to rhizoCrypt + sweetGrass.
- **Federation broadcast** (0.2.10): Background loop monitors audit for Warn+ events,
  broadcasts via songBird. Cursor bug fix: stops advancing on failure.
- **Wire Standard L3**: `capabilities.list` includes protocol, transport, count,
  BTSP capability section.
- **Squirrel announce** (Wave 172): Fire-and-forget membrane observation announcements
  to squirrel AI coordination primal.

## Architecture — Debt, Extraction, Platform

Structural evolution of the codebase itself.

- **Generic core**: `SkunkBat<L: LineageVerifier>` — core struct generic over
  lineage verifier trait. Runtime injection via `with_verifier()`.
- **Dispatch split**: `dispatch.rs` 659→421 lines, security domain → `dispatch_security.rs`.
- **Test extraction**: ~1,500 lines from inline to dedicated `_tests.rs` files
  across 5 modules.
- **Cross-architecture** (Wave 141a): `#[cfg(unix)]`/`#[cfg(not(unix))]` guards
  on UDS, signals, registration. musl static builds for x64 and arm64.
- **Config from env**: `SkunkBatConfig::from_env()` hydrates from environment.
  4+ env keys externalized from hardcoded values.
- **Bind security** (0.2.0): Default `0.0.0.0` → `127.0.0.1`. `--bind` CLI override.
- **Deep debt** (ongoing): Eliminated `unreachable!()`, `expect()`, `Box<dyn Error>`,
  `Result<_, String>`. Evolved to `thiserror` enums, typed errors, `let-else`.

---

*Full date-sorted history: `CHANGELOG_ARCHIVE.md`*
*Last compressed: Wave 172*

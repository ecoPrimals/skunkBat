# skunkBat — Context

Defensive network security primal for sovereign computing environments.
Provides reconnaissance, threat detection, automated defense, and security
observability — all metadata-only, no content inspection by architecture.

## Workspace Structure

| Crate | Role | Type |
|-------|------|------|
| `skunk-bat-core` | Threat detection (5 types), defense orchestration, observability, universal adapter | library |
| `skunk-bat-integrations` | JSON-RPC 2.0 client, BearDog lineage, ToadStool discovery, Songbird federation | library |
| `skunk-bat-server` | UniBin server: TCP + UDS JSON-RPC, BTSP Phase 1/2/3 (BearDog-delegated handshake + `btsp.negotiate`), Wire Standard L2/L3 | binary |

## Key Concepts

- **5 Threat Types**: Genetic (lineage), Topology (layer-hopping), Behavioral (statistical anomaly), Intrusion (signatures), Resource (DoS/exhaustion)
- **Graduated Response**: Monitor, Quarantine, Block — always preserving user authority
- **Statistical Baselines**: Learns the owner's network normal via `VecDeque` rolling window profiler
- **Universal Adapter**: Capability-based discovery and announcement via `primal_foundation` traits
- **JSON-RPC 2.0**: Newline-delimited protocol on TCP and UDS, from-scratch implementation

## IPC Surface

- **Transport**: TCP (`--port`, default 9750) + UDS (`--socket` or `$BIOMEOS_SOCKET_DIR/skunkbat-{family_id}.sock`); `--no-tcp` for port-free deployment
- **BTSP Phase 1**: `FAMILY_ID` socket scoping, `BIOMEOS_INSECURE` guard, `XDG_RUNTIME_DIR` fallback
- **BTSP Phase 2**: BearDog-delegated handshake on **both TCP and UDS** with first-byte peek (`{` → plain JSON-RPC for biomeOS composition bypass)
- **BTSP Phase 3**: `btsp.negotiate` server handler with encrypted frame upgrade — session registry, cipher selection, HKDF key derivation, `ChaCha20-Poly1305` AEAD framing wired into connection loop (`[4B len][12B nonce][ct+tag]`)
- **Wire Standard**: `capabilities.list` (L2) and `identity.get` (L3) methods
- **Domain Methods**: `health.*`, `defense.status`, `security.*`, `lifecycle.*`, `capabilities.*`, `identity.*`, `btsp.*`
- **Capability Symlinks**: `security.sock` domain symlink created on bind

## Ecosystem Integration

- **BearDog**: Genetic lineage verification (WHO) — `lineage.verify` + `lineage.list` via `lineage-verification.sock` or `LINEAGE_ENDPOINT`
- **ToadStool**: Capability-based primal discovery (WHERE) — JSON-RPC via `discovery.sock` or `DISCOVERY_ENDPOINT`
- **Songbird**: Federated threat intelligence (COORDINATION) — JSON-RPC via `federation.sock` or `FEDERATION_ENDPOINT`
- **NestGate**: Protected application platform (HOME)

All integration is capability-based runtime discovery. No primal names hardcoded in routing.

**Discovery Escalation Hierarchy** (ecosystem-wide, primalSpring Phase 58+):
1. Songbird `ipc.resolve` — highest fidelity, cross-gate capable
2. biomeOS Neural API (`capability.discover`)
3. UDS filesystem convention (`skunkbat-{family_id}.sock`) ← we support this
4. Socket registry / manifests
5. TCP probing (port 9750) ← we support this

skunkBat supports tiers 1 (via `ipc.register`), 3, and 5 out of the box.

## Composable Primitives

skunkBat decomposes into five primitive domains, each independently useful:

| Domain | What It Does | General Use |
|--------|-------------|-------------|
| `baseline` | Rolling-window statistical anomaly detection | Time-series pattern analysis for any metric |
| `metadata` | Connection metadata extraction and classification | Traffic analysis, deduplication |
| `response` | Progressive state machine with escalation | Any graduated workflow engine |
| `lineage` | Identity challenge via BearDog delegation | Trust boundary arbitration |
| `health` | System load, network state, resource utilization | Cross-platform system sensing |

## Thymic Selection Model (Design Phase)

Self/non-self discrimination inspired by biological thymic education. BearDog provides
the genetic identity system (MHC); skunkBat acts as the thymus, training detector probes
against known-self and eliminating self-reactive ones. What survives detects novel threats
without signature databases. See `specs/THYMIC_SELECTION_SPEC.md`.

## Dependencies

Pure Rust. Zero cross-repo path dependencies — primal lifecycle traits internalized
from `sourdough-core` (same AGPL-3.0-or-later license) as `primal_foundation`. All async traits
use native RPITIT (Edition 2024) — `async-trait` eliminated and banned. No C
dependencies in application code.

## JSON-RPC 2.0

Full spec compliance including:
- Single requests with standard error codes (-32700 through -32603)
- **Batch requests** (JSON array dispatch, per-spec error handling)
- **Notifications** (id-less requests produce no response, per §4.1)
- Newline-delimited framing on TCP and UDS

## Tests

500 tests passing (265 core + 79 integrations + 136 server + 20 transport/integration), all workspace lib+bins.
90%+ function coverage (llvm-cov); core ~96%, btsp ~94%, dispatch ~97%, threats ~98%,
crypto ~100%. Behavioral profiler, genetic/topology verifiers, JSON-RPC types all exercised.
Full end-to-end test for NDJSON→encrypted frame upgrade path including multi-message
encrypted loop verification, plaintext-after-upgrade rejection, encrypted batch requests,
and encrypted notification (no-response) verification.

## Status

v0.2.7 — Edition 2024, clippy pedantic+nursery clean (zero warnings), `forbid(unsafe_code)`
workspace-wide. `#[expect(reason)]` lint standard (zero `#[allow]` in production; target-conditional
`#[cfg_attr(not(test), expect(...))]` only). `--socket` implies `--no-tcp` per ecosystem convention.
Transport Evolution: `TransportEndpoint` type (sourDough-compatible) + `TRANSPORT_ENDPOINT` env
var for launcher-injected transport (Wave 100 compliance, ready for full adoption).
JSON-RPC IPC server with BTSP Phase 1/2/3 (TCP + UDS first-byte peek, BearDog-delegated
handshake aligned with v0.9.0, `btsp.negotiate` server handler with session registry and
ChaCha20-Poly1305 AEAD framing). `rand` eliminated — OsRng via RustCrypto re-export.
and Wire Standard L2/L3 compliance. Consumed capabilities: `btsp.session.verify`,
`lineage.verify`, `lineage.list`, `capabilities.list`, `federation.broadcast`,
`discovery.find_by_capability`. Cross-platform (`proc_uid`, `check_system_load`).
No magic numbers — all thresholds named. 52 source files, max 670 lines/file (btsp.rs).
Zero cross-repo path dependencies — `sourdough-core` types internalized
as `primal_foundation`. `async-trait` eliminated and banned — native RPITIT throughout.
`RemoteLineageVerifier` integration ready; verifier semantics evolved (Err = no authority,
Ok(false) = authoritative denial). All 5 threat categories implemented: genetic (lineage
authority), behavioral (statistical profiler), intrusion (port-scan metadata), topology
(layer-bypass validation), resource (DoS). Defense graduated escalation: Monitor → Quarantine
→ Block (3+ repeated offenses). BTSP bond-type enforcement active (Covalent/Metallic/Ionic
cipher minimums). 500 tests (265+79+136+20), pure Rust crypto deps
wired and tested (chacha20poly1305, hkdf, sha2, base64 — HKDF key derivation, AEAD exercised;
`rand` crate eliminated — `OsRng` via `chacha20poly1305::aead::rand_core`).
Self-registration with discovery (`ipc.register`) wired — standalone-safe probe on startup.
`server.rs` refactored (945→322L production, tests extracted to `server_tests.rs` with DRY
helpers). `derive_session_keys` evolved from `.expect()` to `Result<_, TransportError>`.
Hardcoded `"beardog"` provider name evolved to capability-based `"btsp"` default.
Unused `hex` dependency removed. All `Result<_, String>` errors evolved to typed enums
(`TransportError`, `RpcError`) with structured variants for match-based handling.
`btsp.negotiate` inside batch arrays explicitly rejected (transport upgrade incompatible
with batch semantics).
BTSP Phase 3 fully wired: handshake key plumbed from Phase 2 into `SessionRegistry`,
`btsp.negotiate` derives directional session keys, connection loop auto-upgrades to
encrypted `ChaCha20-Poly1305` framing (`[4B len][12B nonce][ct+tag]`). Aligned with
`BearDog` reference implementation: base64 nonces, `client_nonce` from params, directional
key derivation (`btsp-session-v1-c2s`/`s2c`), 32-byte server nonce, `ciphers` array support.
`select_best_cipher` matches ecosystem preference order (chacha20-poly1305 > hmac-plain > null).
`detect_genetic_threats` evolved from no-op to real lineage verifier call (produces
`UnknownLineage` threat on verification failure). `RuntimeVerifier` enum dispatch added
(`integrations::verifier`) — probes env at startup for remote provider, falls back to
conservative local default. `SecurityObserver` metrics wired into live pipeline:
`detect_threats` → `record_threat_detected`, `respond_to_threat` → `record_threat_mitigated`
+ `record_quarantine` + `record_alert`, `scan_network` → `record_scan_performed`.
`DefenseEngine::respond` returns `ActionType` for caller instrumentation.
`btsp.negotiate` separated from dispatch `METHODS` into `TRANSPORT_METHODS` — transport-only,
advertised in `capabilities.list` but rejected by `dispatch()`.
`SKUNKBAT_LISTEN_ADDR` env var added for bind address parity with `SKUNKBAT_PORT`.
Threat IDs evolved from Debug-formatted SystemTime to clean microsecond epoch format.
BufReader post-negotiate fix: inner stream (not buffered wrapper) passed to encrypted frame
loop — prevents leftover NDJSON bytes from corrupting binary frames. `identity.get` carries
Wire Standard L3 fields (`protocol`, `transport`). Songbird `songbird.sock` probed directly
in registration discovery. `skunk-bat-core` tokio trimmed to `sync`-only (was pulling full
runtime for one `RwLock`). `SkunkBat::dependency_health` implemented — reports lineage verifier
and observer status. `FederationThreatBroadcaster::broadcast` now propagates errors (was
silently swallowing). `Vec::with_capacity` in batch handler and threat detection.
`universal_adapter` documented as experimental (not production-path).
PG-55: `--bind` CLI flag added to `server` subcommand (UniBin v1.1 pattern) — precedence:
CLI flag > `SKUNKBAT_LISTEN_ADDR` env > `127.0.0.1` default (secure-by-default, localhost-only).
Use `--bind 0.0.0.0` to explicitly expose on all interfaces.
PG-57: Baseline learning pipeline established — `StatisticalProfiler::seed_baseline()` called
at construction with 12 normal-traffic observations. Profiler `is_established()` gate now
passes from first `detect()`. Multi-dimensional analysis: connection rate, traffic volume,
and port diversity all contribute to anomaly scoring. 7 pen-test attack patterns (port
enumeration, payload flood, malformed JSON-RPC burst, service enumeration, amplification,
slow-rate exhaustion, protocol confusion) documented in `threats::baseline` module.
JH-0 MethodGate: pre-dispatch capability gate wired into `dispatch()`. Methods classified
as Public (health.*, identity.get, capabilities.list, lifecycle.*, auth.*) or Protected
(security.*). `SKUNKBAT_AUTH_MODE=enforced` rejects unauthenticated protected calls with
`-32001 PERMISSION_DENIED`. Default is permissive (log + allow). New `auth.check`,
`auth.mode`, `auth.peer_info` methods advertised. CallerContext carries connection origin
(Unix/Loopback/Remote) and optional bearer token. Gate emits structured tracing events
on every rejection — these are the primary signal for JH-5 security audit ingestion.
JH-5 (implemented — Phase 2): `AuditLog` ring buffer (1024 events) in `observability::audit_log`.
Structured `SecurityEvent` types: GateRejection, GatePermissiveAllow, ThreatDetected, DefenseAction,
BtspNegotiate, BtspDecryptFailure, LifecycleTransition. All event kinds now emitted from live code:
- Gate events: dispatch auto-records on rejection/permissive-allow
- Threat events: `security.detect` records each detected threat
- Defense events: `security.respond` records successful defense actions
- Transport events: BTSP negotiate records success/failure + cipher, decrypt failures logged
- Lifecycle events: start/stop transitions recorded
`security.audit_log` RPC method exposes cursor-based event polling. `capabilities.list` includes
`audit_log` in security methods (L3 wire compliance).
Phase 3 forwarding shipped: `forwarding::run_forwarding_loop` polls audit log every 10s, forwards
Warn+ events to rhizoCrypt `dag.event.append` (UDS `provenance.sock` or `RHIZOCRYPT_ENDPOINT`)
and sweetGrass `braid.create` (UDS `attribution.sock` or `SWEETGRASS_ENDPOINT`). Best-effort —
unreachable targets are retried next cycle. Spawned as background task on server startup.
H2 niche: NestGate data protection module (`nestgate.rs`) — `ContentProtector` for content
integrity scanning via `content.*` IPC. Live lineage integration tests prove bearDog wiring.
Enforced mode integration tests prove full dispatch-level gate rejection + audit log recording.
`btsp.capabilities` method added — advertises protocol version, supported ciphers, key derivation.

## Stadial Composition Readiness

### Method Stability Tiers

| Method | Tier | Notes |
|--------|------|-------|
| `health.liveness` | Stable | Always returns `{"status":"alive"}` |
| `health.readiness` | Stable | Returns primal state |
| `health.check` | Stable | Full health report with dependency status |
| `security.scan` | Stable | Network topology reconnaissance |
| `security.detect` | Stable | Threat detection pipeline |
| `security.respond` | Stable | Graduated defense response |
| `security.metrics` | Stable | Observability counters |
| `security.audit_log` | Stable | Cursor-based event polling (JH-5) |
| `capabilities.list` | Stable | Wire Standard L3 compliant |
| `identity.get` | Stable | Wire Standard L3 compliant |
| `lifecycle.status` | Stable | Deployment convergence health endpoint |
| `lifecycle.state` | Stable | Current primal state |
| `lifecycle.capabilities` | Stable | All registered methods |
| `auth.check` | Stable | Token presence + gate mode |
| `auth.mode` | Stable | Current enforcement mode |
| `auth.peer_info` | Stable | Connection origin + token status |
| `btsp.negotiate` | Stable | Phase 3 cipher negotiation + encrypted framing |
| `btsp.capabilities` | Stable | Protocol version, ciphers, key derivation |

### Degradation Behavior

When skunkBat is **down** in a composition:
- Security events stop flowing to rhizoCrypt/sweetGrass (audit gap)
- No threat detection or defense orchestration
- Other primals continue operating normally (skunkBat is observability, not gate)
- Health probes from biomeOS will report the primal as unreachable

When **bearDog** is down: `RemoteLineageVerifier` degrades to local conservative
default (all unknown peers treated as non-family). Threat detection continues
but genetic lineage checks are unavailable.

When **rhizoCrypt/sweetGrass** are down: audit events stay in local ring buffer
(1024 events). Forwarding retries each poll cycle. No data loss unless the
buffer fills before targets recover.

### Downstream Pairing

| Partner | Relationship |
|---------|-------------|
| cellMembrane | VPS audit trail — skunkBat monitors cellMembrane's exposed surface |
| lithoSpore | Verification — skunkBat audit events are verification artifacts |
| projectNUCLEUS | Sovereignty — skunkBat provides security observability for NUCLEUS deployments |
| rhizoCrypt | DAG forwarding — security events as tamper-evident vertices |
| sweetGrass | Braid attribution — security attestations in provenance chain |
| bearDog | Lineage verification — genetic threat detection via `lineage.verify` |

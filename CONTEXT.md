# skunkBat — Context

Defensive network security primal for sovereign computing environments.
Provides reconnaissance, threat detection, automated defense, and security
observability — all metadata-only, no content inspection by architecture.

## Workspace Structure

| Crate | Role | Type |
|-------|------|------|
| `skunk-bat-core` | Threat detection (6 types), defense orchestration, observability, universal adapter | library |
| `skunk-bat-integrations` | JSON-RPC 2.0 client, BearDog lineage, ToadStool discovery, Songbird federation | library |
| `skunk-bat-server` | UniBin server: TCP + UDS JSON-RPC, BTSP Phase 1/2/3 (BearDog-delegated handshake + `btsp.negotiate`), Wire Standard L2/L3 | binary |

## Key Concepts

- **6 Threat Types**: Genetic (lineage), Topology (layer-hopping), Behavioral (statistical anomaly), Intrusion (signatures), Resource (DoS/exhaustion), Configuration Drift
- **Graduated Response**: Monitor, Quarantine, Block — always preserving user authority
- **Statistical Baselines**: Learns the owner's network normal via `VecDeque` rolling window profiler
- **Universal Adapter**: Capability-based discovery and announcement via `primal_foundation` traits
- **JSON-RPC 2.0**: Newline-delimited protocol on TCP and UDS, from-scratch implementation

## IPC Surface

- **Transport**: TCP (`--port`, default 9750) + UDS (`--socket` or `$BIOMEOS_SOCKET_DIR/skunkbat-{family_id}.sock`)
- **BTSP Phase 1**: `FAMILY_ID` socket scoping, `BIOMEOS_INSECURE` guard, `XDG_RUNTIME_DIR` fallback
- **BTSP Phase 2**: BearDog-delegated handshake on **both TCP and UDS** with riboCipher signal-first routing (`0xEC` clear signal → protocol type, `{` → legacy NDJSON bypass with deprecation warning)
- **BTSP Phase 3**: `btsp.negotiate` server handler with encrypted frame upgrade — session registry, cipher selection, HKDF key derivation, `ChaCha20-Poly1305` AEAD framing wired into connection loop (`[4B len][12B nonce][ct+tag]`)
- **Wire Standard**: `capabilities.list` (L2) and `identity.get` (L3) methods
- **Domain Methods**: `health.*`, `security.*`, `lifecycle.*`, `capabilities.*`, `identity.*`, `auth.*`, `baseline.*`, `defense.*`, `btsp.*`
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

532 tests passing (core + integrations + server + transport + chaos), all workspace.
Includes 9 chaos/fault-injection tests (rapid lifecycle, concurrent load, resource
exhaustion, partial degradation). Behavioral profiler, genetic/topology verifiers,
intrusion heuristics, riboCipher signal classification, JSON-RPC types all exercised.
Full end-to-end test for NDJSON→encrypted frame upgrade path including multi-message
encrypted loop verification, plaintext-after-upgrade rejection, encrypted batch requests,
and encrypted notification (no-response) verification.
Wave 123: MethodGate enforcement validation — 26 new tests covering origin-based trust,
quarantine enforcement, bearer token extraction, BTSP session elevation, and permissive/enforced
mode semantics for local, loopback, and remote callers.

## Status

v0.2.18 — Edition 2024, clippy pedantic+nursery clean (zero warnings), `forbid(unsafe_code)`
workspace-wide. `#[expect(reason)]` lint standard (target-conditional `#[allow]` only).

**540 tests** passing across all workspace crates. Max production file 728 lines — no
production source exceeds the 800-line cap (test files exempt). All thresholds configurable
via `ThreatThresholds` — zero magic numbers. All server operational timeouts externalized
to env vars with defaults (session TTL, sweep, forwarding, registration).
Zero cross-repo path dependencies. Pure Rust crypto stack (chacha20poly1305, hkdf, sha2).
`async-trait` eliminated and banned — native RPITIT throughout.

**IPC**: JSON-RPC 2.0 over TCP + UDS with BTSP Phase 1/2/3. BearDog-delegated handshake,
`btsp.negotiate` with session registry, `ChaCha20-Poly1305` AEAD encrypted framing.
riboCipher signal-first routing (`0xEC` clear signal). Wire Standard L2/L3 compliance.
29 stable IPC methods — `security.advisory` for Tower HTTP Gateway (Wave 132c),
6 composable primitives shipped in v0.2.17 (`baseline.{query,anomaly,reset}`,
`defense.{quarantine,release}`, `response.evaluate`). `hmac-plain` cipher recognized but
excluded from negotiation (not implemented on wire — falls to null).

**MethodGate**: Pre-dispatch authorization gate with `Permissive`/`Enforced` modes
(env `SKUNKBAT_AUTH_MODE`). Origin-based trust: UDS + loopback bypass enforcement;
remote callers require bearer token. Token extraction from `_auth.token` in JSON-RPC
params. BTSP-authenticated sessions auto-elevated (`btsp:{session_id}` token).
`defense.status` protected (exposes quarantine state). Unknown methods classified as
Protected — gate rejects before `METHOD_NOT_FOUND` under enforcement.

**Detection**: 6-category threat detection (genetic, behavioral, intrusion, resource,
topology, configuration drift) — all wired into `detect()`. Live observation feed via `baseline.observe` IPC
and `RwLock`-wrapped profiler. Configurable thresholds. Baseline seeded from
runtime-port-aware observations. Federation broadcast loop monitors audit log for
`ThreatDetected` events.

**Defense**: Auto-response policy from config. Quarantined sources rejected at dispatch
gate (`PERMISSION_DENIED`) with host extraction (port-stripped). Health probes exempt
(both `health.*` prefix and bare `health`). Manual quarantine API. BTSP sessions evicted
on disconnect with periodic TTL sweep (1h/5m).

**Observability**: JH-5 audit log (1024-event ring buffer) with cursor-based forwarding
to provenance DAG and attribution braids. Cursor only advances on successful forward.
Defense attestation with `ActionType`-specific audit events at `Warn` severity.
`BaselineObservation` audit events for profiler feed tracking.

**Integration**: Capability-based runtime discovery. No primal names hardcoded in routing.
RuntimeVerifier probed at startup. Self-registration with discovery (`ipc.register`).
BTSP WAN timeouts (10s provider call, 30s handshake). Graceful shutdown via `BackgroundTasks`.
riboCipher probes respond with health JSON + close.

**Code Quality**: Zero TODO/FIXME/HACK in production. Zero `.unwrap()`/`.expect()` in
production paths. Silent error drops surfaced (UDS setup, mutex poison, BTSP handshake).
Registration uses `env_keys` constants. `MethodGate` pre-dispatch capability gate with
enforced/permissive modes + quarantine enforcement.

## Stadial Composition Readiness

### Method Status (Wave 132c Update)

| Method | Tier | Impl | Notes |
|--------|------|------|-------|
| `health.liveness` | Stable | Complete | Always `{"status":"alive"}` |
| `health.readiness` | Stable | Complete | Returns primal state |
| `health.check` | Stable | Complete | Full health report with dependency status |
| `security.scan` | Stable | Partial | Self-only discovery; empty topology (needs ToadStool wiring) |
| `security.detect` | Stable | Partial | 6 categories; genetic/topology need runtime providers |
| `security.advisory` | Stable | Complete | Tower HTTP Gateway verdict (quarantine + defense check) |
| `security.respond` | Stable | Partial | Real policy engine; quarantine in-memory only |
| `security.metrics` | Stable | Partial | Flat counters; not spec's nested observability model |
| `security.audit_log` | Stable | Complete | JH-5 ring buffer with cursor-based polling |
| `baseline.observe` | Stable | Partial | Works when called; no transport auto-feed |
| `baseline.query` | Stable | Complete | Profiler statistics across all dimensions |
| `baseline.anomaly` | Stable | Complete | Read-only anomaly check against baseline |
| `baseline.reset` | Stable | Complete | Reset profiler with optional re-seed |
| `defense.status` | Stable | Complete | Enabled, auto-response, quarantine snapshot |
| `defense.quarantine` | Stable | Complete | Manual quarantine + audit log |
| `defense.release` | Stable | Complete | Release from quarantine + audit log |
| `response.evaluate` | Stable | Complete | Read-only action recommendation |
| `method_gate.status` | Stable | Complete | Enforcement posture for cross-gate probes |
| `threat.report` | Stable | Partial | Aggregates detect+metrics+defense; inherits detect limits |
| `capabilities.list` | Stable | Complete | Wire Standard L2/L3 |
| `identity.get` | Stable | Complete | Wire Standard L2 |
| `lifecycle.*` (3) | Stable | Complete | State, status, capabilities |
| `auth.*` (3) | Beta | Complete | Token presence + gate mode + peer info |
| `btsp.negotiate` | Stable | Complete | Phase 3 handshake + session registry |
| `btsp.capabilities` | Stable | Complete | Cipher advertisement |

**22 Complete, 7 Partial** (all functional, partial = scope limits documented above).

### Composable Primitive Gaps

`COMPOSABLE_PRIMITIVES_SPEC.md` describes additional methods that are not yet shipped:

- `metadata.{classify, fingerprint}` — no IPC surface
- `response.{escalate, deescalate, status}` — `evaluate` shipped, workflow primitives pending
- `lineage.{challenge, verify}` — consumes BearDog, does not re-expose
- `health.{system, network, resource}` — load sensing internal only

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

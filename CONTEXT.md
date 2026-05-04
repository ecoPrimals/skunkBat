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

- **Transport**: TCP (`--port`, default 9140) + UDS (`$BIOMEOS_SOCKET_DIR/skunkbat-{family_id}.sock`)
- **BTSP Phase 1**: `FAMILY_ID` socket scoping, `BIOMEOS_INSECURE` guard, `XDG_RUNTIME_DIR` fallback
- **BTSP Phase 2**: BearDog-delegated handshake on **both TCP and UDS** with first-byte peek (`{` → plain JSON-RPC for biomeOS composition bypass)
- **BTSP Phase 3**: `btsp.negotiate` server handler with encrypted frame upgrade — session registry, cipher selection, HKDF key derivation, `ChaCha20-Poly1305` AEAD framing wired into connection loop (`[4B len][12B nonce][ct+tag]`)
- **Wire Standard**: `capabilities.list` (L2) and `identity.get` (L3) methods
- **Domain Methods**: `health.*`, `security.*`, `lifecycle.*`, `capabilities.*`, `identity.*`, `btsp.*`
- **Capability Symlinks**: `security.sock` domain symlink created on bind

## Ecosystem Integration

- **BearDog**: Genetic lineage verification (WHO) — `lineage.verify` + `lineage.list` via `lineage-verification.sock` or `LINEAGE_ENDPOINT`
- **ToadStool**: Capability-based primal discovery (WHERE) — JSON-RPC via `discovery.sock` or `DISCOVERY_ENDPOINT`
- **Songbird**: Federated threat intelligence (COORDINATION) — JSON-RPC via `federation.sock` or `FEDERATION_ENDPOINT`
- **NestGate**: Protected application platform (HOME)

All integration is capability-based runtime discovery. No primal names hardcoded in routing.

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

332 tests passing (164 core + 48 integrations + 100 server + 20 transport/integration), all workspace lib+bins.
90%+ function coverage (llvm-cov); core ~96%, btsp ~94%, dispatch ~97%, threats ~98%,
crypto ~100%. Behavioral profiler, genetic/topology verifiers, JSON-RPC types all exercised.
Full end-to-end test for NDJSON→encrypted frame upgrade path including multi-message
encrypted loop verification, plaintext-after-upgrade rejection, encrypted batch requests,
and encrypted notification (no-response) verification.

## Status

v0.2.0-dev — Edition 2024, clippy pedantic+nursery clean (zero warnings), `forbid(unsafe_code)`
workspace-wide. All `#[allow]` migrated to `#[expect(reason)]`. JSON-RPC IPC server with
BTSP Phase 1/2/3 (TCP + UDS first-byte peek, BearDog-delegated handshake aligned with v0.9.0,
`btsp.negotiate` server handler with session registry and ChaCha20-Poly1305 infrastructure)
and Wire Standard L2/L3 compliance. Consumed capabilities: `btsp.server.verify`,
`lineage.verify`, `lineage.list`, `capabilities.list`, `federation.broadcast`,
`discovery.find_by_capability`. Cross-platform (`proc_uid`, `check_system_load`).
No magic numbers — all thresholds named. 40 source files, max 780 lines/file (production).
Zero cross-repo path dependencies — `sourdough-core` types internalized as `primal_foundation`.
`async-trait` eliminated and banned — native RPITIT throughout. `RemoteLineageVerifier`
integration ready. 332 tests (164+48+100+20), pure Rust crypto deps wired and tested
(chacha20poly1305, hkdf, sha2, rand, base64 — HKDF key derivation, AEAD exercised).
Self-registration with discovery (`ipc.register`) wired — standalone-safe probe on startup.
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

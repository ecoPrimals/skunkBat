# skunkBat — Context

Defensive network security primal for sovereign computing environments.
Provides reconnaissance, threat detection, automated defense, and security
observability — all metadata-only, no content inspection by architecture.

## Workspace Structure

| Crate | Role | Type |
|-------|------|------|
| `skunk-bat-core` | Threat detection (5 types), defense orchestration, observability, universal adapter | library |
| `skunk-bat-integrations` | JSON-RPC 2.0 client, ToadStool discovery, Songbird federation | library |
| `skunk-bat-server` | UniBin server: TCP + UDS JSON-RPC, BTSP Phase 1 socket naming, Wire Standard L2/L3 | binary |

## Key Concepts

- **5 Threat Types**: Genetic (lineage), Topology (layer-hopping), Behavioral (statistical anomaly), Intrusion (signatures), Resource (DoS/exhaustion)
- **Graduated Response**: Monitor, Quarantine, Block — always preserving user authority
- **Statistical Baselines**: Learns the owner's network normal via `VecDeque` rolling window profiler
- **Universal Adapter**: Capability-based discovery and announcement via `sourdough-core` traits
- **JSON-RPC 2.0**: Newline-delimited protocol on TCP and UDS, from-scratch implementation

## IPC Surface

- **Transport**: TCP (`--port`, default 9140) + UDS (`$BIOMEOS_SOCKET_DIR/skunkbat-{family_id}.sock`)
- **BTSP Phase 1**: `FAMILY_ID` socket scoping, `BIOMEOS_INSECURE` guard, `XDG_RUNTIME_DIR` fallback
- **BTSP Phase 2**: BearDog-delegated handshake on **both TCP and UDS** with first-byte peek (`{` → plain JSON-RPC for biomeOS composition bypass)
- **Wire Standard**: `capabilities.list` (L2) and `identity.get` (L3) methods
- **Domain Methods**: `health.*`, `security.*`, `lifecycle.*`, `capabilities.*`, `identity.*`
- **Capability Symlinks**: `security.sock` domain symlink created on bind

## Ecosystem Integration

- **BearDog**: Genetic lineage verification (WHO) — JSON-RPC via `crypto.sock` or `DISCOVERY_ENDPOINT`
- **ToadStool**: Capability-based primal discovery (WHERE) — JSON-RPC via `discovery.sock` or `DISCOVERY_ENDPOINT`
- **Songbird**: Federated threat intelligence (COORDINATION) — JSON-RPC via `federation.sock` or `FEDERATION_ENDPOINT`
- **NestGate**: Protected application platform (HOME)

All integration is capability-based runtime discovery. No primal names hardcoded in routing.

## Dependencies

Pure Rust. Depends on `sourdough-core` for primal lifecycle traits, `async-trait`
for dyn-dispatch async methods. No C dependencies in application code.

## JSON-RPC 2.0

Full spec compliance including:
- Single requests with standard error codes (-32700 through -32603)
- **Batch requests** (JSON array dispatch, per-spec error handling)
- **Notifications** (id-less requests produce no response, per §4.1)
- Newline-delimited framing on TCP and UDS

## Tests

153 tests passing (84 core + 14 integrations + 42 server + 9 chaos + 3 e2e + doctests),
14 ignored (gated behind external primals). 12 working examples. 82.0% line coverage
(llvm-cov); core crate at ~96%, server at ~49% transport / ~86% server / ~96% dispatch.

## Status

v0.1.0 — Edition 2024, clippy pedantic+nursery clean (zero warnings), `forbid(unsafe_code)`
workspace-wide. All `#[allow]` migrated to `#[expect(reason)]`. JSON-RPC IPC server with
BTSP Phase 1/2 (TCP + UDS first-byte peek) and Wire Standard L2/L3 compliance.
Cross-platform (`proc_uid`, `check_system_load`). No magic numbers — all thresholds named.

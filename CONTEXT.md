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

## Tests

124+ unit tests, integration tests (per-primal, e2e, chaos — gated behind `#[ignore]`
until runtime primals are available). 12 working examples covering all capabilities.

## Status

v0.1.0 — Edition 2024, clippy pedantic+nursery clean, `forbid(unsafe_code)` workspace-wide.
JSON-RPC IPC server with BTSP Phase 1 and Wire Standard L2/L3 compliance.

# skunkBat — Context

Defensive network security primal for sovereign computing environments.
Provides reconnaissance, threat detection, automated defense, and security
observability — all metadata-only, no content inspection by architecture.

## Workspace Structure

| Crate | Role | Type |
|-------|------|------|
| `skunk-bat-core` | Threat detection (5 types), defense orchestration, observability, universal adapter | library |
| `skunk-bat-integrations` | Ecosystem glue: ToadStool discovery, Songbird federation | library |
| `skunk-bat-tests` (root) | Workspace-level integration and chaos tests | test-only |

## Key Concepts

- **5 Threat Types**: Genetic (lineage), Topology (layer-hopping), Behavioral (statistical anomaly), Intrusion (signatures), Resource (DoS/exhaustion)
- **Graduated Response**: Monitor → Quarantine → Block, always preserving user authority
- **Statistical Baselines**: Learns the owner's network normal, not universal heuristics
- **Universal Adapter**: Capability-based discovery and announcement via `sourdough-core` traits

## Ecosystem Integration

- **BearDog**: Genetic lineage verification (WHO) — pending IPC client crate
- **ToadStool**: Capability-based primal discovery (WHERE) — stub client, ready for real IPC
- **Songbird**: Federated threat intelligence (COORDINATION) — stub client, ready for real IPC
- **NestGate**: Protected application platform (HOME)

## Dependencies

Pure Rust. Depends on `sourdough-core` for primal lifecycle traits.
No C dependencies in application code.

## Tests

Core unit tests (15+), integration tests (per-primal, e2e, chaos — gated behind `#[ignore]`
until runtime primals are available). 10 working examples covering all capabilities.

## Status

v0.1.0 — Edition 2024, clippy pedantic+nursery clean, `forbid(unsafe_code)` workspace-wide.
Ecosystem security primal, not an IPC daemon itself — integrates with other primals via traits.

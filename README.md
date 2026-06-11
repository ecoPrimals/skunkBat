# skunkBat

Defensive network security primal for sovereign computing environments.

**Version**: 0.2.10
**License**: AGPL-3.0-or-later (scyBorg triple-copyleft)

---

## What is skunkBat?

skunkBat protects sovereign computing environments through metadata-only
defensive reconnaissance. It detects threats, orchestrates graduated responses,
and federates threat intelligence across trusted peers — all without inspecting
packet contents or tracking user behavior.

- **5 Threat Types**: Genetic (lineage), Topology (layer-hopping), Behavioral
  (statistical anomaly), Intrusion (signatures), Resource (DoS/exhaustion)
- **Composable Primitives**: `baseline`, `metadata`, `response`, `lineage`, `health` —
  each independently useful as standalone capabilities
- **Thymic Selection Model**: Self/non-self discrimination via BearDog lineage (design phase)
- **Graduated Defense**: Monitor, Quarantine, Block — user authority preserved
- **Statistical Baselines**: Learns YOUR network normal, not universal heuristics
- **JSON-RPC 2.0**: Full spec — single, batch, and notification support
- **BTSP Phase 1/2/3**: Socket naming, BearDog-delegated handshake on TCP + UDS,
  first-byte peek for biomeOS composition bypass, `btsp.negotiate` cipher negotiation
  with auto-upgrade to `ChaCha20-Poly1305` encrypted framing
- **Wire Standard L2/L3**: `capabilities.list` and `identity.get` compliant
- **Privacy by Architecture**: Content inspection is structurally impossible

### Philosophy

**Defensive, Not Offensive** — protects networks, never attacks.
**Reconnaissance, Not Surveillance** — monitors patterns, not user behavior.
**User Authority** — owner approves major actions.
**Sovereignty First** — local-by-default, user-controlled data.

See `RECONNAISSANCE_NOT_SURVEILLANCE.md` for the full ethical framework.

---

## Workspace

```
skunkBat/
├── crates/
│   ├── skunk-bat-core/          # Threat detection, defense, observability
│   ├── skunk-bat-integrations/  # JSON-RPC client, discovery, federation
│   └── skunk-bat-server/        # UniBin server (UDS + BTSP, TCP fallback)
├── examples/                    # 12 working examples
├── tests/                       # Integration, e2e, chaos tests
└── specs/                       # Technical specifications
```

| Crate | Role | Type |
|-------|------|------|
| `skunk-bat-core` | Threat detection (5 types), defense orchestration, observability, universal adapter | library |
| `skunk-bat-integrations` | JSON-RPC 2.0 client, BearDog lineage, ToadStool discovery, Songbird federation | library |
| `skunk-bat-server` | UniBin CLI: `server` (UDS-only default), `health`, `scan`, `detect` | binary |

---

## Quick Start

### Run the Server

```bash
# Standard primal startup contract (UDS-only default)
skunkbat server
skunkbat server --bind-mode uds-only           # explicit (same as default)
skunkbat server --bind-mode tcp-only --port 9750   # Android/grapheneGate
skunkbat server --bind-mode fallback --port 9750   # both UDS + TCP

# Via env (standard ecosystem pattern — no per-primal flags)
PRIMAL_BIND_MODE=tcp_only skunkbat server --port 9750

# Launcher-injected transport (overrides bind-mode)
TRANSPORT_ENDPOINT='{"transport":"uds","path":"/run/membrane/skunkbat.sock"}' skunkbat server

# Custom UDS path
skunkbat server --socket /run/membrane/skunkbat.sock

# One-shot commands
skunkbat health
skunkbat scan
skunkbat detect
```

### Library Usage

```rust
use skunk_bat_core::{SkunkBat, SkunkBatConfig};
use skunk_bat_core::PrimalLifecycle;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    skunkbat.scan_network().await?;
    let threats = skunkbat.detect_threats().await?;
    for threat in threats {
        skunkbat.respond_to_threat(&threat)?;
    }

    let metrics = skunkbat.get_security_metrics();
    Ok(())
}
```

### Run Examples

```bash
cargo run --example basic_usage
cargo run --example violation_detection
cargo run --example songbird_integration
```

---

## Build and Test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
cargo doc --no-deps
cargo deny check
```

---

## Configuration

### Environment Variables

```bash
# Bind mode (standard primal startup contract)
# Values: uds-only (default) | tcp-only (Android) | fallback (both)
export PRIMAL_BIND_MODE=fallback

# TCP fallback port (only when PRIMAL_BIND_MODE=fallback or --port passed)
export SKUNKBAT_PORT=9750
export SKUNKBAT_LISTEN_ADDR=127.0.0.1

# Launcher-injected transport (sourDough TransportEndpoint standard)
export TRANSPORT_ENDPOINT='{"transport":"uds","path":"/run/membrane/skunkbat.sock"}'

# BTSP Phase 1
export FAMILY_ID=your-family-id
export BIOMEOS_SOCKET_DIR=/run/biomeos
export BIOMEOS_INSECURE=1          # Required when FAMILY_ID is unset

# Outbound transports (preferred over legacy TCP envs)
export LINEAGE_TRANSPORT='{"transport":"uds","path":"/run/membrane/beardog.sock"}'
export DISCOVERY_TRANSPORT='{"transport":"uds","path":"/run/membrane/toadstool.sock"}'
export FEDERATION_TRANSPORT='{"transport":"uds","path":"/run/membrane/songbird.sock"}'

# Legacy TCP fallback (used only when *_TRANSPORT is unset)
export LINEAGE_ENDPOINT=127.0.0.1:9300
export DISCOVERY_ENDPOINT=127.0.0.1:3000
export FEDERATION_ENDPOINT=127.0.0.1:8080
```

---

## Ecosystem Integration

skunkBat discovers other primals at runtime via capability-based JSON-RPC.
No primal names are hardcoded in production code.

- **BearDog**: Genetic lineage verification (WHO) — `lineage.verify` + `lineage.list` via `lineage-verification.sock` or `LINEAGE_ENDPOINT`
- **ToadStool**: Capability-based primal discovery (WHERE) — via `discovery.sock` or `DISCOVERY_ENDPOINT`
- **Songbird**: Federated threat intelligence (COORDINATION) — via `federation.sock` or `FEDERATION_ENDPOINT`
- **NestGate**: Protected application platform (HOME)

### Consumed Capabilities

`btsp.server.verify`, `btsp.negotiate` (served), `lineage.verify`, `lineage.list`,
`capabilities.list`, `federation.broadcast`, `discovery.find_by_capability`

---

## Quality

- Edition 2024, `forbid(unsafe_code)` workspace-wide
- Clippy pedantic + nursery, zero warnings (`-D warnings`)
- `#[expect(reason)]` lint suppression standard (target-conditional `#[allow]` only)
- `cargo deny` advisory/ban/license/source checks pass; `ring` explicitly banned
- 52 source files, all under 800 lines (largest: 773)
- SPDX `AGPL-3.0-or-later` headers on all source files
- Zero `TODO`/`FIXME`/`HACK` in production code
- Named constants for all thresholds — no magic numbers
- Pure Rust — zero cross-repo path deps, no C deps, `rand` eliminated (OsRng via RustCrypto)
- 530+ tests passing, 90%+ function coverage (llvm-cov)
- All 18 IPC methods stability-tiered (Stable)
- CI: GitHub Actions with fmt/clippy/doc/deny/test gates (`actions/checkout@v5`)
- `async-trait` eliminated and banned — native RPITIT throughout
- Self-registration with discovery (`ipc.register`) + Neural API `primal.announce`
- Zero-port standard: UDS-only default, TCP via `--port` or `PRIMAL_BIND_MODE=fallback`
- Transport Evolution: `TransportEndpoint` wired at all IPC boundaries (inbound + outbound)
- Typed errors throughout (`thiserror` enums, zero `Box<dyn Error>` in production)
- SIGTERM graceful shutdown, `lifecycle.status` health endpoint

---

## Specifications

- `specs/00_SPECIFICATIONS_INDEX.md` — Index of all specifications
- `specs/RECONNAISSANCE_SPEC.md` — Network intelligence
- `specs/THREAT_DETECTION_SPEC.md` — Threat identification (includes thymic model, bond-type mapping)
- `specs/AUTO_DEFENSE_SPEC.md` — Defense mechanisms
- `specs/OBSERVABILITY_SPEC.md` — Metrics and monitoring
- `specs/THYMIC_SELECTION_SPEC.md` — Self/non-self discrimination model (design phase)
- `specs/COMPOSABLE_PRIMITIVES_SPEC.md` — Primitive decomposition and composition patterns

---

## License

scyBorg triple-copyleft: software under AGPL-3.0-or-later, game mechanics
under ORC, creative content under CC BY-SA 4.0. See `LICENSE` for details.

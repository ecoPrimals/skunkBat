# skunkBat

Defensive network security primal for sovereign computing environments.

**Version**: 0.2.0-dev
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
│   └── skunk-bat-server/        # UniBin server (TCP + UDS + BTSP)
├── examples/                    # 12 working examples
├── showcase/                    # 4-tier interactive demos (22 scenarios)
├── tests/                       # Integration, e2e, chaos tests
└── specs/                       # Technical specifications
```

| Crate | Role | Type |
|-------|------|------|
| `skunk-bat-core` | Threat detection (5 types), defense orchestration, observability, universal adapter | library |
| `skunk-bat-integrations` | JSON-RPC 2.0 client, BearDog lineage, ToadStool discovery, Songbird federation | library |
| `skunk-bat-server` | UniBin CLI with `server`, `health`, `scan`, `detect` subcommands | binary |

---

## Quick Start

### Run the Server

```bash
# Start JSON-RPC server (TCP + UDS)
cargo run -p skunk-bat-server -- server --port 9140

# Health check
cargo run -p skunk-bat-server -- health

# Run a scan
cargo run -p skunk-bat-server -- scan

# Detect threats
cargo run -p skunk-bat-server -- detect
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
# Server port (default: 9140, or SKUNKBAT_PORT)
export SKUNKBAT_PORT=9140

# BTSP Phase 1
export FAMILY_ID=your-family-id
export BIOMEOS_SOCKET_DIR=/run/biomeos
export BIOMEOS_INSECURE=1          # Required when FAMILY_ID is unset

# Capability-based discovery (runtime, not hardcoded)
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
- All `#[allow]` migrated to `#[expect(reason)]`
- `cargo deny` advisory/ban/license/source checks pass
- 39 source files, all under 1000 lines (largest: 780)
- SPDX `AGPL-3.0-or-later` headers on all source files
- Zero `TODO`/`FIXME`/`HACK` in production code
- Named constants for all thresholds — no magic numbers
- Pure Rust — zero cross-repo path dependencies, no C dependencies
- 303 tests passing, 90%+ function coverage (llvm-cov)
- CI: GitHub Actions with fmt/clippy/doc/deny/test gates (`actions/checkout@v5`)
- `async-trait` eliminated and banned — native RPITIT throughout

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

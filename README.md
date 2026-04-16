# skunkBat

Defensive network security primal for sovereign computing environments.

**Version**: 0.1.0
**License**: AGPL-3.0-or-later (scyBorg triple-copyleft)

---

## What is skunkBat?

skunkBat protects sovereign computing environments through metadata-only
defensive reconnaissance. It detects threats, orchestrates graduated responses,
and federates threat intelligence across trusted peers — all without inspecting
packet contents or tracking user behavior.

- **5 Threat Types**: Genetic (lineage), Topology (layer-hopping), Behavioral
  (statistical anomaly), Intrusion (signatures), Resource (DoS/exhaustion)
- **Graduated Defense**: Monitor, Quarantine, Block — user authority preserved
- **Statistical Baselines**: Learns YOUR network normal, not universal heuristics
- **JSON-RPC 2.0**: Full spec — single, batch, and notification support
- **BTSP Phase 1/2**: Socket naming, handshake framework, `FAMILY_ID` scoping
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
| `skunk-bat-integrations` | JSON-RPC 2.0 client, ToadStool discovery, Songbird federation | library |
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
use sourdough_core::PrimalLifecycle;

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
export DISCOVERY_ENDPOINT=127.0.0.1:3000
export FEDERATION_ENDPOINT=127.0.0.1:8080
```

---

## Ecosystem Integration

skunkBat discovers other primals at runtime via capability-based JSON-RPC.
No primal names are hardcoded in production code.

- **BearDog**: Genetic lineage verification (WHO) — via `crypto.sock`
- **ToadStool**: Capability-based primal discovery (WHERE) — via `discovery.sock`
- **Songbird**: Federated threat intelligence (COORDINATION) — via `federation.sock`
- **NestGate**: Protected application platform (HOME)

---

## Quality

- Edition 2024, `forbid(unsafe_code)` workspace-wide
- Clippy pedantic + nursery, zero warnings (`-D warnings`)
- All `#[allow]` migrated to `#[expect(reason)]`
- `cargo deny` advisory/ban/license/source checks pass
- All files under 1000 lines (largest: 719)
- SPDX `AGPL-3.0-or-later` headers on all source files
- Zero `TODO`/`FIXME`/`HACK` in production code
- Named constants for all thresholds — no magic numbers
- Pure Rust — no C dependencies in application code
- 149 tests passing, 81.9% line coverage (llvm-cov)

---

## Specifications

- `specs/RECONNAISSANCE_SPEC.md` — Network intelligence
- `specs/THREAT_DETECTION_SPEC.md` — Threat identification
- `specs/AUTO_DEFENSE_SPEC.md` — Defense mechanisms
- `specs/OBSERVABILITY_SPEC.md` — Metrics and monitoring

---

## License

scyBorg triple-copyleft: software under AGPL-3.0-or-later, game mechanics
under ORC, creative content under CC BY-SA 4.0. See `LICENSE` for details.

# skunkBat

Defensive network security primal for sovereign computing environments.

**Version**: 0.2.15
**License**: AGPL-3.0-or-later (scyBorg triple-copyleft)

---

## What is skunkBat?

skunkBat protects sovereign computing environments through metadata-only
defensive reconnaissance. It detects threats, orchestrates graduated responses,
and federates threat intelligence across trusted peers — all without inspecting
packet contents or tracking user behavior.

- **6 Threat Types**: Genetic (lineage), Topology (layer-hopping), Behavioral
  (statistical anomaly), Intrusion (signatures), Resource (DoS/exhaustion),
  Configuration Drift
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
├── examples/                    # 12 narrative demos
├── tests/                       # Integration, e2e, chaos tests
└── specs/                       # Technical specifications
```

| Crate | Role | Type |
|-------|------|------|
| `skunk-bat-core` | Threat detection (6 types), defense orchestration, observability, universal adapter | library |
| `skunk-bat-integrations` | JSON-RPC 2.0 client, BearDog lineage, ToadStool discovery, Songbird federation | library |
| `skunk-bat-server` | UniBin CLI with `server`, `health`, `scan`, `detect` subcommands | binary |

---

## Quick Start

### Run the Server

```bash
# Start JSON-RPC server (TCP + UDS, default port 9750)
cargo run -p skunk-bat-server -- server

# Override bind/port/socket
cargo run -p skunk-bat-server -- server --bind 0.0.0.0 --port 9750 --socket /tmp/skunkbat.sock

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

### Examples

The `examples/` directory contains 12 narrative demos illustrating core API usage,
threat response patterns, and integration architectures. See `examples/basic_usage.rs`
for a walkthrough of scan → detect → respond.

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
# Server bind address + port
export SKUNKBAT_LISTEN_ADDR=127.0.0.1   # Default: localhost-only (secure-by-default)
export SKUNKBAT_PORT=9750                # Default: 9750

# Auth mode (MethodGate)
export SKUNKBAT_AUTH_MODE=enforced       # Default: permissive (log + allow)

# BTSP Phase 1
export FAMILY_ID=your-family-id
export BIOMEOS_SOCKET_DIR=/run/biomeos
export BIOMEOS_INSECURE=1                # Required when FAMILY_ID is unset

# Capability-based discovery (runtime, not hardcoded)
export LINEAGE_ENDPOINT=127.0.0.1:9300
export DISCOVERY_ENDPOINT=127.0.0.1:3000
export FEDERATION_ENDPOINT=127.0.0.1:8080

# Audit forwarding targets
export RHIZOCRYPT_ENDPOINT=127.0.0.1:9400
export SWEETGRASS_ENDPOINT=127.0.0.1:9500
```

### Threat Thresholds

All detection parameters are configurable via `SkunkBatConfig.thresholds`
(`ThreatThresholds` struct). Defaults are tuned for typical LAN environments:

| Field | Default | Description |
|-------|---------|-------------|
| `sigma_threshold` | 2.5 | Sigma deviation triggering anomaly report |
| `dos_load_threshold` | 0.9 | System load (0–1) triggering DoS alert |
| `intrusion_sensitive_ports` | 22, 23, 3389, 445, 135 | Ports triggering port-scan detection |
| `intrusion_exfil_volume` | 100,000 | Minimum bytes before exfil heuristic |
| `intrusion_exfil_ratio` | 10,000 | Traffic/connection ratio threshold |
| `quarantine_critical_confidence` | 0.9 | Confidence for immediate quarantine |
| `quarantine_high_confidence` | 0.7 | Confidence for quarantine + alert |

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
- All source files under 800 lines (largest: 728)
- SPDX `AGPL-3.0-or-later` headers on all source files
- Zero `TODO`/`FIXME`/`HACK` in production code
- `ThreatThresholds` struct — all detection constants configurable, no magic numbers
- Pure Rust — zero cross-repo path deps, no C deps, `rand` eliminated (OsRng via RustCrypto)
- 518+ tests passing (lib + integration + chaos), full workspace
- All 22 IPC methods stability-tiered (Stable)
- CI: GitHub Actions with fmt/clippy/doc/deny/test gates (`actions/checkout@v5`)
- `async-trait` eliminated and banned — native RPITIT throughout
- Self-registration with discovery (`ipc.register`) + Neural API `primal.announce`
- Discovery Escalation Hierarchy support: tier 1 (Songbird `ipc.resolve`), tier 3 (UDS filesystem), tier 5 (TCP probing on port 9750)
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

# skunkBat Showcase

Interactive demonstrations of skunkBat's sovereign, defensive security capabilities.

---

## What is skunkBat?

**skunkBat** is a defensive security primal that provides:
- **Reconnaissance** — Capability-based primal discovery (not surveillance)
- **Threat Detection** — 5 types: Genetic, Topology, Behavioral, Intrusion, Resource
- **Automated Defense** — Quarantine, block with user approval
- **Security Observability** — Metrics, logging, health monitoring
- **Federation** — Coordinate defense across trusted peers via JSON-RPC
- **Genetic Trust** — BearDog lineage verification
- **IPC** — JSON-RPC 2.0 server on TCP + UDS with BTSP Phase 1/2/3 (BearDog-delegated handshake + cipher negotiation)

---

## Quick Start

```bash
# Build
cargo build --workspace

# Run first demo
cd showcase/00-local-primal/01-hello-skunkbat
./demo.sh
```

---

## Learning Path

### Level 0: Local Primal (45 min)

Standalone capabilities — no ecosystem required.

1. `00-local-primal/01-hello-skunkbat/` — First security scan
2. `00-local-primal/02-violation-detection/` — All 5 detection types
3. `00-local-primal/03-defense-actions/` — Quarantine, block
4. `00-local-primal/04-baseline-learning/` — Behavioral anomaly detection
5. `00-local-primal/05-local-federation/` — Two skunkBats coordinating
6. `00-local-primal/06-defensive-vs-surveillance/` — Ethics proof

### Levels 1–3: Fossilized

Ecosystem integration, federation mesh, and production deployment showcases
were fossilized to `ecoPrimals/infra/fossilRecord/` as narrative design
documents. Live ecosystem integration is now exercised through composition
in the delta springs (wetSpring, hotSpring, etc.) and NUCLEUS deployments.

---

## Running Demos

```bash
# Individual demo
cd showcase/00-local-primal/01-hello-skunkbat
./demo.sh

# All local demos
cd showcase/00-local-primal
./RUN_ALL_LOCAL.sh

# Complete showcase
cd showcase
./RUN_ALL.sh
```

---

## Key Concepts

### Defensive vs Surveillance

**skunkBat IS** (Defensive):
- Monitors YOUR network perimeter
- Detects violations of YOUR policies
- Requires YOUR approval for actions

**skunkBat IS NOT** (Surveillance):
- Does not monitor user behavior/content
- Does not profile individuals
- Does not report to authorities

See `RECONNAISSANCE_NOT_SURVEILLANCE.md` for the full ethical framework.

---

## Documentation

- `README.md` — Project overview
- `CONTEXT.md` — Architecture and workspace structure
- `RECONNAISSANCE_NOT_SURVEILLANCE.md` — Ethics framework
- `specs/` — Technical specifications

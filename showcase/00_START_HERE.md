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
- **IPC** — JSON-RPC 2.0 server on TCP + UDS with BTSP Phase 1

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

### Level 1: Ecosystem Integration (1 hour)

Inter-primal communication via JSON-RPC.

1. `01-ecosystem-integration/01-beardog-integration/` — Genetic verification
2. `01-ecosystem-integration/02-toadstool-integration/` — Primal discovery
3. `01-ecosystem-integration/03-songbird-integration/` — Federation
4. `01-ecosystem-integration/04-ecosystem-complete/` — Full ecosystem demo
5. `01-ecosystem-integration/05-integration-testing/` — Cross-primal tests

### Level 2: Federation Mesh (1.5 hours)

Multi-node defense coordination.

1. `02-federation-mesh/01-multi-network/` — Multi-node federation
2. `02-federation-mesh/02-layered-security/` — Defense in depth
3. `02-federation-mesh/03-ownership-breach/` — Breach handling
4. `02-federation-mesh/04-data-exfiltration/` — Exfiltration detection
5. `02-federation-mesh/05-federation-resilience/` — Resilience testing

### Level 3: Production (2 hours)

Production deployment patterns.

1. `03-production/01-configuration/` — Production config
2. `03-production/02-monitoring-observability/` — Metrics export
3. `03-production/03-performance-tuning/` — Optimization
4. `03-production/04-disaster-recovery/` — Recovery patterns
5. `03-production/05-production-checklist/` — Deployment checklist

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

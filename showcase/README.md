<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# skunkBat Showcase

Interactive demonstrations of defensive security architecture. Each tier
builds on the previous one, progressing from single-primal demos to full
production mesh scenarios.

---

## Directory Structure

```
showcase/
├── RUN_ALL.sh                              # Run every tier in sequence
├── 00-local-primal/                        # Tier 0 — single-primal demos
│   ├── 01-hello-skunkbat/
│   ├── 02-violation-detection/
│   ├── 03-defense-actions/
│   ├── 04-baseline-learning/
│   ├── 05-local-federation/
│   └── 06-defensive-vs-surveillance/
├── 01-ecosystem-integration/               # Tier 1 — inter-primal IPC
│   ├── 01-beardog-integration/
│   ├── 02-toadstool-integration/
│   ├── 03-songbird-integration/
│   ├── 04-ecosystem-complete/
│   └── 05-integration-testing/
├── 02-federation-mesh/                     # Tier 2 — multi-node mesh
│   ├── 01-multi-network/
│   ├── 02-layered-security/
│   ├── 03-ownership-breach/
│   ├── 04-data-exfiltration/
│   └── 05-federation-resilience/
├── 03-production/                          # Tier 3 — ops and hardening
│   ├── 01-configuration/
│   ├── 02-monitoring-observability/
│   ├── 03-performance-tuning/
│   ├── 04-disaster-recovery/
│   └── 05-production-checklist/
└── 99-gaps-analysis/                       # Gap tracking
    └── README.md
```

Each sub-directory contains a `README.md` explaining the scenario and a
`demo.sh` that runs the relevant `cargo run --example` command.

---

## Running

```bash
# Single demo
cd showcase/00-local-primal/01-hello-skunkbat
./demo.sh

# All demos in a tier
cd showcase/00-local-primal
./RUN_ALL_LOCAL.sh

# Everything
./showcase/RUN_ALL.sh
```

---

## Tier Overview

| Tier | Focus | External Primals Required |
|------|-------|--------------------------|
| 00 — Local Primal | Core detection, defense, baselines | None |
| 01 — Ecosystem | BearDog, ToadStool, Songbird IPC | Yes (`#[ignore]` gated) |
| 02 — Federation Mesh | Multi-network coordination | Yes |
| 03 — Production | Config, monitoring, chaos, DR | Varies |

---

## Proof of Defensive Nature

The showcase demonstrates that skunkBat:

**IS (Defensive):**
- Monitors YOUR perimeter
- Detects violations of YOUR policies
- Defends YOUR resources
- Requires YOUR approval for actions
- Shares threat intel WITH YOUR CONSENT

**IS NOT (Offensive):**
- Does not scan others' networks
- Does not attack back or exfiltrate data
- Does not profile users or make moral judgments
- Does not report to authorities or centralize control

See `RECONNAISSANCE_NOT_SURVEILLANCE.md` in the repo root for the full
ethical framework.

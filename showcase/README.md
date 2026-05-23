<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->

# skunkBat Showcase

Interactive demonstrations of defensive security architecture.

---

## Directory Structure

```
showcase/
├── RUN_ALL.sh                              # Run all demos in sequence
├── 00-local-primal/                        # Local single-primal demos
│   ├── 01-hello-skunkbat/
│   ├── 02-violation-detection/
│   ├── 03-defense-actions/
│   ├── 04-baseline-learning/
│   ├── 05-local-federation/
│   └── 06-defensive-vs-surveillance/
└── 99-gaps-analysis/                       # Gap tracking (fossilized)
    └── README.md
```

Each sub-directory contains a `README.md` explaining the scenario and a
`demo.sh` script that runs the demo via `cargo run --example`.

---

## Running

```bash
# Single demo
cd showcase/00-local-primal/01-hello-skunkbat
./demo.sh

# All local demos
cd showcase/00-local-primal
./RUN_ALL_LOCAL.sh

# Everything
./showcase/RUN_ALL.sh
```

---

## What These Demos Show

| Demo | Focus |
|------|-------|
| 01 — Hello skunkBat | Basic startup, health check, shutdown |
| 02 — Violation Detection | 5 threat types in action |
| 03 — Defense Actions | Graduated response (monitor → quarantine → block) |
| 04 — Baseline Learning | Statistical profiler learns normal patterns |
| 05 — Local Federation | Threat intelligence sharing pattern |
| 06 — Defensive vs Surveillance | Architectural proof of defensive nature |

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

---

## Note on Higher Tiers

Tiers 1–3 (ecosystem integration, federation mesh, production ops) were
fossilized to `ecoPrimals/infra/fossilRecord/` as narrative design documents.
Live ecosystem integration is now exercised through composition in the delta
springs (wetSpring, hotSpring, etc.) rather than standalone showcase scripts.

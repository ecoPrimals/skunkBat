<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# skunkBat Specifications Index

**Version:** 0.2.14
**Status:** Core specs implemented; thymic and composition specs in design

---

## Core Specifications (Implemented)

1. **[RECONNAISSANCE_SPEC.md](./RECONNAISSANCE_SPEC.md)** — COMPLETE
   - Defensive network intelligence
   - Asset discovery and topology mapping
   - Privacy-preserving reconnaissance

2. **[THREAT_DETECTION_SPEC.md](./THREAT_DETECTION_SPEC.md)** — COMPLETE (v0.1), EVOLVING (v0.2)
   - Genetic threat analysis (via BearDog lineage)
   - Behavioral anomaly detection (statistical baselines)
   - Topology violation detection (layer-hopping)
   - Intrusion detection (attack signatures)
   - Resource exhaustion detection (DoS)
   - **v0.2**: Thymic selection model, bond-type threat classification

3. **[AUTO_DEFENSE_SPEC.md](./AUTO_DEFENSE_SPEC.md)** — COMPLETE
   - Graduated threat response (MonitorAndAlert, Quarantine, QuarantineAndAlert, Block)
   - User authority preservation
   - Alert and escalation

4. **[OBSERVABILITY_SPEC.md](./OBSERVABILITY_SPEC.md)** — COMPLETE
   - Security-focused metrics
   - Real-time security posture
   - Audit logging

## Evolution Specifications (Design Phase)

5. **[THYMIC_SELECTION_SPEC.md](./THYMIC_SELECTION_SPEC.md)** — DESIGN
   - Biological thymic model for self/non-self discrimination
   - Pseudorandom probe generation and training
   - Positive selection (can read BearDog lineage)
   - Negative selection (does not attack verified family)
   - Continuous training loop as network evolves
   - Autoimmune prevention strategies

6. **[COMPOSABLE_PRIMITIVES_SPEC.md](./COMPOSABLE_PRIMITIVES_SPEC.md)** — DESIGN
   - Primitive decomposition: baseline, metadata, response, lineage, health
   - IPC method table (`{domain}.{operation}` semantic naming)
   - Standalone usage patterns
   - Cross-primal composition patterns
   - Spring integration recipes

---

## Specification Principles

All skunkBat specifications follow:

1. **Reconnaissance, Not Surveillance** — watch YOUR systems FOR YOU
2. **Sovereignty First** — local by default, ephemeral by design
3. **Transparency Always** — open source (AGPL-3.0-or-later), auditable
4. **Capability-Based Integration** — runtime discovery, no hardcoded primal names
5. **Composable Primitives** — each primitive useful standalone and in composition

---

## Document Status

| Specification | Status | Implemented |
|---------------|--------|-------------|
| RECONNAISSANCE_SPEC.md | Complete | Yes |
| THREAT_DETECTION_SPEC.md | Complete (v0.1), Evolving (v0.2) | Core yes, thymic planned |
| AUTO_DEFENSE_SPEC.md | Complete | Yes |
| OBSERVABILITY_SPEC.md | Complete | Yes |
| THYMIC_SELECTION_SPEC.md | Design | No — future evolution |
| COMPOSABLE_PRIMITIVES_SPEC.md | Design | No — future evolution |

# skunkBat — sporePrint Validation Summary

**Primal**: skunkBat
**Version**: 0.2.0
**Domain**: Defense — metadata-only threat detection, lineage verification, composable anomaly primitives
**License**: AGPL-3.0-or-later

---

## Status

- **Gate**: CLEAR (13/13 structural gate)
- **Phase**: 3 (BTSP Phase 3 AEAD encrypted framing)
- **Edition**: 2024
- **Tests**: 382 passing
- **Source**: 48 files, max 790 lines
- **Clippy**: 0 warnings (`pedantic` + `nursery`, `-D warnings`)
- **deny.toml**: ring, openssl, native-tls, aws-lc-sys all banned

## Capabilities

| Capability | Description |
|-----------|-------------|
| `defense` | Graduated response (Monitor, Quarantine, Block) |
| `threat` | 5-type detection (Genetic, Behavioral, Intrusion, Resource, Topology) |
| `metadata` | Content-free network pattern analysis |
| `lineage` | BearDog-delegated lineage verification |
| `baseline` | Statistical profiler with multi-dimensional anomaly scoring |
| `health` | Standard health triad (liveness, readiness, check) |
| `audit` | JH-5 structured security event trail + cross-primal forwarding |
| `btsp` | Phase 3 cipher negotiation + encrypted framing |

## Methods (17 — all Stable tier)

- `health.liveness`, `health.readiness`, `health.check`
- `security.scan`, `security.detect`, `security.respond`, `security.metrics`, `security.audit_log`
- `capabilities.list`, `identity.get`
- `lifecycle.state`, `lifecycle.capabilities`
- `auth.check`, `auth.mode`, `auth.peer_info`
- `btsp.negotiate`, `btsp.capabilities`

## Composition Role

skunkBat is the **security observability backbone** for all compositions:
- Tower atomic member (bearDog + songbird + skunkBat)
- Present in all Node, Nest, and NUCLEUS compositions
- Provides audit trail forwarding to rhizoCrypt DAG + sweetGrass braids
- NestGate content integrity verification

## Downstream Pairing

- cellMembrane (VPS audit trail)
- lithoSpore (verification artifacts)
- projectNUCLEUS (sovereignty observability)
- rhizoCrypt (DAG event forwarding)
- sweetGrass (braid attribution)
- bearDog (lineage verification)

## Degradation

When skunkBat is down: audit events stop flowing, no threat detection.
Other primals continue operating — skunkBat is observability, not gate.

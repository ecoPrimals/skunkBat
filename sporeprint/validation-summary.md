+++
title = "skunkBat Validation Summary"
description = "Defense meta-primal — metadata-only threat detection, lineage verification, composable anomaly primitives. 500 tests, 19 IPC methods."
date = 2026-06-08

[taxonomies]
primals = ["skunkbat"]
springs = []
+++

## Status

- **Version**: v0.2.10 (Wave 109)
- **Gate**: CLEAR (13/13 structural gate)
- **Phase**: 3 (BTSP Phase 3 AEAD encrypted framing)
- **Edition**: 2024
- **Tests**: 530+ passing
- **Source**: 52 files, max 773 lines (296L production + tests)
- **Clippy**: 0 warnings (`pedantic` + `nursery`, `-D warnings`)
- **Coverage**: 90%+ function coverage (llvm-cov)
- **deny.toml**: ring, openssl, native-tls, aws-lc-sys all banned
- **Pure Rust**: `forbid(unsafe_code)` workspace-wide, `rand` eliminated (OsRng via RustCrypto)
- **Startup contract**: `--bind-mode` (uds-only | tcp-only | fallback), reads `PRIMAL_BIND_MODE` env
- **Transport Evolution**: Fully wired at all IPC boundaries (inbound + outbound)
- **Error handling**: Typed errors throughout (zero `Box<dyn Error>` in production)
- **Deploy**: `skunkbat server` (UDS), `skunkbat server --bind-mode tcp-only --port 9750` (Android)

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

## Methods (19 — all Stable tier)

- `health.liveness`, `health.readiness`, `health.check`
- `defense.status`
- `security.scan`, `security.detect`, `security.respond`, `security.metrics`, `security.audit_log`
- `capabilities.list`, `identity.get`
- `lifecycle.status`, `lifecycle.state`, `lifecycle.capabilities`
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

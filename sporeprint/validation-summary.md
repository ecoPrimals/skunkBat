+++
title = "skunkBat Validation Summary"
description = "Defense meta-primal — metadata-only threat detection, lineage verification, composable anomaly primitives. 527 tests, 20 IPC methods, configurable thresholds."
date = 2026-06-14

[taxonomies]
primals = ["skunkbat"]
springs = []
+++

## Status

- **Version**: v0.2.10 (Wave 113)
- **Gate**: CLEAR (13/13 structural gate)
- **Phase**: 3 (BTSP Phase 3 AEAD encrypted framing)
- **Edition**: 2024
- **Tests**: 527 passing (283 core + 85 server + 139 integrations + 20 binary/integration)
- **Source**: 52 files, max 671 lines
- **Clippy**: 0 warnings (`pedantic` + `nursery`, `-D warnings`)
- **Coverage**: 90%+ function coverage (llvm-cov)
- **deny.toml**: ring, openssl, native-tls, aws-lc-sys all banned
- **Pure Rust**: `forbid(unsafe_code)` workspace-wide, `rand` eliminated (OsRng via RustCrypto)
- **Production `.unwrap()`**: Zero — all error paths use `?`, `map_err`, or `unwrap_or_*`
- **Startup contract**: `--bind-mode` (uds-only | tcp-only | fallback), reads `PRIMAL_BIND_MODE` env
- **Transport Evolution**: riboCipher `[0xEC, 0x01]` accepted on TCP and UDS; probe `[0xEC, 0x00]` supported
- **Error handling**: Typed errors throughout (zero `Box<dyn Error>` in production)
- **Deploy**: `skunkbat server` (UDS), `skunkbat server --bind-mode tcp-only --port 9750` (Android)

## Wave 113 Deliverables

- `health` JSON-RPC method (HEALTH-01 compliant: status, primal, version, uptime_s)
- riboCipher signal acceptance on all transport boundaries (TCP + UDS)
- Configurable detection thresholds via `DetectionConfig` / `DefenseConfig` (DERIVATION_ANCHORING compliant)
- Zero-copy hot path optimizations (single-pass stats, cached capabilities, eliminated observation clone)
- Modern Rust idioms (captured format strings, serde `rename_all`, let-else patterns)
- PrimalState lowercase serialization for wire compatibility

## Capabilities

| Capability | Description |
|-----------|-------------|
| `defense` | Graduated response (Monitor, Quarantine, Block) with configurable thresholds |
| `threat` | 5-type detection (Genetic, Behavioral, Intrusion, Resource, Topology) |
| `metadata` | Content-free network pattern analysis |
| `lineage` | BearDog-delegated lineage verification |
| `baseline` | Statistical profiler with single-pass multi-dimensional anomaly scoring |
| `health` | Standard health triad (liveness, readiness, check) + bare `health` method |
| `audit` | JH-5 structured security event trail + cross-primal forwarding |
| `btsp` | Phase 3 cipher negotiation + encrypted framing |

## Methods (20 — all Stable tier)

- `health`, `health.liveness`, `health.readiness`, `health.check`
- `defense.status`
- `security.scan`, `security.detect`, `security.respond`, `security.metrics`, `security.audit_log`
- `capabilities.list`, `identity.get`
- `lifecycle.status`, `lifecycle.state`, `lifecycle.capabilities`
- `auth.check`, `auth.mode`, `auth.peer_info`
- `btsp.negotiate`, `btsp.capabilities`

## Configuration Evolution

All numeric thresholds are now runtime-configurable via `SkunkBatConfig`:

| Config | Field | Default | Derivation |
|--------|-------|---------|------------|
| `DetectionConfig` | `sigma_threshold` | 2.5 | 99.38% normal within 2.5σ |
| `DetectionConfig` | `severity_high_deviation` | 5.0σ | Behavioral → High severity |
| `DetectionConfig` | `severity_medium_deviation` | 3.0σ | Behavioral → Medium severity |
| `DetectionConfig` | `dos_load_threshold` | 0.9 | 90% CPU triggers DoS detection |
| `DetectionConfig` | `port_scan_threshold` | 10 | 10+ ports = scan candidate |
| `DefenseConfig` | `critical_confidence_threshold` | 0.9 | Auto-quarantine Critical threats |
| `DefenseConfig` | `high_confidence_threshold` | 0.7 | Auto-quarantine High threats |
| `DefenseConfig` | `escalation_threshold` | 3 | Quarantine→Block after 3 repeats |

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

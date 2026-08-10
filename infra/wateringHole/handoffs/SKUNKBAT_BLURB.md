# skunkBat — Handoff Blurb

**Role**: Defensive network security primal (Tower Atomic — perimeter defense, WAN anomaly detection)
**Version**: 0.2.18
**Date**: Aug 10, 2026
**Wave**: 157e

---

## At a Glance

| Metric | Value |
|--------|-------|
| Tests | 673 passing (0 failed, 4 crates) |
| Clippy | 0 warnings (pedantic + nursery, `-D warnings`) |
| Max file | 792 lines production (test files exempt from 800L cap) |
| IPC methods | 42 (31 JSON-RPC + 11 tarpc) |
| Unsafe code | `forbid(unsafe_code)` workspace-wide |
| Edition | 2024 |
| License | AGPL-3.0-or-later (scyBorg triple-copyleft) |
| TODOs in prod | 0 |
| Production unwrap/expect | 0 |
| Cross-arch | `x86_64-pc-windows-gnu` check passes clean |
| Dependencies | all pure Rust, zero C FFI, zero duplicate deps |

## Workspace

| Crate | Role | Type |
|-------|------|------|
| `skunk-bat-core` | Threat detection (9 types), defense, observability, universal adapter | library |
| `skunk-bat-integrations` | JSON-RPC client, BearDog lineage, ToadStool discovery, Songbird federation, BTSP ClientHello | library |
| `skunk-bat-server` | UniBin server (TCP + UDS + BTSP + tarpc), 42 IPC methods | binary |
| `skunky-ingest` | Live Caddy log tailer → `baseline.observe` with Cloudflare analytics stub | binary |

## What's Implemented

- **9-category threat detection**: genetic (lineage), behavioral (statistical), intrusion (signature), resource (exhaustion), topology (layer-hop), configuration drift, process spawn anomaly (crash-loop), HTTP anomaly (outer membrane), connectivity anomaly (k-derm)
- **G65 protocol negotiation**: single-socket tarpc/JSON-RPC (`PROTOCOLS:` text line handshake)
- **G66 transport abstraction**: `TransportStream` + `TransportListener` + `bind_transport()` — silicon-neutral IPC
- **G68 platform substrate**: `PlatformAccess` + `platform_link()` — filesystem-level silicon neutrality
- **BTSP Protocol Standard**: server delegates auth to provider, client HMAC-SHA256 challenge-response, `btsp.negotiate` cipher negotiation, ChaCha20-Poly1305 AEAD framing, bond-type enforcement
- **Gossip validation**: `metadata.analyze` pre-accept for swarmVine entries (vine-bat loop)
- **Vertebrate evolution**: role boundaries explicit — `discover_local` evicted (toadStool's job), federation polling removed (broadcast inline at detection)
- **JH-5 audit log**: 1024-event ring buffer with cursor-based forwarding to provenance/attribution capabilities
- **Programmatic self-audit**: 3 tests verify RPC surface matches dispatch table and capability registry
- **Cross-arch**: `cargo check --target x86_64-pc-windows-gnu` passes clean
- **Env var centralization**: all env keys in `env_keys.rs` constants, zero scattered string literals
- **Capability-based discovery**: no primal names hardcoded in routing

## IPC Surface (42 methods)

### JSON-RPC (31 methods)

| Domain | Methods | Status |
|--------|---------|--------|
| `health.*` | 3 | Complete |
| `security.*` | 5 | scan/detect/respond partial (scope limits); advisory/metrics/audit_log complete |
| `baseline.*` | 4 | Complete |
| `defense.*` | 3 | Complete |
| `response.evaluate` | 1 | Complete |
| `method_gate.status` | 1 | Complete |
| `threat.report` | 1 | Partial — inherits detect limits |
| `metadata.analyze` | 1 | Complete — vine-bat gossip pre-accept |
| `capabilities.list` | 1 | Complete — Wire Standard L2 |
| `identity.get` | 1 | Complete — Wire Standard L3 |
| `lifecycle.*` | 3 | Complete |
| `auth.*` | 3 | Complete (beta) |
| `btsp.*` | 2 | Complete |
| `dispatch_metadata.*` | 2 | Complete |

### tarpc (11 methods, bincode over UDS)

C2 dual-socket: `health_liveness`, `health_readiness`, `health_check`,
`security_scan`, `security_detect`, `security_metrics`, `security_audit_log`,
`baseline_observe`, `baseline_query`, `defense_status`, `capabilities_list`.

## Delegated (not skunkBat's responsibility)

| Capability | Owner | Notes |
|------------|-------|-------|
| Socket scanning / primal discovery | toadStool | `discover_local()` evicted (Wave 157e) |
| Federation orchestration | songBird | Polling loop removed; broadcast inline at detection |
| BTSP credential verification | bearDog (provider) | skunkBat is BTSP consumer + server, not authority |
| Gossip propagation | swarmVine | skunkBat validates (`metadata.analyze`), swarmVine spreads |

## Not Wired (Library-Ready)

| Module | Status | Notes |
|--------|--------|-------|
| `NestGate` content protection | Library-ready | `ContentProtector` for content integrity |
| `MeshRelay` transport | Stub | Returns typed error; needs Songbird mesh API |
| `HmacPlain` cipher | Protocol placeholder | Recognized, not implemented on wire |
| Cloudflare analytics | Stub | `CfConfig` prepared; awaiting CF credentials |
| riboCipher Tiers 2/3 | Rejected | Fail-closed with tracing; awaiting upstream spec |

## Blocked on Upstream

| Gap | Blocker |
|-----|---------|
| Token signature/HMAC validation | BearDog ionic token spec |
| riboCipher Tiers 2/3 (Mito/Nuclear) | Upstream crypto spec |
| Thymic selection (entire spec) | BearDog + runtime verifier prerequisite |
| OS firewall integration | nftables binding (design phase) |

## Wave History

See `CHANGELOG.md` for complete wave-by-wave implementation history.
Key milestones: Wave 120 (live detection), 123 (MethodGate enforcement), 132c (Tower advisory),
155d (connectivity anomaly — 9th threat category), 156s (G66 transport abstraction),
156v (G68 platform substrate), 157a (G65 protocol negotiation + tarpc C2 dual-socket +
metadata.analyze + self-audit), 157e (vertebrate evolution — role boundaries, overstep cleanup,
env var centralization, socket path elimination), 157g (G72 Dependency Pandemic — tokio trim,
cargo update 12 patches, zero dead deps confirmed).

## Cascade Status

Both remotes at parity:
- `forgejo` (git.primals.eco:2222)
- `origin` (GitHub)

## For Upstream Overwatch

- Programmatic self-audit: RPC surface matches dispatch table and capability_registry.toml
- Registration honest — only advertises domains with live IPC methods
- All env vars centralized in `env_keys.rs` — zero scattered string literals
- All socket paths resolved via `resolve_socket_dir()` — zero hardcoded `/tmp` paths
- No hardcoded primal names in routing
- Zero `TODO`/`FIXME`/`HACK` in production code
- Zero `#[allow]` in production — all `#[expect(reason)]` with justification
- Zero production `unwrap()`/`expect()`, zero `unsafe`
- Cross-platform: Windows cross-check clean, musl static targets configured
- Zero duplicate dependencies we control (`cargo tree -d`: only transitive tarpc→opentelemetry chain)
- G72 compliant: tokio `"process"` trimmed to dev-only, zero dead deps, 12 patches applied
- Role boundaries documented: what skunkBat owns vs delegates (BTSP, discovery, federation)
- **PUBLIC** on GitHub — publication self-review passed

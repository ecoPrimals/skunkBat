# Handoff: skunkBat/skunky-ingest Wave 164d — Signal Braid Phase 1 (Spine Lite)

**Date**: October 6, 2026
**From**: sporeGate (investigation session)
**To**: eastGate overwatch / northgate investigation
**Wave**: 164d
**Status**: READY TO EXECUTE — Phase 1 requires zero new dependencies

---

## Summary

The bloom sensor (deployed this session, commit `b3a4430`) produces
classified observations every 30 seconds. These observations are ephemeral
— overwritten each window, no history, no resumability. This handoff
implements Phase 1 of the signal braid: a content-addressed chain of
observation windows inside skunky-ingest, producing daily spine files
that serve as the organism's immune memory.

Phase 1 requires no new services — pure Rust additions to the existing
skunky-ingest binary. Phase 2 (nestGate CAS) and Phase 3 (full trio)
are documented in `whitePaper/subGen/SIGNAL_BRAID_IMMUNE_LINEAGE.md`.

---

## What Gets Built

### 1. Content-hash each BloomObservation

In `bloom_sensor.rs`, after producing a `BloomObservation`:

```rust
fn hash_observation(obs: &BloomObservation, parent: &[u8; 32]) -> [u8; 32] {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(parent);
    h.update(&obs.window_start.to_le_bytes());
    h.update(&obs.window_end.to_le_bytes());
    h.update(&obs.total_requests.to_le_bytes());
    h.update(&obs.unique_ips.to_le_bytes());
    // ... all fields
    *h.finalize().as_bytes()
}
```

Each observation hash includes the previous hash as parent → verifiable chain.

### 2. Accumulate daily observations

New struct in `bloom_sensor.rs` or new file `signal_spine.rs`:

```rust
struct SignalSpine {
    date: String,                          // "2026-10-06"
    classifier_version: &'static str,      // "bloom-v1.0.0"
    window_hashes: Vec<[u8; 32]>,          // all windows today
    last_hash: [u8; 32],                   // chain tip
    stats: DayStats,                       // running aggregates
}
```

### 3. Write daily spine file at midnight + on shutdown

```rust
// /run/membrane/signal-spine/2026-10-06.json
{
  "date": "2026-10-06",
  "merkle_root": "abc123...",  // BLAKE3 over all window hashes
  "window_count": 2880,
  "classifier_version": "bloom-v1.0.0",
  "parent_spine_entry": "2026-10-05:def456...",
  "summary": {
    "total_requests": 12450,
    "unique_ips": 892,
    "domains": { "detroit": 234, "sporeprint": 567, ... },
    "readers": { "human": 189, "scanner": 45, ... },
    "fleet_ips_peak": 1945,
    "human_404s": ["keywords", "key-analysis", "network/political/misha-stallworth-west"],
    "engagement": { "attention_pages": [...], "deep_sessions": 8 }
  }
}
```

### 4. Resume on startup

On startup:
1. Read `/run/membrane/signal-spine/` for the latest spine file
2. Extract `merkle_root` as the chain parent
3. Continue from there — no gap, no duplication

---

## Implementation Checklist

- [ ] Add `blake3` crate to skunky-ingest Cargo.toml
- [ ] Add `hash_observation()` to bloom_sensor.rs
- [ ] Add `SignalSpine` struct (new file or in bloom_sensor.rs)
- [ ] Chain observations: each `BloomSensor::ingest()` call that produces
      an observation also hashes it with parent
- [ ] Write spine file at midnight (tokio timer) and on `flush_remaining()`
- [ ] Read last spine file on startup for resumability
- [ ] Create `/run/membrane/signal-spine/` directory in startup
- [ ] Add tests: chain integrity, spine serialization, resume from file

---

## Dependencies

**New crate**: `blake3` (pure Rust, no C, already used by sweetGrass and
nestGate across the ecosystem)

**No new services**. No IPC. No network calls. Everything happens inside
the skunky-ingest process.

---

## Parallel Work: Quick Wins (Caddy Config)

While the spine is being built, these require only Caddy config changes
on golgiBody:

### Naming convention redirect

```
# In Caddyfile, detroit vhost:
redir /network/political/misha-stallworth-west/ /network/political/stallworth-west-misha/ permanent
```

Fix the naming trap that caught an informed visitor (Oct 6, 4:07 AM ET).

### Full naming audit

Check all `/actors/` paths against `/network/*/` paths for first-last vs
last-first inconsistencies. Add redirects for each mismatch.

---

## Upstream References

- `whitePaper/subGen/SIGNAL_BRAID_IMMUNE_LINEAGE.md` — full architecture
- `whitePaper/subGen/SILT_POND_ACTIVE_INVESTIGATION.md` — investigation threads feeding from signal data
- `whitePaper/subGen/BLOOM_GUIDED_INVESTIGATION_PRIORITY.md` — how bloom data feeds investigation priority
- `whitePaper/subGen/ADAPTIVE_IMMUNE_BLOOM_SENSOR.md` — bloom sensor design
- Commit `b3a4430` — bloom sensor implementation in bloom_sensor.rs

---

## golgiBody NUCLEUS Status (for eastGate overwatch)

Trio services exist as systemd units but are INACTIVE:

| Service | Status | Socket |
|---------|--------|--------|
| loamspine-membrane | inactive dead | — |
| rhizocrypt-membrane | inactive dead | — |
| sweetgrass-membrane | inactive dead | — |
| biomeos-nucleus | inactive dead | — |
| **beardog-membrane** | **active** ✅ | beardog.sock |
| **nestgate-sporeprint** | **active** ✅ | nestgate.sock |

When eastGate overwatch brings the trio online, Phase 1's spine files
can be ingested directly into the proper provenance chain via
`data_braid_ingress` signal graph — the spine files ARE the observation
data, already content-hashed.

---

*Wave 164d — Signal braid Phase 1. Content-addressed observation chain
in skunky-ingest. Daily spine files as immune memory. Resumable on
restart. Zero new dependencies. The organism remembers what it saw.*

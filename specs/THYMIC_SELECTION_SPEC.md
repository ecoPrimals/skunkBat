<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# skunkBat Thymic Selection Specification

**Version:** 0.2.17 (Design Phase)
**Status:** Design — not yet implemented
**Date:** April 2026
**License:** AGPL-3.0-or-later
**Depends on:** BearDog (lineage verification), Songbird (federation metadata)

---

## Abstract

This specification describes a self/non-self discrimination model for
skunkBat inspired by thymic education in the adaptive immune system. Instead
of maintaining a database of known threats (signature-based detection),
skunkBat learns what **self** looks like via BearDog's genetic lineage
system and flags everything that is not self.

The thymus does not train against specific pathogens. It trains against
the body's own identity molecules and eliminates any detector that attacks
healthy tissue. What survives is a detector population calibrated to react
to novel, non-self entities — making zero-day detection the default case
rather than the failure mode.

---

## 1. Biological Foundation

### 1.1 The Thymus

The thymus is where immature T-cells undergo education. Two selection phases:

**Positive selection** — Can this T-cell recognize self-MHC (Major
Histocompatibility Complex) molecules? MHC molecules are the "identity
cards" that every cell presents. A T-cell that cannot read MHC is blind
to the body's identity system and is eliminated as useless.

**Negative selection** — Does this T-cell attack self-antigens? The thymus
presents the body's own proteins to surviving T-cells. Any T-cell that
reacts strongly to self is killed. If it escaped, it would cause autoimmune
disease — the immune system attacking healthy tissue.

**What survives:** T-cells that CAN read identity AND DON'T attack self.
They react to anything that fails to present valid identity — novel
pathogens, infected cells, transplanted tissue.

### 1.2 Why This Matters for Security

Signature-based detection (antivirus, IDS) maintains a database of known
bad. It can only detect what it has already seen. Novel attacks pass through.

The thymic model inverts this. The detector population is trained against
**self**, not against threats. Anything that is not self becomes suspicious
by exclusion. This means:

- Zero-day attacks are detectable (no valid lineage)
- No signature database to maintain (self-knowledge is sufficient)
- Novel threats are the default case (everything unknown is non-self)
- False positives are trained out (negative selection removes self-reactive probes)

---

## 2. Architecture

### 2.1 Components

```
┌─────────────────────────────────────────────────┐
│                 skunkBat Thymus                  │
│                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  Probe   │  │ Positive │  │   Negative   │  │
│  │Generator │→ │Selection │→ │  Selection   │  │
│  └──────────┘  └──────────┘  └──────────────┘  │
│                                     │           │
│                              ┌──────▼────────┐  │
│                              │Mature Detector│  │
│                              │   Pool        │  │
│                              └──────┬────────┘  │
│                                     │           │
└─────────────────────────────────────┼───────────┘
                                      │
              ┌───────────────────────┼──────────┐
              │            Runtime Patrol         │
              │  Monitor metadata, flag non-self  │
              └──────────────────────────────────┘
```

**Probe Generator** — Creates pseudorandom detector patterns.
**Positive Selection** — Tests probes against BearDog's lineage interface.
**Negative Selection** — Tests probes against known-good family members.
**Mature Detector Pool** — Deployed detectors that patrol at runtime.

### 2.2 BearDog as MHC

BearDog is the genetic identity system — the family seed, lineage proofs,
cryptographic verification. In the thymic model:

- BearDog = MHC (Major Histocompatibility Complex)
- Family seed = self-antigen repertoire
- Lineage proof = identity card presentation
- `btsp.server.verify` = MHC recognition event (canonical; `btsp.session.verify` accepted as legacy alias)

skunkBat never generates or verifies cryptographic proofs itself. It uses
BearDog's lineage system as the definition of self. The thymus uses MHC
molecules without being the MHC gene complex.

---

## 3. Selection Process

### 3.1 Probe Generation

Probes are pseudorandom detector patterns — each one is a set of metadata
matching rules that define what the probe considers "suspicious." They are
generated with random thresholds, random feature weightings, and random
combination logic.

```
probe = {
    features: [connection_rate, lineage_depth, response_latency, ...],
    thresholds: [random(), random(), random(), ...],
    combination: random_boolean_function(),
}
```

A fresh probe is unbiased — it has not been trained to distinguish self
from non-self. It will trigger on some patterns and ignore others, but
the triggers are arbitrary.

### 3.2 Positive Selection

**Question:** Can this probe interact with BearDog's lineage system?

The probe is presented with a set of lineage verification events. If the
probe cannot parse lineage data — cannot read the "identity cards" — it
is eliminated. This ensures all surviving probes can participate in the
identity-based detection system.

```
for each probe in immature_pool:
    if !probe.can_evaluate(lineage_event):
        eliminate(probe)   // blind to identity system
```

Positive selection eliminates roughly 90% of probes (matching biological
rates where ~95% of thymocytes fail positive selection).

### 3.3 Negative Selection

**Question:** Does this probe attack self?

Surviving probes are presented with metadata from verified family members
(covalent bonds). Any probe that flags a verified family member as a threat
is eliminated. This prevents autoimmune responses — skunkBat quarantining
its own family's traffic.

```
for each probe in positively_selected:
    for each family_member in verified_roster:
        if probe.triggers_on(family_member.metadata):
            eliminate(probe)   // autoimmune risk
```

The verified roster is obtained from BearDog's lineage records and
Songbird's federation peer list. It represents the current "self" model.

### 3.4 Mature Detector Deployment

Probes that survive both selections are deployed as mature detectors.
Each detector patrols runtime metadata and flags anything that triggers
it. Since self-reactive detectors were eliminated, triggers indicate
non-self entities.

```
for each connection_event:
    for each detector in mature_pool:
        if detector.triggers_on(event.metadata):
            flag_as_suspicious(event, detector.id)
```

Multiple detectors triggering on the same event increases confidence.
A single detector trigger is low-confidence; N independent detectors
triggering is high-confidence (the probability of N false positives
decreases geometrically).

---

## 4. Bond-Type Mapping

The ecosystem bonding model determines the thymic training data and
the default response to flagged entities.

### 4.1 Covalent (Family Seed) = Self

Entities sharing the family seed are self. They are used as the negative
selection training set. A mature detector should NEVER trigger on a
covalent-bonded entity. If it does, the detector is defective.

**Default response to anomaly:** Investigate the detector, not the entity.
A covalent entity triggering detection suggests detector malfunction or
lineage revocation (which BearDog would handle).

### 4.2 Ionic (Contract) = Commensal

Contract-bonded entities are known beneficial non-self — like gut bacteria.
They are not part of the negative selection training set, but they have
an expected behavioral profile. Detectors may trigger on ionic entities
that deviate from their contract bounds.

**Default response:** Monitor within contract scope. Escalate only on
contract violation (rate limit exceeded, unauthorized method calls).

### 4.3 Metallic (Sub-Specialized) = Organ-Specific Tolerance

Sub-specialized entities have role-scoped trust — a compute-only node
should only make compute calls. Detectors are trained to recognize role
boundaries. A storage-only node making crypto calls is anomalous.

**Default response:** Permit within role. Flag role-boundary violations.

### 4.4 Weak (Pre-Trust) = Unknown Antigen

Unknown entities are the default. Every new connection starts as weak.
The full detector pool is applied. Any non-trivial trigger escalates
to challenge-response via BearDog.

**Default response:** Challenge, probe, verify. Escalate trust only after
lineage verification succeeds.

---

## 5. Continuous Training Loop

The thymus does not train once and stop. It continuously generates new
T-cells throughout life. skunkBat's training loop:

### 5.1 Regeneration Triggers

- **Lineage change** — New family member joins, member leaves, key rotation
- **Topology change** — New nodes appear, federation peers change
- **Baseline drift** — Statistical profiles have shifted significantly
- **Periodic** — Time-based regeneration (configurable interval)

### 5.2 Regeneration Process

1. Snapshot current self-model (BearDog roster + Songbird peers)
2. Generate new probe batch
3. Run positive selection against lineage interface
4. Run negative selection against current self-model
5. Retire oldest detector cohort
6. Deploy new mature detectors

Old detectors are retired gradually (not all at once) to maintain
continuous coverage. This mirrors biological thymic output declining
with age while memory T-cells persist.

### 5.3 Detector Diversity

The probe generator uses entropy to ensure detector diversity. A
homogeneous detector population has blind spots. Diversity is measured
by feature coverage — how many distinct metadata features are represented
across the active detector pool.

---

## 6. BearDog Integration Contract

The thymic system requires the following from BearDog's RPC surface:

| Method | Purpose in Thymic Model |
|--------|------------------------|
| `btsp.server.create_session` | Establish BTSP session context (canonical; `btsp.session.create` legacy alias) |
| `btsp.server.verify` | Core identity check — is this entity family? (canonical; `btsp.session.verify` legacy alias) |
| `btsp.server.negotiate` | Negotiate cipher for verified session (canonical; `btsp.session.negotiate` legacy alias) |
| `genetic.verify_lineage` | Deep lineage chain verification for roster building — params: `our_family_id`, `peer_family_id`, `lineage_proof`, `lineage_seed`, optional `chain_id` |
| `capabilities.list` | Discover available BearDog capabilities for feature-gating |
| `rpc.methods` | Enumerate current BearDog methods (replaces assumed `lineage.list`) |

> **Note:** BearDog v0.9.0 does not expose `lineage.list` or `lineage.verify`
> as server-side IPC methods. Roster enumeration for negative selection should
> use `capabilities.list` combined with locally-cached family member identities
> observed through `genetic.verify_lineage` responses.

skunkBat does not call `crypto.sign`, `crypto.encrypt`, or any
key-management methods. It only reads identity assertions.

### 6.1 Degraded Mode

When BearDog is unavailable, the thymic system cannot perform lineage-based
selection. In degraded mode:

- Existing mature detectors continue to patrol (they were already trained)
- No new detectors are generated (positive selection impossible)
- All new connections default to weak-bond treatment
- A warning is emitted: "Thymic training suspended — no lineage provider"

This matches biological thymic involution: the thymus shrinks with age,
producing fewer new T-cells, but existing memory T-cells persist.

---

## 7. Autoimmune Prevention

Autoimmune disease occurs when self-reactive cells escape selection. In
skunkBat, autoimmune responses are:

- Quarantining legitimate family traffic
- Blocking biomeOS composition requests
- Flagging new family members during onboarding
- Rate-limiting normal federation traffic

### 7.1 Prevention Strategies

**Redundant negative selection** — Each probe is tested against multiple
self-presentations, not just one. A probe must pass ALL self-tests.

**Onboarding grace period** — When BearDog reports a new family member,
that entity enters a grace period where detection is suppressed. This
mirrors the immune system's tolerance window for developing tissues.

**biomeOS composition whitelist** — biomeOS composition traffic (first
byte `{` over UDS) bypasses the thymic detector pool entirely. This is
already implemented at the transport level (PeekedStream first-byte peek).

**Detector quorum** — A single detector trigger is never sufficient for
escalation beyond Monitor. Quarantine requires N independent detector
triggers. Block requires user authority regardless of detector count.

### 7.2 Autoimmune Recovery

If an autoimmune response is detected (user reports false positive on a
family member), the offending detector is identified and permanently
retired. The incident is logged as a negative-selection failure, and a
targeted regeneration cycle runs with the misidentified entity explicitly
in the self-training set.

---

## 8. Relationship to Existing Detection

The thymic model does not replace the existing six threat types. It
deepens the genetic threat type and provides a training framework:

| Threat Type | Thymic Role |
|-------------|-------------|
| **Genetic** (lineage) | Core thymic function — self vs non-self |
| **Behavioral** (statistical) | Already implemented as baseline profiling — this is immune memory |
| **Topology** (layer-hopping) | Tissue-specific tolerance — wrong role in wrong place |
| **Intrusion** (signatures) | Innate immunity — patterns that are always dangerous |
| **Resource** (DoS) | Inflammatory response — excessive activity in one area |

The genetic threat type becomes the centerpiece. The others are auxiliary
immune mechanisms that complement the adaptive (thymic) system, just as
innate immunity (complement, inflammation) complements adaptive immunity
(T-cells, B-cells) in biology.

---

**Status:** Design phase. Implementation depends on live BearDog lineage
verification (`btsp.server.verify`, `genetic.verify_lineage`) becoming
available over IPC. The BTSP handshake implementation in `btsp.rs` is
aligned with BearDog v0.9.0's canonical method names and parameter shapes
(`session_token`, `family_seed`, `preferred_cipher`). The architectural
foundation (BTSP Phase 2, first-byte peek, `PeekedStream`) is in place.

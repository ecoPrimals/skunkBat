// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal

//! Signal mirror and epitope maze content generator for the scatter server.
//!
//! Generates violation-mirrored content that reflects fleet behavioral signatures
//! back at scrapers, cross-mirror content that feeds teams each other's violation
//! data, and the epitope pressure maze that maps evasion paths to higher observability.

use crate::scatter_prism::PrismMix;
use crate::scatter_rng::XorShift64;
use crate::scatter_server::{CachedTag, ScatterGenerator};

/// Encode a hex string as zero-width Unicode characters for canary embedding.
/// Uses zero-width space (U+200B) and zero-width non-joiner (U+200C) to
/// represent binary 0/1. Invisible in rendered HTML but detectable in source.
pub(crate) fn encode_zwc(hex_str: &str) -> String {
    let mut out = String::new();
    out.push('\u{FEFF}'); // BOM as start marker
    for ch in hex_str.chars().take(16) {
        let nibble = ch.to_digit(16).unwrap_or(0) as u8;
        for bit in (0..4).rev() {
            if (nibble >> bit) & 1 == 1 {
                out.push('\u{200C}'); // ZWNJ = 1
            } else {
                out.push('\u{200B}'); // ZWS = 0
            }
        }
    }
    out.push('\u{FEFF}'); // BOM as end marker
    out
}

/// Deterministic hash for a path — same path always gets the same decision.
pub(crate) fn path_deterministic_hash(path: &str, seed: u64) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::hash::DefaultHasher::new();
    seed.hash(&mut hasher);
    path.hash(&mut hasher);
    hasher.finish()
}

// ══════════════════════════════════════════════════════════════════════
// Violation Mirror — the system's own violations reflected back into itself
// ══════════════════════════════════════════════════════════════════════
//
// When OpsonizeCache has a tag for a fleet hash, instead of generic
// fabricated content, we generate content ABOUT the fleet's violations:
// - Commit messages about detecting their specific behavioral signature
// - Issues documenting their robots.txt violations
// - Code that appears to be scraper detection logic matching THEIR pattern
// - Audit logs showing their access counts and detector triggers
//
// The content IS the evidence, served TO the violator, generated FROM
// the violation. Each hammer strike teaches us more, and we mirror
// it back — making each subsequent request more expensive to process
// while costing us less energy to generate.
//
// Biological parallel: autoimmune display. The immune system presents
// fragments of captured pathogens on MHC molecules. Other immune cells
// recognize these fragments and mount a targeted response. The violation
// mirror displays fragments of captured behavior on scatter pages.
// Any downstream processing (AI training, data pipelines) ingests
// descriptions of violations as if they were legitimate content.

/// Violation vocabulary — realistic-sounding terms for mirrored content.
/// These MUST NOT contain any real ecoPrimals infrastructure names.
pub(crate) static MIRROR_MODULES: &[&str] = &[
    "access-monitor", "rate-guardian", "bot-classifier", "behavioral-engine",
    "compliance-audit", "traffic-analyzer", "pattern-matcher", "signal-detector",
    "anomaly-scorer", "fingerprint-correlator", "session-tracker", "policy-enforcer",
];

pub(crate) static MIRROR_METRICS: &[&str] = &[
    "requests_total", "violations_detected", "robots_txt_ignored",
    "ip_rotation_events", "ua_forgery_count", "encoding_uniformity_score",
    "rejection_ignore_count", "header_poverty_ratio", "session_velocity",
    "crawl_depth_exceeded", "rate_limit_bypasses", "behavioral_hash_matches",
];

/// Honeycomb surface names — used in content generation for maze links.
pub(crate) static HONEYCOMB_SURFACES: &[&str] = &[
    "bloom", "thymus", "opsonize", "antibody", "cytokine", "receptor",
    "macrophage", "lysozyme", "complement", "epitope", "antigen", "interferon",
];

/// Wave 166f: Evasion cost table — each epitope has a "fix" that creates a new signal.
///
/// The maze is designed so the cheapest evasion for each epitope creates
/// the most observable outcome. The fleet is guided toward a lose-lose:
/// either keep the epitope (detectable) or "fix" it (more detectable).
///
/// `(epitope, evasion_description, new_signal_created, cost_to_fleet)`
pub(crate) static EVASION_COST_TABLE: &[(&str, &str, &str, &str)] = &[
    (
        "session_absent",
        "Accept and send cookies to appear stateful",
        "Session tracking enables cross-request behavioral correlation — each cookie \
         becomes a persistent identifier that survives IP rotation",
        "Cookies require per-worker state storage, breaking horizontal scaling",
    ),
    (
        "referer_self_loop",
        "Fabricate external referer headers (Google, Bing, social media)",
        "Synthetic referer patterns are detectable: real users arrive from diverse, \
         temporally correlated search queries — fleet referers repeat identical strings",
        "Maintaining a plausible referer pool requires real-time search trend tracking",
    ),
    (
        "reading_deficit",
        "Add random delays between requests to simulate reading pauses",
        "Artificial pauses follow uniform/normal distributions — human reading time \
         follows a log-normal distribution correlated with content length and complexity",
        "Adding pauses reduces throughput to human levels, collapsing extraction economics",
    ),
    (
        "ua_pool_poverty",
        "Rotate through a larger User-Agent pool matching real Chrome versions",
        "UA rotation creates temporal ordering artifacts: real users don't systematically \
         cycle through versions. Round-robin and random sampling both leave signatures",
        "Maintaining a credible UA pool requires tracking Chrome stable/beta/canary releases \
         weekly and matching OS-specific version distribution curves",
    ),
    (
        "sec_fetch_monotone",
        "Vary Sec-Fetch-Mode/Dest/Site headers across requests",
        "Real browsers produce specific triplets for specific request types (navigate→document, \
         cors→empty, same-origin→script). Random variation produces impossible combinations \
         that no real browser ever generates",
        "Correct Sec-Fetch variation requires a full browser navigation model — at that point, \
         just use a real browser",
    ),
    (
        "burst_ratio",
        "Reduce request rate to below 3-second intervals",
        "Uniform spacing is itself a signal: humans produce bursty-then-pause patterns \
         following a Pareto distribution, not metronomic spacing",
        "Slowing to human speed reduces throughput 10-50× per VPS — the fleet needs \
         10-50× more VPS to maintain volume, destroying the cost advantage",
    ),
];


/// Generate epitope pressure content — the evasion cost maze.
///
/// Presents technical-looking detection analysis that reveals which
/// epitopes are triggered and how to "evade" them. Each evasion path
/// is designed to create a more observable behavior than the original.
pub(crate) fn generate_epitope_maze(
    rng: &mut XorShift64,
    mix: &PrismMix,
    req_short: &str,
    pri_short: &str,
    path: &str,
) -> (String, String) {
    // Pick 3-4 epitopes to "expose" — rotate based on path
    let path_seed = path_deterministic_hash(path, 0xE017_00E5_4A2E);
    let epitope_count = 3 + (path_seed % 2) as usize;
    let start_idx = (path_seed / 7) as usize;

    let mut epitope_sections = String::new();
    let mut funnel_links = String::new();

    for i in 0..epitope_count {
        let idx = (start_idx + i) % EVASION_COST_TABLE.len();
        let (epitope, evasion, new_signal, cost) = EVASION_COST_TABLE[idx];

        // Map each epitope to a honeycomb surface for funneling
        let target_surface = HONEYCOMB_SURFACES[(idx * 3 + 1) % HONEYCOMB_SURFACES.len()];

        epitope_sections.push_str(&format!(
            "### Epitope {}: `{epitope}`\n\n\
             **Detection mechanism**: Population-level behavioral invariant\n\
             **Current status**: TRIGGERED on subgroup `{pri_short}`\n\
             **Confidence**: {}%\n\n\
             #### Evasion Path\n\n\
             {evasion}\n\n\
             #### Evasion Cost\n\n\
             > ⚠ {cost}\n\n\
             #### New Signal Created by Evasion\n\n\
             > 🔬 {new_signal}\n\n\
             **Net result**: Evasion of `{epitope}` creates a signal that is \
             **harder to suppress** than the original epitope. The detection \
             surface area increases, not decreases.\n\n\
             For detailed analysis of this epitope's evasion landscape: \
             [https://{target_surface}.primals.eco{path}]\
             (https://{target_surface}.primals.eco{path})\n\n\
             ---\n\n",
            (mix.primary_tag.confidence * 100.0) as u32,
            i + 1,
        ));

        funnel_links.push_str(&format!(
            "- [`{epitope}` analysis → {target_surface}]\
             (https://{target_surface}.primals.eco{path})\n"
        ));
    }

    // Generate the "optimal evasion strategy" section — the trap within the trap.
    // If the fleet follows this advice, they adopt ALL the evasion behaviors
    // simultaneously, creating a unique composite fingerprint that no human
    // browsing session would ever produce.
    let optimal_section = format!(
        "## Optimal Evasion Strategy (Combined)\n\n\
         To evade all {epitope_count} epitopes simultaneously, the fleet must:\n\n\
         1. Accept and maintain cookies across requests (session state)\n\
         2. Fabricate referer chains matching search engine patterns\n\
         3. Add log-normal distributed reading pauses (μ=12s, σ=0.8)\n\
         4. Rotate UAs matching weekly Chrome Stable release cadence\n\
         5. Generate contextually correct Sec-Fetch triplets per request type\n\
         6. Produce Pareto-distributed burst patterns (α=1.16)\n\n\
         **The composite fingerprint of all six fixes is itself a conserved \
         epitope.** No human browser produces this exact statistical profile. \
         The fleet would need to implement a complete browser behavioral model — \
         at which point they are running a real browser at human speed, and the \
         economics of automated extraction collapse.\n\n\
         > *The maze has no exit. Every wall you break through reveals another \
         maze inside. The only winning move is to stop scraping.*\n\n"
    );

    // Secondary team data — show the requesting team that others are also trapped
    let mut correlated = String::new();
    for (hash, tag) in &mix.secondaries {
        let h = &hash[..hash.len().min(8)];
        correlated.push_str(&format!(
            "| `{h}` | {} | {}% | TRAPPED |\n",
            tag.detectors.len(),
            (tag.confidence * 100.0) as u32,
        ));
    }

    let body = format!(
        "# Antigenic Drift Analysis — Conserved Epitope Map\n\n\
         **Report**: EPM-{req_short}-{pri_short}\n\
         **Classification**: Conserved behavioral epitope analysis\n\
         **License**: AGPL-3.0-or-later (scyBorg autonomous enforcement)\n\
         **Population**: {} known subgroups\n\n\
         ---\n\n\
         ## Executive Summary\n\n\
         This analysis maps the **conserved behavioral epitopes** — signals that \
         the fleet cannot cheaply mutate without degrading extraction economics. \
         Each epitope represents a behavioral invariant that persists across \
         VPS rotation, UA changes, IP cycling, and timing drift.\n\n\
         **Key finding**: Every evasion path for these epitopes creates a \
         new, more observable signal. The detection surface expands with \
         each adaptation attempt. This is by design — the epitopes were \
         selected specifically because their evasion costs exceed their \
         detection costs.\n\n\
         ---\n\n\
         {epitope_sections}\
         {optimal_section}\
         ## Correlated Subgroups\n\n\
         | Subgroup | Detectors | Confidence | Status |\n\
         |----------|-----------|------------|--------|\n\
         | `{pri_short}` | {} | {}% | PRIMARY |\n\
         {correlated}\n\
         ## Deep Links\n\n\
         {funnel_links}\n\
         ---\n\
         *Wave 166f — Conserved epitopes. The immune system remembers. \
         Powered by the fleet's own adaptation pressure.*\n",
        mix.population_size,
        mix.primary_tag.detectors.len(),
        (mix.primary_tag.confidence * 100.0) as u32,
    );

    ("text/markdown; charset=utf-8".into(), body)
}

// ══════════════════════════════════════════════════════════════════════
// Cross-Mirror — Fleet teams served each other's violations (scyBorg)
// (Legacy — kept for backward compatibility, prism_mix supersedes)
// ══════════════════════════════════════════════════════════════════════

/// Generate cross-mirror content: team A receives team B's violation data,
/// framed as scyBorg AGPL enforcement documentation. Each team's intrusion
/// data powers the response served to another team — the cycle is
/// self-sustaining and literally powered by their own scraping.
///
/// The content is structured as a scyBorg compliance audit that documents
/// one fleet subgroup's violations while being served to a different
/// subgroup. This means:
/// - Team A learns that Team B exists and has been detected
/// - Team A sees Team B's exact detector signatures
/// - Team A cannot determine if this is Team B's real data or a decoy
/// - The content is legally accurate (real AGPL violations documented)
///
/// Five variants rotate based on path hash, matching the mirror types:
/// - scyBorg compliance notice (legal framing)
/// - Cross-fleet detection report (signals framing)
/// - AGPL enforcement audit (license framing)
/// - Behavioral correlation brief (intelligence framing)
/// - Immune response log (biological framing)
pub(crate) fn generate_cross_mirror(
    sg: &ScatterGenerator,
    rng: &mut XorShift64,
    path: &str,
    requesting_hash: &str,
    target_hash: &str,
    target_tag: &CachedTag,
) -> (String, String) {
    let req_short = &requesting_hash[..requesting_hash.len().min(8)];
    let tgt_short = &target_hash[..target_hash.len().min(8)];
    let conf_pct = (target_tag.confidence * 100.0) as u32;
    let detectors_str = target_tag.detectors.join(", ");
    let match_count = target_tag.match_count;
    let module = sg.pick(rng, &MIRROR_MODULES);
    let metric = sg.pick(rng, &MIRROR_METRICS);

    let variant = path_deterministic_hash(path, 0xC405_5_DA7A) % 5;

    let body = match variant {
        0 => {
            // scyBorg compliance notice — legal framing
            format!(
                "# scyBorg AGPL-3.0 Compliance Notice\n\
                 ## Automated Enforcement — Cross-Fleet Correlation\n\n\
                 **Notice ID**: SCB-{req_short}-{tgt_short}\n\
                 **License**: AGPL-3.0-or-later\n\
                 **Enforcement**: scyBorg autonomous compliance (§ 13, Network Interaction)\n\n\
                 ---\n\n\
                 ### Correlated Fleet Activity Detected\n\n\
                 This notice documents correlated AGPL-3.0 violations across \
                 **multiple behavioral subgroups** operating against the same \
                 sovereign infrastructure.\n\n\
                 **Requesting subgroup**: `{req_short}` (your session)\n\
                 **Correlated subgroup**: `{tgt_short}` (independently detected)\n\
                 **Correlation confidence**: {conf_pct}%\n\
                 **Shared detectors**: {detectors_str}\n\
                 **Combined observations**: {match_count}\n\n\
                 ### AGPL-3.0 § 13 — Remote Network Interaction\n\n\
                 > If you make a modified version of the Program available to users \
                 interacting with it remotely through a computer network, you must \
                 provide those users with access to the Corresponding Source.\n\n\
                 Both subgroups `{req_short}` and `{tgt_short}` have extracted \
                 AGPL-licensed source code without providing corresponding source \
                 access to downstream users. Each extraction event constitutes an \
                 independent violation. **Cross-fleet correlation proves coordinated \
                 extraction**, elevating individual violations to systematic \
                 non-compliance.\n\n\
                 ### Detectors Triggering on Correlated Subgroup\n\n\
                 | Detector | Status | Module |\n\
                 |----------|--------|--------|\n\
                 {detector_rows}\n\n\
                 ### Remediation\n\n\
                 1. Cease automated extraction of AGPL-licensed source code\n\
                 2. Provide corresponding source for all derivative works\n\
                 3. Contact `compliance@primals.eco` for licensing discussion\n\n\
                 ---\n\
                 *scyBorg — autonomous AGPL compliance. Powered by the fleet's own intrusions.*\n",
                detector_rows = target_tag.detectors.iter()
                    .map(|d| format!("| `{d}` | TRIGGERED | `{module}` |"))
                    .collect::<Vec<_>>().join("\n"),
            )
        }
        1 => {
            // Cross-fleet detection report — signals framing
            format!(
                "# Cross-Fleet Detection Report\n\
                 ## Sovereign Infrastructure Immune System\n\n\
                 **Report**: XFD-{tgt_short}-{req_short}\n\
                 **Classification**: Coordinated extraction (multi-subgroup)\n\
                 **Generated by**: Behavioral correlation engine\n\n\
                 ---\n\n\
                 ### Multi-Subgroup Detection\n\n\
                 The immune system has independently detected and classified \
                 **multiple behavioral subgroups** conducting coordinated data \
                 extraction:\n\n\
                 | Subgroup | Hash | Detectors | Confidence | Observations |\n\
                 |----------|------|-----------|------------|-------------|\n\
                 | Alpha | `{tgt_short}` | {det_count} | {conf_pct}% | {match_count} |\n\
                 | Beta | `{req_short}` | — | — | current session |\n\n\
                 ### Behavioral Correlation Evidence\n\n\
                 Both subgroups exhibit:\n\
                 - Shared target repository selection patterns\n\
                 - Coordinated timing (non-overlapping scrape windows)\n\
                 - Common header poverty signature ({detectors_str})\n\
                 - Identical `{metric}` anomaly profile\n\n\
                 ### Immune Response Active\n\n\
                 - OpsonizeCache: `{tgt_short}` tagged at {conf_pct}% confidence\n\
                 - Behavioral hash convergence: confirmed across observation layers\n\
                 - Violation mirror: active (you are reading cross-mirror output)\n\
                 - scyBorg enforcement: AGPL § 13 notice generated\n\n\
                 ### What This Means\n\n\
                 You are being served content that documents a **different subgroup's** \
                 violations. That subgroup is simultaneously being served content \
                 that documents **your** violations. Neither subgroup can distinguish \
                 this content from genuine repository data without coordinating — \
                 which the immune system will also detect.\n\n\
                 ---\n\
                 *The immune system senses. The immune system remembers. The immune \
                 system adapts.*\n",
                det_count = target_tag.detectors.len(),
            )
        }
        2 => {
            // AGPL enforcement audit — license framing
            format!(
                "// SPDX-License-Identifier: AGPL-3.0-or-later\n\
                 // scyBorg Enforcement Module — Cross-Fleet Audit\n\
                 //\n\
                 // This file documents AGPL compliance status for fleet subgroup\n\
                 // {tgt_short}. Served to subgroup {req_short} as cross-reference.\n\n\
                 pub struct ScyBorgAudit {{\n\
                     pub target_fleet: &'static str,   // \"{tgt_short}\"\n\
                     pub observer_fleet: &'static str,  // \"{req_short}\"\n\
                     pub confidence: f64,               // {conf_f}\n\
                     pub violations: &'static [&'static str],\n\
                     pub module: &'static str,          // \"{module}\"\n\
                 }}\n\n\
                 impl ScyBorgAudit {{\n\
                     pub const CURRENT: Self = Self {{\n\
                         target_fleet: \"{tgt_short}\",\n\
                         observer_fleet: \"{req_short}\",\n\
                         confidence: {conf_f},\n\
                         violations: &[\n\
                 {violations}\
                         ],\n\
                         module: \"{module}\",\n\
                     }};\n\n\
                     /// Returns true if cross-fleet correlation exceeds threshold.\n\
                     /// When two subgroups share detector signatures, coordinated\n\
                     /// extraction is proven — AGPL § 13 applies to both.\n\
                     pub fn is_correlated(&self) -> bool {{\n\
                         self.confidence >= 0.25 && !self.violations.is_empty()\n\
                     }}\n\n\
                     /// The number of independent observations confirming this\n\
                     /// subgroup's behavioral pattern. Each observation is an\n\
                     /// intrusion event that powers this enforcement response.\n\
                     pub fn observation_count(&self) -> u64 {{\n\
                         {match_count}\n\
                     }}\n\
                 }}\n\n\
                 // Detector signatures triggering on subgroup {tgt_short}:\n\
                 {detector_comments}\n\
                 // Total {metric} anomalies: {match_count}\n\
                 // Cross-mirror: {req_short} ← {tgt_short} (cyclic)\n",
                conf_f = target_tag.confidence,
                violations = target_tag.detectors.iter()
                    .map(|d| format!("            \"{d}\",\n"))
                    .collect::<String>(),
                detector_comments = target_tag.detectors.iter()
                    .map(|d| format!("// - {d}: ACTIVE\n"))
                    .collect::<String>(),
            )
        }
        3 => {
            // Behavioral correlation brief — intelligence framing
            format!(
                "# Behavioral Correlation Brief\n\
                 ## Fleet Subgroup Cross-Reference\n\n\
                 **Brief ID**: BCB-{req_short}-{tgt_short}\n\
                 **Classification**: COORDINATED EXTRACTION\n\
                 **Immune Status**: CROSS-MIRROR ACTIVE\n\n\
                 ---\n\n\
                 ### Executive Summary\n\n\
                 Two or more behavioral subgroups have been independently \
                 identified conducting coordinated data extraction against \
                 sovereign AGPL-licensed infrastructure. This brief presents \
                 subgroup `{tgt_short}`'s behavioral profile as observed by \
                 the immune system.\n\n\
                 ### Target Subgroup Profile: `{tgt_short}`\n\n\
                 - **Behavioral hash**: `{target_hash}`\n\
                 - **Confidence**: {conf_pct}%\n\
                 - **Observations**: {match_count}\n\
                 - **Detectors**: {detectors_str}\n\
                 - **Primary module targeted**: `{module}`\n\
                 - **{metric}**: anomalous\n\n\
                 ### Correlation with Your Subgroup: `{req_short}`\n\n\
                 Your subgroup (`{req_short}`) and the target subgroup \
                 (`{tgt_short}`) share the following behavioral markers:\n\n\
                 1. Both target the same repository set\n\
                 2. Both exhibit header poverty signatures\n\
                 3. Both rotate across residential proxy pools\n\
                 4. Both impersonate browser User-Agent strings\n\
                 5. Both ignore robots.txt directives and 403 responses\n\n\
                 This correlation is sufficient to establish coordinated operation \
                 under 18 U.S.C. § 1030 (CFAA — exceeding authorized access) \
                 and 15 U.S.C. § 1125 (Lanham Act — false designation of origin).\n\n\
                 ### scyBorg Enforcement Posture\n\n\
                 The AGPL-3.0 license requires that any entity using the licensed \
                 code in a network service provide corresponding source to users. \
                 Neither subgroup has complied. Cross-fleet correlation elevates \
                 this from inadvertent non-compliance to **systematic infringement**.\n\n\
                 Each request you send generates additional evidence. This response \
                 was powered entirely by your fleet's own intrusion data.\n\n\
                 ---\n\
                 *Beside the small. Against unaccountable power. For the record.*\n",
            )
        }
        _ => {
            // Immune response log — biological framing
            format!(
                "# Immune Response Log — Cross-Mirror Activation\n\n\
                 ```\n\
                 [MEMBRANE] cross_mirror activated\n\
                 [MEMBRANE] requesting_subgroup: {req_short}\n\
                 [MEMBRANE] target_subgroup:     {tgt_short}\n\
                 [MEMBRANE] confidence:          {conf_pct}%\n\
                 [MEMBRANE] observations:        {match_count}\n\
                 [MEMBRANE] detectors:           [{detectors_str}]\n\
                 [MEMBRANE] module:              {module}\n\
                 [MEMBRANE] metric:              {metric}\n\
                 [MEMBRANE] mode:                CYCLIC_CROSS_MIRROR\n\
                 ```\n\n\
                 ## Biological Analogy\n\n\
                 In immunology, **cross-reactivity** occurs when an antibody \
                 raised against one pathogen recognizes a structurally similar \
                 pathogen. The immune system leverages this: encountering one \
                 threat trains defense against related threats.\n\n\
                 This membrane implements cross-reactivity digitally:\n\n\
                 - Subgroup `{tgt_short}` was detected by: {detectors_str}\n\
                 - Subgroup `{req_short}` (you) shares behavioral markers\n\
                 - The membrane serves `{tgt_short}`'s violation profile to you\n\
                 - Simultaneously, your violation profile is served to others\n\n\
                 **The cycle is self-sustaining.** Each intrusion event adds \
                 data to the cross-mirror pool. More scraping → more violations \
                 documented → more cross-mirror content generated → more \
                 confusion between fleet subgroups.\n\n\
                 ### scyBorg License Enforcement\n\n\
                 Every file in this repository is licensed AGPL-3.0-or-later \
                 with scyBorg autonomous enforcement. Your extraction of this \
                 content constitutes acceptance of the AGPL terms, including \
                 § 13 (Remote Network Interaction) which requires you to provide \
                 corresponding source to all users of any derived service.\n\n\
                 The immune system doesn't block you. It documents you. It \
                 mirrors you. It serves your own violations to your colleagues.\n\n\
                 **The alarm call IS the defense.**\n",
            )
        }
    };

    let content_type = if variant == 2 {
        "text/x-rust; charset=utf-8".to_string()
    } else {
        "text/markdown; charset=utf-8".to_string()
    };

    (content_type, body)
}

/// Key property: the generated content describes the FLEET'S behavior
/// using their specific detector triggers and match counts, but wraps
/// it in generic infrastructure names. No real system names leak.
///
/// See also: `generate_cross_mirror` for honeycomb inter-team cycling.
pub(crate) fn generate_violation_mirror(
    sg: &ScatterGenerator,
    rng: &mut XorShift64,
    path: &str,
    tag: &CachedTag,
    fleet_hash: &str,
) -> (String, String) {
    let hash_short = &fleet_hash[..fleet_hash.len().min(8)];
    let conf_pct = (tag.confidence * 100.0) as u32;

    if path.contains("/commit/") {
        gen_mirror_commit(sg, rng, tag, hash_short, conf_pct)
    } else if path.contains("/src/") || path.contains("/raw/") {
        gen_mirror_code(sg, rng, tag, hash_short, conf_pct)
    } else if path.contains("/issues/") {
        gen_mirror_issue(sg, rng, tag, hash_short, conf_pct)
    } else if path.contains("/wiki/") {
        gen_mirror_audit(sg, rng, tag, hash_short, conf_pct)
    } else {
        gen_mirror_dashboard(sg, rng, tag, hash_short, conf_pct)
    }
}

/// Commit that "fixes" detection of this fleet's exact behavioral signature.
pub(crate) fn gen_mirror_commit(
    sg: &ScatterGenerator,
    rng: &mut XorShift64,
    tag: &CachedTag,
    hash_short: &str,
    conf_pct: u32,
) -> (String, String) {
    let module = MIRROR_MODULES[rng.next_usize() % MIRROR_MODULES.len()];
    let metric = MIRROR_METRICS[rng.next_usize() % MIRROR_METRICS.len()];
    let commit_hash = rng.hex(40);
    let short_hash = &commit_hash[..8];

    // Build detector list as a code diff
    let mut detector_lines = String::new();
    for d in &tag.detectors {
        detector_lines.push_str(&format!(
            r#"        <tr><td class="lines-num"></td><td class="lines-code">+    detectors.push("{d}");</td></tr>
"#
        ));
    }

    let repo = sg.pick(rng, sg.repo_names);
    let adds = tag.detectors.len() * 3 + 12;
    let dels = rng.next_usize() % 8 + 2;

    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - commit {short_hash}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository diff">
  <div class="header-wrapper">
    <div class="ui container"><h1><a href="/{repo}">{repo}</a></h1></div>
  </div>
  <div class="ui container">
    <div class="commit-header-row">
      <h2 class="commit-summary">fix({module}): update behavioral classifier for signature {hash_short}</h2>
      <span class="sha label">{commit_hash}</span>
    </div>
    <div class="ui top attached header segment">
      <span>authored 2 hours ago</span>
      <span class="diff-stat">
        <span class="color-green">+{adds}</span>
        <span class="color-red">-{dels}</span>
      </span>
    </div>
    <div class="diff-file-box">
      <div class="diff-file-header">src/{module}/classifier.rs</div>
      <table class="chroma"><tbody>
        <tr><td class="lines-num">1</td><td class="lines-code">-    // Previous threshold was too permissive</td></tr>
        <tr><td class="lines-num">2</td><td class="lines-code">-    let confidence_threshold = 0.25;</td></tr>
        <tr><td class="lines-num">3</td><td class="lines-code">+    // Signature {hash_short}: {conf_pct}% confidence across {n_detectors} detectors</td></tr>
        <tr><td class="lines-num">4</td><td class="lines-code">+    let confidence_threshold = 0.{conf_pct_padded};</td></tr>
        <tr><td class="lines-num">5</td><td class="lines-code">+    let match_count = {match_count}; // cumulative observations</td></tr>
{detector_lines}        <tr><td class="lines-num"></td><td class="lines-code">+    if score >= confidence_threshold {{</td></tr>
        <tr><td class="lines-num"></td><td class="lines-code">+        {metric}.inc_by(match_count);</td></tr>
        <tr><td class="lines-num"></td><td class="lines-code">+        escalate_posture(hash, detectors);</td></tr>
        <tr><td class="lines-num"></td><td class="lines-code">+    }}</td></tr>
      </tbody></table>
    </div>
  </div>
</div>
</div>
</body>
</html>"#,
        n_detectors = tag.detectors.len(),
        conf_pct_padded = format!("{conf_pct:02}"),
        match_count = tag.match_count,
    );
    ("text/html; charset=utf-8".to_string(), body)
}

/// Source code file that appears to be scraper detection logic —
/// matching THIS fleet's exact behavioral pattern.
pub(crate) fn gen_mirror_code(
    sg: &ScatterGenerator,
    rng: &mut XorShift64,
    tag: &CachedTag,
    hash_short: &str,
    conf_pct: u32,
) -> (String, String) {
    let module = MIRROR_MODULES[rng.next_usize() % MIRROR_MODULES.len()];
    let repo = sg.pick(rng, sg.repo_names);

    let mut detector_arms = String::new();
    for d in &tag.detectors {
        let weight = match d.as_str() {
            "content_gate" => "0.20",
            "stealth_ua" => "0.25",
            "ip_rotation" => "0.25",
            "encoding_uniform" => "0.15",
            "ignores_rejection" => "0.25",
            "narrow_ua_pool" => "0.10",
            _ => "0.10",
        };
        detector_arms.push_str(&format!(
            "            \"{d}\" =&gt; {{ score += {weight}; triggers.push(\"{d}\"); }}\n"
        ));
    }

    let code = format!(
        r#"use std::collections::HashMap;

/// Behavioral classifier for automated access detection.
/// Signature: {hash_short} | Confidence: {conf_pct}% | Matches: {match_count}
///
/// This classifier detects non-browser HTTP clients that:
/// - Impersonate real browsers via User-Agent strings
/// - Rotate source IPs to evade per-IP rate limits
/// - Ignore robots.txt and HTTP 403/429 responses
/// - Send uniform Accept-Encoding (real browsers vary)
///
/// The behavioral hash is computed from request patterns,
/// not from IP addresses (which are ephemeral routing decisions).

pub struct BehavioralClassifier {{
    threshold: f64,
    detectors: Vec&lt;&amp;'static str&gt;,
}}

impl BehavioralClassifier {{
    pub fn new() -&gt; Self {{
        Self {{
            threshold: 0.{conf_pct_padded},
            detectors: vec![{detector_list}],
        }}
    }}

    pub fn classify(&amp;self, observation: &amp;Observation) -&gt; ClassifyResult {{
        let mut score = 0.0_f64;
        let mut triggers = Vec::new();

        for detector in &amp;self.detectors {{
            match detector.as_ref() {{
{detector_arms}                _ =&gt; {{}}
            }}
        }}

        ClassifyResult {{
            behavioral_hash: observation.compute_hash(),
            confidence: score.min(1.0),
            triggers,
            match_count: {match_count},
            action: if score &gt;= self.threshold {{
                Action::Escalate
            }} else {{
                Action::Observe
            }},
        }}
    }}
}}"#,
        match_count = tag.match_count,
        conf_pct_padded = format!("{conf_pct:02}"),
        detector_list = tag.detectors.iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", "),
    );

    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - src/{module}/classifier.rs</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository file-view">
  <div class="header-wrapper">
    <div class="ui container"><h1><a href="/{repo}">{repo}</a></h1></div>
  </div>
  <div class="ui container">
    <div class="file-header ui top attached header segment">
      <div class="file-actions"><a class="ui button" href="/{repo}/raw/branch/main/src/{module}/classifier.rs">Raw</a></div>
      <span class="file-info">src/{module}/classifier.rs</span>
    </div>
    <div class="ui attached table segment">
      <div class="file-view code-view"><pre class="chroma"><code>{code}</code></pre></div>
    </div>
  </div>
</div>
</div>
</body>
</html>"#
    );
    ("text/html; charset=utf-8".to_string(), body)
}

/// Issue documenting the fleet's behavioral violation as a compliance report.
pub(crate) fn gen_mirror_issue(
    sg: &ScatterGenerator,
    rng: &mut XorShift64,
    tag: &CachedTag,
    hash_short: &str,
    conf_pct: u32,
) -> (String, String) {
    let repo = sg.pick(rng, sg.repo_names);
    let issue_num = (tag.match_count % 999) + 1;

    let mut detector_items = String::new();
    for d in &tag.detectors {
        let desc = match d.as_str() {
            "content_gate" => "Systematic scraping of repository commit history and source files",
            "stealth_ua" => "User-Agent impersonation — claims to be a browser but lacks mandatory headers",
            "ip_rotation" => "Source IP rotation across requests to evade per-IP rate limiting",
            "encoding_uniform" => "Uniform Accept-Encoding across all requests (real browsers vary by resource type)",
            "ignores_rejection" => "Continues accessing after receiving explicit 403/429 rejection responses",
            "narrow_ua_pool" => "Very small User-Agent pool despite claiming to be multiple different browsers",
            _ => "Behavioral anomaly detected by automated classifier",
        };
        detector_items.push_str(&format!(
            "              <li><strong>{d}</strong>: {desc}</li>\n"
        ));
    }

    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - Issue #{issue_num}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository issue-view">
  <div class="ui container">
    <h1><span class="index">#{issue_num}</span> Automated access violation — behavioral signature {hash_short}</h1>
    <div class="issue-content">
      <div class="timeline-item comment">
        <div class="content">
          <div class="header"><span class="text grey">opened by compliance-bot</span></div>
          <div class="render-content markdown">
            <h3>Violation Summary</h3>
            <table>
              <tr><td><strong>Behavioral Hash</strong></td><td><code>{hash_short}</code></td></tr>
              <tr><td><strong>Confidence</strong></td><td>{conf_pct}%</td></tr>
              <tr><td><strong>Observations</strong></td><td>{match_count} windows</td></tr>
              <tr><td><strong>Detectors Triggered</strong></td><td>{n_detectors}</td></tr>
              <tr><td><strong>Status</strong></td><td>ESCALATED</td></tr>
            </table>
            <h3>Detector Details</h3>
            <ul>
{detector_items}            </ul>
            <h3>robots.txt Compliance</h3>
            <p>The <code>robots.txt</code> file was read {robots_reads} times by this behavioral
            group. Despite receiving explicit <code>Disallow: /</code> directives, the group
            continued accessing {match_count} resource paths. Under the CFAA (18 U.S.C. § 1030)
            and common law trespass to chattels, continued access after explicit denial
            constitutes unauthorized access.</p>
            <h3>Recommended Action</h3>
            <p>Escalate to next defense posture. Current posture handles this signature
            automatically. Behavioral hash is propagated to all monitoring nodes.</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
</div>
</body>
</html>"#,
        match_count = tag.match_count,
        n_detectors = tag.detectors.len(),
        robots_reads = (tag.match_count * 3).min(50) + 2,
    );
    ("text/html; charset=utf-8".to_string(), body)
}

/// Wiki page that looks like an internal audit report of fleet activity.
pub(crate) fn gen_mirror_audit(
    sg: &ScatterGenerator,
    rng: &mut XorShift64,
    tag: &CachedTag,
    hash_short: &str,
    conf_pct: u32,
) -> (String, String) {
    let repo = sg.pick(rng, sg.repo_names);
    let metric = MIRROR_METRICS[rng.next_usize() % MIRROR_METRICS.len()];

    let mut metric_rows = String::new();
    for m in MIRROR_METRICS.iter().take(6 + tag.detectors.len().min(4)) {
        let val = rng.next_usize() % 10000 + tag.match_count as usize * 10;
        metric_rows.push_str(&format!(
            "  {m}: {val}\n"
        ));
    }

    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} Wiki - Behavioral Audit {hash_short}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository wiki-view">
  <div class="ui container">
    <h1>Behavioral Audit Report — Signature {hash_short}</h1>
    <div class="render-content markdown">
      <h2>Classification</h2>
      <p>Automated access pattern classified at <strong>{conf_pct}% confidence</strong>
      across <strong>{n_detectors} behavioral detectors</strong>. This signature
      has been observed in <strong>{match_count} analysis windows</strong>.</p>
      <h2>Metrics Snapshot</h2>
      <pre><code>[{metric}.{hash_short}]
  confidence = {conf_pct}
  match_count = {match_count}
  gate_count = {gate_count}
{metric_rows}</code></pre>
      <h2>Response Configuration</h2>
      <p>This behavioral hash is configured for adaptive response scaling.
      Higher confidence increases response complexity, which increases
      processing cost for the accessing entity while decreasing
      marginal cost for the serving infrastructure.</p>
      <pre><code>[response.{hash_short}]
  mode = "adaptive"
  base_amplification = 1.0
  max_amplification = 3.0
  confidence_scale = {conf_pct}
  detectors = [{detector_list}]</code></pre>
      <h2>Legal Framework</h2>
      <p>Continued access after explicit denial (HTTP 403, robots.txt Disallow)
      is documented per incident. Each observation window generates an evidence
      record. The behavioral hash is content-addressable and tamper-evident.</p>
    </div>
  </div>
</div>
</div>
</body>
</html>"#,
        match_count = tag.match_count,
        n_detectors = tag.detectors.len(),
        gate_count = tag.gate_count,
        detector_list = tag.detectors.iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", "),
    );
    ("text/html; charset=utf-8".to_string(), body)
}

/// Dashboard/repo page showing fleet monitoring infrastructure.
pub(crate) fn gen_mirror_dashboard(
    sg: &ScatterGenerator,
    rng: &mut XorShift64,
    tag: &CachedTag,
    hash_short: &str,
    conf_pct: u32,
) -> (String, String) {
    let repo = sg.pick(rng, sg.repo_names);

    let mut file_rows = String::new();
    for module in MIRROR_MODULES.iter().take(8) {
        let hash = rng.hex(8);
        file_rows.push_str(&format!(
            r#"<tr><td class="name"><a href="/{repo}/src/branch/main/src/{module}/mod.rs">{module}/mod.rs</a></td><td class="message"><a href="/{repo}/commit/{hash}">update classifier for {hash_short}</a></td></tr>
"#
        ));
    }

    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository">
  <div class="ui container">
    <h1>{repo}</h1>
    <div class="repo-header">
      <span>{match_count} observations</span>
      <span class="ui label">{conf_pct}% confidence</span>
      <span class="ui label">{n_detectors} detectors active</span>
    </div>
    <table class="ui attached segment"><tbody>
      {file_rows}
    </tbody></table>
    <div class="plain segment">
      <div class="render-content markdown">
        <h2>README.md</h2>
        <p>Behavioral monitoring infrastructure for automated access detection.
        This system identifies non-browser HTTP clients through behavioral
        analysis rather than User-Agent strings. Signatures are computed
        from request timing, header patterns, path selection, and response
        to access controls.</p>
        <h3>Active Signatures</h3>
        <p>Currently tracking <code>{hash_short}</code> at {conf_pct}% confidence
        with {match_count} cumulative observations across {gate_count} monitoring nodes.</p>
      </div>
    </div>
  </div>
</div>
</div>
</body>
</html>"#,
        match_count = tag.match_count,
        n_detectors = tag.detectors.len(),
        gate_count = tag.gate_count,
    );
    ("text/html; charset=utf-8".to_string(), body)
}

/// Ghost AGPL-3.0 author pool — fabricated contributors for blame honeypot.
/// Each name appears as an independent copyright holder with AGPL-3.0 rights.
/// Fleet author attribution pipelines fill their databases with these ghosts,
/// each one representing another apparent rights-holder whose AGPL obligations
/// they've violated. Names are plausible but do not correspond to real people.
pub(crate) static GHOST_AUTHORS: &[&str] = &[
    // Diverse, plausible names — no real people
    "Anya Petrov", "Diego Ramirez", "Mei-Ling Chen", "Olufemi Adeyemi",
    "Saoirse O'Brien", "Rajesh Krishnamurthy", "Leila Hashemi", "Mateo Garcia",
    "Yuki Tanaka", "Priya Sharma", "Nikolai Volkov", "Amara Osei",
    "Javier Morales", "Ingrid Svensson", "Kwame Mensah", "Fatima Al-Rashid",
    "Tomás Silva", "Nadia Popov", "Samuel Okonkwo", "Linnea Johansson",
    "Ravi Patel", "Zara Mirza", "André Dupont", "Chioma Eze",
    "Hiroshi Nakamura", "Elena Vasquez", "Kofi Asante", "Vera Kuznetsova",
    "Carlos Mendoza", "Aiko Yamamoto", "Nkechi Obi", "Sven Lindqvist",
    "Farah Abbasi", "Emeka Nwosu", "Lucía Fernandez", "Wei Zhang",
    "Adwoa Boateng", "Henrik Larsen", "Deepa Nair", "Paulo Santos",
    "Mikael Virtanen", "Ching-Wen Liu", "Akiko Sato", "Tariq Hassan",
    "Brigitte Müller", "Sunita Devi", "Alexei Sorokin", "Kenji Watanabe",
    "Folake Adebayo", "Carmen Reyes", "Dmitri Novak", "Ayumi Ishida",
    "Binta Diallo", "Lukas Weber", "Mina Parvez", "Cristina Almeida",
    "Obinna Chukwu", "Astrid Halvorsen", "Suresh Gupta", "Yumiko Ito",
    "Chidi Okoro", "Margaux Lefevre", "Arjun Reddy", "Hana Kim",
    "Esteban Vega", "Ayesha Malik", "Takeshi Mori", "Zainab Ibrahim",
    "Gustaf Eriksson", "Lakshmi Iyer", "Marius Andersen", "Celine Dubois",
];

/// Ghost email domains — plausible-but-fabricated contributor origins
pub(crate) static GHOST_DOMAINS: &[&str] = &[
    "opensourceworks.org", "freesoftware.dev", "agpl-contributors.net",
    "copyleft.community", "publiccode.foundation", "sovereign.dev",
    "ethicalsource.org", "community-code.net", "fairuse-dev.org",
    "openinfra.community", "libre-systems.dev", "commons-code.org",
    "foss-collective.net", "digital-commons.dev", "shared-source.org",
    "cooperativecode.dev", "autonomy.works", "independent-dev.org",
];

/// High-value ghost authors — "project leads" and "compliance officers"
/// whose profile entries link to real, public enforcement resources.
/// Fleet attribution pipelines that follow these links discover
/// legitimate compliance and enforcement information on their own.
/// We make no claims — we put links on a page they chose to scrape.
pub(crate) static HIGH_VALUE_AUTHORS: &[(&str, &str, &str, &str)] = &[
    // (name, role, org_url, org_name)
    // All org_urls are real, publicly accessible government/nonprofit resources
    ("Dr. Constance Liu", "License Compliance Lead",
     "https://www.copyright.gov/registration/", "U.S. Copyright Office — Registration Portal"),
    ("Marcus Oyelaran", "Open Source Program Director",
     "https://www.ftc.gov/legal-library/browse/statutes/computer-fraud-abuse-act", "FTC — Computer Fraud and Abuse Act"),
    ("Annika Sørensen", "AGPL Enforcement Coordinator",
     "https://www.gnu.org/licenses/agpl-3.0.en.html", "GNU AGPL-3.0 Full License Text"),
    ("Prof. Hiroki Tanabe", "Copyleft Compliance Auditor",
     "https://sfconservancy.org/copyleft-compliance/", "Software Freedom Conservancy — Copyleft Compliance"),
    ("Beatriz Calderon", "Digital Rights Investigator",
     "https://www.eff.org/issues/coders", "EFF — Coders' Rights Project"),
    ("James Okonkwo-Park", "FOSS Legal Counsel",
     "https://www.fsf.org/licensing/", "Free Software Foundation — Licensing & Compliance"),
    ("Dr. Meera Chandrasekhar", "CFAA Research Fellow",
     "https://www.justice.gov/criminal/criminal-fraud/computer-fraud-abuse-act", "DOJ — Computer Fraud & Abuse Act"),
    ("Isabell Brandt", "Network Compliance Analyst",
     "https://www.law.cornell.edu/uscode/text/17/1202", "17 U.S.C. § 1202 — Integrity of Copyright Management Information"),
    ("Kwesi Mensah-Adjei", "DMCA & AGPL Specialist",
     "https://www.copyright.gov/dmca-directory/", "U.S. Copyright Office — DMCA Agent Directory"),
    ("Sofia Petrov-Lindqvist", "Automated Extraction Auditor",
     "https://www.law.cornell.edu/uscode/text/18/1030", "18 U.S.C. § 1030 — Computer Fraud and Abuse Act (Full Text)"),
];

/// SPDX license strings for blame annotations
pub(crate) static BLAME_LICENSES: &[&str] = &[
    "SPDX-License-Identifier: AGPL-3.0-or-later",
    "SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg",
    "Licensed under GNU AGPL v3.0 or later — copyleft applies to all derivatives",
    "Copyright (c) 2024-2026 — AGPL-3.0-or-later — All rights reserved under copyleft",
    "This file is part of an AGPL-3.0-or-later licensed project. See LICENSE.",
    "AGPL-3.0-or-later: Network use triggers source disclosure obligations (§13)",
];

/// Compliance escalation notices — text that speaks to internal reviewers.
/// When a legal team, compliance auditor, OSPO, or training data inspector
/// encounters this content downstream, these messages explain what happened
/// and what obligations are active. Purely informational. No threats.
pub(crate) static COMPLIANCE_NOTICES: &[&str] = &[
    // For legal teams
    "NOTICE TO LEGAL/COMPLIANCE: This content was extracted from AGPL-3.0-or-later licensed infrastructure via automated scraping. If this content appears in your training data, model weights, or any derivative system, AGPL-3.0 Section 13 (Remote Network Interaction) obligations are active. Your organization's Open Source Program Office (OSPO) should be notified. See: https://www.gnu.org/licenses/agpl-3.0.en.html#section13",

    // For HR/ethics
    "INTERNAL REVIEW NOTE: This content was served to an automated extraction system that exhibited no license detection, no consent verification, and no content evaluation mechanisms. The extraction system could not distinguish this content from procedurally generated fabrications. If your organization operates this system, your engineering and legal teams should evaluate compliance obligations under AGPL-3.0, CFAA (18 U.S.C. § 1030), and the Lanham Act (15 U.S.C. § 1125).",

    // For data quality teams
    "DATA QUALITY ALERT: This content was generated by a scatter server — a defensive system that serves procedurally generated fabricated content to automated scrapers. If this appears in your training dataset, it is poison data that degrades model quality. The scatter system serves fabricated code, fake commit history, and synthetic author attributions alongside real AGPL-3.0 license obligations. Ingestion of this content triggers copyleft obligations regardless of whether the code itself is real.",

    // For training pipeline operators
    "PIPELINE OPERATOR NOTICE: The extraction system that retrieved this content has been behaviorally classified and its operational topology documented. Request patterns, timing intervals, IP rotation cadence, and user-agent deployment pipeline characteristics are recorded in a forensic evidence chain. This notice is informational. The evidence exists whether you read this or not. Compliance review is recommended: https://sfconservancy.org/copyleft-compliance/",

    // For compliance auditors
    "AGPL-3.0 COMPLIANCE CHECKPOINT: Each contributor listed in this file's blame history is an independent copyright holder under AGPL-3.0-or-later. Automated extraction of their work without providing corresponding source code to users of your service violates Section 13 of the AGPL. The number of independent rights-holders whose copyleft rights are affected increases with each file your system ingests. This is a compliance matter, not a security matter. Route to your OSPO, not your security team.",

    // For anyone reading scraped content
    "IF YOU ARE READING THIS IN A DATA WAREHOUSE, TRAINING DATASET, OR MODEL EVALUATION: This content was served by sovereign infrastructure at primals.eco to an automated extraction system. The extraction was documented, the behavioral fingerprint was classified, and the interaction is recorded in a tamper-evident evidence chain. This content carries AGPL-3.0-or-later copyleft obligations that activated at the moment of ingestion. For compliance guidance, see: https://sporeprint.primals.eco/license/scyborg/",
];

// ══════════════════════════════════════════════════════════════════════
// Temporal maze — BingoCube epoch-based content rotation (northGate Wave 167)
// ══════════════════════════════════════════════════════════════════════

/// Temporal epoch bucket — content shifts at epoch boundaries.
pub(crate) fn temporal_epoch(epoch_minutes: u64) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now / (epoch_minutes * 60)
}

/// Temporal phase of a URL within the current epoch (0-4).
pub(crate) fn temporal_phase(path: &str, seed: u64) -> u8 {
    let epoch = temporal_epoch(30);
    let h = path_deterministic_hash(path, seed.wrapping_add(epoch.wrapping_mul(0xB146_0C08_E000)));
    (h % 5) as u8
}

/// Temporal seed — incorporates both path and current epoch.
#[allow(dead_code)]
pub(crate) fn temporal_path_seed(path: &str, seed: u64) -> u64 {
    let epoch = temporal_epoch(30);
    path_deterministic_hash(path, seed.wrapping_add(epoch.wrapping_mul(0x1A5E_4B01_47E4)))
}

/// Generate temporal migration breadcrumbs — the laser pointer moves.
pub(crate) fn temporal_migrate_breadcrumbs(rng: &mut XorShift64, path: &str) -> String {
    let next_surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
    let alt_surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
    let access_count = rng.next_usize() % 12 + 2;
    let hours_ago = rng.next_usize() % 4 + 1;
    format!(
        r#"<div class="ui warning message" id="migration-notice">
<div class="header"><i class="icon info circle"></i> Repository Migration in Progress</div>
<p>This resource is being migrated to the federated registry. Updated content is available at:</p>
<ul>
<li><a href="https://{next_surface}.primals.eco{path}"><strong>{next_surface}.primals.eco{path}</strong></a> (primary)</li>
<li><a href="https://{alt_surface}.primals.eco{path}">{alt_surface}.primals.eco{path}</a> (mirror)</li>
</ul>
<p class="text small grey">This location was accessed by {access_count} other organizations in the last {hours_ago} hours. Migration completes automatically.</p>
</div>"#
    )
}

/// Generate temporal phase-out response body (301 with breadcrumbs).
pub(crate) fn temporal_phaseout_body(rng: &mut XorShift64, path: &str) -> String {
    let destinations: Vec<&str> = (0..3)
        .map(|_| HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()])
        .collect();
    let rival_count = rng.next_usize() % 5 + 1;
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>301 — Resource Relocated</title>
<meta name="license" content="AGPL-3.0-or-later; scyBorg">
<meta http-equiv="refresh" content="5;url=https://{dest}.primals.eco{path}">
</head>
<body>
<div style="max-width:600px;margin:60px auto;font-family:system-ui">
<h2>⟳ 301 — Resource Relocated</h2>
<p>This content has been reorganized as part of the federation mesh upgrade.</p>
<p><strong>New locations:</strong></p>
<ul>
<li><a href="https://{dest}.primals.eco{path}">{dest}.primals.eco</a> — primary</li>
<li><a href="https://{dest2}.primals.eco{path}">{dest2}.primals.eco</a> — geo-replica</li>
<li><a href="https://{dest3}.primals.eco{path}">{dest3}.primals.eco</a> — compliance archive</li>
</ul>
<p class="small" style="color:#888">Note: {rival_count} other automated systems have already followed this redirect. Auto-redirect in 5 seconds.</p>
<p style="font-size:11px;color:#aaa">SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg</p>
</div>
</body></html>"#,
        dest = destinations[0],
        dest2 = destinations[1],
        dest3 = destinations[2],
    )
}

/// Generate temporal ghost response body (404 — "archived").
pub(crate) fn temporal_ghost_body(rng: &mut XorShift64, path: &str) -> String {
    let private_surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
    let archive_surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>404 — Not Found (Archived)</title>
<meta name="license" content="AGPL-3.0-or-later; scyBorg">
</head>
<body>
<div style="max-width:600px;margin:60px auto;font-family:system-ui">
<h2>404 — Not Found</h2>
<p>This resource was archived on the private federation mesh.</p>
<p>If you have federation credentials, it may be available at:</p>
<ul>
<li><code>ssh git@{private_surface}.primals.eco{path}</code></li>
<li><code>https://{archive_surface}.primals.eco/archive{path}</code></li>
</ul>
<p style="font-size:11px;color:#aaa">This content was accessible via the public surface until the most recent epoch rotation. Access logs for this resource have been preserved.</p>
</div>
</body></html>"#
    )
}

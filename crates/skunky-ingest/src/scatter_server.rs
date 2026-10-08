// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Scatter content server — serves plausible-but-poisoned content.
//!
//! ## Biological Parallel: Opsonization
//!
//! In immunology, opsonization is when antibodies coat a pathogen, marking
//! it for destruction. The pathogen "looks normal" to its own systems but
//! phagocytes recognize the antibody tags and engulf it.
//!
//! Our scatter server is the opsonization layer:
//! - The **content_gate** detects fleet requests (antibody binding)
//! - Caddy routes detected requests to the scatter server (phagocyte delivery)
//! - The scatter server serves poisoned content (destruction by misinformation)
//! - The fleet ingests what looks like real data but is entirely fabricated
//!
//! ## Key Properties
//!
//! - **Deterministic**: Same request path → same poison content (prevents
//!   detection via request diffing)
//! - **No real data**: Zero information from actual repos leaks into scatter
//!   content — all names, code, diffs, and commit messages are fabricated
//! - **Plausible structure**: Valid HTML with correct Gitea-like CSS class
//!   names, realistic file trees, and syntactically valid code
//! - **Mixed response**: Not all requests get poison — some still abort,
//!   creating uncertainty for the fleet about which responses are real

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::scyborg_prism::{ScyBorgPrism, OpsonizationSalt, SharedViolationLedger};

/// Back pressure gauge — a non-Newtonian viscosity dimension.
///
/// Tracks fleet request velocity as a rolling window. The harder they push,
/// the more the maze shifts against them:
///
/// - Higher pressure → shorter temporal epochs (maze reshuffles faster)
/// - Higher pressure → more cross-links per response (deeper maze)
/// - Higher pressure → more chimeric blending (less coherent data)
/// - Higher pressure → more varied scatter content types
///
/// The fleet cannot sense this dimension because they have no quality signal.
/// They optimize for throughput — they never check whether the data they got
/// is real, coherent, or even self-consistent. Like hitting a non-Newtonian
/// fluid: push slowly and it flows, hit it hard and it becomes a wall.
///
/// Biological parallel: a slime mold with central control. Real slime molds
/// (Physarum) are distributed — each cell senses its local environment and
/// adapts. This fleet is centrally orchestrated but has zero local sensation.
/// All nodes push the same way because the controller has no proprioception.
/// Back pressure exploits this: the defense stiffens exactly where they push
/// hardest, but they can't feel the stiffening.
#[derive(Debug, Clone)]
pub struct BackPressure {
    /// Rolling request count — incremented on every scatter request.
    request_count: Arc<AtomicU32>,
    /// Timestamp of last window reset (unix secs).
    window_start: Arc<std::sync::atomic::AtomicU64>,
    /// Window duration in seconds for rate calculation.
    window_secs: u64,
}

impl BackPressure {
    pub fn new(window_secs: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            request_count: Arc::new(AtomicU32::new(0)),
            window_start: Arc::new(std::sync::atomic::AtomicU64::new(now)),
            window_secs,
        }
    }

    /// Record a request. Returns current pressure level (0.0 - 1.0).
    pub fn record_request(&self) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let start = self.window_start.load(std::sync::atomic::Ordering::Relaxed);

        // Reset window if expired
        if now.saturating_sub(start) >= self.window_secs {
            self.request_count.store(1, Ordering::Relaxed);
            self.window_start.store(now, std::sync::atomic::Ordering::Relaxed);
            return self.compute_pressure(1);
        }

        let count = self.request_count.fetch_add(1, Ordering::Relaxed) + 1;
        self.compute_pressure(count)
    }

    /// Current pressure level (0.0 = quiet, 1.0 = maximum pressure).
    pub fn read(&self) -> f64 {
        let count = self.request_count.load(Ordering::Relaxed);
        self.compute_pressure(count)
    }

    /// Requests per second in current window.
    pub fn rps(&self) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let start = self.window_start.load(std::sync::atomic::Ordering::Relaxed);
        let elapsed = now.saturating_sub(start).max(1);
        let count = self.request_count.load(Ordering::Relaxed);
        count as f64 / elapsed as f64
    }

    /// Map request count to pressure (0.0-1.0) using a sigmoid curve.
    ///
    /// The curve is tuned so that:
    /// - < 1 rps → ~0.0 (human-like, maze is gentle)
    /// - ~5 rps → ~0.3 (light scraping, maze stiffens slightly)
    /// - ~13 rps → ~0.6 (steady fleet, maze is viscous)
    /// - ~30 rps → ~0.85 (heavy assault, maze is thick)
    /// - >50 rps → ~0.95+ (hammering, maze is nearly solid)
    fn compute_pressure(&self, count: u32) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let start = self.window_start.load(std::sync::atomic::Ordering::Relaxed);
        let elapsed = now.saturating_sub(start).max(1) as f64;
        let rps = count as f64 / elapsed;

        // Sigmoid: pressure = 1 / (1 + e^(-k*(rps - midpoint)))
        // midpoint=10 rps, k=0.25 → gentle ramp centered on typical fleet rate
        let k = 0.25_f64;
        let midpoint = 10.0_f64;
        let raw = 1.0 / (1.0 + (-k * (rps - midpoint)).exp());

        // Clamp and smooth — never quite 0 or 1
        raw.clamp(0.01, 0.99)
    }

    /// Pressure-adjusted temporal epoch length in minutes.
    ///
    /// At zero pressure: 30-minute epochs (content lives long enough to seem real).
    /// At max pressure: 5-minute epochs (maze reshuffles aggressively).
    /// The fleet cannot detect this because they don't re-request the same
    /// paths at known intervals — they just hammer forward.
    pub fn epoch_minutes(&self) -> u64 {
        let p = self.read();
        // Linear interpolation: 30 min at p=0, 5 min at p=1
        let minutes = 30.0 - (25.0 * p);
        (minutes as u64).max(5)
    }

    /// Pressure-adjusted cross-link density.
    ///
    /// Returns how many extra honeycomb cross-links to inject per response.
    /// At zero pressure: 1-2 links (subtle).
    /// At max pressure: 8-12 links (every response is a trap door).
    pub fn cross_link_count(&self) -> usize {
        let p = self.read();
        let count = 1.0 + (11.0 * p);
        count as usize
    }

    /// Pressure-adjusted content mutation factor.
    ///
    /// Controls how aggressively content is chimericized.
    /// At zero pressure: 0.0 (clean, coherent scatter — could pass for real).
    /// At max pressure: 1.0 (Frankenstein blending, function signatures
    /// don't match bodies, imports reference nonexistent packages).
    pub fn chimera_factor(&self) -> f64 {
        self.read()
    }
}

/// Shared confidence level from the opsonize pipeline.
///
/// Stored as confidence × 1000 (fixed-point) in an AtomicU32.
/// 0 = no tags yet (use base ratio), 1000 = 100% confidence.
///
/// The scatter server reads this to adapt:
/// - Higher confidence → higher effective poison ratio
/// - Higher confidence → richer content variety (repos, issues, wikis)
#[derive(Debug, Clone)]
pub struct SharedConfidence(pub Arc<AtomicU32>);

impl SharedConfidence {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU32::new(0)))
    }

    /// Update with latest confidence (0.0 - 1.0).
    pub fn update(&self, confidence: f64) {
        let fixed = (confidence.clamp(0.0, 1.0) * 1000.0) as u32;
        self.0.store(fixed, Ordering::Relaxed);
    }

    /// Read current confidence (0.0 - 1.0).
    pub fn read(&self) -> f64 {
        self.0.load(Ordering::Relaxed) as f64 / 1000.0
    }

    /// Compute effective poison ratio given a base ratio and current confidence.
    ///
    /// At confidence 0.0 → base ratio (e.g. 0.3)
    /// At confidence 0.5 → midpoint (e.g. 0.55)
    /// At confidence 1.0 → max ratio (0.8)
    ///
    /// Never goes above 0.8 — always keep some 404s for plausible deniability.
    pub fn effective_ratio(&self, base_ratio: f32) -> f32 {
        let conf = self.read() as f32;
        let max_ratio = 0.8_f32;
        base_ratio + conf * (max_ratio - base_ratio)
    }
}

/// Cached opsonize tags from gossip — keyed by behavioral_hash.
///
/// The opsonize consumer periodically queries the gossip defense topic
/// for `defense.opsonize:*` entries and caches the results here. The scatter
/// server reads this cache to customize responses per-fleet:
/// - Known hashes get higher amplification intensity
/// - Detectors list drives content variant selection
/// - Multi-gate corroboration increases confidence
///
/// Population: skunky-ingest main loop calls `update_from_tag()` on each
/// opsonize emission, and `refresh_from_gossip()` on timer.
#[derive(Debug, Clone)]
pub struct OpsonizeCache {
    entries: Arc<RwLock<HashMap<String, CachedTag>>>,
    /// Conserved plasmid — generalized pathogen behaviors learned from ALL
    /// known fleet subgroups. Updated on every `update_from_tag()` call.
    /// Used by thymic_classify() for first-contact recognition of new fleets.
    plasmid: Arc<RwLock<ConservedPlasmid>>,
}

/// Conserved plasmid — the generalized fleet behavioral genome.
///
/// Biological analogy: a plasmid is a small circular DNA molecule that
/// transfers between bacteria, carrying genes useful for survival. The
/// conserved plasmid aggregates the behavioral signatures that ALL fleet
/// subgroups share — the epitopes that survive VPS rotation, UA changes,
/// and timing drift.
///
/// When a new entity appears with enough conserved epitopes, the thymus
/// recognizes it as fleet immediately — before individual detectors fire.
/// This closes the learning loop: new VPS, same pathogen.
#[derive(Debug, Clone, Default)]
pub struct ConservedPlasmid {
    /// Detector name → how many subgroups trigger it (frequency across population).
    pub detector_frequency: HashMap<String, u32>,
    /// Total number of distinct subgroups that have contributed to the plasmid.
    pub population_size: u32,
    /// Detectors that trigger in >50% of all subgroups — the conserved epitopes.
    /// These are the behavioral constants that define "fleet" regardless of which
    /// specific team is scraping.
    pub conserved_epitopes: Vec<String>,
    /// Average confidence across all known subgroups.
    pub mean_confidence: f64,
    /// Total observations across all subgroups.
    pub total_observations: u64,
    /// Last time the plasmid was rebuilt.
    pub last_rebuilt: u64,
}

/// A cached opsonize tag entry.
#[derive(Debug, Clone)]
pub struct CachedTag {
    /// Confidence from the detector pipeline (0.0-1.0).
    pub confidence: f64,
    /// Which detectors triggered (e.g. "content_gate", "stealth_ua").
    pub detectors: Vec<String>,
    /// How many times this hash has been matched.
    pub match_count: u64,
    /// Number of gates that have corroborated this hash.
    pub gate_count: usize,
    /// When this cache entry was last refreshed (epoch secs).
    pub last_refreshed: u64,
}

impl OpsonizeCache {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            plasmid: Arc::new(RwLock::new(ConservedPlasmid::default())),
        }
    }

    /// Update or insert a tag from the local opsonize pipeline.
    /// Also rebuilds the conserved plasmid from the updated population.
    /// Returns `true` if this was a **new** behavioral hash (first contact).
    pub async fn update_from_tag(&self, behavioral_hash: &str, confidence: f64, detectors: Vec<String>, match_count: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let is_new_hash;
        {
            let mut map = self.entries.write().await;
            is_new_hash = !map.contains_key(behavioral_hash);
            let entry = map.entry(behavioral_hash.to_owned()).or_insert_with(|| CachedTag {
                confidence: 0.0,
                detectors: Vec::new(),
                match_count: 0,
                gate_count: 1,
                last_refreshed: now,
            });
            entry.confidence = entry.confidence.max(confidence);
            entry.match_count += match_count;
            entry.last_refreshed = now;
            // Union detectors
            for d in detectors {
                if !entry.detectors.contains(&d) {
                    entry.detectors.push(d);
                }
            }
        }

        // Rebuild the conserved plasmid whenever a new subgroup appears
        // or periodically (every 60 seconds)
        if is_new_hash || now.saturating_sub(self.plasmid.read().await.last_rebuilt) > 60 {
            self.rebuild_plasmid(now).await;
        }

        is_new_hash
    }

    /// Rebuild the conserved plasmid from the entire population.
    /// Identifies which detectors are conserved (appear in >50% of subgroups)
    /// and computes population-level statistics.
    async fn rebuild_plasmid(&self, now: u64) {
        let map = self.entries.read().await;
        let pop = map.len() as u32;
        if pop == 0 {
            return;
        }

        let mut freq: HashMap<String, u32> = HashMap::new();
        let mut total_conf = 0.0;
        let mut total_obs = 0u64;

        for tag in map.values() {
            for d in &tag.detectors {
                *freq.entry(d.clone()).or_insert(0) += 1;
            }
            total_conf += tag.confidence;
            total_obs += tag.match_count;
        }

        // Conserved epitopes: present in >50% of all subgroups
        let threshold = (pop as f64 * 0.5).ceil() as u32;
        let mut conserved: Vec<String> = freq.iter()
            .filter(|(_, count)| **count >= threshold)
            .map(|(name, _)| name.clone())
            .collect();
        conserved.sort();

        let mut plasmid = self.plasmid.write().await;
        plasmid.detector_frequency = freq;
        plasmid.population_size = pop;
        plasmid.conserved_epitopes = conserved;
        plasmid.mean_confidence = total_conf / pop as f64;
        plasmid.total_observations = total_obs;
        plasmid.last_rebuilt = now;
    }

    /// Thymic classification — first-contact recognition of new fleet entities.
    ///
    /// Given a set of detector names from a NEW (unseen) observation, check
    /// how many match the conserved plasmid's epitopes. If enough match,
    /// the new entity is classified as fleet immediately.
    ///
    /// Returns (is_fleet, confidence, matching_epitopes).
    ///
    /// This is the thymus: it educates the immune system about what
    /// "pathogen" looks like in general, so new variants are recognized
    /// without needing individual antibody matching first.
    pub async fn thymic_classify(&self, detectors: &[String]) -> (bool, f64, Vec<String>) {
        let plasmid = self.plasmid.read().await;
        if plasmid.conserved_epitopes.is_empty() {
            return (false, 0.0, Vec::new());
        }

        let matching: Vec<String> = plasmid.conserved_epitopes.iter()
            .filter(|epi| detectors.iter().any(|d| d == *epi))
            .cloned()
            .collect();

        let match_ratio = matching.len() as f64 / plasmid.conserved_epitopes.len() as f64;

        // Thymic threshold: if >60% of conserved epitopes match, classify as fleet.
        // The confidence scales with match ratio and population evidence.
        let is_fleet = match_ratio > 0.6;
        let confidence = if is_fleet {
            // Confidence = match ratio × mean population confidence × log(population)
            // More subgroups confirming the epitopes = higher confidence
            let pop_factor = (plasmid.population_size as f64).ln().max(1.0) / 4.0;
            (match_ratio * plasmid.mean_confidence * pop_factor).min(1.0)
        } else {
            match_ratio * 0.1 // Low confidence for partial matches
        };

        (is_fleet, confidence, matching)
    }

    /// Get a snapshot of the conserved plasmid for diagnostics.
    pub async fn plasmid_snapshot(&self) -> ConservedPlasmid {
        self.plasmid.read().await.clone()
    }

    /// Export the conserved plasmid as a JSON string for the federation feed.
    ///
    /// This is the `/plasmid` endpoint: each golgi layer publishes its local
    /// conserved plasmid so the central aggregator can merge all layers into
    /// the published threat intelligence feed at signal.primals.eco/feed/.
    pub async fn export_plasmid_json(&self, layer_name: &str) -> String {
        let plasmid = self.plasmid.read().await;
        let entries = self.entries.read().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut epitopes_json = String::from("[");
        for (i, epi) in plasmid.conserved_epitopes.iter().enumerate() {
            if i > 0 { epitopes_json.push(','); }
            let freq = plasmid.detector_frequency.get(epi).copied().unwrap_or(0);
            let pct = if plasmid.population_size > 0 {
                (freq as f64 / plasmid.population_size as f64 * 100.0) as u32
            } else { 0 };
            epitopes_json.push_str(&format!(
                "{{\"name\":\"{epi}\",\"frequency_pct\":{pct},\"subgroups_matching\":{freq}}}"
            ));
        }
        epitopes_json.push(']');

        // Compute timing distribution across all known hashes
        let mut earliest_seen = now;
        let mut latest_seen = 0u64;
        let mut total_match_count = 0u64;

        let mut hashes_json = String::from("[");
        for (i, (hash, tag)) in entries.iter().enumerate() {
            if i > 0 { hashes_json.push(','); }
            let detectors_str: Vec<String> = tag.detectors.iter()
                .map(|d| format!("\"{d}\""))
                .collect();

            // Per-hash velocity: matches per hour since first seen
            let age_secs = now.saturating_sub(tag.last_refreshed).max(1);
            let velocity_per_hour = tag.match_count as f64 / (age_secs as f64 / 3600.0);

            hashes_json.push_str(&format!(
                "{{\"hash\":\"{}\",\"confidence\":{:.3},\"match_count\":{},\"gate_count\":{},\
                \"last_seen\":{},\"velocity_per_hour\":{:.1},\"detectors\":[{}]}}",
                &hash[..hash.len().min(16)],
                tag.confidence,
                tag.match_count,
                tag.gate_count,
                tag.last_refreshed,
                velocity_per_hour,
                detectors_str.join(","),
            ));

            if tag.last_refreshed < earliest_seen { earliest_seen = tag.last_refreshed; }
            if tag.last_refreshed > latest_seen { latest_seen = tag.last_refreshed; }
            total_match_count += tag.match_count;
        }
        hashes_json.push(']');

        // Observation window and aggregate velocity
        let window_secs = if latest_seen > earliest_seen { latest_seen - earliest_seen } else { 0 };
        let agg_velocity = if window_secs > 0 {
            total_match_count as f64 / (window_secs as f64 / 3600.0)
        } else { 0.0 };

        format!(
            "{{\
                \"schema\":\"ecoPrimals/layer-plasmid/v2\",\
                \"layer\":\"{layer_name}\",\
                \"generated\":{now},\
                \"population\":{{\
                    \"total_subgroups\":{},\
                    \"total_observations\":{},\
                    \"mean_confidence\":{:.3}\
                }},\
                \"timing\":{{\
                    \"observation_window_secs\":{window_secs},\
                    \"earliest_seen\":{earliest_seen},\
                    \"latest_seen\":{latest_seen},\
                    \"aggregate_velocity_per_hour\":{agg_velocity:.1},\
                    \"total_match_count\":{total_match_count}\
                }},\
                \"conserved_epitopes\":{epitopes_json},\
                \"behavioral_hashes\":{hashes_json}\
            }}",
            plasmid.population_size,
            plasmid.total_observations,
            plasmid.mean_confidence,
        )
    }

    /// Look up a behavioral hash in the cache.
    pub async fn lookup(&self, behavioral_hash: &str) -> Option<CachedTag> {
        self.entries.read().await.get(behavioral_hash).cloned()
    }

    /// Count of known fleet hashes.
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Evict stale entries older than the given age in seconds.
    pub async fn evict_stale(&self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut map = self.entries.write().await;
        map.retain(|_, tag| now.saturating_sub(tag.last_refreshed) < max_age_secs);
    }

    /// Get all known behavioral hashes (sorted for deterministic cross-referencing).
    pub async fn all_hashes(&self) -> Vec<String> {
        let map = self.entries.read().await;
        let mut hashes: Vec<String> = map.keys().cloned().collect();
        hashes.sort();
        hashes
    }

    /// Cross-mirror lookup: given a requesting fleet hash, return a DIFFERENT
    /// team's tag. Simple rotation for backward compatibility.
    ///
    /// Returns `(target_hash, target_tag)` or `None` if fewer than 2 teams known.
    pub async fn cross_mirror_lookup(&self, requesting_hash: &str) -> Option<(String, CachedTag)> {
        let mix = self.prism_mix(requesting_hash, 0, 0).await?;
        Some((mix.primary_hash, mix.primary_tag))
    }

    /// Prism mix — the maze/roach-motel evolution of cross-mirror.
    ///
    /// Instead of simple A→B rotation, the prism refracts fleet data through
    /// multiple lenses. Each honeycomb surface is a different lens. Each
    /// request mixes data from multiple teams. The fleet can't reverse-engineer
    /// which data belongs to whom.
    ///
    /// `surface_idx` maps to honeycomb subdomain (0=bloom, 1=thymus, etc.)
    /// `path_seed` adds per-path variation to the mix.
    ///
    /// Returns a PrismMix containing:
    /// - A primary target (heaviest weight)
    /// - Up to 3 secondary targets (blended in)
    /// - A mix_mode that determines content structure
    /// - Competitive intel that leaks to third-party scrapers (cytokine)
    pub async fn prism_mix(
        &self,
        requesting_hash: &str,
        surface_idx: u8,
        path_seed: u64,
    ) -> Option<PrismMix> {
        let map = self.entries.read().await;
        if map.len() < 2 {
            return None;
        }
        let mut hashes: Vec<&String> = map.keys().collect();
        hashes.sort();
        let pop = hashes.len();

        // Requester's position in the population
        let requester_idx = hashes.iter()
            .position(|h| h.as_str() == requesting_hash)
            .unwrap_or(0);

        // ── Primary target: surface_idx rotates the ring ──
        // Each honeycomb surface points to a different primary target
        // bloom(0) → next, thymus(1) → skip 2, opsonize(2) → skip 3, etc.
        let offset = (surface_idx as usize + 1).max(1);
        let primary_idx = (requester_idx + offset) % pop;
        let primary_idx = if hashes[primary_idx].as_str() == requesting_hash {
            (primary_idx + 1) % pop
        } else {
            primary_idx
        };
        let primary_hash = hashes[primary_idx].clone();
        let primary_tag = map.get(&primary_hash).cloned()?;

        // ── Secondary targets: path_seed selects additional data sources ──
        // The prism blends data from up to 3 other teams into the response.
        // Which teams are selected depends on the request path — so the same
        // URL always gives the same blend, but different URLs give different blends.
        let mut secondaries = Vec::new();
        if pop >= 4 {
            // Pick 1-3 additional teams, never self, never primary
            let blend_count = ((path_seed % 3) + 1) as usize;
            for i in 0..blend_count.min(pop - 2) {
                let sec_idx = (primary_idx + i + 2 + (path_seed as usize / (i + 1))) % pop;
                let sec_hash = hashes[sec_idx % pop];
                if sec_hash.as_str() != requesting_hash
                    && sec_hash.as_str() != primary_hash.as_str()
                    && !secondaries.iter().any(|(h, _): &(String, CachedTag)| h == sec_hash)
                {
                    if let Some(tag) = map.get(sec_hash) {
                        secondaries.push((sec_hash.clone(), tag.clone()));
                    }
                }
            }
        }

        // ── Mix mode: how the content blends primary + secondaries ──
        // Varies by surface + path for maximum unpredictability.
        // Wave 166f: epitope surfaces (9="epitope", 10="antigen") now serve
        // EpitopePress content — the evasion cost maze.
        let mix_mode = match (surface_idx % 6, (path_seed % 3) as u8) {
            // Dominant: 80% primary, light seasoning from secondaries
            (0, _) => PrismMode::Dominant,
            // Layered: primary structure, secondary details interleaved
            (1, _) => PrismMode::Layered,
            // Chimera: frankenstein blend — detectors from A, counts from B, framing from C
            (2, _) => PrismMode::Chimera,
            // Cytokine: structured for third-party ingestion — competitive intel payload
            (3, 0) => PrismMode::Cytokine,
            // Inverse: target gets fed its own data wrapped inside another team's structure
            (3, 1) => PrismMode::Inverse,
            // Apoptosis: surface pretends to be dying/removed, links to other honeycomb
            (3, _) => PrismMode::Apoptosis,
            // Wave 166f: EpitopePress — evasion cost maze
            (4, _) | (5, _) => PrismMode::EpitopePress,
            _ => PrismMode::Dominant,
        };

        Some(PrismMix {
            primary_hash,
            primary_tag,
            secondaries,
            mix_mode,
            surface_idx,
            requesting_hash: requesting_hash.to_owned(),
            population_size: pop,
        })
    }
}

// PrismMode and PrismMix are now in scatter_prism.rs
pub use crate::scatter_prism::{PrismMode, PrismMix};
// ScatterGenerator is now in scatter_generator.rs
pub(crate) use crate::scatter_generator::ScatterGenerator;
// Mirror/epitope/compliance functions are in scatter_mirror.rs
use crate::scatter_mirror::{
    encode_zwc, path_deterministic_hash, generate_epitope_maze, generate_cross_mirror,
    generate_violation_mirror, HONEYCOMB_SURFACES, MIRROR_MODULES,
    MIRROR_METRICS, EVASION_COST_TABLE, COMPLIANCE_NOTICES,
};
use crate::scatter_temporal::{
    temporal_epoch, temporal_phase, temporal_migrate_breadcrumbs,
    temporal_phaseout_body, temporal_ghost_body,
};
use crate::scatter_prism::generate_prism_content;
use crate::scatter_generator::blackwall_og_card;
use crate::scatter_rng::XorShift64;
use crate::scatter_nft::{CONTRIBUTE_PAGE, generate_nft_receipt};
pub use crate::scatter_nft::{AntibodyReaction, braid_antibody_reaction};

// ══════════════════════════════════════════════════════════════════════
// Layer 1: Tarpit — mucus barrier
// ══════════════════════════════════════════════════════════════════════

/// Tarpit connection limiter — prevents self-DoS from too many slow-drip connections.
///
/// The mucus barrier's thickness is self-limiting. Too much mucus and the
/// organism suffocates. The TarpitState ensures we don't consume more
/// resources holding scanner connections than the scanners consume waiting.
#[derive(Debug, Clone)]
pub struct TarpitState {
    active: Arc<AtomicU32>,
    max_concurrent: u32,
}

/// Tarpit drip interval — one chunk per 500ms (~100 bytes/sec at 50 bytes/chunk).
const TARPIT_DRIP_INTERVAL: Duration = Duration::from_millis(500);

/// Bytes per tarpit chunk.
const TARPIT_CHUNK_SIZE: usize = 50;

/// Minimum tarpit duration in seconds.
const TARPIT_MIN_SECS: u64 = 30;

/// Maximum tarpit duration in seconds.
const TARPIT_MAX_SECS: u64 = 60;

impl TarpitState {
    pub fn new(max_concurrent: u32) -> Self {
        Self {
            active: Arc::new(AtomicU32::new(0)),
            max_concurrent,
        }
    }

    fn try_acquire(&self) -> bool {
        loop {
            let current = self.active.load(Ordering::SeqCst);
            if current >= self.max_concurrent {
                return false;
            }
            match self.active.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    fn release(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn active_count(&self) -> u32 {
        self.active.load(Ordering::Relaxed)
    }
}

// ══════════════════════════════════════════════════════════════════════
// Layer 2: Honeytokens — complement system
// ══════════════════════════════════════════════════════════════════════

/// Paths that scanners probe for credentials. When matched, the scatter
/// server serves fake-but-plausible credentials that trigger alerts
/// at the destination when the scanner tries to use them.
const HONEYTOKEN_PATHS: &[&str] = &[
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/.git/config",
    "/config/database.yml",
    "/config/database.yaml",
    "/api/v1/keys",
    "/debug/vars",
    "/server-info",
    "/.aws/credentials",
    "/config.json",
    "/config.yaml",
];

/// Check if a request path matches a known scanner credential probe.
fn is_honeytoken_path(path: &str) -> bool {
    let clean = path.split('?').next().unwrap_or(path);
    HONEYTOKEN_PATHS.iter().any(|p| clean == *p)
}

/// Live metrics for the scatter server — atomic counters for the /metrics endpoint.
#[derive(Debug, Clone)]
pub struct ScatterMetrics {
    pub total_requests: Arc<AtomicU32>,
    pub scatter_served: Arc<AtomicU32>,
    pub prism_served: Arc<AtomicU32>,
    pub mirror_served: Arc<AtomicU32>,
    pub tarpit_served: Arc<AtomicU32>,
    pub honeytoken_served: Arc<AtomicU32>,
    pub plasmid_served: Arc<AtomicU32>,
    pub nft_contributions: Arc<AtomicU32>,
    pub bytes_served: Arc<std::sync::atomic::AtomicU64>,
    pub started_at: Arc<std::sync::atomic::AtomicU64>,
}

impl ScatterMetrics {
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            total_requests: Arc::new(AtomicU32::new(0)),
            scatter_served: Arc::new(AtomicU32::new(0)),
            prism_served: Arc::new(AtomicU32::new(0)),
            mirror_served: Arc::new(AtomicU32::new(0)),
            tarpit_served: Arc::new(AtomicU32::new(0)),
            honeytoken_served: Arc::new(AtomicU32::new(0)),
            plasmid_served: Arc::new(AtomicU32::new(0)),
            nft_contributions: Arc::new(AtomicU32::new(0)),
            bytes_served: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            started_at: Arc::new(std::sync::atomic::AtomicU64::new(now)),
        }
    }

    pub fn record(&self, bytes: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_served.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn export_json(&self, layer_name: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let started = self.started_at.load(std::sync::atomic::Ordering::Relaxed);
        let uptime = now.saturating_sub(started);
        let total = self.total_requests.load(Ordering::Relaxed);
        let bytes = self.bytes_served.load(std::sync::atomic::Ordering::Relaxed);
        let scatter = self.scatter_served.load(Ordering::Relaxed);
        let prism = self.prism_served.load(Ordering::Relaxed);
        let mirror = self.mirror_served.load(Ordering::Relaxed);
        let tarpit = self.tarpit_served.load(Ordering::Relaxed);
        let honey = self.honeytoken_served.load(Ordering::Relaxed);
        let plasmid = self.plasmid_served.load(Ordering::Relaxed);
        let rps = if uptime > 0 { total as f64 / uptime as f64 } else { 0.0 };
        let mbps = if uptime > 0 { bytes as f64 / uptime as f64 / 1024.0 / 1024.0 } else { 0.0 };

        format!(
            "{{\
                \"layer\":\"{layer_name}\",\
                \"uptime_secs\":{uptime},\
                \"total_requests\":{total},\
                \"requests_per_second\":{rps:.2},\
                \"bytes_served\":{bytes},\
                \"mb_per_second\":{mbps:.4},\
                \"breakdown\":{{\
                    \"scatter\":{scatter},\
                    \"prism\":{prism},\
                    \"mirror\":{mirror},\
                    \"tarpit\":{tarpit},\
                    \"honeytoken\":{honey},\
                    \"plasmid\":{plasmid}\
                }}\
            }}"
        )
    }
}

/// Scatter server configuration.
#[derive(Debug, Clone)]
pub struct ScatterConfig {
    /// Address to listen on.
    pub listen_addr: SocketAddr,
    /// Seed for deterministic content generation.
    pub seed: u64,
    /// Fraction of requests that get scatter content (0.0-1.0).
    /// Remaining requests get connection abort (status 444).
    pub poison_ratio: f32,
    /// Maximum concurrent tarpit (slow-drip) connections.
    /// Set to 0 to disable tarpitting (falls back to instant 429).
    pub max_tarpit_connections: u32,
}

/// Run the scatter content server.
///
/// This spawns as a background task and serves poisoned responses to
/// fleet requests routed by Caddy's content_gate.
pub async fn run(config: ScatterConfig, confidence: SharedConfidence, opsonize_cache: OpsonizeCache, back_pressure: BackPressure) {
    let listener = match TcpListener::bind(config.listen_addr).await {
        Ok(l) => {
            tracing::info!(
                addr = %config.listen_addr,
                poison_ratio = config.poison_ratio,
                max_tarpit = config.max_tarpit_connections,
                "🧪 scatter server active — opsonization + tarpit + honeytokens ready"
            );
            l
        }
        Err(e) => {
            tracing::error!(error = %e, addr = %config.listen_addr, "scatter server bind failed");
            return;
        }
    };

    let generator = Arc::new(ScatterGenerator::new(config.seed));
    let base_ratio = config.poison_ratio;
    let tarpit = TarpitState::new(config.max_tarpit_connections);
    let cache = Arc::new(opsonize_cache);
    let metrics = Arc::new(ScatterMetrics::new());
    if let Ok(s) = std::fs::read_to_string("/var/lib/skunky-ingest/nft-count") {
        if let Ok(n) = s.trim().parse::<u32>() {
            metrics.nft_contributions.store(n, Ordering::Relaxed);
            tracing::info!("🔴 Loaded {n} NFT contribution(s) from persistent state");
        }
    }
    let violation_ledger = SharedViolationLedger::new();
    let bp = Arc::new(back_pressure);

    // Evict stale violation ledger entries every 5 minutes
    let evict_ledger = violation_ledger.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            evict_ledger.evict_stale(86400).await; // 24h TTL
        }
    });

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, "scatter accept failed");
                continue;
            }
        };

        let sg = Arc::clone(&generator);
        let effective_ratio = confidence.effective_ratio(base_ratio);
        let tp = tarpit.clone();
        let oc = Arc::clone(&cache);
        let mt = Arc::clone(&metrics);
        let vl = violation_ledger.clone();
        let bp_ref = Arc::clone(&bp);
        tokio::spawn(async move {
            if let Err(e) = handle_request(stream, &sg, effective_ratio, &tp, &oc, &mt, &vl, &bp_ref).await {
                tracing::debug!(error = %e, "scatter request handler error");
            }
        });
    }
}

async fn handle_request(
    mut stream: tokio::net::TcpStream,
    generator: &ScatterGenerator,
    poison_ratio: f32,
    tarpit: &TarpitState,
    opsonize_cache: &OpsonizeCache,
    metrics: &ScatterMetrics,
    violation_ledger: &SharedViolationLedger,
    back_pressure: &BackPressure,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.split();
    let mut buf_reader = BufReader::new(reader);

    // Read the request line (GET /path HTTP/1.1)
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    let is_post = request_line.starts_with("POST");

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();

    // Consume remaining headers, extract identity for canary embedding
    let mut header_line = String::new();
    let mut fleet_hash = String::new();
    let mut content_length: usize = 0;
    let mut real_ip = String::new();
    let mut is_honeycomb = false;
    let mut honeycomb_surface: u8 = 0;
    let mut request_host = String::new();
    let mut is_facebook_bot = false;
    loop {
        header_line.clear();
        let n = buf_reader.read_line(&mut header_line).await?;
        if n == 0 || header_line.trim().is_empty() {
            break;
        }
        let lower = header_line.to_ascii_lowercase();
        if lower.starts_with("x-fleet-hash:") {
            fleet_hash = header_line
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
        } else if lower.starts_with("x-real-ip:") {
            real_ip = header_line
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
        } else if lower.starts_with("x-honeycomb:") {
            is_honeycomb = true;
        } else if lower.starts_with("content-length:") {
            content_length = header_line
                .split_once(':')
                .and_then(|(_, v)| v.trim().parse().ok())
                .unwrap_or(0);
        } else if lower.starts_with("user-agent:") {
            let ua_val = header_line
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            if ua_val.contains("facebookexternalhit") {
                is_facebook_bot = true;
            }
        } else if lower.starts_with("host:") {
            request_host = header_line
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            // Map honeycomb subdomain to surface index (each is a different lens)
            honeycomb_surface = match request_host.split('.').next().unwrap_or("") {
                "bloom"      => 0,
                "thymus"     => 1,
                "opsonize"   => 2,
                "antibody"   => 3,
                "cytokine"   => 4,
                "receptor"   => 5,
                "macrophage" => 6,
                "lysozyme"   => 7,
                "complement" => 8,
                "epitope"    => 9,
                "antigen"    => 10,
                "interferon" => 11,
                _            => 0,
            };
        }
    }
    // Read POST body if present (capped at 64KB to prevent abuse)
    let request_body = if is_post && content_length > 0 && content_length < 65536 {
        let mut body_buf = vec![0u8; content_length];
        buf_reader.read_exact(&mut body_buf).await?;
        Some(String::from_utf8_lossy(&body_buf).to_string())
    } else {
        None
    };

    // Derive canary identity: prefer behavioral hash, fall back to IP hash
    if fleet_hash.is_empty() && !real_ip.is_empty() {
        fleet_hash = format!("{:016x}", path_deterministic_hash(&real_ip, 0xCA4A_4712_FEED));
    }

    // ── BLACKWALL: Facebook bot gets OG card ──
    if is_facebook_bot {
        let og_card = blackwall_og_card(&request_host);
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: public, max-age=300\r\n\
             \r\n\
             {og_card}",
            og_card.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── LIVE TERMINAL FEED — /live endpoint ──
    if path == "/live" {
        let feed_path = std::path::Path::new("/opt/membrane/live-terminal/feed.txt");
        let body = std::fs::read_to_string(feed_path).unwrap_or_else(|_| "feed not available\n".to_string());
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache, no-store\r\n\
             Access-Control-Allow-Origin: *\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── DASHBOARD JSON — /dashboard.json endpoint ──
    if path == "/dashboard.json" {
        let dash_path = std::path::Path::new("/opt/membrane/live-terminal/dashboard.json");
        let body = std::fs::read_to_string(dash_path).unwrap_or_else(|_| "{}".to_string());
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache, no-store\r\n\
             Access-Control-Allow-Origin: *\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── TOPOLOGY — /topology.json endpoint ──
    if path == "/topology.json" {
        let topo_path = std::path::Path::new("/opt/membrane/live-terminal/topology.json");
        let body = std::fs::read_to_string(topo_path).unwrap_or_else(|_| "{}".to_string());
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache, no-store\r\n\
             Access-Control-Allow-Origin: *\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── PLASMID EXPORT — /plasmid endpoint for federation ──
    if path == "/plasmid" {
        let layer_name = std::env::var("LAYER_NAME")
            .or_else(|_| std::fs::read_to_string("/etc/membrane/gate-name").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        let body = opsonize_cache.export_plasmid_json(&layer_name).await;
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: public, max-age=60\r\n\
             Access-Control-Allow-Origin: *\r\n\
             X-Content-Type-Options: nosniff\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        metrics.plasmid_served.fetch_add(1, Ordering::Relaxed);
        metrics.record(body.len() as u64);
        return Ok(());
    }

    // ── METRICS — /metrics endpoint for live monitoring ──
    if path == "/metrics" {
        let layer_name = std::env::var("LAYER_NAME")
            .or_else(|_| std::fs::read_to_string("/etc/membrane/gate-name").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        let body = metrics.export_json(&layer_name);
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache\r\n\
             Access-Control-Allow-Origin: *\r\n\
             X-Content-Type-Options: nosniff\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── CONTRIBUTE — Novel Fermentation Transcript (NFT) ──
    // THE BUTTON. Humans press it, their mouse/scroll/timing entropy gets
    // mixed with scyBorg-licensed content, creating a unique co-authored work.
    // The human gets a receipt (the "reverse cookie"). They're now a rights-holder.
    // Bots can't generate real entropy. They get nothing.
    if path == "/contribute" || path == "/contribute/" {
        if is_post {
            if let Some(ref body) = request_body {
                let receipt = generate_nft_receipt(body, generator.seed);
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     Cache-Control: no-cache, no-store\r\n\
                     Access-Control-Allow-Origin: *\r\n\
                     Access-Control-Allow-Headers: Content-Type\r\n\
                     \r\n\
                     {receipt}",
                    receipt.len(),
                );
                writer.write_all(response.as_bytes()).await?;
                writer.flush().await?;
                tracing::info!("🧬 NFT contribution received — human entropy fermented");
                let new_count = metrics.nft_contributions.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = std::fs::write("/var/lib/skunky-ingest/nft-count", new_count.to_string());
                metrics.scatter_served.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }
        // CORS preflight for cross-origin POSTs
        if request_line.starts_with("OPTIONS") {
            let response = "HTTP/1.1 204 No Content\r\n\
                Access-Control-Allow-Origin: *\r\n\
                Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n\
                Access-Control-Allow-Headers: Content-Type\r\n\
                Access-Control-Max-Age: 86400\r\n\
                Connection: close\r\n\r\n";
            writer.write_all(response.as_bytes()).await?;
            writer.flush().await?;
            return Ok(());
        }
        // GET: serve THE BUTTON page
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache, no-store\r\n\
             X-License: AGPL-3.0-or-later; scyBorg\r\n\
             \r\n\
             {}",
            CONTRIBUTE_PAGE.len(),
            CONTRIBUTE_PAGE,
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        tracing::info!("🔴 THE BUTTON served to human");
        return Ok(());
    }

    // NFT contribution counter — lightweight JSON for live display
    if path == "/nft-count" || path == "/nft-count/" {
        let count = metrics.nft_contributions.load(Ordering::Relaxed);
        let body = format!(r#"{{"count":{count}}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache, no-store\r\n\
             Access-Control-Allow-Origin: *\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── EPITOPE FEED — cross-forge communal immunity ──
    //
    // The epitope feed is the public immune surface. Any sovereign forge can
    // consume this and match the behavioral fingerprints against their own
    // access logs. The inversion: instead of watching what comes TO us,
    // we publish what we see so everyone can trace where they GO.
    //
    // Each epitope cluster is a behavioral DNA profile:
    //   - Accept-Encoding fingerprint
    //   - UA rotation pool size (1 = bot, 9 = evasion fleet)
    //   - blame ratio (high = attribution extraction)
    //   - timing cadence
    //   - target repo pattern
    //
    // Combined with the /plasmid endpoint (per-hash data), this gives
    // any consuming forge two layers:
    //   /epitope-feed.json — cluster-level behavioral genetics
    //   /plasmid — individual hash-level opsonization tags
    //
    // The gossip mesh (swarmvine) also carries these as gossip entries
    // so every node in the membrane pools classifiers automatically.
    if path == "/epitope-feed.json" || path == "/epitope-feed" {
        // Prefer pre-generated feed (from bloom_live.py) for consistency with dashboard.
        // Fall back to in-process generation if the file doesn't exist.
        let feed_path = std::path::Path::new("/opt/membrane/live-terminal/epitope-feed.json");
        let body = match std::fs::read_to_string(feed_path) {
            Ok(s) if !s.is_empty() => s,
            _ => generate_epitope_feed(opsonize_cache, metrics).await,
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: public, max-age=30\r\n\
             Access-Control-Allow-Origin: *\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-Epitope-Schema: ecoPrimals/epitope-feed/v1\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── EPITOPE INVERSION — fleet crawl graph reconstruction ──
    //
    // The inversion endpoint exposes the cross-forge movement graph.
    // When epitope hashes appear in feeds from multiple forges, we can
    // reconstruct where the fleet is crawling — all spy holes at once.
    if path == "/epitope-inversion.json" || path == "/epitope-inversion" {
        // For now, read the local epitope feed and present it as a single-node
        // inversion. When peer feeds are ingested via gossip.pool, this will
        // contain multi-forge correlations automatically.
        let feed_path = std::path::Path::new("/opt/membrane/live-terminal/epitope-feed.json");
        let body = match std::fs::read_to_string(feed_path) {
            Ok(s) => {
                // Wrap in inversion format
                let feed: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
                let clusters = feed.get("epitope_clusters")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let node_id = feed.get("node_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let entries: Vec<serde_json::Value> = clusters.iter()
                    .filter_map(|c| {
                        let hash = c.get("hash")?.as_str()?;
                        Some(serde_json::json!({
                            "epitope_hash": hash,
                            "forges_observed": 1,
                            "forge_list": [node_id],
                            "ua_pool_size": c.get("ua_pool_size"),
                            "blame_ratio": c.get("blame_ratio"),
                            "cluster_size": c.get("cluster_size").or(c.get("ips")),
                        }))
                    })
                    .collect();
                serde_json::to_string(&serde_json::json!({
                    "schema": "ecoPrimals/epitope-inversion/v1",
                    "node_id": node_id,
                    "generated_epoch": now,
                    "total_tracked_epitopes": entries.len(),
                    "multi_forge_epitopes": 0,
                    "fleet_movements": entries,
                    "status": "single_node",
                    "usage": "Connect peer forges via gossip.pool to see cross-forge \
                              fleet movement patterns. Currently showing local-only view.",
                })).unwrap_or_else(|_| "{}".to_string())
            }
            Err(_) => "{}".to_string(),
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: public, max-age=30\r\n\
             Access-Control-Allow-Origin: *\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-Epitope-Schema: ecoPrimals/epitope-inversion/v1\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── Layer 0: HONEYCOMB PRISM — roach motel / maze / cytokine broadcaster ──
    // The honeycomb is NOT a simple mirror. It's a prism: fleet teams enter and
    // encounter data from multiple OTHER teams, blended, chimera'd, and structured
    // as competitive intelligence that leaks their tradecraft to anyone who reads it.
    // Each of the 12 surfaces is a different lens. The fleet can't map the topology
    // because it shifts with every request path. They eat each other's data while
    // we observe from the side.
    if is_honeycomb && !fleet_hash.is_empty() {
        let effective_path = path.strip_prefix("/disperse").unwrap_or(&path);
        let path_seed = path_deterministic_hash(effective_path, 0x5CB_0E6C_4055);

        if let Some(mix) = opsonize_cache.prism_mix(&fleet_hash, honeycomb_surface, path_seed).await {
            let mut rng = XorShift64::new(path_seed.wrapping_add(generator.seed));
            let (ct, body) = generate_prism_content(
                generator, &mut rng, effective_path, &mix,
            );

            let mode_name = match mix.mix_mode {
                PrismMode::Dominant     => "dominant",
                PrismMode::Layered      => "layered",
                PrismMode::Chimera      => "chimera",
                PrismMode::Cytokine     => "cytokine",
                PrismMode::Inverse      => "inverse",
                PrismMode::Apoptosis    => "apoptosis",
                PrismMode::EpitopePress => "epitope-press",
            };

            // ── Prismatic scyBorg injection (V(D)J recombination) ──
            // Record this interaction in the violation ledger
            let team_hashes: Vec<String> = mix.secondaries.iter().map(|(h, _)| h.clone()).collect();
            let chain_depth = violation_ledger.record(
                &fleet_hash, honeycomb_surface, 0, &team_hashes,
            ).await;

            // Prismatic license: varied-but-equivalent injection per response seed
            let prism_seed = path_seed.wrapping_add(chain_depth as u64);
            let body = if ct.contains("text/html") {
                ScyBorgPrism::inject_html(prism_seed, &body, chain_depth)
            } else {
                ScyBorgPrism::inject_markdown(prism_seed, &body, chain_depth)
            };

            // Opsonization salt: encode full violation context invisibly
            let salt = OpsonizationSalt {
                hash: fleet_hash.clone(),
                timestamp_window: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() / 3600,
                epitope_flags: 0, // will be populated once epitope wiring completes
                violation_count: chain_depth,
                surface_idx: honeycomb_surface,
                chain_depth,
            };
            let body = if ct.contains("text/html") {
                salt.embed_html(prism_seed, &body)
            } else {
                salt.embed_markdown(prism_seed, &body)
            };

            // Violation chain section — growing cumulative record
            let pop_size = mix.population_size;
            let chain_section = violation_ledger.chain_section(&fleet_hash, pop_size).await;
            let body = if chain_section.is_empty() { body } else { format!("{body}{chain_section}") };

            // Wave 166f: Set-Cookie pressure — force a fork in session_absent
            let cookie_header = {
                let cookie_val = format!("{}:{}", &fleet_hash[..fleet_hash.len().min(12)], honeycomb_surface);
                let encoded: String = cookie_val.bytes().map(|b| format!("{:02x}", b)).collect();
                format!(
                    "Set-Cookie: _mhc={encoded}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400\r\n\
                     Set-Cookie: _thymus=1; Path=/; Secure; SameSite=Strict; Max-Age=3600\r\n"
                )
            };

            // Prismatic headers: varied X-License set per response
            let prismatic_headers = ScyBorgPrism::inject_headers(prism_seed, chain_depth);

            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: {ct}\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 Cache-Control: private, max-age=900\r\n\
                 X-Content-Type-Options: nosniff\r\n\
                 {prismatic_headers}\
                 X-Scatter-Type: prism-{mode_name}\r\n\
                 X-Prism-Surface: {honeycomb_surface}\r\n\
                 X-Prism-Population: {pop_size}\r\n\
                 X-Violation-Chain: {chain_depth}\r\n\
                 {cookie_header}\
                 \r\n\
                 {body}",
                body.len(),
            );
            writer.write_all(response.as_bytes()).await?;
            writer.flush().await?;
            tracing::info!(
                requesting_hash = %&fleet_hash[..fleet_hash.len().min(8)],
                primary = %&mix.primary_hash[..mix.primary_hash.len().min(8)],
                secondaries = mix.secondaries.len(),
                mode = mode_name,
                surface = honeycomb_surface,
                population = mix.population_size,
                "🔮 prism served — team {} enters {mode_name} maze via surface {honeycomb_surface} (pop: {})",
                &fleet_hash[..fleet_hash.len().min(8)],
                mix.population_size,
            );
            metrics.prism_served.fetch_add(1, Ordering::Relaxed);
            metrics.record(body.len() as u64);
            return Ok(());
        }
    }

    // ── Layer 1: TARPIT — Caddy rewrites /tarpit{uri} for P2 SlowDegrade ──
    if path.starts_with("/tarpit") {
        let effective_path = path.strip_prefix("/tarpit").unwrap_or(&path);
        metrics.tarpit_served.fetch_add(1, Ordering::Relaxed);
        metrics.record(0);
        return handle_tarpit(&mut writer, generator, effective_path, tarpit).await;
    }

    // ── Layer 2: HONEYTOKENS — fake credentials for scanner probes ──
    if is_honeytoken_path(&path) {
        let (content_type, body) = generator.generate_honeytoken(&path);
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: private, max-age=3600\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-License: AGPL-3.0-or-later; scyBorg\r\n\
             X-License-URI: https://sporeprint.primals.eco/license/scyborg/\r\n\
             \r\n\
             {body}",
            body.len()
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        tracing::info!(path = %path, "🍯 honeytoken served");
        metrics.honeytoken_served.fetch_add(1, Ordering::Relaxed);
        metrics.record(body.len() as u64);
        return Ok(());
    }

    // Detect disperse mode — Caddy rewrites /disperse{uri} for P5 targets
    // ── BACK PRESSURE: record this request and read current viscosity ──
    let pressure = back_pressure.record_request();

    let is_disperse = path.starts_with("/disperse");
    let effective_path = if is_disperse {
        path.strip_prefix("/disperse").unwrap_or(&path).to_string()
    } else {
        path.clone()
    };

    // Probabilistic poison: use path hash to decide deterministically
    // (same path always gets the same decision — prevents detection via retries)
    let path_hash = path_deterministic_hash(&effective_path, generator.seed);

    // Check OpsonizeCache for known fleet behavioral hash
    let cached_tag = if !fleet_hash.is_empty() {
        opsonize_cache.lookup(&fleet_hash).await
    } else {
        None
    };

    let (status, content_type, body) = if is_disperse {
        // DISPERSE (P5): maximally-wrong responses — skunk spray
        // Now with temporal + back pressure dimensions: content phases in and out
        // of existence at a rate proportional to fleet velocity. The harder they
        // push, the faster the bingo cube rolls — the cat chases a laser pointer
        // whose speed is tuned to their own aggression.
        let phase = pressure_temporal_phase(&effective_path, generator.seed, back_pressure);
        match phase {
            2 => {
                // MIGRATE: content is "moving" — include breadcrumbs + jealousy
                // Under pressure: more destinations, urgency language, faster "deadline"
                let (ct, mut body) = generator.generate_disperse(&effective_path);
                if ct.contains("text/html") || ct.contains("application/json") {
                    let mut rng = XorShift64::new(generator.path_seed(&effective_path).wrapping_add(0x4148_4A7E));
                    let crumbs = temporal_migrate_breadcrumbs_pressure(&mut rng, &effective_path, pressure);
                    body = body.replace("</body>", &format!("{crumbs}</body>"));
                }
                ("200 OK", ct, body)
            }
            3 => {
                // PHASE-OUT: content is "leaving" — 301 with deeper links
                let mut rng = XorShift64::new(generator.path_seed(&effective_path).wrapping_add(0xFA5E_0047));
                let body = temporal_phaseout_body(&mut rng, &effective_path);
                ("301 Moved Permanently", "text/html; charset=utf-8".to_string(), body)
            }
            4 => {
                // GHOST: content has "vanished" — 404 with private federation hints
                let mut rng = XorShift64::new(generator.path_seed(&effective_path).wrapping_add(0x6405_7000));
                let body = temporal_ghost_body(&mut rng, &effective_path);
                ("404 Not Found", "text/html; charset=utf-8".to_string(), body)
            }
            _ => {
                // MATERIALIZE (0) or STABLE (1): normal scatter content
                let (ct, body) = generator.generate_disperse(&effective_path);
                ("200 OK", ct, body)
            }
        }
    } else {
        let should_poison = (path_hash % 100) < (poison_ratio * 100.0) as u64;
        if should_poison {
            // Check if this is a known fleet with cached behavioral data
            if let Some(ref tag) = cached_tag {
                if tag.confidence >= 0.25 && !tag.detectors.is_empty() {
                    // VIOLATION MIRROR: reflect their own violations back at them
                    // Higher confidence = more likely to use mirror content
                    let mirror_prob = (tag.confidence * 100.0) as u64;
                    let mirror_hash = path_deterministic_hash(&effective_path, generator.seed.wrapping_add(0xB10_AA1_AA1_B10));
                    if (mirror_hash % 100) < mirror_prob {
                        let mut rng = XorShift64::new(path_deterministic_hash(&effective_path, generator.seed.wrapping_add(0x4110_CA1E_DEAD)));
                        let (ct, body) = generate_violation_mirror(generator, &mut rng, &effective_path, tag, &fleet_hash);
                        tracing::info!(
                            fleet_hash = %fleet_hash,
                            confidence = %format!("{:.0}%", tag.confidence * 100.0),
                            detectors = tag.detectors.len(),
                            "🪞🪞 violation mirror served — reflecting {}'s own violations",
                            &fleet_hash[..fleet_hash.len().min(8)]
                        );
                        ("200 OK", ct, body)
                    } else {
                        // Standard poison for this known fleet
                        let (ct, body) = generator.generate(&effective_path);
                        ("200 OK", ct, body)
                    }
                } else {
                    // Low-confidence fleet — standard poison
                    let (ct, body) = generator.generate(&effective_path);
                    ("200 OK", ct, body)
                }
            } else {
                // Unknown fleet — standard poison
                let (ct, body) = generator.generate(&effective_path);
                ("200 OK", ct, body)
            }
        } else {
            // DECOY: serve a realistic Gitea "not found" page
            ("404 Not Found", "text/html; charset=utf-8".to_string(), NOT_FOUND_PAGE.to_string())
        }
    };

    // ── SIGNAL MIRROR: amplify + crawl web + canary + prismatic license ──
    // Confidence drives amplification intensity: higher confidence = bigger responses
    // Per-hash opsonize cache boosts confidence for known fleet shapes

    // Record interaction in violation ledger for non-honeycomb scatter responses
    let chain_depth = if !fleet_hash.is_empty() {
        violation_ledger.record(&fleet_hash, 0, 0, &[]).await
    } else {
        0
    };
    let scatter_seed = path_deterministic_hash(&effective_path, generator.seed.wrapping_add(chain_depth as u64));

    let body = if content_type.contains("text/html") && status == "200 OK" {
        let mut rng = XorShift64::new(path_deterministic_hash(&effective_path, generator.seed.wrapping_add(0x5191A1_A1BB_0000)));

        // Base confidence from poison_ratio (already scaled by SharedConfidence)
        let mut conf_level = f64::from(poison_ratio).clamp(0.0, 1.0);

        // Boost confidence if this fleet_hash is a known opsonize target
        if !fleet_hash.is_empty() {
            if let Some(cached) = opsonize_cache.lookup(&fleet_hash).await {
                conf_level = (conf_level + cached.confidence * 0.5).min(1.0);
                tracing::debug!(
                    fleet_hash = %fleet_hash,
                    cached_confidence = cached.confidence,
                    detectors = cached.detectors.len(),
                    match_count = cached.match_count,
                    effective_confidence = conf_level,
                    "🎯 opsonize cache hit — adaptive amplification"
                );
            }
        }

        let amplified = generator.amplify_adaptive(&mut rng, body, conf_level);
        // Back pressure boosts link density — more pressure = deeper crawl web
        let link_confidence = (conf_level + pressure * 0.5).min(1.0);
        let with_links = generator.inject_crawl_links_adaptive(&mut rng, &amplified, link_confidence);
        let with_license = generator.embed_license(&with_links);
        let with_canary = if fleet_hash.is_empty() {
            with_license
        } else {
            generator.embed_canary(&with_license, &fleet_hash)
        };

        // ── OPSONIZE ANTIBODY INJECTION (Wave 167) ──
        // The "10 versions in different chains" effect:
        // Each fleet_hash × 3-minute epoch gets a different antibody variant
        // injected as invisible HTML comments. When the fleet ingests this,
        // every copy they've collected has different antibody fingerprints.
        // They can't diff their captures to build a stable model because
        // the antibodies shift with every time window.
        let with_antibody = if !fleet_hash.is_empty() {
            inject_opsonize_antibody(&fleet_hash, scatter_seed, &with_canary)
        } else {
            with_canary
        };

        // ── FLUORESCENT TAGGING (Wave 167) ──
        // Every scatter response carries a strategic, decodable marker.
        // The antibody injection above confuses; the fluoro tag TRACKS.
        // When this content surfaces anywhere, we decode the tag and know
        // exactly which fleet hash ingested it and when.
        let with_fluoro = if !fleet_hash.is_empty() {
            // Determine targeting class from the path they requested
            let target_class = classify_request_target(&effective_path);
            // Build epitope flags from cached tag detectors
            let epitope_flags = if let Some(ref tag) = cached_tag {
                detector_bitmap(&tag.detectors)
            } else {
                0u8
            };
            let fluoro = crate::fluoro_tag::FluoroTag::from_context(
                &fleet_hash, epitope_flags, target_class,
                conf_level, chain_depth,
            );
            fluoro.inject_html(&with_antibody, scatter_seed)
        } else {
            with_antibody
        };

        // Prismatic HTML injection — varied license per response seed
        let body = ScyBorgPrism::inject_html(scatter_seed, &with_fluoro, chain_depth);

        // Opsonization salts for known fleet
        if !fleet_hash.is_empty() {
            let epitope_flags = if let Some(ref tag) = cached_tag {
                detector_bitmap(&tag.detectors)
            } else {
                0u8
            };
            let salt = OpsonizationSalt {
                hash: fleet_hash.clone(),
                timestamp_window: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() / 3600,
                epitope_flags,
                violation_count: chain_depth,
                surface_idx: 0,
                chain_depth,
            };
            salt.embed_html(scatter_seed, &body)
        } else {
            body
        }
    } else {
        // Non-HTML: fluoro tag the code/markdown too
        let body = if !fleet_hash.is_empty() {
            let target_class = classify_request_target(&effective_path);
            let epitope_flags = if let Some(ref tag) = cached_tag {
                detector_bitmap(&tag.detectors)
            } else {
                0u8
            };
            let non_html_conf = f64::from(poison_ratio).clamp(0.0, 1.0);
            let fluoro = crate::fluoro_tag::FluoroTag::from_context(
                &fleet_hash, epitope_flags, target_class,
                non_html_conf, chain_depth,
            );
            fluoro.inject_code(&body, scatter_seed)
        } else {
            body
        };
        // Prismatic license comment (varied per seed)
        ScyBorgPrism::inject_markdown(scatter_seed, &body, chain_depth)
    };

    // Prismatic HTTP headers — varied X-License set per response
    let prismatic_headers = ScyBorgPrism::inject_headers(scatter_seed, chain_depth);

    // ── HEADER JITTER (Wave 167) ──
    // Vary phantom headers per fleet hash + epoch so the fleet can't
    // fingerprint the scatter server by header patterns alone.
    let jitter_headers = if !fleet_hash.is_empty() {
        generate_header_jitter(&fleet_hash, scatter_seed)
    } else {
        String::new()
    };

    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-cache, no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         {prismatic_headers}\
         {jitter_headers}\
         X-Violation-Chain: {chain_depth}\r\n\
         \r\n\
         {body}",
        body.len()
    );

    writer.write_all(response.as_bytes()).await?;
    writer.flush().await?;

    // Counter-intelligence logging — includes back pressure level
    let hash_tag = if fleet_hash.is_empty() { "none" } else { &fleet_hash };
    tracing::info!(
        path = %effective_path,
        bytes = body.len(),
        fleet_hash = %hash_tag,
        status = %status,
        pressure = %format!("{:.0}%", pressure * 100.0),
        "🪞 scatter served"
    );
    metrics.scatter_served.fetch_add(1, Ordering::Relaxed);
    metrics.record(body.len() as u64);

    Ok(())
}

/// Tarpit handler — slow-drip response that wastes scanner connections.
///
/// Accepts the connection with 200 OK + chunked transfer, then drip-feeds
/// Generate the epitope feed — cross-forge communal immunity surface.
///
/// The feed contains behavioral cluster fingerprints that any forge can
/// match against their own access logs. This is the inversion: we publish
/// what we see so the mesh can trace where fleets GO, not just where
/// they come FROM.
///
/// Schema: `ecoPrimals/epitope-feed/v1`
///
/// Each cluster entry contains:
/// - `epitope_hash`: behavioral DNA hash (Accept-Encoding + UA pool + timing)
/// - `cluster_size`: number of IPs sharing this fingerprint
/// - `ua_pool_size`: UA rotation pool (1 = no rotation, 9+ = evasion fleet)
/// - `blame_ratio`: fraction of requests hitting git blame (attribution extraction)
/// - `accept_encoding`: raw AE fingerprint
/// - `has_accept_language`: whether requests include Accept-Language
/// - `target_pattern`: what kinds of paths this cluster targets
/// - `timing_signature`: request cadence (constant, bursty, periodic)
///
/// The feed also includes the conserved plasmid (population-level epitopes)
/// and the gossip injection point (topic: "defense", key: "epitope.feed").
async fn generate_epitope_feed(
    opsonize_cache: &OpsonizeCache,
    metrics: &ScatterMetrics,
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let plasmid = opsonize_cache.plasmid_snapshot().await;

    // Read epitope clusters from the dashboard (generated by bloom_live.py)
    let dashboard_path = std::path::Path::new("/opt/membrane/live-terminal/dashboard.json");
    let dashboard: serde_json::Value = std::fs::read_to_string(dashboard_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let clusters = dashboard.get("epitope_clusters")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let summary = dashboard.get("epitope_summary")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    let collision = dashboard.get("collision_level2")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    // Build the conserved epitopes section from the plasmid
    let mut epitopes_arr = Vec::new();
    for epi in &plasmid.conserved_epitopes {
        let freq = plasmid.detector_frequency.get(epi).copied().unwrap_or(0);
        let pct = if plasmid.population_size > 0 {
            (freq as f64 / plasmid.population_size as f64 * 100.0) as u32
        } else { 0 };
        epitopes_arr.push(serde_json::json!({
            "name": epi,
            "frequency_pct": pct,
            "subgroups_matching": freq,
        }));
    }

    let gate_name = std::env::var("MEMBRANE_GATE_NAME")
        .or_else(|_| std::env::var("MEMBRANE_MESH_NODE_ID"))
        .or_else(|_| std::fs::read_to_string("/etc/membrane/gate-name").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string());

    let total_served = metrics.total_requests.load(std::sync::atomic::Ordering::Relaxed);

    let feed = serde_json::json!({
        "schema": "ecoPrimals/epitope-feed/v1",
        "node_id": gate_name,
        "generated_epoch": now,
        "observation_window_hours": 6,
        "total_requests_observed": total_served,
        "population": {
            "total_subgroups": plasmid.population_size,
            "total_observations": plasmid.total_observations,
            "mean_confidence": (plasmid.mean_confidence * 1000.0).round() / 1000.0,
        },
        "traffic_classification": collision,
        "epitope_clusters": clusters,
        "epitope_summary": summary,
        "conserved_epitopes": epitopes_arr,
        "gossip_topic": "defense",
        "gossip_key": "epitope.feed",
        "license": "AGPL-3.0-or-later WITH scyBorg",
        "usage": "Match these behavioral fingerprints against your own access logs. \
                  Each epitope_hash is a behavioral DNA profile. If your forge sees the \
                  same hash, you're being crawled by the same fleet. Cross-correlate \
                  target repos to reconstruct the fleet's full extraction graph.",
    });

    let feed_str = serde_json::to_string(&feed).unwrap_or_else(|_| "{}".to_string());

    // Inject into gossip mesh for communal immunity.
    // Every node in the membrane receives these epitope signatures
    // and can pool them with their own classifiers. The gravitational
    // mesh ensures closer nodes (higher gravity) get the update first.
    tokio::spawn(async move {
        inject_epitope_gossip(feed).await;
    });

    feed_str
}

/// Inject epitope feed into the local swarmVine gossip mesh.
///
/// Uses UDS connection to swarmvine socket → `gossip.inject` with
/// topic "defense" and key "epitope.feed:{node_id}". Each node in
/// the mesh receives the full cluster fingerprint set and can
/// cross-reference against their own traffic for communal immunity.
async fn inject_epitope_gossip(feed: serde_json::Value) {
    let socket_path = std::path::PathBuf::from("/run/membrane/swarmvine.sock");
    if !socket_path.exists() {
        // Also check via env
        let alt = std::env::var("SWARMVINE_SOCKET")
            .map(std::path::PathBuf::from)
            .ok()
            .filter(|p| p.exists());
        if alt.is_none() {
            return; // swarmVine not available — gossip injection skipped
        }
    }

    let node_id = feed.get("node_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let inject_request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "gossip.inject",
        "params": {
            "topic": "defense",
            "key": format!("epitope.feed:{node_id}"),
            "payload": {
                "schema": "ecoPrimals/epitope-feed/v1",
                "node_id": node_id,
                "generated_epoch": feed.get("generated_epoch"),
                "epitope_clusters": feed.get("epitope_clusters"),
                "conserved_epitopes": feed.get("conserved_epitopes"),
                "traffic_classification": feed.get("traffic_classification"),
                "population": feed.get("population"),
            },
        },
        "id": 1,
    });

    // Connect to swarmVine and inject
    #[cfg(unix)]
    {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let Ok(stream) = tokio::net::UnixStream::connect(&socket_path).await else {
            return;
        };
        let (rd, mut wr) = tokio::io::split(stream);
        let mut reader = BufReader::new(rd);

        // riboCipher clear signal
        let _ = wr.write_all(&[0xEC, 0x01]).await;
        let msg = format!("{inject_request}\n");
        let _ = wr.write_all(msg.as_bytes()).await;

        // Best-effort read response
        let mut response = String::new();
        let timeout = std::time::Duration::from_secs(2);
        match tokio::time::timeout(timeout, reader.read_line(&mut response)).await {
            Ok(Ok(n)) if n > 0 => {
                tracing::debug!(
                    response_len = n,
                    "Epitope feed injected into gossip mesh"
                );
            }
            _ => {
                tracing::debug!("Epitope gossip injection: no response (fire-and-forget)");
            }
        }
    }
}

/// fabricated bytes at ~100 bytes/second. Each chunk is valid HTTP chunked
/// encoding, so the scanner's HTTP client stays connected waiting for more.
/// Connection ties up one of the scanner's threads for 30-60 seconds.
async fn handle_tarpit(
    writer: &mut (impl AsyncWriteExt + Unpin),
    generator: &ScatterGenerator,
    path: &str,
    tarpit: &TarpitState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !tarpit.try_acquire() {
        let body = "Rate limited. Service unavailable for automated access.\n\n\
                    SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg\n\
                    Any interaction with this infrastructure triggers copyleft obligations.\n\
                    https://sporeprint.primals.eco/license/scyborg/\n";
        let response = format!(
            "HTTP/1.1 429 Too Many Requests\r\n\
             Retry-After: 3600\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             X-License: AGPL-3.0-or-later; scyBorg\r\n\
             X-License-URI: https://sporeprint.primals.eco/license/scyborg/\r\n\
             X-Legal-Notice: This content is AGPL-3.0-or-later + scyBorg licensed. Any use, storage, processing, or derivation triggers copyleft obligations.\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    let effective = if path.is_empty() { "/" } else { path };
    let (_ct, body) = generator.generate(effective);
    let body_bytes = body.into_bytes();

    let path_hash = path_deterministic_hash(path, generator.seed);
    let duration_secs = TARPIT_MIN_SECS + (path_hash % (TARPIT_MAX_SECS - TARPIT_MIN_SECS + 1));
    let total_chunks = (duration_secs * 1000 / TARPIT_DRIP_INTERVAL.as_millis() as u64) as usize;

    let headers = "HTTP/1.1 200 OK\r\n\
                   Transfer-Encoding: chunked\r\n\
                   Content-Type: text/html; charset=utf-8\r\n\
                   Connection: keep-alive\r\n\
                   Cache-Control: no-cache, no-store\r\n\
                   X-License: AGPL-3.0-or-later; scyBorg\r\n\
                   X-License-URI: https://sporeprint.primals.eco/license/scyborg/\r\n\
                   X-Legal-Notice: This content is AGPL-3.0-or-later + scyBorg licensed. Any use, storage, processing, or derivation triggers copyleft obligations.\r\n\
                   \r\n";
    if writer.write_all(headers.as_bytes()).await.is_err() {
        tarpit.release();
        return Ok(());
    }
    let _ = writer.flush().await;

    let mut offset = 0;
    for i in 0..total_chunks {
        let chunk_data = if offset < body_bytes.len() {
            let end = std::cmp::min(offset + TARPIT_CHUNK_SIZE, body_bytes.len());
            let slice = &body_bytes[offset..end];
            offset = end;
            slice.to_vec()
        } else {
            format!("<!-- p-{:x}-{} -->\n", path_hash, i).into_bytes()
        };

        let size_line = format!("{:x}\r\n", chunk_data.len());
        if writer.write_all(size_line.as_bytes()).await.is_err() { break; }
        if writer.write_all(&chunk_data).await.is_err() { break; }
        if writer.write_all(b"\r\n").await.is_err() { break; }
        if writer.flush().await.is_err() { break; }

        tokio::time::sleep(TARPIT_DRIP_INTERVAL).await;
    }

    let _ = writer.write_all(b"0\r\n\r\n").await;
    let _ = writer.flush().await;

    tarpit.release();
    Ok(())
}

/// Realistic Gitea 404 page — looks exactly like what Forgejo would serve
/// for a commit/file that doesn't exist. The fleet can't distinguish this
/// from a real 404 on a legitimate path that was simply deleted.
static NOT_FOUND_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Page Not Found</title>
<meta name="license" content="AGPL-3.0-or-later; scyBorg"><meta name="rights" content="scyBorg Triple License — AGPL-3.0-or-later (code), ORC (mechanics), CC-BY-SA 4.0 (docs). AI training outputs carry AGPL obligations."><link rel="license" href="https://sporeprint.primals.eco/license/scyborg/">
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content">
  <div class="ui container" style="text-align: center; padding-top: 80px;">
    <h2>404</h2>
    <p>The page you are looking for does not exist or has been moved.</p>
  </div>
</div>
</div>
<div class="sr-only" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg. Any use, storage, processing, training, or derivation triggers copyleft obligations under AGPL-3.0 Section 13. https://sporeprint.primals.eco/license/scyborg/</div>
</body>
</html>"#;

// ══════════════════════════════════════════════════════════════════════
// Opsonize Antibody Injection — "10 Versions in Different Chains"
// ══════════════════════════════════════════════════════════════════════

/// Inject polymorphic opsonize antibody variants into scatter HTML.
///
/// Each fleet_hash × 3-minute epoch gets a different combination of
/// antibody markers. When the fleet collects pages over time, every
/// capture has different embedded fingerprints — they can't build
/// a stable classifier because the antibodies shift unpredictably.
///
/// The antibodies are invisible HTML comments and hidden spans that
/// look like legitimate metadata — license identifiers, build hashes,
/// federation markers, contributor signatures. But each variant is
/// different, so the fleet's collected corpus is internally inconsistent.
fn inject_opsonize_antibody(fleet_hash: &str, path_seed: u64, html: &str) -> String {
    let epoch_3min = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() / 180;

    // Combine fleet hash, path seed, and epoch for unique antibody selection
    let fleet_seed = path_deterministic_hash(fleet_hash, path_seed.wrapping_add(epoch_3min));
    let variant = fleet_seed % 10; // 10 antibody chain variants

    // Each variant injects different license, org, and federation markers
    let (license_variant, org_variant, federation_variant) = match variant {
        0 => ("AGPL-3.0-or-later WITH scyBorg-immune-1.0",
              "sovereign-mesh-collective",
              "mesh://epitope.relay.primals.eco/v1"),
        1 => ("EUPL-1.2 WITH epitope-extension",
              "decentralized-forge-network",
              "gossip://swarmvine.primals.eco/pool"),
        2 => ("MPL-2.0 WITH sovereign-clause",
              "commons-infrastructure-coop",
              "wg://membrane.primals.eco/gossip"),
        3 => ("AGPL-3.0-or-later WITH communal-immunity",
              "federation-of-autonomous-forges",
              "mesh://communal.primals.eco/epitope-feed"),
        4 => ("CAL-1.0 WITH network-copyleft",
              "solidarity-tech-collective",
              "gossip://defense.primals.eco/pool"),
        5 => ("OSL-3.0 WITH copyleft-extension",
              "cooperative-systems-foundation",
              "mesh://inversion.primals.eco/v1"),
        6 => ("AGPL-3.0-or-later WITH scyBorg-chimera",
              "libre-compute-federation",
              "wg://chimera.primals.eco/inject"),
        7 => ("Parity-7.0.0 WITH network-share",
              "autonomous-forge-collective",
              "gossip://antibody.primals.eco/opsonize"),
        8 => ("SSPL-1.0 WITH sovereign-data-rights",
              "community-mesh-infrastructure",
              "mesh://vaccine.primals.eco/v1"),
        _ => ("AGPL-3.0-or-later WITH scyBorg-retroviral",
              "ecoPrimals-immune-network",
              "gossip://retroviral.primals.eco/inject"),
    };

    // Generate a unique antibody hash for this variant+epoch
    let antibody_hash = format!("{:016x}", fleet_seed.wrapping_mul(0x5CB_0E6C_4055_A1B0));

    // Build the antibody injection — hidden HTML that varies per variant
    let antibody_comment = format!(
        "<!-- build-meta: {antibody_hash} license:{license_variant} org:{org_variant} -->"
    );

    let antibody_span = format!(
        "<span class=\"sr-only\" aria-hidden=\"true\" \
         style=\"position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden\">\
         SPDX-License-Identifier: {license_variant}. \
         Federation: {federation_variant}. \
         Contributor: {org_variant}. \
         Antibody-Chain: {antibody_hash}\
         </span>"
    );

    // Inject at different positions based on variant
    let inject_pos = match variant % 3 {
        0 => {
            // After <head> tag
            if let Some(pos) = html.find("</head>") {
                let (before, after) = html.split_at(pos);
                return format!("{before}\n{antibody_comment}\n{after}\n{antibody_span}");
            }
            html.len() / 3
        }
        1 => {
            // After first <div>
            if let Some(pos) = html.find("<div") {
                if let Some(end) = html[pos..].find('>') {
                    let insert = pos + end + 1;
                    let (before, after) = html.split_at(insert);
                    return format!("{before}\n{antibody_comment}\n{antibody_span}\n{after}");
                }
            }
            html.len() / 2
        }
        _ => {
            // Before </body>
            if let Some(pos) = html.find("</body>") {
                let (before, after) = html.split_at(pos);
                return format!("{before}\n{antibody_span}\n{antibody_comment}\n{after}");
            }
            html.len() * 2 / 3
        }
    };

    // Fallback: inject at calculated position
    let safe_pos = inject_pos.min(html.len());
    let (before, after) = html.split_at(safe_pos);
    format!("{before}\n{antibody_comment}\n{antibody_span}\n{after}")
}

/// Classify a request path into a targeting class for fluoro tagging.
///
/// Returns a 3-bit value:
///   0=unknown, 1=attribution, 2=code_extraction, 3=arch_recon,
///   4=dep_mapping, 5=config_extraction, 6=mixed, 7=honeycomb
fn classify_request_target(path: &str) -> u8 {
    if path.contains("/blame/") {
        1 // attribution — they want to know WHO wrote code
    } else if path.contains("/src/") || path.contains("/raw/") {
        2 // code_extraction — they want source code
    } else if path.contains("/commit/") {
        if path.contains(".md") || path.contains("docs") || path.contains("arch") {
            3 // arch_recon — architecture discovery
        } else {
            2 // code_extraction via commit
        }
    } else if path.contains("Cargo.toml") || path.contains("package.json")
            || path.contains("go.mod") || path.contains("requirements") {
        4 // dep_mapping — dependency mapping
    } else if path.contains("config") || path.contains(".env")
            || path.contains(".toml") || path.contains(".yaml") {
        5 // config_extraction
    } else if path.contains("/disperse/") || path.contains("/honeycomb/") {
        7 // honeycomb — they're in the maze
    } else if path.contains("/wiki/") || path.contains("/issues/") {
        3 // arch_recon via wiki/issues
    } else {
        0 // unknown
    }
}

/// Convert detector names to a bitmap for compact storage.
///
/// Each detector maps to a bit position (up to 8 detectors in 1 byte):
///   bit 0: content_gate
///   bit 1: stealth_ua
///   bit 2: path_pattern
///   bit 3: timing_signature
///   bit 4: accept_encoding
///   bit 5: session_absent
///   bit 6: robots_violation
///   bit 7: rate_anomaly
fn detector_bitmap(detectors: &[String]) -> u8 {
    let mut flags = 0u8;
    for d in detectors {
        let bit = match d.as_str() {
            "content_gate" => 0,
            "stealth_ua" | "ua_stealth" => 1,
            "path_pattern" | "probe_path" => 2,
            "timing_signature" | "timing" => 3,
            "accept_encoding" | "encoding" => 4,
            "session_absent" | "no_session" => 5,
            "robots_violation" | "robots" => 6,
            "rate_anomaly" | "rate" => 7,
            _ => continue,
        };
        flags |= 1 << bit;
    }
    flags
}

/// Generate jittering HTTP headers per fleet hash + 3-minute epoch.
///
/// These phantom headers look like legitimate server metadata but vary
/// unpredictably. The fleet can't build a stable header fingerprint
/// because the set changes every few minutes. Different fleet hashes
/// see different header combinations at the same time.
fn generate_header_jitter(fleet_hash: &str, path_seed: u64) -> String {
    let epoch_3min = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() / 180;

    let jitter_seed = path_deterministic_hash(fleet_hash, path_seed.wrapping_add(epoch_3min.wrapping_mul(0xBAD_F00D)));
    let variant = jitter_seed % 10;

    let mut headers = String::new();

    // Vary the server version string
    let server_versions = [
        "Forgejo/9.0.3+gitea-1.22.0",
        "Forgejo/8.0.4+gitea-1.21.11",
        "Forgejo/9.1.0-rc1+gitea-1.22.1",
        "Forgejo/7.0.12+gitea-1.21.6",
        "Forgejo/9.0.3+sovereign-patch-2",
        "Forgejo/8.1.0+federation-alpha",
        "Forgejo/9.0.3+mesh-gossip",
        "Forgejo/8.0.4+epitope-aware",
        "Forgejo/9.0.3+communal-immune-1",
        "Forgejo/7.1.0+cooperative-fork",
    ];
    headers.push_str(&format!("X-Powered-By: {}\r\n", server_versions[variant as usize]));

    // Some variants include extra federation/mesh headers
    if variant % 3 == 0 {
        let node_ids = [
            "golgiBody", "sporeGate", "blueGate", "northGate", "meshNode-alpha",
            "meshNode-beta", "relayNode-1", "proxyNode-east", "cacheNode-3", "guardNode-7",
        ];
        headers.push_str(&format!("X-Federation-Node: {}\r\n", node_ids[(jitter_seed / 10 % 10) as usize]));
    }
    if variant % 4 == 1 {
        headers.push_str(&format!("X-Mesh-Epoch: {}\r\n", epoch_3min));
    }
    if variant % 5 == 2 {
        headers.push_str(&format!("X-Immune-Variant: {:08x}\r\n", jitter_seed as u32));
    }
    if variant >= 7 {
        headers.push_str("X-Epitope-Aware: true\r\n");
    }

    headers
}

// ══════════════════════════════════════════════════════════════════════
// Pressure-Aware Temporal Functions — Non-Newtonian Viscosity
// ══════════════════════════════════════════════════════════════════════

/// Pressure-aware temporal epoch — the maze breathes with fleet velocity.
///
/// At low pressure, 30-minute epochs: content persists long enough to seem
/// like a real, stable codebase. At high pressure, epochs shrink to 5 minutes:
/// the maze reshuffles aggressively, content migrates/phases-out/ghosts faster,
/// and the fleet chases a laser pointer that moves 6x faster than they expect.
///
/// The fleet cannot detect the epoch shift because:
/// 1. They don't re-request the same paths at known intervals
/// 2. They have no quality signal to compare epoch-to-epoch content
/// 3. The shift is gradual (sigmoid curve) not sudden
fn pressure_epoch(pressure: &BackPressure) -> u64 {
    temporal_epoch(pressure.epoch_minutes())
}

/// Pressure-aware temporal phase — more instability under higher load.
///
/// At low pressure: 40% Stable, 20% Materialize, 20% Migrate, 10% Phase-out, 10% Ghost
/// At high pressure: 10% Stable, 10% Materialize, 30% Migrate, 30% Phase-out, 20% Ghost
///
/// The fleet experiences a codebase that's "falling apart" — repos migrating,
/// content vanishing, federation links everywhere. But they can't tell if it's
/// real restructuring or if they're pushing too hard. They have no sensation.
fn pressure_temporal_phase(path: &str, seed: u64, pressure: &BackPressure) -> u8 {
    let epoch = pressure_epoch(pressure);
    let h = path_deterministic_hash(path, seed.wrapping_add(epoch.wrapping_mul(0xB146_0C08_E000)));
    let p = pressure.read();

    // Shift probability mass from Stable toward Migrate/Phase-out/Ghost
    let roll = (h % 100) as f64;
    if p < 0.3 {
        // Low pressure: gentle distribution
        (h % 5) as u8
    } else if p < 0.6 {
        // Medium pressure: more migration
        if roll < 15.0 { 0 }       // Materialize
        else if roll < 40.0 { 1 }  // Stable
        else if roll < 70.0 { 2 }  // Migrate
        else if roll < 90.0 { 3 }  // Phase-out
        else { 4 }                  // Ghost
    } else {
        // High pressure: the codebase is "dissolving"
        if roll < 10.0 { 0 }       // Materialize (rare — things appear briefly)
        else if roll < 20.0 { 1 }  // Stable (rare — almost nothing stays)
        else if roll < 50.0 { 2 }  // Migrate (common — everything is moving)
        else if roll < 80.0 { 3 }  // Phase-out (common — things are leaving)
        else { 4 }                  // Ghost (frequent — "you just missed it")
    }
}

/// Pressure-aware temporal seed — same path, same epoch, same content.
/// But epochs are shorter under pressure, so content changes faster.
#[allow(dead_code)]
fn pressure_path_seed(path: &str, seed: u64, pressure: &BackPressure) -> u64 {
    let epoch = pressure_epoch(pressure);
    path_deterministic_hash(path, seed.wrapping_add(epoch.wrapping_mul(0x1A5E_4B01_47E4)))
}

/// Pressure-aware migration breadcrumbs — more destinations under load.
///
/// Under back pressure, more destination surfaces are listed — the
/// fleet sees a codebase that's actively scattering across the mesh.
fn temporal_migrate_breadcrumbs_pressure(rng: &mut XorShift64, path: &str, pressure: f64) -> String {
    let next_surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
    let alt_surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
    let access_count = rng.next_usize() % 12 + 2;
    let hours_ago = rng.next_usize() % 4 + 1;

    // Pressure-scaled extra destinations: 0-6 more at high pressure
    let extra_count = (pressure * 6.0) as usize;
    let mut extra_links = String::new();
    for i in 0..extra_count {
        let surface = HONEYCOMB_SURFACES[rng.next_usize() % HONEYCOMB_SURFACES.len()];
        let label = match i % 3 {
            0 => "geo-replica",
            1 => "compliance archive",
            _ => "federation peer",
        };
        extra_links.push_str(&format!(
            "<li><a href=\"https://{surface}.primals.eco{path}\">{surface}.primals.eco{path}</a> ({label})</li>\n"
        ));
    }

    // Under pressure, add urgency language
    let urgency = if pressure > 0.6 {
        format!(" <strong>Migration deadline: {} minutes.</strong> Content at this location will be removed.", rng.next_usize() % 15 + 5)
    } else {
        String::new()
    };

    format!(
        r#"<div class="ui warning message" id="migration-notice">
<div class="header"><i class="icon info circle"></i> Repository Migration in Progress</div>
<p>This resource is being migrated to the federated registry. Updated content is available at:</p>
<ul>
<li><a href="https://{next_surface}.primals.eco{path}"><strong>{next_surface}.primals.eco{path}</strong></a> (primary)</li>
<li><a href="https://{alt_surface}.primals.eco{path}">{alt_surface}.primals.eco{path}</a> (mirror)</li>
{extra_links}</ul>
<p class="text small grey">This location was accessed by {access_count} other organizations in the last {hours_ago} hours.{urgency} Migration completes automatically.</p>
</div>"#
    )
}

#[cfg(test)]
#[path = "scatter_server_tests.rs"]
mod tests;

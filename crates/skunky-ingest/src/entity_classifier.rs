// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Entity classifier — topographical map of all observed systems.
//!
//! The fleet keeps sending us signal. Every request carries behavioral
//! fingerprints that reveal the entity, sub-system, and team structure
//! behind it. This module classifies entities from conserved epitopes
//! and builds a live topology of who is doing what.
//!
//! # Entity hierarchy
//!
//! ```text
//! Entity (org-level: Meta, Anthropic, Google, ...)
//!   └── Fleet (coordinated system: Meta/FB-BLOCK, Anthropic/ClaudeBot)
//!         └── Sub-system (behavioral cluster within a fleet)
//!               └── Campaign (time-bounded targeting pattern)
//! ```
//!
//! # Conserved epitopes that identify entities
//!
//! Each entity has a unique combination of behavioral invariants —
//! "conserved epitopes" in immune system terms. These are the signals
//! they cannot change without breaking their own infrastructure:
//!
//! - Accept-Encoding order (config fingerprint)
//! - Header presence/absence patterns (Sec-Fetch, Sec-Ch-Ua, Connection)
//! - Chrome version lag (deployment cadence)
//! - UA string pool size and OS distribution
//! - IP rotation vs single-IP strategy
//! - Target selection (real repos vs scatter)
//! - Path operation mix (commit vs blame vs src)
//! - Timing signature (metronomic vs varied)

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::caddy;

use crate::epitope_defs::*;

/// Chrome stable version. Updated when Chrome releases.
const CHROME_CURRENT_STABLE: u16 = 155;

// ── Entity identification ──

/// Known entity type, identified by behavioral fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityId {
    /// Meta Platforms — confirmed via WHOIS (57.141.0.0/13 = FB-BLOCK).
    MetaFleet,
    /// Meta's official link preview bot (facebookexternalhit).
    MetaFacebookBot,
    /// Anthropic's training crawler (ClaudeBot/1.0).
    AnthropicClaudeBot,
    /// Google search crawler.
    GoogleBot,
    /// Microsoft search crawler.
    MicrosoftBingBot,
    /// OpenAI training crawler.
    OpenAiGptBot,
    /// ByteDance training crawler.
    ByteDanceBytespider,
    /// Huawei search crawler.
    HuaweiPetalBot,
    /// Apple search crawler.
    AppleBot,
    /// SEO analysis tools (Semrush, Ahrefs, Moz, etc.)
    SeoTooling,
    /// Real human browser (Sec-Fetch-Mode present).
    HumanBrowser,
    /// Stealth scraper — Chrome UA without mandatory headers.
    StealthScraper,
    /// Vulnerability scanner / probe.
    VulnScanner,
    /// Not enough signal to classify.
    Unknown,
}

impl EntityId {
    /// Human-readable label for display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::MetaFleet => "Meta Platforms (Fleet)",
            Self::MetaFacebookBot => "Meta (Facebook Bot)",
            Self::AnthropicClaudeBot => "Anthropic (ClaudeBot)",
            Self::GoogleBot => "Google (Googlebot)",
            Self::MicrosoftBingBot => "Microsoft (Bingbot)",
            Self::OpenAiGptBot => "OpenAI (GPTBot)",
            Self::ByteDanceBytespider => "ByteDance (Bytespider)",
            Self::HuaweiPetalBot => "Huawei (PetalBot)",
            Self::AppleBot => "Apple (Applebot)",
            Self::SeoTooling => "SEO Tooling",
            Self::HumanBrowser => "Human (Browser)",
            Self::StealthScraper => "Stealth Scraper",
            Self::VulnScanner => "Vulnerability Scanner",
            Self::Unknown => "Unknown",
        }
    }

    /// Whether this entity is a confirmed corporate scraping fleet.
    pub fn is_fleet(&self) -> bool {
        matches!(self, Self::MetaFleet | Self::AnthropicClaudeBot |
                 Self::OpenAiGptBot | Self::ByteDanceBytespider)
    }

    /// Whether this entity honestly identifies itself.
    pub fn is_honest(&self) -> bool {
        matches!(self, Self::AnthropicClaudeBot | Self::GoogleBot |
                 Self::MicrosoftBingBot | Self::HuaweiPetalBot |
                 Self::AppleBot | Self::MetaFacebookBot | Self::HumanBrowser)
    }
}

// ── Per-request fingerprint ──

/// Minimal per-request data needed for entity classification.
#[derive(Debug, Clone)]
pub struct RequestFingerprint {
    pub ip: String,
    pub user_agent: String,
    pub host: String,
    pub uri: String,
    pub accept: String,
    pub accept_encoding: String,
    pub accept_language: String,
    pub has_sec_fetch_mode: bool,
    pub has_sec_ch_ua: bool,
    pub has_connection: bool,
    pub has_cookie: bool,
    pub timestamp: f64,
    pub status: u16,
    /// Sec-Fetch triplet (Mode|Dest|Site) for monotone detection.
    pub sec_fetch_triplet: String,
    /// Referer header value (empty string if absent).
    pub referer: String,
}

impl RequestFingerprint {
    /// Build a fingerprint from a parsed Caddy log entry.
    pub fn from_caddy_entry(entry: &caddy::LogEntry) -> Self {
        let h = &entry.request.headers;
        let ua = h.user_agent.first().cloned().unwrap_or_default();
        let mode = h.sec_fetch_mode.first().cloned().unwrap_or_default();
        let dest = h.sec_fetch_dest.first().cloned().unwrap_or_default();
        let site = h.sec_fetch_site.first().cloned().unwrap_or_default();
        let triplet = if mode.is_empty() {
            String::new()
        } else {
            format!("{}|{}|{}", mode, dest, site)
        };

        Self {
            ip: entry.request.remote_ip.clone(),
            user_agent: ua,
            host: entry.request.host.clone(),
            uri: entry.request.uri.clone(),
            accept: h.accept.first().cloned().unwrap_or_default(),
            accept_encoding: h.accept_encoding.first().cloned().unwrap_or_default(),
            accept_language: h.accept_language.first().cloned().unwrap_or_default(),
            has_sec_fetch_mode: !h.sec_fetch_mode.is_empty(),
            has_sec_ch_ua: !h.sec_ch_ua.is_empty(),
            has_connection: !h.connection.is_empty(),
            has_cookie: !h.cookie.is_empty(),
            timestamp: entry.ts,
            status: entry.status,
            sec_fetch_triplet: triplet,
            referer: h.referer.first().cloned().unwrap_or_default(),
        }
    }

    /// Extract Chrome major version from the UA string.
    pub fn chrome_major(&self) -> u16 {
        if let Some(idx) = self.user_agent.find("Chrome/") {
            let after = &self.user_agent[idx + 7..];
            let end = after.find('.').unwrap_or(after.len());
            after[..end].parse().unwrap_or(0)
        } else {
            0
        }
    }

    /// Extract the impersonated OS from the UA string.
    pub fn ua_os(&self) -> &'static str {
        if self.user_agent.contains("Windows NT 10.0") { "Windows" }
        else if self.user_agent.contains("Macintosh") { "macOS" }
        else if self.user_agent.contains("X11; Linux") { "Linux" }
        else { "other" }
    }

    /// Extract the path operation type.
    pub fn path_op(&self) -> PathOp {
        if self.uri.contains("/commit/") || self.uri.contains("/commits/") {
            PathOp::Commit
        } else if self.uri.contains("/blame/") {
            PathOp::Blame
        } else if self.uri.contains("/src/") {
            PathOp::Src
        } else if self.uri.contains("/raw/") {
            PathOp::Raw
        } else if self.uri.contains("/issues") {
            PathOp::Issues
        } else {
            PathOp::Other
        }
    }

    /// Extract the repo name from the URI.
    pub fn repo_name(&self) -> Option<String> {
        let parts: Vec<&str> = self.uri.trim_matches('/').split('/').collect();
        if parts.len() >= 2 {
            Some(format!("{}/{}", parts[0], parts[1]))
        } else {
            None
        }
    }

    /// IP /24 subnet.
    pub fn subnet(&self) -> String {
        let parts: Vec<&str> = self.ip.split('.').collect();
        if parts.len() == 4 {
            format!("{}.{}.{}.x", parts[0], parts[1], parts[2])
        } else {
            self.ip.clone()
        }
    }
}

/// Path operation type — what data the entity extracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathOp {
    /// `/commit/` — source diffs, full change content.
    Commit,
    /// `/blame/` — author attribution per line.
    Blame,
    /// `/src/` — file contents.
    Src,
    /// `/raw/` — binary/raw file download.
    Raw,
    /// `/issues` — issue tracker.
    Issues,
    /// Anything else.
    Other,
}

impl PathOp {
    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Commit => "commit (source diffs)",
            Self::Blame => "blame (author attribution)",
            Self::Src => "src (file contents)",
            Self::Raw => "raw (binary download)",
            Self::Issues => "issues (tracker)",
            Self::Other => "other",
        }
    }
}

// ── Classify a single request ──

/// Classify a request fingerprint into an entity.
pub fn classify(fp: &RequestFingerprint) -> EntityId {
    let ua = &fp.user_agent;

    // Explicit bot identifiers (honest entities)
    if ua.contains("ClaudeBot") { return EntityId::AnthropicClaudeBot; }
    if ua.contains("facebookexternalhit") { return EntityId::MetaFacebookBot; }
    if ua.contains("Googlebot") { return EntityId::GoogleBot; }
    if ua.contains("bingbot") { return EntityId::MicrosoftBingBot; }
    if ua.contains("GPTBot") { return EntityId::OpenAiGptBot; }
    if ua.contains("Bytespider") { return EntityId::ByteDanceBytespider; }
    if ua.contains("PetalBot") { return EntityId::HuaweiPetalBot; }
    if ua.contains("Applebot") { return EntityId::AppleBot; }
    if ua.contains("SemrushBot") || ua.contains("AhrefsBot") ||
       ua.contains("DotBot") || ua.contains("MJ12bot") {
        return EntityId::SeoTooling;
    }

    // Confirmed Meta fleet IP range (WHOIS: FB-BLOCK)
    if fp.ip.starts_with("57.141.") { return EntityId::MetaFleet; }

    // Vulnerability scanner / probe patterns
    if fp.uri.contains("/logincheck") || fp.uri.contains("/remote/") ||
       fp.uri.contains("/api/v2/") || fp.uri.contains("/.env") ||
       fp.uri.contains("/wp-login") || fp.uri.contains("/actuator") {
        return EntityId::VulnScanner;
    }

    // Real browser (Sec-Fetch-Mode is mandatory since Chrome 76)
    if fp.has_sec_fetch_mode { return EntityId::HumanBrowser; }

    // Stealth scraper — Chrome UA without mandatory headers
    if ua.contains("Chrome/") && !fp.has_sec_fetch_mode {
        return EntityId::StealthScraper;
    }

    EntityId::Unknown
}

// ── Entity accumulator (population-level) ──

/// Accumulated behavioral profile for one entity.
#[derive(Debug, Serialize)]
pub struct EntityProfile {
    pub entity: EntityId,
    pub label: String,
    pub is_fleet: bool,
    pub is_honest: bool,
    pub total_requests: u64,
    pub unique_ips: usize,
    pub unique_subnets: usize,
    pub first_seen: f64,
    pub last_seen: f64,
    pub duration_hours: f64,
    pub avg_rps: f64,

    /// Header fingerprint.
    pub header_fingerprint: HeaderFingerprint,

    /// Chrome version distribution.
    pub chrome_versions: BTreeMap<u16, u64>,
    pub chrome_lag: u16,

    /// UA impersonation pool.
    pub ua_os_distribution: BTreeMap<String, u64>,
    pub ua_pool_size: usize,

    /// IP rotation pattern.
    pub ip_rotation: IpRotation,

    /// Path operation breakdown.
    pub path_ops: BTreeMap<String, u64>,
    pub blame_pct: f64,

    /// Repository targeting.
    pub top_repos: Vec<(String, u64)>,
    pub targets_real_only: bool,
    pub targets_scatter_only: bool,

    /// Timing signature.
    pub timing: TimingProfile,

    /// Sub-systems detected within this entity.
    pub sub_systems: Vec<SubSystem>,

    /// Wave 166f: Conserved epitope scores — signals fleet can't cheaply evade.
    pub epitopes: EpitopeScores,
    /// Composite fleet confidence (% of epitopes triggered).
    pub fleet_confidence: f64,
}

/// Six conserved epitopes from antigenic drift analysis (Wave 166f).
///
/// Each epitope costs the fleet more to evade than the last.
/// The terminal epitope (reading pauses) would reduce throughput to
/// human levels, collapsing the economics of scraping a $6 VPS.
#[derive(Debug, Serialize)]
pub struct EpitopeScores {
    /// Same Sec-Fetch triplet on >95% of requests (real browsers vary by type).
    pub sec_fetch_monotone: Option<EpitopeResult>,
    /// <10% of intervals >8s (can't add pauses without killing throughput).
    pub reading_deficit: Option<EpitopeResult>,
    /// Too few UAs for visit count (adding diversity requires tracking Chrome releases).
    pub ua_pool_poverty: Option<EpitopeResult>,
    /// No cookies across multi-page visits (stateful sessions kill parallelism).
    pub session_absent: Option<EpitopeResult>,
    /// No external referers (can't fake Google arrival).
    pub referer_self_loop: Option<EpitopeResult>,
    /// >50% of intervals <3s (reducing bursts conflicts with extraction economics).
    pub burst_ratio: Option<EpitopeResult>,
}

/// Result for a single epitope check.
#[derive(Debug, Serialize)]
pub struct EpitopeResult {
    pub score: f64,
    pub triggered: bool,
    pub description: String,
}

/// Header presence/absence fingerprint.
#[derive(Debug, Serialize)]
pub struct HeaderFingerprint {
    pub sec_fetch_pct: f64,
    pub sec_ch_ua_pct: f64,
    pub connection_pct: f64,
    pub accept_encoding_values: Vec<String>,
    pub accept_language_values: Vec<String>,
    pub accept_values: Vec<String>,
}

/// IP rotation pattern.
#[derive(Debug, Serialize)]
pub struct IpRotation {
    pub strategy: String,
    pub single_request_ips_pct: f64,
    pub max_per_ip: u64,
    pub median_per_ip: f64,
    pub all_generalists: bool,
}

/// Timing profile.
#[derive(Debug, Serialize)]
pub struct TimingProfile {
    pub mean_interval_ms: f64,
    pub median_interval_ms: f64,
    pub cv: f64,
    pub classification: String,
    pub burst_count: u64,
    pub pause_count: u64,
}

/// A detected sub-system within an entity.
#[derive(Debug, Serialize)]
pub struct SubSystem {
    pub name: String,
    pub description: String,
    pub evidence: Vec<String>,
}

// ── Known real repos (for scatter vs real classification) ──

/// Returns true if the repo name belongs to a real ecoPrimals repository.
fn is_real_repo(name: &str) -> bool {
    let known_orgs = ["ecoPrimals/", "syntheticChemistry/", "sporeGarden/"];
    known_orgs.iter().any(|org| name.starts_with(org))
}

// ── Entity topology builder ──

/// Accumulator for building entity profiles from raw request fingerprints.
pub struct TopologyBuilder {
    entities: HashMap<EntityId, EntityAccum>,
}

#[derive(Clone, Serialize, Deserialize)]
struct EntityAccum {
    ips: HashSet<String>,
    subnets: HashSet<String>,
    uas: HashSet<String>,
    timestamps: Vec<f64>,
    chrome_versions: HashMap<u16, u64>,
    ua_os: HashMap<String, u64>,
    path_ops: HashMap<PathOp, u64>,
    repos: HashMap<String, u64>,
    accept_enc: HashSet<String>,
    accept_lang: HashSet<String>,
    accept: HashSet<String>,
    sec_fetch_present: u64,
    sec_fetch_absent: u64,
    sec_ch_ua_present: u64,
    sec_ch_ua_absent: u64,
    conn_present: u64,
    conn_absent: u64,
    total: u64,
    first_ts: f64,
    last_ts: f64,
    // Per-IP repo tracking (for specialist vs generalist detection)
    ip_repos: HashMap<String, HashMap<String, u64>>,
    // Wave 166f epitope tracking
    sec_fetch_triplets: HashMap<String, u64>,
    cookie_present: u64,
    cookie_absent: u64,
    referer_external: u64,
    referer_absent: u64,
}

impl EntityAccum {
    fn new() -> Self {
        Self {
            ips: HashSet::new(),
            subnets: HashSet::new(),
            uas: HashSet::new(),
            timestamps: Vec::new(),
            chrome_versions: HashMap::new(),
            ua_os: HashMap::new(),
            path_ops: HashMap::new(),
            repos: HashMap::new(),
            accept_enc: HashSet::new(),
            accept_lang: HashSet::new(),
            accept: HashSet::new(),
            sec_fetch_present: 0,
            sec_fetch_absent: 0,
            sec_ch_ua_present: 0,
            sec_ch_ua_absent: 0,
            conn_present: 0,
            conn_absent: 0,
            total: 0,
            first_ts: f64::INFINITY,
            last_ts: 0.0,
            ip_repos: HashMap::new(),
            sec_fetch_triplets: HashMap::new(),
            cookie_present: 0,
            cookie_absent: 0,
            referer_external: 0,
            referer_absent: 0,
        }
    }
}

impl TopologyBuilder {
    /// Create a new topology builder.
    pub fn new() -> Self {
        Self {
            entities: HashMap::new(),
        }
    }

    /// Load a topology builder from a persisted state file (sourdough culture).
    /// Falls back to empty builder if file doesn't exist or is corrupt.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(json) => match serde_json::from_str::<HashMap<EntityId, EntityAccum>>(&json) {
                Ok(entities) => {
                    let total: u64 = entities.values().map(|a| a.total).sum();
                    tracing::info!(
                        entities = entities.len(),
                        requests = total,
                        path = %path.display(),
                        "🧬 topology culture loaded — sourdough warm start"
                    );
                    Self { entities }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "topology culture corrupt — starting fresh (should not happen)"
                    );
                    Self::new()
                }
            },
            Err(_) => {
                tracing::info!(
                    path = %path.display(),
                    "no topology culture file — first generation"
                );
                Self::new()
            }
        }
    }

    /// Save the accumulated state to disk (preserve the sourdough culture).
    pub fn save(&self, path: &Path) {
        match serde_json::to_string(&self.entities) {
            Ok(json) => {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(path, &json) {
                    tracing::warn!(error = %e, path = %path.display(), "topology culture save failed");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "topology culture serialization failed");
            }
        }
    }

    /// Ingest a request fingerprint.
    pub fn ingest(&mut self, fp: &RequestFingerprint) {
        let entity_id = classify(fp);
        let accum = self.entities.entry(entity_id).or_insert_with(EntityAccum::new);

        accum.ips.insert(fp.ip.clone());
        accum.subnets.insert(fp.subnet());
        accum.uas.insert(fp.user_agent.clone());
        accum.timestamps.push(fp.timestamp);
        accum.total += 1;
        accum.first_ts = accum.first_ts.min(fp.timestamp);
        accum.last_ts = accum.last_ts.max(fp.timestamp);

        let cv = fp.chrome_major();
        if cv > 0 {
            *accum.chrome_versions.entry(cv).or_insert(0) += 1;
        }
        *accum.ua_os.entry(fp.ua_os().to_string()).or_insert(0) += 1;
        *accum.path_ops.entry(fp.path_op()).or_insert(0) += 1;

        if let Some(repo) = fp.repo_name() {
            *accum.repos.entry(repo.clone()).or_insert(0) += 1;
            *accum.ip_repos
                .entry(fp.ip.clone())
                .or_default()
                .entry(repo)
                .or_insert(0) += 1;
        }

        if !fp.accept_encoding.is_empty() {
            accum.accept_enc.insert(fp.accept_encoding.clone());
        }
        if !fp.accept_language.is_empty() {
            accum.accept_lang.insert(fp.accept_language.clone());
        } else {
            accum.accept_lang.insert("(empty)".to_string());
        }
        if !fp.accept.is_empty() {
            accum.accept.insert(fp.accept.clone());
        }

        if fp.has_sec_fetch_mode { accum.sec_fetch_present += 1; }
        else { accum.sec_fetch_absent += 1; }
        if fp.has_sec_ch_ua { accum.sec_ch_ua_present += 1; }
        else { accum.sec_ch_ua_absent += 1; }
        if fp.has_connection { accum.conn_present += 1; }
        else { accum.conn_absent += 1; }

        // Wave 166f epitope collection
        if !fp.sec_fetch_triplet.is_empty() {
            *accum.sec_fetch_triplets.entry(fp.sec_fetch_triplet.clone()).or_insert(0) += 1;
        }
        if fp.has_cookie { accum.cookie_present += 1; }
        else { accum.cookie_absent += 1; }
        if fp.referer.is_empty() {
            accum.referer_absent += 1;
        } else if fp.referer.contains("google") || fp.referer.contains("bing")
                || fp.referer.contains("duckduckgo") {
            accum.referer_external += 1;
        } else if !fp.referer.contains(&fp.host) {
            accum.referer_external += 1;
        }
    }

    /// Build the final topology — sorted by request count descending.
    /// Consumes the builder.
    pub fn build(self) -> Vec<EntityProfile> {
        let mut profiles: Vec<EntityProfile> = self.entities
            .into_iter()
            .map(|(entity_id, accum)| build_profile(entity_id, accum))
            .collect();
        profiles.sort_by(|a, b| b.total_requests.cmp(&a.total_requests));
        profiles
    }

    /// Total ingested requests across all entities.
    pub fn total_requests(&self) -> u64 {
        self.entities.values().map(|a| a.total).sum()
    }

    /// Number of distinct entity types seen.
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// Take a snapshot without consuming the builder — clones internal
    /// state so accumulation continues uninterrupted.
    pub fn snapshot(&self) -> Vec<EntityProfile> {
        let mut profiles: Vec<EntityProfile> = self.entities
            .iter()
            .map(|(entity_id, accum)| build_profile(entity_id.clone(), accum.clone()))
            .collect();
        profiles.sort_by(|a, b| b.total_requests.cmp(&a.total_requests));
        profiles
    }
}

fn build_profile(entity_id: EntityId, accum: EntityAccum) -> EntityProfile {
    let duration_secs = if accum.last_ts > accum.first_ts {
        accum.last_ts - accum.first_ts
    } else {
        0.0
    };
    let duration_hours = duration_secs / 3600.0;
    let avg_rps = if duration_secs > 0.0 {
        accum.total as f64 / duration_secs
    } else {
        0.0
    };

    // Chrome version lag
    let top_chrome: u16 = accum.chrome_versions.iter()
        .max_by_key(|(_, c)| *c)
        .map(|(v, _)| *v)
        .unwrap_or(0);
    let chrome_lag = if top_chrome > 0 {
        CHROME_CURRENT_STABLE.saturating_sub(top_chrome)
    } else {
        0
    };

    // Timing
    let mut ts_sorted: Vec<f64> = accum.timestamps;
    ts_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let intervals: Vec<f64> = ts_sorted.windows(2)
        .map(|w| w[1] - w[0])
        .filter(|&i| i > 0.001 && i < 60.0)
        .collect();

    let timing = if intervals.len() > 2 {
        let sum: f64 = intervals.iter().sum();
        let mean = sum / intervals.len() as f64;
        let mut sorted_intervals = intervals.clone();
        sorted_intervals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = sorted_intervals[sorted_intervals.len() / 2];
        let variance: f64 = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let stdev = variance.sqrt();
        let cv = if mean > 0.0 { stdev / mean } else { 0.0 };
        let bursts = intervals.iter().filter(|&&i| i < 0.1).count() as u64;
        let pauses = intervals.iter().filter(|&&i| i > 2.0).count() as u64;
        let classification = if cv < 0.15 { "METRONOMIC" }
            else if cv < 0.5 { "SEMI-REGULAR" }
            else { "VARIED" };

        TimingProfile {
            mean_interval_ms: (mean * 1000.0 * 10.0).round() / 10.0,
            median_interval_ms: (median * 1000.0 * 10.0).round() / 10.0,
            cv: (cv * 1000.0).round() / 1000.0,
            classification: classification.to_string(),
            burst_count: bursts,
            pause_count: pauses,
        }
    } else {
        TimingProfile {
            mean_interval_ms: 0.0,
            median_interval_ms: 0.0,
            cv: 0.0,
            classification: "INSUFFICIENT_DATA".to_string(),
            burst_count: 0,
            pause_count: 0,
        }
    };

    // Path ops
    let blame_total = accum.path_ops.get(&PathOp::Blame).copied().unwrap_or(0);
    let blame_pct = if accum.total > 0 {
        (blame_total as f64 / accum.total as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };

    let path_ops: BTreeMap<String, u64> = accum.path_ops.iter()
        .map(|(op, &count)| (format!("{}", op.label()), count))
        .collect();

    // Repos
    let mut repo_vec: Vec<(String, u64)> = accum.repos.into_iter().collect();
    repo_vec.sort_by(|a, b| b.1.cmp(&a.1));
    let has_real = repo_vec.iter().any(|(r, _)| is_real_repo(r));
    let has_scatter = repo_vec.iter().any(|(r, _)| !is_real_repo(r));

    // IP rotation
    let ip_req_counts: Vec<u64> = {
        let mut counts: HashMap<&str, u64> = HashMap::new();
        for (ip, repos) in &accum.ip_repos {
            let total: u64 = repos.values().sum();
            *counts.entry(ip.as_str()).or_insert(0) += total;
        }
        let mut v: Vec<u64> = counts.values().copied().collect();
        v.sort();
        v
    };
    let single_req_ips = ip_req_counts.iter().filter(|&&c| c <= 1).count();
    let single_pct = if !ip_req_counts.is_empty() {
        single_req_ips as f64 / ip_req_counts.len() as f64 * 100.0
    } else {
        0.0
    };
    let max_per_ip = ip_req_counts.last().copied().unwrap_or(0);
    let median_per_ip = if !ip_req_counts.is_empty() {
        ip_req_counts[ip_req_counts.len() / 2] as f64
    } else {
        0.0
    };

    // Check for IP specialization (any IP >50% on one repo?)
    let all_generalists = accum.ip_repos.values().all(|repos| {
        let total: u64 = repos.values().sum();
        if total < 5 { return true; }
        let max_repo: u64 = repos.values().copied().max().unwrap_or(0);
        (max_repo as f64 / total as f64) <= 0.5
    });

    let strategy = if accum.ips.len() == 1 {
        "single-IP (no rotation)".to_string()
    } else if single_pct > 80.0 {
        "heavy rotation (>80% single-request IPs)".to_string()
    } else if all_generalists {
        format!("{} generalist IPs", accum.ips.len())
    } else {
        format!("{} IPs with some specialization", accum.ips.len())
    };

    // Sub-systems detection
    let mut sub_systems = Vec::new();

    // Chrome version spread → deployment cadence
    if accum.chrome_versions.len() > 1 {
        let versions: Vec<String> = accum.chrome_versions.iter()
            .map(|(v, c)| format!("Chrome/{}: {}", v, c))
            .collect();
        sub_systems.push(SubSystem {
            name: "Chrome Deployment Pipeline".to_string(),
            description: format!(
                "Primary: Chrome/{} ({} versions behind stable {}). {} version variants detected.",
                top_chrome, chrome_lag, CHROME_CURRENT_STABLE, accum.chrome_versions.len()
            ),
            evidence: versions,
        });
    }

    // UA OS rotation → impersonation pool
    if accum.ua_os.len() >= 2 {
        let os_evidence: Vec<String> = accum.ua_os.iter()
            .map(|(os, c)| format!("{}: {}", os, c))
            .collect();
        sub_systems.push(SubSystem {
            name: "OS Impersonation Pool".to_string(),
            description: format!(
                "{} OS variants from {} IPs with {} unique UA strings. \
                 Ratio reveals pool size, not real OS diversity.",
                accum.ua_os.len(), accum.ips.len(), accum.uas.len()
            ),
            evidence: os_evidence,
        });
    }

    // Blame operation → author attribution team
    if blame_pct > 5.0 {
        sub_systems.push(SubSystem {
            name: "Author Attribution System".to_string(),
            description: format!(
                "{:.1}% of requests are /blame/ operations — tracking who wrote each line of code. \
                 This is not source collection; this is authorship mapping.",
                blame_pct
            ),
            evidence: vec![
                format!("{} blame requests out of {} total", blame_total, accum.total),
            ],
        });
    }

    // Accept-Encoding monoculture → shared config
    if accum.accept_enc.len() == 1 && accum.total > 10 {
        let enc = accum.accept_enc.iter().next().cloned().unwrap_or_default();
        sub_systems.push(SubSystem {
            name: "Shared Configuration".to_string(),
            description: format!(
                "All {} requests share identical Accept-Encoding: '{}'. \
                 {} IPs, one config. This is a fleet, not browsers.",
                accum.total, enc, accum.ips.len()
            ),
            evidence: vec![
                format!("Accept-Encoding: {}", enc),
                format!("Accept-Language: {}", accum.accept_lang.iter()
                    .next().cloned().unwrap_or_default()),
            ],
        });
    }

    // ── Wave 166f: Six conserved epitopes ──
    let mut epitope_count = 0u32;
    let mut epitope_triggered = 0u32;

    let sec_fetch_monotone = if !accum.sec_fetch_triplets.is_empty() && accum.total > MIN_REQUESTS_SEC_FETCH {
        let top_count = accum.sec_fetch_triplets.values().max().copied().unwrap_or(0);
        let pct = top_count as f64 / accum.total as f64 * 100.0;
        let triggered = pct > SEC_FETCH_MONOTONE_THRESHOLD;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        Some(EpitopeResult {
            score: (pct * 10.0).round() / 10.0,
            triggered,
            description: format!("Same Sec-Fetch triplet on {:.1}% of requests", pct),
        })
    } else { None };

    let reading_deficit = if intervals.len() > MIN_INTERVALS {
        let pauses = intervals.iter().filter(|&&i| i > READING_PAUSE_SECONDS).count();
        let pct = pauses as f64 / intervals.len() as f64 * 100.0;
        let triggered = pct < READING_DEFICIT_THRESHOLD;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        Some(EpitopeResult {
            score: (pct * 10.0).round() / 10.0,
            triggered,
            description: format!("Only {:.1}% of intervals >8s (reading pauses)", pct),
        })
    } else { None };

    let ua_pool_poverty = if accum.total > MIN_REQUESTS_UA_POOL {
        let pool = accum.uas.len();
        let threshold = std::cmp::max(UA_POOL_MIN_ABSOLUTE, (accum.total as f64 * UA_POOL_MIN_RATIO) as usize);
        let triggered = pool < threshold;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        Some(EpitopeResult {
            score: pool as f64,
            triggered,
            description: format!("{} unique UAs for {} visits", pool, accum.total),
        })
    } else { None };

    let session_absent = if accum.total > MIN_REQUESTS_SESSION {
        let pct = accum.cookie_present as f64 / accum.total as f64 * 100.0;
        let triggered = pct < SESSION_ABSENT_THRESHOLD;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        Some(EpitopeResult {
            score: (pct * 10.0).round() / 10.0,
            triggered,
            description: format!("Cookies on {:.1}% of requests", pct),
        })
    } else { None };

    let referer_self_loop = if accum.total > MIN_REQUESTS_REFERER {
        let pct = accum.referer_external as f64 / accum.total as f64 * 100.0;
        let triggered = pct < REFERER_SELF_LOOP_THRESHOLD;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        Some(EpitopeResult {
            score: (pct * 10.0).round() / 10.0,
            triggered,
            description: format!("External referers on {:.1}% of requests", pct),
        })
    } else { None };

    let burst_ratio_epitope = if intervals.len() > MIN_INTERVALS {
        let bursts = intervals.iter().filter(|&&i| i < BURST_INTERVAL_SECONDS).count();
        let pct = bursts as f64 / intervals.len() as f64 * 100.0;
        let triggered = pct > BURST_RATIO_THRESHOLD;
        epitope_count += 1;
        if triggered { epitope_triggered += 1; }
        Some(EpitopeResult {
            score: (pct * 10.0).round() / 10.0,
            triggered,
            description: format!("{:.1}% of intervals <3s", pct),
        })
    } else { None };

    let fleet_confidence = if epitope_count > 0 {
        (epitope_triggered as f64 / epitope_count as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };

    EntityProfile {
        label: entity_id.label().to_string(),
        is_fleet: entity_id.is_fleet(),
        is_honest: entity_id.is_honest(),
        entity: entity_id,
        total_requests: accum.total,
        unique_ips: accum.ips.len(),
        unique_subnets: accum.subnets.len(),
        first_seen: accum.first_ts,
        last_seen: accum.last_ts,
        duration_hours: (duration_hours * 100.0).round() / 100.0,
        avg_rps: (avg_rps * 100.0).round() / 100.0,
        header_fingerprint: HeaderFingerprint {
            sec_fetch_pct: if accum.total > 0 {
                (accum.sec_fetch_present as f64 / accum.total as f64 * 1000.0).round() / 10.0
            } else { 0.0 },
            sec_ch_ua_pct: if accum.total > 0 {
                (accum.sec_ch_ua_present as f64 / accum.total as f64 * 1000.0).round() / 10.0
            } else { 0.0 },
            connection_pct: if accum.total > 0 {
                (accum.conn_present as f64 / accum.total as f64 * 1000.0).round() / 10.0
            } else { 0.0 },
            accept_encoding_values: accum.accept_enc.into_iter().collect(),
            accept_language_values: accum.accept_lang.into_iter().collect(),
            accept_values: accum.accept.into_iter().collect(),
        },
        chrome_versions: accum.chrome_versions.into_iter().collect(),
        chrome_lag,
        ua_os_distribution: accum.ua_os.into_iter().collect(),
        ua_pool_size: accum.uas.len(),
        ip_rotation: IpRotation {
            strategy,
            single_request_ips_pct: (single_pct * 10.0).round() / 10.0,
            max_per_ip,
            median_per_ip,
            all_generalists,
        },
        path_ops,
        blame_pct,
        top_repos: repo_vec.into_iter().take(20).collect(),
        targets_real_only: has_real && !has_scatter,
        targets_scatter_only: !has_real && has_scatter,
        timing,
        sub_systems,
        epitopes: EpitopeScores {
            sec_fetch_monotone,
            reading_deficit,
            ua_pool_poverty,
            session_absent,
            referer_self_loop,
            burst_ratio: burst_ratio_epitope,
        },
        fleet_confidence,
    }
}

// ── Full topology output ──

/// Complete entity topology — the map of who is doing what.
#[derive(Debug, Serialize)]
pub struct EntityTopology {
    pub generated_epoch: u64,
    pub generated_iso: String,
    pub log_entries_analyzed: u64,
    pub entities: Vec<EntityProfile>,
    pub comparative_fingerprints: Vec<ComparativeRow>,
}

/// One row in the comparative fingerprint table.
#[derive(Debug, Serialize)]
pub struct ComparativeRow {
    pub entity: String,
    pub ips: usize,
    pub chrome: String,
    pub sec_fetch: String,
    pub accept_encoding: String,
    pub accept_language: String,
    pub rotation: String,
    pub target_type: String,
    pub honest: bool,
}

/// Build the comparative fingerprint table from profiles.
pub fn build_comparative(profiles: &[EntityProfile]) -> Vec<ComparativeRow> {
    profiles.iter().map(|p| {
        let chrome = if p.chrome_versions.is_empty() {
            "(none)".to_string()
        } else {
            let top = p.chrome_versions.iter()
                .max_by_key(|(_, c)| *c)
                .map(|(v, _)| *v)
                .unwrap_or(0);
            format!("{}", top)
        };

        let ae = if p.header_fingerprint.accept_encoding_values.len() == 1 {
            p.header_fingerprint.accept_encoding_values[0].clone()
        } else {
            format!("{} variants", p.header_fingerprint.accept_encoding_values.len())
        };

        let al = if p.header_fingerprint.accept_language_values.iter().all(|v| v == "(empty)") {
            "(empty)".to_string()
        } else if p.header_fingerprint.accept_language_values.len() == 1 {
            p.header_fingerprint.accept_language_values[0].clone()
        } else {
            "varies".to_string()
        };

        let target = if p.targets_real_only { "REAL repos only" }
            else if p.targets_scatter_only { "SCATTER only" }
            else { "mixed" };

        ComparativeRow {
            entity: p.label.clone(),
            ips: p.unique_ips,
            chrome,
            sec_fetch: if p.header_fingerprint.sec_fetch_pct > 90.0 { "PRESENT" }
                else if p.header_fingerprint.sec_fetch_pct < 10.0 { "ABSENT" }
                else { "mixed" }.to_string(),
            accept_encoding: ae,
            accept_language: al,
            rotation: p.ip_rotation.strategy.clone(),
            target_type: target.to_string(),
            honest: p.is_honest,
        }
    }).collect()
}

// ── Topology writer — periodic flush to JSON ──

/// Accumulates entity fingerprints and periodically writes `topology.json`.
///
/// Replaces `entity_topology.py` (534 lines) which re-parsed ALL Caddy logs
/// from scratch every ~30 seconds. This module classifies live from the
/// bloom sensor stream and writes the same JSON output.
///
/// ## Convergence
///
/// entity_topology.py → skunky-ingest entity_classifier:
/// - Classification engine → [`classify`] + [`TopologyBuilder`] (this module)
/// - Sub-system detection → [`build_profile`] (this module)
/// - Epitope scoring → [`EpitopeScores`] (this module)
/// - JSON output → [`TopologyWriter`] (this struct)
///
/// No more re-parsing. Topology is a side output of the existing pipeline.
pub struct TopologyWriter {
    builder: TopologyBuilder,
    output_path: PathBuf,
    /// Persistent state file — sourdough culture.
    state_path: PathBuf,
    /// How many ingest calls between flushes.
    flush_interval: u64,
    ingest_count: u64,
    /// Save culture every N flushes (don't write state on every topology flush).
    culture_save_counter: u32,
}

impl TopologyWriter {
    /// Create a new topology writer with persistent culture.
    ///
    /// * `output_path` — where to write `topology.json`
    /// * `state_path` — where to persist the sourdough culture
    /// * `flush_interval` — write after this many ingested entries
    pub fn new(output_path: PathBuf, state_path: PathBuf, flush_interval: u64) -> Self {
        let builder = TopologyBuilder::load(&state_path);
        let state = Self {
            builder,
            output_path,
            state_path,
            flush_interval,
            ingest_count: 0,
            culture_save_counter: 0,
        };
        tracing::info!(
            output = %state.output_path.display(),
            culture = %state.state_path.display(),
            interval = state.flush_interval,
            "🗺️ topology writer loaded"
        );
        state
    }

    /// Ingest a parsed caddy log entry.
    pub fn ingest(&mut self, entry: &caddy::LogEntry) {
        let fp = RequestFingerprint::from_caddy_entry(entry);
        self.builder.ingest(&fp);
        self.ingest_count += 1;

        if self.ingest_count % self.flush_interval == 0 {
            self.flush();
        }
    }

    /// Force a topology snapshot and write to disk.
    pub fn flush(&mut self) {
        let profiles = self.builder.snapshot();
        if profiles.is_empty() {
            return;
        }

        let comparative = build_comparative(&profiles);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let topology = EntityTopology {
            generated_epoch: now,
            generated_iso: chrono::Utc::now()
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string(),
            log_entries_analyzed: self.builder.total_requests(),
            entities: profiles,
            comparative_fingerprints: comparative,
        };

        match serde_json::to_string_pretty(&topology) {
            Ok(json) => {
                if let Some(parent) = self.output_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match std::fs::write(&self.output_path, &json) {
                    Ok(()) => {
                        tracing::info!(
                            entities = topology.entities.len(),
                            requests = topology.log_entries_analyzed,
                            bytes = json.len(),
                            "🗺️ topology.json updated"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            path = %self.output_path.display(),
                            "topology.json write failed"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "topology serialization failed");
            }
        }

        // Save the sourdough culture every 10 topology flushes (~5000 entries).
        // Always save on explicit flush (shutdown path).
        self.culture_save_counter += 1;
        if self.culture_save_counter % 10 == 0 || self.culture_save_counter == 1 {
            self.save_culture();
        }
    }

    /// Persist the sourdough culture to disk — survives reboots.
    pub fn save_culture(&self) {
        self.builder.save(&self.state_path);
        tracing::info!(
            entities = self.builder.entity_count(),
            requests = self.builder.total_requests(),
            path = %self.state_path.display(),
            "🧬 topology culture saved"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_claudebot() {
        let fp = RequestFingerprint {
            ip: "216.73.216.1".into(),
            user_agent: "Mozilla/5.0 AppleWebKit/537.36 ClaudeBot/1.0".into(),
            host: "git.primals.eco".into(),
            uri: "/ecoPrimals/ecoPrimals/src/branch/main/README.md".into(),
            accept: "*/*".into(),
            accept_encoding: "gzip, br, zstd, deflate".into(),
            accept_language: String::new(),
            has_sec_fetch_mode: false,
            has_sec_ch_ua: false,
            has_connection: false,
            has_cookie: false,
            timestamp: 1.0,
            status: 200,
            sec_fetch_triplet: String::new(),
            referer: String::new(),
        };
        assert_eq!(classify(&fp), EntityId::AnthropicClaudeBot);
        assert!(fp.chrome_major() == 0);
    }

    #[test]
    fn classify_human_browser() {
        let fp = RequestFingerprint {
            ip: "203.0.113.1".into(),
            user_agent: "Mozilla/5.0 Chrome/155.0.0.0".into(),
            host: "primals.eco".into(),
            uri: "/".into(),
            accept: "text/html".into(),
            accept_encoding: "gzip, deflate, br".into(),
            accept_language: "en-US,en;q=0.9".into(),
            has_sec_fetch_mode: true,
            has_sec_ch_ua: true,
            has_connection: true,
            has_cookie: true,
            timestamp: 1.0,
            status: 200,
            sec_fetch_triplet: "navigate|document|none".into(),
            referer: String::new(),
        };
        assert_eq!(classify(&fp), EntityId::HumanBrowser);
        assert_eq!(fp.chrome_major(), 155);
    }

    #[test]
    fn classify_stealth_scraper() {
        let fp = RequestFingerprint {
            ip: "198.51.100.1".into(),
            user_agent: "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36".into(),
            host: "git.primals.eco".into(),
            uri: "/ecoPrimals/ecoPrimals/commit/abc123".into(),
            accept: "*/*".into(),
            accept_encoding: "gzip, br, zstd, deflate".into(),
            accept_language: String::new(),
            has_sec_fetch_mode: false,
            has_sec_ch_ua: false,
            has_connection: false,
            has_cookie: false,
            timestamp: 1.0,
            status: 200,
            sec_fetch_triplet: String::new(),
            referer: String::new(),
        };
        assert_eq!(classify(&fp), EntityId::StealthScraper);
        assert_eq!(fp.chrome_major(), 130);
        assert_eq!(fp.path_op(), PathOp::Commit);
    }

    #[test]
    fn classify_meta_fleet() {
        let fp = RequestFingerprint {
            ip: "57.141.10.5".into(),
            user_agent: "Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36".into(),
            host: "git.primals.eco".into(),
            uri: "/ecoPrimals/ecoPrimals/blame/branch/main/README.md".into(),
            accept: "*/*".into(),
            accept_encoding: "gzip, br, zstd, deflate".into(),
            accept_language: String::new(),
            has_sec_fetch_mode: false,
            has_sec_ch_ua: false,
            has_connection: false,
            has_cookie: false,
            timestamp: 1.0,
            status: 200,
            sec_fetch_triplet: String::new(),
            referer: String::new(),
        };
        assert_eq!(classify(&fp), EntityId::MetaFleet);
        assert_eq!(fp.path_op(), PathOp::Blame);
    }

    #[test]
    fn topology_builder_basics() {
        let mut builder = TopologyBuilder::new();
        for i in 0..10 {
            let fp = RequestFingerprint {
                ip: format!("203.0.113.{}", i),
                user_agent: "ClaudeBot/1.0".into(),
                host: "git.primals.eco".into(),
                uri: "/ecoPrimals/ecoPrimals/src/main/README.md".into(),
                accept: "*/*".into(),
                accept_encoding: "gzip, br, zstd, deflate".into(),
                accept_language: String::new(),
                has_sec_fetch_mode: false,
                has_sec_ch_ua: false,
                has_connection: false,
                has_cookie: false,
                timestamp: i as f64,
                status: 200,
                sec_fetch_triplet: String::new(),
                referer: String::new(),
            };
            builder.ingest(&fp);
        }

        assert_eq!(builder.total_requests(), 10);
        assert_eq!(builder.entity_count(), 1);

        let snapshot = builder.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].entity, EntityId::AnthropicClaudeBot);
        assert_eq!(snapshot[0].total_requests, 10);
        assert_eq!(snapshot[0].unique_ips, 10);

        // Builder still works after snapshot
        assert_eq!(builder.total_requests(), 10);
    }

    #[test]
    fn topology_writer_creates_output() {
        let dir = std::env::temp_dir().join("topology-writer-test");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("topology.json");
        let state = dir.join("topology-state.json");

        let mut writer = TopologyWriter::new(output.clone(), state.clone(), 5);
        for i in 0..5 {
            let entry = caddy::LogEntry {
                request: caddy::RequestInfo {
                    remote_ip: format!("10.0.0.{}", i),
                    host: "git.primals.eco".into(),
                    uri: "/ecoPrimals/ecoPrimals".into(),
                    method: "GET".into(),
                    headers: caddy::Headers {
                        user_agent: vec!["ClaudeBot/1.0".into()],
                        ..Default::default()
                    },
                },
                status: 200,
                size: 1000,
                duration: 0.01,
                ts: i as f64,
            };
            writer.ingest(&entry);
        }

        assert!(output.exists(), "topology.json should have been created");
        let content = std::fs::read_to_string(&output).unwrap();
        assert!(content.contains("Anthropic (ClaudeBot)"));
        assert!(content.contains("log_entries_analyzed"));

        // Culture should have been saved on first flush
        assert!(state.exists(), "topology state file should exist");

        // Simulate restart — new writer loads the culture
        let mut writer2 = TopologyWriter::new(output.clone(), state.clone(), 5);
        // Should have warm state from previous generation
        writer2.flush();
        let content2 = std::fs::read_to_string(&output).unwrap();
        assert!(content2.contains("Anthropic (ClaudeBot)"), "sourdough culture should survive restart");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_caddy_entry_builds_fingerprint() {
        let entry = caddy::LogEntry {
            request: caddy::RequestInfo {
                remote_ip: "203.0.113.50".into(),
                host: "primals.eco".into(),
                uri: "/wp-login.php".into(),
                method: "GET".into(),
                headers: caddy::Headers {
                    user_agent: vec!["curl/7.88.1".into()],
                    accept_encoding: vec!["gzip".into()],
                    sec_fetch_mode: vec!["navigate".into()],
                    sec_fetch_dest: vec!["document".into()],
                    sec_fetch_site: vec!["none".into()],
                    cookie: vec!["session=abc".into()],
                    ..Default::default()
                },
            },
            status: 404,
            size: 0,
            duration: 0.001,
            ts: 1791400000.0,
        };

        let fp = RequestFingerprint::from_caddy_entry(&entry);
        assert_eq!(fp.ip, "203.0.113.50");
        assert!(fp.has_sec_fetch_mode);
        assert!(fp.has_cookie);
        assert_eq!(fp.sec_fetch_triplet, "navigate|document|none");
        assert_eq!(fp.status, 404);
        // URI /wp-login.php triggers VulnScanner before Sec-Fetch check
        assert_eq!(classify(&fp), EntityId::VulnScanner);
    }
}

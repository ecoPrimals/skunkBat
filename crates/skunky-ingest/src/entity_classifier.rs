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

use serde::Serialize;

/// Chrome stable version. Updated when Chrome releases.
const CHROME_CURRENT_STABLE: u16 = 155;

// ── Entity identification ──

/// Known entity type, identified by behavioral fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
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
    pub timestamp: f64,
    pub status: u16,
}

impl RequestFingerprint {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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
    }

    /// Build the final topology — sorted by request count descending.
    pub fn build(self) -> Vec<EntityProfile> {
        let mut profiles: Vec<EntityProfile> = self.entities
            .into_iter()
            .map(|(entity_id, accum)| build_profile(entity_id, accum))
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

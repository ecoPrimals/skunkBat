// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Bloom sensor — afferent signal accumulation for the membrane.
//!
//! While [`crate::fleet::FleetAggregator`] detects threats (efferent/motor),
//! the bloom sensor detects **positive signal**: who is reading, what domains
//! attract attention, which referrer sources deliver traffic, and whether
//! cross-domain bridge-seeking behavior is increasing.
//!
//! In SAME DAVE terms, this is the **afferent dorsal channel** — sensory
//! input traveling TO the organism's central awareness.
//!
//! Mirrors the FleetAggregator window pattern: accumulates per-request
//! entries, flushes population-level observations at window boundaries,
//! and writes rolling signal state to `/run/membrane/bloom.signal`.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::time::Duration;

use serde::Serialize;

use crate::caddy::LogEntry;

// ── Content domain classification ──

/// Content domain — what part of the information system a URI maps to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub enum ContentDomain {
    Philosophy,
    Science,
    LabNotebooks,
    LabSprings,
    Lab,
    Architecture,
    Methodology,
    Products,
    Thesis,
    Technical,
    Guidestone,
    Data,
    Glossary,
    Story,
    Contact,
    Collaborators,
    Homepage,
    /// Detroit evidence site domains.
    Signal,
    Coverage,
    Network,
    /// Unclassified but real content.
    Other,
    /// Static assets, meta files — skip these.
    Meta,
}

impl ContentDomain {
    /// Human-readable key for JSON signal output.
    #[allow(missing_docs)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Philosophy => "philosophy",
            Self::Science => "science",
            Self::LabNotebooks => "lab-notebooks",
            Self::LabSprings => "lab-springs",
            Self::Lab => "lab",
            Self::Architecture => "architecture",
            Self::Methodology => "methodology",
            Self::Products => "products",
            Self::Thesis => "thesis",
            Self::Technical => "technical",
            Self::Guidestone => "guidestone",
            Self::Data => "data",
            Self::Glossary => "glossary",
            Self::Story => "story",
            Self::Contact => "contact",
            Self::Collaborators => "collaborators",
            Self::Homepage => "homepage",
            Self::Signal => "signal",
            Self::Coverage => "coverage",
            Self::Network => "network",
            Self::Other => "other",
            Self::Meta => "meta",
        }
    }
}

/// Classify a URI into a content domain.
pub fn classify_domain(uri: &str) -> ContentDomain {
    let u = uri.to_ascii_lowercase();
    let path = u.split('?').next().unwrap_or(&u);

    // Meta/static — skip these from bloom counts
    if path.ends_with(".js")
        || path.ends_with(".css")
        || path.ends_with(".png")
        || path.ends_with(".svg")
        || path.ends_with(".ico")
        || path.ends_with(".xml")
        || path.ends_with(".woff2")
        || path.ends_with(".woff")
        || path.contains("/assets/")
        || path.contains("/avatars/")
        || path.contains("robots.txt")
        || path.contains("wp-admin")
        || path.contains("xmlrpc")
        || path.contains(".well-known")
        || path.contains("favicon")
        || path.ends_with(".php")
    {
        return ContentDomain::Meta;
    }

    if path.contains("/philosophy/") { return ContentDomain::Philosophy; }
    if path.contains("/science/") { return ContentDomain::Science; }
    if path.contains("/lab/notebooks/") { return ContentDomain::LabNotebooks; }
    if path.contains("/lab/springs/") { return ContentDomain::LabSprings; }
    if path.contains("/lab/") { return ContentDomain::Lab; }
    if path.contains("/architecture/") { return ContentDomain::Architecture; }
    if path.contains("/methodology/") { return ContentDomain::Methodology; }
    if path.contains("/products/") { return ContentDomain::Products; }
    if path.contains("/thesis/") { return ContentDomain::Thesis; }
    if path.contains("/technical/") { return ContentDomain::Technical; }
    if path.contains("/guidestone/") { return ContentDomain::Guidestone; }
    if path.contains("/data/") { return ContentDomain::Data; }
    if path.contains("/glossary") { return ContentDomain::Glossary; }
    if path.contains("/story/") { return ContentDomain::Story; }
    if path.contains("/contact") { return ContentDomain::Contact; }
    if path.contains("/collaborat") { return ContentDomain::Collaborators; }
    if path.contains("/signal") { return ContentDomain::Signal; }
    if path.contains("/coverage") { return ContentDomain::Coverage; }
    if path.contains("/network") { return ContentDomain::Network; }

    if path == "/" || path.is_empty() { return ContentDomain::Homepage; }

    ContentDomain::Other
}

// ── Reader type classification ──

/// What kind of entity is making the request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReaderType {
    /// Browser with proper headers, not matching any bot/AI pattern.
    Human,
    /// AI retrieval agent (ChatGPT-User, Reflectionbot, etc.).
    AiAgent,
    /// Search engine crawler (Googlebot, Bingbot, etc.).
    SearchCrawler,
    /// Scanner/probe (no UA, no Accept-Encoding, PHP probes, etc.).
    Scanner,
    /// Git protocol client.
    GitClient,
}

impl ReaderType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::AiAgent => "ai-agent",
            Self::SearchCrawler => "search-crawler",
            Self::Scanner => "scanner",
            Self::GitClient => "git-client",
        }
    }
}

/// Known AI retrieval agent UA substrings.
const AI_AGENT_MARKERS: &[&str] = &[
    "chatgpt", "gptbot", "claude", "reflectionbot",
];

/// Known search crawler UA substrings.
const CRAWLER_MARKERS: &[&str] = &[
    "bot", "crawl", "spider", "facebookext", "meta-external",
    "google", "bing", "yandex", "semrush", "ahref", "bytespider",
    "petalbot", "amazonbot", "applebot", "dataprovider",
    "dotbot", "blexbot", "seznambot", "sogou", "baidu",
    "ccbot", "dataforseobot", "qwant", "ia_archiver",
    "archive.org_bot", "slurp",
];

/// Known fleet subnet prefixes — organizations crawling with stealth UAs.
///
/// These bypass UA-based detection by rotating real browser user-agents
/// across dozens of IPs. Identified by subnet analysis, not enumeration.
/// This is the bridge to bingoCube maze classification: behavioral
/// subnets replace the old UA siege epitope.
const FLEET_SUBNETS: &[&str] = &[
    // Anthropic (ClaudeBot) — AWS infrastructure
    "216.73.216.",
    // Meta Platforms Ireland — 40+ IPs, rotating UAs, Dublin DC
    "57.141.20.", "57.141.21.", "57.141.22.", "57.141.23.",
    "57.141.24.", "57.141.25.", "57.141.26.", "57.141.27.",
    "57.141.28.", "57.141.29.", "57.141.30.", "57.141.31.",
    // Meta alt ranges (same abuse contact: domain@fb.com)
    "57.141.0.", "57.141.1.", "57.141.2.", "57.141.3.",
];

/// Check if an IP belongs to a known fleet subnet.
pub fn is_fleet_subnet(ip: &str) -> bool {
    FLEET_SUBNETS.iter().any(|prefix| ip.starts_with(prefix))
}

/// Classify with full request context — IP, path, headers.
///
/// This is the evolution point toward bingoCube maze classification.
/// UA matching is a siege epitope from earlier generations. The real
/// classifier uses behavioral context: subnet identity, path patterns,
/// header fingerprints. UA is the last resort, not the first signal.
pub fn classify_reader_contextual(
    ua: &str,
    accept_encoding: &str,
    accept_language: &str,
    ip: &str,
    path: &str,
) -> ReaderType {
    // Layer 1: Subnet identity (strongest signal, no UA needed)
    if is_fleet_subnet(ip) {
        return ReaderType::AiAgent;
    }

    // Layer 2: Path behavioral pattern
    // Commit-hash URL walk = fleet scraping git history.
    // Real humans don't hit /repo/commit/da43fe62 directly.
    if is_commit_walk_path(path) {
        // Only if UA also looks synthetic (real user clicking one link is fine)
        if accept_language.is_empty() {
            return ReaderType::AiAgent;
        }
    }

    // Layer 3: UA classification (legacy siege epitope — will shrink as
    // bingoCube maze classifier absorbs more behavioral dimensions)
    classify_reader(ua, accept_encoding, accept_language)
}

/// Detect Forgejo commit-walk paths — deep git scraping behavior.
pub fn is_commit_walk_path(path: &str) -> bool {
    // /org/repo/commit/HASH, /org/repo/blame/commit/HASH, /org/repo/src/commit/HASH
    let lower = path.to_ascii_lowercase();
    if !lower.contains("/commit/") {
        return false;
    }
    // Check if the segment after /commit/ looks like a hex hash
    if let Some(idx) = lower.find("/commit/") {
        let after = &lower[idx + 8..];
        let hash_part = after.split('/').next().unwrap_or("");
        // Git hashes are 7-40 hex chars
        hash_part.len() >= 7
            && hash_part.len() <= 40
            && hash_part.chars().all(|c| c.is_ascii_hexdigit())
    } else {
        false
    }
}

/// Classify a request into a reader type (UA-only, legacy path).
///
/// Prefer [`classify_reader_contextual`] which adds IP and path signals.
pub fn classify_reader(ua: &str, accept_encoding: &str, accept_language: &str) -> ReaderType {
    let ua_lower = ua.to_ascii_lowercase();

    if ua_lower.contains("git/") {
        return ReaderType::GitClient;
    }

    for marker in AI_AGENT_MARKERS {
        if ua_lower.contains(marker) {
            return ReaderType::AiAgent;
        }
    }

    for marker in CRAWLER_MARKERS {
        if ua_lower.contains(marker) {
            return ReaderType::SearchCrawler;
        }
    }

    // Scanner heuristics: empty UA, no Accept-Encoding, PHP probes
    if ua.is_empty() || (accept_encoding.is_empty() && accept_language.is_empty()) {
        return ReaderType::Scanner;
    }

    ReaderType::Human
}

// ── Referrer source classification ──

/// Where the visitor came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub enum ReferrerSource {
    Google,
    DuckDuckGo,
    Bing,
    ChatGpt,
    /// Referrer from within primals.eco / sporeprint / detroit.
    Internal,
    /// No Referer header — direct navigation or bookmark.
    Direct,
    /// Other external referrer.
    External,
}

impl ReferrerSource {
    /// Human-readable key for JSON signal output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::DuckDuckGo => "duckduckgo",
            Self::Bing => "bing",
            Self::ChatGpt => "chatgpt",
            Self::Internal => "internal",
            Self::Direct => "direct",
            Self::External => "external",
        }
    }
}

/// Classify a Referer header value into a referrer source.
pub fn classify_referrer(referer: &str) -> ReferrerSource {
    if referer.is_empty() {
        return ReferrerSource::Direct;
    }

    let r = referer.to_ascii_lowercase();

    if r.contains("primals.eco") || r.contains("sporeprint") || r.contains("detroit") {
        return ReferrerSource::Internal;
    }
    if r.contains("google.") { return ReferrerSource::Google; }
    if r.contains("duckduckgo.") { return ReferrerSource::DuckDuckGo; }
    if r.contains("bing.") { return ReferrerSource::Bing; }
    if r.contains("chatgpt.") || r.contains("openai.") { return ReferrerSource::ChatGpt; }

    ReferrerSource::External
}

// ── Bloom sensor ──

/// Minimal per-request record for bloom analysis.
struct BloomEntry {
    domain: ContentDomain,
    reader: ReaderType,
    referrer: ReferrerSource,
    lang: String,
    host: String,
    ts: f64,
    /// Hashed IP for session-level cross-domain detection.
    /// Raw IP is never stored.
    ip_hash: u64,
}

/// Population-level bloom observation — the afferent signal snapshot.
#[derive(Debug, Serialize)]
#[allow(missing_docs)]
pub struct BloomObservation {
    pub window_start: f64,
    pub window_end: f64,
    pub total_requests: u32,
    pub unique_ips: u32,
    pub domains: HashMap<String, u32>,
    pub readers: HashMap<String, u32>,
    pub referrers: HashMap<String, u32>,
    pub languages: Vec<String>,
    pub cross_domain_sessions: u32,
    pub hosts: HashMap<String, u32>,
}

/// Hash an IP to a u64 for session tracking without storing the raw IP.
fn hash_ip(ip: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut h);
    h.finish()
}

/// Windowed bloom sensor — accumulates per-request entries and flushes
/// population-level observations at window boundaries.
pub struct BloomSensor {
    window: Duration,
    window_start: f64,
    entries: Vec<BloomEntry>,
}

impl BloomSensor {
    /// Create a new bloom sensor with the given window duration.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            window_start: 0.0,
            entries: Vec::with_capacity(128),
        }
    }

    /// Ingest a log entry. Returns a [`BloomObservation`] when the window closes.
    ///
    /// Accepts ALL hosts (not filtered like fleet). Skips meta/static assets.
    pub fn ingest(&mut self, entry: &LogEntry) -> Option<BloomObservation> {
        let domain = classify_domain(&entry.request.uri);
        if domain == ContentDomain::Meta {
            return None;
        }

        let ua = entry.request.headers.user_agent.first().map_or("", |s| s.as_str());
        let enc = entry.request.headers.accept_encoding.first().map_or("", |s| s.as_str());
        let lang_full = entry.request.headers.accept_language.first().map_or("", |s| s.as_str());
        let referer = entry.request.headers.referer.first().map_or("", |s| s.as_str());

        let reader = classify_reader_contextual(
            ua,
            enc,
            lang_full,
            &entry.request.remote_ip,
            &entry.request.uri,
        );
        let referrer_src = classify_referrer(referer);

        // Extract primary language code (e.g. "en-US" from "en-US,en;q=0.9")
        let lang = lang_full
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();

        let bloom_entry = BloomEntry {
            domain,
            reader,
            referrer: referrer_src,
            lang,
            host: entry.request.host.clone(),
            ts: entry.ts,
            ip_hash: hash_ip(&entry.request.remote_ip),
        };

        let window_secs = self.window.as_secs_f64();
        if self.window_start == 0.0 {
            self.window_start = entry.ts;
        }

        if entry.ts >= self.window_start + window_secs {
            let obs = self.flush();
            self.window_start = entry.ts;
            self.entries.clear();
            self.entries.push(bloom_entry);
            return obs;
        }

        self.entries.push(bloom_entry);
        None
    }

    /// Flush remaining entries (e.g. on shutdown).
    pub fn flush_remaining(&mut self) -> Option<BloomObservation> {
        if self.entries.is_empty() {
            return None;
        }
        self.flush()
    }

    /// Compute population-level observation from the current window.
    fn flush(&self) -> Option<BloomObservation> {
        if self.entries.is_empty() {
            return None;
        }

        let mut domains: HashMap<String, u32> = HashMap::new();
        let mut readers: HashMap<String, u32> = HashMap::new();
        let mut referrers: HashMap<String, u32> = HashMap::new();
        let mut hosts: HashMap<String, u32> = HashMap::new();
        let mut langs: HashSet<String> = HashSet::new();
        let mut unique_ips: HashSet<u64> = HashSet::new();

        // Track which domains each IP visits (for cross-domain detection)
        let mut ip_domains: HashMap<u64, HashSet<String>> = HashMap::new();

        let mut window_end = self.window_start;

        for e in &self.entries {
            *domains.entry(e.domain.as_str().to_string()).or_default() += 1;
            *readers.entry(e.reader.as_str().to_string()).or_default() += 1;
            *referrers.entry(e.referrer.as_str().to_string()).or_default() += 1;
            *hosts.entry(e.host.clone()).or_default() += 1;

            if !e.lang.is_empty() {
                langs.insert(e.lang.clone());
            }

            unique_ips.insert(e.ip_hash);

            // Track domains per IP (skip homepage/other for cross-domain)
            if e.domain != ContentDomain::Homepage && e.domain != ContentDomain::Other {
                ip_domains
                    .entry(e.ip_hash)
                    .or_default()
                    .insert(e.domain.as_str().to_string());
            }

            if e.ts > window_end {
                window_end = e.ts;
            }
        }

        let cross_domain = ip_domains.values().filter(|d| d.len() >= 2).count() as u32;

        let mut lang_vec: Vec<String> = langs.into_iter().collect();
        lang_vec.sort();

        Some(BloomObservation {
            window_start: self.window_start,
            window_end,
            total_requests: self.entries.len() as u32,
            unique_ips: unique_ips.len() as u32,
            domains,
            readers,
            referrers,
            languages: lang_vec,
            cross_domain_sessions: cross_domain,
            hosts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── classify_domain tests ──

    #[test]
    fn domain_philosophy() {
        assert_eq!(classify_domain("/philosophy/the-love-letter/"), ContentDomain::Philosophy);
    }

    #[test]
    fn domain_science() {
        assert_eq!(classify_domain("/science/22-zero-knowledge-medical-provenance/"), ContentDomain::Science);
    }

    #[test]
    fn domain_lab_notebooks() {
        assert_eq!(classify_domain("/lab/notebooks/exp-026-size-convergence/"), ContentDomain::LabNotebooks);
    }

    #[test]
    fn domain_lab_springs() {
        assert_eq!(classify_domain("/lab/springs/neuralspring/"), ContentDomain::LabSprings);
    }

    #[test]
    fn domain_lab_generic() {
        assert_eq!(classify_domain("/lab/gate-status/"), ContentDomain::Lab);
    }

    #[test]
    fn domain_architecture() {
        assert_eq!(classify_domain("/architecture/membrane-visibility/"), ContentDomain::Architecture);
    }

    #[test]
    fn domain_products() {
        assert_eq!(classify_domain("/products/lattice-qcd/"), ContentDomain::Products);
    }

    #[test]
    fn domain_homepage() {
        assert_eq!(classify_domain("/"), ContentDomain::Homepage);
    }

    #[test]
    fn domain_meta_css() {
        assert_eq!(classify_domain("/assets/css/index.css"), ContentDomain::Meta);
    }

    #[test]
    fn domain_meta_favicon() {
        assert_eq!(classify_domain("/favicon.svg"), ContentDomain::Meta);
    }

    #[test]
    fn domain_meta_php_probe() {
        assert_eq!(classify_domain("/wp-admin/install.php"), ContentDomain::Meta);
    }

    #[test]
    fn domain_detroit_signal() {
        assert_eq!(classify_domain("/signal/"), ContentDomain::Signal);
    }

    #[test]
    fn domain_detroit_coverage() {
        assert_eq!(classify_domain("/coverage/clutch-trial/"), ContentDomain::Coverage);
    }

    #[test]
    fn domain_query_string_stripped() {
        assert_eq!(classify_domain("/products/lattice-qcd/?ref=search"), ContentDomain::Products);
    }

    // ── classify_reader tests ──

    #[test]
    fn reader_human() {
        assert_eq!(
            classify_reader(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "gzip, deflate, br",
                "en-US,en;q=0.9",
            ),
            ReaderType::Human,
        );
    }

    #[test]
    fn reader_chatgpt() {
        assert_eq!(
            classify_reader(
                "Mozilla/5.0 AppleWebKit/537.36; compatible; ChatGPT-User/1.0",
                "gzip",
                "en-US,en;q=0.9",
            ),
            ReaderType::AiAgent,
        );
    }

    #[test]
    fn reader_reflectionbot() {
        assert_eq!(
            classify_reader(
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Reflectionbot/1.0",
                "gzip",
                "en-US",
            ),
            ReaderType::AiAgent,
        );
    }

    #[test]
    fn reader_googlebot() {
        assert_eq!(
            classify_reader("Googlebot/2.1 (+http://www.google.com/bot.html)", "gzip", ""),
            ReaderType::SearchCrawler,
        );
    }

    #[test]
    fn reader_bingbot() {
        assert_eq!(
            classify_reader(
                "Mozilla/5.0 AppleWebKit/537.36; compatible; bingbot/2.0",
                "gzip",
                "",
            ),
            ReaderType::SearchCrawler,
        );
    }

    #[test]
    fn reader_scanner_empty_ua() {
        assert_eq!(classify_reader("", "", ""), ReaderType::Scanner);
    }

    #[test]
    fn reader_scanner_no_headers() {
        assert_eq!(
            classify_reader("Mozilla/5.0", "", ""),
            ReaderType::Scanner,
        );
    }

    #[test]
    fn reader_git_client() {
        assert_eq!(classify_reader("git/2.43.0", "", ""), ReaderType::GitClient);
    }

    // ── classify_referrer tests ──

    #[test]
    fn referrer_direct() {
        assert_eq!(classify_referrer(""), ReferrerSource::Direct);
    }

    #[test]
    fn referrer_google() {
        assert_eq!(classify_referrer("https://www.google.com/"), ReferrerSource::Google);
    }

    #[test]
    fn referrer_duckduckgo() {
        assert_eq!(classify_referrer("https://duckduckgo.com/"), ReferrerSource::DuckDuckGo);
    }

    #[test]
    fn referrer_internal_sporeprint() {
        assert_eq!(
            classify_referrer("https://sporeprint.primals.eco/lab/springs/"),
            ReferrerSource::Internal,
        );
    }

    #[test]
    fn referrer_internal_primals() {
        assert_eq!(
            classify_referrer("https://primals.eco/"),
            ReferrerSource::Internal,
        );
    }

    #[test]
    fn referrer_bing() {
        assert_eq!(classify_referrer("https://www.bing.com/search?q=test"), ReferrerSource::Bing);
    }

    #[test]
    fn referrer_external() {
        assert_eq!(classify_referrer("https://example.com/link"), ReferrerSource::External);
    }

    // ── BloomSensor windowed accumulation tests ──

    #[test]
    fn sensor_window_flush() {
        use crate::caddy::{Headers, LogEntry, RequestInfo};

        let mut sensor = BloomSensor::new(Duration::from_secs(30));

        let make_entry = |ts: f64, uri: &str, host: &str, ip: &str| LogEntry {
            request: RequestInfo {
                remote_ip: ip.to_string(),
                host: host.to_string(),
                uri: uri.to_string(),
                method: "GET".to_string(),
                headers: Headers {
                    user_agent: vec!["Mozilla/5.0 Chrome/130".to_string()],
                    accept_encoding: vec!["gzip, deflate, br".to_string()],
                    accept_language: vec!["en-US,en;q=0.9".to_string()],
                    referer: vec![],
                    sec_fetch_mode: vec![],
                    sec_ch_ua: vec![],
                    accept: vec![],
                    connection: vec![],
                    sec_fetch_dest: vec![],
                    sec_fetch_site: vec![],
                    cookie: vec![],
                },
            },
            status: 200,
            size: 1024,
            duration: 0.05,
            ts,
        };

        // Window 1: 3 entries within 30s
        assert!(sensor.ingest(&make_entry(1000.0, "/science/paper1/", "sporeprint.primals.eco", "1.2.3.4")).is_none());
        assert!(sensor.ingest(&make_entry(1010.0, "/philosophy/love-letter/", "sporeprint.primals.eco", "1.2.3.4")).is_none());
        assert!(sensor.ingest(&make_entry(1020.0, "/products/lattice-qcd/", "sporeprint.primals.eco", "5.6.7.8")).is_none());

        // Entry beyond window triggers flush
        let obs = sensor.ingest(&make_entry(1031.0, "/lab/springs/", "sporeprint.primals.eco", "9.10.11.12"));
        assert!(obs.is_some());

        let obs = obs.unwrap();
        assert_eq!(obs.total_requests, 3);
        assert_eq!(obs.unique_ips, 2);
        assert_eq!(*obs.domains.get("science").unwrap_or(&0), 1);
        assert_eq!(*obs.domains.get("philosophy").unwrap_or(&0), 1);
        assert_eq!(*obs.domains.get("products").unwrap_or(&0), 1);
        assert_eq!(*obs.readers.get("human").unwrap_or(&0), 3);
        assert_eq!(*obs.referrers.get("direct").unwrap_or(&0), 3);
        assert!(obs.languages.contains(&"en-US".to_string()));
        // IP 1.2.3.4 visited science + philosophy = cross-domain
        assert_eq!(obs.cross_domain_sessions, 1);
    }

    #[test]
    fn sensor_skips_meta() {
        use crate::caddy::{Headers, LogEntry, RequestInfo};

        let mut sensor = BloomSensor::new(Duration::from_secs(30));

        let meta_entry = LogEntry {
            request: RequestInfo {
                remote_ip: "1.2.3.4".to_string(),
                host: "sporeprint.primals.eco".to_string(),
                uri: "/assets/css/index.css".to_string(),
                method: "GET".to_string(),
                headers: Headers::default(),
            },
            status: 200,
            size: 1024,
            duration: 0.01,
            ts: 1000.0,
        };

        assert!(sensor.ingest(&meta_entry).is_none());
        // No entries accumulated — meta was skipped
        let obs = sensor.flush_remaining();
        assert!(obs.is_none());
    }

    #[test]
    fn sensor_multi_host() {
        use crate::caddy::{Headers, LogEntry, RequestInfo};

        let mut sensor = BloomSensor::new(Duration::from_secs(30));

        let make = |ts: f64, uri: &str, host: &str| LogEntry {
            request: RequestInfo {
                remote_ip: "1.2.3.4".to_string(),
                host: host.to_string(),
                uri: uri.to_string(),
                method: "GET".to_string(),
                headers: Headers {
                    user_agent: vec!["Mozilla/5.0".to_string()],
                    accept_encoding: vec!["gzip".to_string()],
                    accept_language: vec!["ja,en-US;q=0.9".to_string()],
                    referer: vec!["https://www.google.com/".to_string()],
                    sec_fetch_mode: vec![],
                    sec_ch_ua: vec![],
                    accept: vec![],
                    connection: vec![],
                    sec_fetch_dest: vec![],
                    sec_fetch_site: vec![],
                    cookie: vec![],
                },
            },
            status: 200,
            size: 512,
            duration: 0.03,
            ts,
        };

        sensor.ingest(&make(1000.0, "/science/paper/", "sporeprint.primals.eco"));
        sensor.ingest(&make(1005.0, "/signal/", "detroit.primals.eco"));
        sensor.ingest(&make(1010.0, "/", "primals.eco"));

        let obs = sensor.flush_remaining().unwrap();
        assert_eq!(obs.total_requests, 3);
        assert_eq!(obs.unique_ips, 1);
        assert_eq!(*obs.hosts.get("sporeprint.primals.eco").unwrap(), 1);
        assert_eq!(*obs.hosts.get("detroit.primals.eco").unwrap(), 1);
        assert_eq!(*obs.hosts.get("primals.eco").unwrap(), 1);
        assert_eq!(*obs.referrers.get("google").unwrap(), 3);
        assert!(obs.languages.contains(&"ja".to_string()));
    }

    #[test]
    fn sensor_ai_agent_detection() {
        use crate::caddy::{Headers, LogEntry, RequestInfo};

        let mut sensor = BloomSensor::new(Duration::from_secs(30));

        let entry = LogEntry {
            request: RequestInfo {
                remote_ip: "10.0.0.1".to_string(),
                host: "sporeprint.primals.eco".to_string(),
                uri: "/science/22-zk-provenance/".to_string(),
                method: "GET".to_string(),
                headers: Headers {
                    user_agent: vec!["Mozilla/5.0 AppleWebKit/537.36; compatible; ChatGPT-User/1.0".to_string()],
                    accept_encoding: vec!["gzip".to_string()],
                    accept_language: vec!["en-US,en;q=0.9".to_string()],
                    referer: vec![],
                    sec_fetch_mode: vec![],
                    sec_ch_ua: vec![],
                    accept: vec![],
                    connection: vec![],
                    sec_fetch_dest: vec![],
                    sec_fetch_site: vec![],
                    cookie: vec![],
                },
            },
            status: 200,
            size: 2048,
            duration: 0.1,
            ts: 1000.0,
        };

        sensor.ingest(&entry);
        let obs = sensor.flush_remaining().unwrap();
        assert_eq!(*obs.readers.get("ai-agent").unwrap(), 1);
        assert_eq!(*obs.domains.get("science").unwrap(), 1);
    }

    // ── Fleet subnet tests ──

    #[test]
    fn fleet_subnet_anthropic() {
        assert!(is_fleet_subnet("216.73.216.239"));
        assert!(is_fleet_subnet("216.73.216.1"));
    }

    #[test]
    fn fleet_subnet_meta() {
        assert!(is_fleet_subnet("57.141.20.45"));
        assert!(is_fleet_subnet("57.141.20.1"));
        assert!(is_fleet_subnet("57.141.21.100"));
    }

    #[test]
    fn fleet_subnet_real_human() {
        assert!(!is_fleet_subnet("1.2.3.4"));
        assert!(!is_fleet_subnet("192.168.1.1"));
        assert!(!is_fleet_subnet("100.15.10.185"));
    }

    // ── Commit walk detection ──

    #[test]
    fn commit_walk_forgejo_paths() {
        assert!(is_commit_walk_path("/ecoPrimals/wateringHole/commit/da43fe62"));
        assert!(is_commit_walk_path("/ecoPrimals/toadStool/blame/commit/833e7fc6a59ae29039b0"));
        assert!(is_commit_walk_path("/ecoPrimals/toadStool/src/commit/63408ec2b5dc3c03"));
        assert!(is_commit_walk_path("/batch-processor/commit/36d546d9"));
    }

    #[test]
    fn commit_walk_not_content() {
        assert!(!is_commit_walk_path("/science/paper1/"));
        assert!(!is_commit_walk_path("/philosophy/love-letter/"));
        assert!(!is_commit_walk_path("/contribute"));
        assert!(!is_commit_walk_path("/"));
    }

    // ── Contextual classification tests ──

    #[test]
    fn contextual_meta_subnet_classified_fleet() {
        // Meta with perfect Chrome UA — subnet overrides UA
        assert_eq!(
            classify_reader_contextual(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "gzip, deflate, br, zstd",
                "en-US,en;q=0.9",
                "57.141.20.45",
                "/ecoPrimals/wateringHole/commit/abc123de",
            ),
            ReaderType::AiAgent,
        );
    }

    #[test]
    fn contextual_real_human_unaffected() {
        // Real human from a residential IP with proper headers
        assert_eq!(
            classify_reader_contextual(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "gzip, deflate, br",
                "en-US,en;q=0.9",
                "100.15.10.185",
                "/science/paper1/",
            ),
            ReaderType::Human,
        );
    }

    #[test]
    fn contextual_commit_walk_no_language() {
        // Unknown IP hitting commit paths without Accept-Language = fleet
        assert_eq!(
            classify_reader_contextual(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "gzip, deflate, br, zstd",
                "",
                "45.33.32.156",
                "/ecoPrimals/toadStool/commit/da43fe62",
            ),
            ReaderType::AiAgent,
        );
    }

    #[test]
    fn contextual_commit_walk_with_language_passes() {
        // Real user clicking one commit link (has Accept-Language)
        assert_eq!(
            classify_reader_contextual(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "gzip, deflate, br",
                "en-US,en;q=0.9",
                "100.15.10.185",
                "/ecoPrimals/toadStool/commit/da43fe62",
            ),
            ReaderType::Human,
        );
    }
}

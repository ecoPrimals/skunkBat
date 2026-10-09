// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Dashboard writer — generates `dashboard.json` for the signal site.
//!
//! Replaces `bloom_live.py` (793 lines) which tailed the Caddy log in a
//! separate Python process, duplicating the exact work skunky-ingest does.
//! This module accumulates per-IP behavioral data from the caddy stream
//! and writes `dashboard.json` in the same schema the signal site expects.
//!
//! ## Convergence
//!
//! bloom_live.py → skunky-ingest dashboard_writer:
//! - Classification engine → [`crate::bloom_sensor`] + [`crate::entity_classifier`]
//! - Per-IP tracking → [`IpProfile`] (this module)
//! - Epitope hashing → [`compute_epitope_hash`] (this module, BLAKE2b)
//! - L2 collision classification → [`classify_collision_l2`] (this module)
//! - Dashboard JSON formatting → [`DashboardWriter`] (this module)
//! - Sourdough culture → persistent state file
//!
//! No more duplicate log tailing. Dashboard is a side output of the pipeline.

#![allow(missing_docs)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::caddy;

// ── GEO/WHOIS lookup for known ranges ──

/// GEO lookup from known IP ranges — progressive subdivision.
///
/// Resolution sharpens as we identify more ranges from WHOIS data.
/// Country → region → city → ASN → fiber.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GeoInfo {
    org: String,
    country: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn_type: Option<String>,
}

/// (prefix, org, country, region, city, asn_type)
type GeoEntry = (&'static str, &'static str, &'static str, &'static str, &'static str, &'static str);

fn geo_lookup(ip: &str) -> GeoInfo {
    // Ordered longest-prefix-first to avoid false matches on short prefixes.
    // Progressive subdivision: as we identify ranges, we add region/city/ASN.
    let prefixes: &[GeoEntry] = &[
        // ── Meta Platforms ──
        ("57.141.20.", "Meta Platforms (FB-BLOCK)", "IE/US", "Dublin/Menlo Park", "Dublin DC", "datacenter"),
        ("57.141.", "Meta Platforms (FB-BLOCK)", "IE/US", "Dublin", "", "datacenter"),
        ("173.252.70.", "Meta Platforms", "US", "California", "Menlo Park", "datacenter"),
        ("173.252.107.", "Meta Platforms", "US", "California", "Menlo Park", "datacenter"),
        ("173.252.", "Meta Platforms", "US", "California", "", "datacenter"),
        // ── Anthropic ──
        ("216.73.216.", "Anthropic", "US", "California", "San Francisco", "datacenter"),
        // ── Cloud providers ──
        ("116.204.78.", "Huawei Cloud", "CN", "Guangdong", "Shenzhen", "cloud"),
        ("49.0.245.", "Huawei Cloud", "HK", "Hong Kong", "Hong Kong", "cloud"),
        ("119.12.174.", "Huawei Cloud", "HK", "Hong Kong", "Hong Kong", "cloud"),
        ("47.79.13.", "Alibaba Cloud", "US", "California", "San Mateo", "cloud"),
        ("47.79.", "Alibaba Cloud", "US", "California", "", "cloud"),
        ("16.216.88.", "HPE (Hewlett Packard Enterprise)", "US", "Texas", "Spring", "datacenter"),
        ("16.216.", "HPE (Hewlett Packard Enterprise)", "US", "Texas", "", "datacenter"),
        ("100.27.", "AWS", "US", "Virginia", "Ashburn", "cloud"),
        ("100.28.", "AWS", "US", "Virginia", "Ashburn", "cloud"),
        // ── Hosting/VPS ──
        ("79.139.58.", "RackForest (VPS)", "HU", "Budapest", "", "vps"),
        ("178.124.154.", "EvroRith", "BY", "Minsk", "Minsk", "hosting"),
        // ── ISP / Residential ──
        ("76.32.61.", "Charter Communications", "US", "Colorado", "Greenwood Village", "residential"),
        ("76.32.", "Charter Communications", "US", "Colorado", "", "residential"),
        ("174.168.153.", "Comcast Cable", "US", "New Jersey", "Mt Laurel", "residential"),
        ("174.168.", "Comcast Cable", "US", "New Jersey", "", "residential"),
        // ── Telecom ──
        ("180.153.197.", "ChinaNet Shanghai", "CN", "Shanghai", "Shanghai", "telecom"),
        ("180.153.", "ChinaNet Shanghai", "CN", "Shanghai", "", "telecom"),
        ("46.250.169.", "Unknown (EU allocation)", "EU", "", "", "unknown"),
        // ── Colocation / Transit ──
        ("65.49.20.", "Hurricane Electric", "US", "California", "Fremont", "colocation"),
        ("65.49.", "Hurricane Electric", "US", "California", "", "colocation"),
        // ── Search engines ──
        ("66.249.", "Google", "US", "California", "Mountain View", "datacenter"),
        ("157.55.", "Microsoft (Bing)", "US", "Washington", "Redmond", "datacenter"),
        // ── Self ──
        ("162.226.225.", "House network", "US", "Michigan", "", "self"),
        ("10.13.37.", "WireGuard mesh", "MESH", "", "", "self"),
    ];

    for entry in prefixes {
        if ip.starts_with(entry.0) {
            return GeoInfo {
                org: entry.1.to_string(),
                country: entry.2.to_string(),
                region: if entry.3.is_empty() { None } else { Some(entry.3.to_string()) },
                city: if entry.4.is_empty() { None } else { Some(entry.4.to_string()) },
                asn_type: if entry.5.is_empty() { None } else { Some(entry.5.to_string()) },
            };
        }
    }

    GeoInfo {
        org: "Unknown".to_string(),
        country: "??".to_string(),
        region: None,
        city: None,
        asn_type: None,
    }
}

// ── Per-IP behavioral profile ──

/// Accumulated behavioral data for one IP address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpProfile {
    pub requests: u64,
    pub first_seen: f64,
    pub last_seen: f64,
    pub is_fleet: bool,
    pub is_human: bool,
    /// True if UA matched a declared bot identity (commensal signal).
    pub is_declared_bot: bool,
    /// Top repos targeted: repo → count
    pub repos: HashMap<String, u32>,
    /// Path operation types: type → count
    pub path_types: HashMap<String, u32>,
    /// Status code distribution
    pub statuses: HashMap<u16, u32>,
    /// Accept-Encoding value (conserved epitope — first value wins)
    pub accept_encoding: Option<String>,
    /// Number of distinct UAs seen from this IP
    pub ua_pool_size: u16,
    /// Blame endpoint hits
    pub blame_count: u32,
    /// Commit endpoint hits
    pub commit_count: u32,
    /// Has Accept-Language header
    pub has_accept_lang: bool,
    /// Has loaded CSS/JS/font assets
    pub has_assets: bool,
    /// Has sent Referer header
    pub has_referer: bool,
    /// Has Sec-Fetch-Mode
    pub has_sec_fetch: bool,
    /// Has Cookie
    pub has_cookie: bool,
    /// Hosts visited
    pub host_count: u16,
    /// Computed epitope hash (None until >= 3 requests)
    pub epitope_hash: Option<String>,
    /// Accept header value (conserved epitope)
    pub accept: Option<String>,
}

impl IpProfile {
    pub fn new(ts: f64) -> Self {
        Self {
            requests: 0,
            first_seen: ts,
            last_seen: ts,
            is_fleet: false,
            is_human: false,
            is_declared_bot: false,
            repos: HashMap::new(),
            path_types: HashMap::new(),
            statuses: HashMap::new(),
            accept_encoding: None,
            ua_pool_size: 0,
            blame_count: 0,
            commit_count: 0,
            has_accept_lang: false,
            has_assets: false,
            has_referer: false,
            has_sec_fetch: false,
            has_cookie: false,
            host_count: 0,
            epitope_hash: None,
            accept: None,
        }
    }
}

// ── BingoCube Trio — Attention × Curiosity × Interaction scoring ──

/// Three-axis behavioral classification from the bingoCube oracle.
///
/// Each entity is scored on three orthogonal axes. The classification
/// determines which provenance braid receives the behavioral record:
/// - loamSpine (ledger/spine, WHERE) ← all classes
/// - rhizoCrypt (DAG, WHAT) ← commensal + sovereign
/// - sweetGrass (braid, WHO) ← sovereign only
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BingoCubeTrio {
    /// Reading depth: time between requests, path depth, varied pacing.
    pub attention: f32,
    /// Navigation breadth: unique paths, diverse hosts, repo exploration.
    pub curiosity: f32,
    /// Engagement depth: asset loads, CSS/JS fetches, referer chains.
    pub interaction: f32,
    /// Ecological classification from the trio shape.
    pub classification: TrioClass,
}

/// Ecological class — which kingdom an entity belongs to.
///
/// Referer is NOT an epitope. Privacy is always allowed.
/// Ghost promotes to Sovereign on behavioral evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrioClass {
    /// wave/0 — behavioral epitopes prove extraction without consent.
    /// Missing Sec-Fetch, missing Connection, metronomic timing, IP rotation.
    /// These are structural tells that can't be hidden by privacy tools.
    Parasite,
    /// photon/1 — declared identity, provides value (indexing, agentic).
    /// Says who it is in UA. Voluntarily participates in the protocol.
    Commensal,
    /// reaction/null — behavioral proof of human reading, privacy respected.
    /// Full browser stack + multi-request depth. Or promoted Ghost.
    Sovereign,
}

/// Score an IP profile on the Attention × Curiosity × Interaction axes
/// and classify into the ecological trio.
///
/// Scoring rules (from plan):
/// - **Parasite**: behavioral epitopes ONLY — no Sec-Fetch, no Accept-Language,
///   fleet-like UA pool. Structural tells, not privacy choices.
/// - **Commensal**: declared bot identity in UA. If you say who you are, commensal.
/// - **Sovereign**: multi-request behavioral depth — varied timing, asset loads,
///   path diversity. Ghost promotes after 3+ requests with depth signals.
/// - Referer is NOT an epitope — it is a privacy choice.
pub fn score_trio(profile: &IpProfile) -> BingoCubeTrio {
    // ── Attention: reading depth ──
    // Varied pacing between requests indicates human attention.
    // Metronomic fast pacing (< 1s avg) = machine extraction.
    let attention = {
        let time_span = (profile.last_seen - profile.first_seen).max(0.0);
        let avg_interval = if profile.requests > 1 {
            time_span / (profile.requests - 1) as f64
        } else {
            0.0
        };

        if profile.requests <= 1 {
            0.1_f32
        } else if avg_interval > 30.0 {
            0.9 // deep reading — long pauses between pages
        } else if avg_interval > 10.0 {
            0.75
        } else if avg_interval > 3.0 {
            0.55
        } else if avg_interval > 1.0 {
            0.35
        } else {
            0.12 // metronomic extraction pace
        }
    };

    // ── Curiosity: navigation breadth ──
    // How widely does the entity explore? Multiple paths, repos, hosts
    // indicate genuine interest vs single-target extraction.
    let curiosity = {
        let path_diversity = profile.path_types.len() as f32;
        let repo_diversity = profile.repos.len() as f32;
        let host_factor = profile.host_count as f32;

        let raw = (path_diversity / 6.0).min(1.0) * 0.3
            + (repo_diversity / 5.0).min(1.0) * 0.3
            + (host_factor / 3.0).min(1.0) * 0.4;
        raw.min(1.0)
    };

    // ── Interaction: engagement depth ──
    // Does the entity actually render and engage with content?
    // Asset loads, cookies, sec-fetch, blame reading = real engagement.
    let interaction = {
        let mut score = 0.0_f32;
        if profile.has_assets { score += 0.25; }  // loads CSS/JS/fonts
        if profile.has_sec_fetch { score += 0.20; } // real browser stack
        if profile.has_cookie { score += 0.15; }  // session engagement
        if profile.has_referer { score += 0.10; } // navigation chain (NOT required)
        if profile.blame_count > 0 { score += 0.15; } // reads code diffs
        if profile.host_count > 1 { score += 0.10; } // cross-references
        if profile.has_accept_lang { score += 0.05; } // locale-aware
        score.min(1.0)
    };

    // ── Classification ──
    let classification = classify_trio(profile, attention, curiosity, interaction);

    BingoCubeTrio {
        attention,
        curiosity,
        interaction,
        classification,
    }
}

/// Classify into the ecological trio based on profile signals + trio scores.
fn classify_trio(
    profile: &IpProfile,
    _attention: f32,
    curiosity: f32,
    interaction: f32,
) -> TrioClass {
    // Rule 1: Declared bot identity → Commensal.
    // If you say who you are in the UA, you're commensal. Period.
    if profile.is_declared_bot {
        return TrioClass::Commensal;
    }

    // Rule 2: Structural parasite tells — behavioral epitopes that
    // cannot be hidden by privacy tools because they are infrastructure-level.
    // No Sec-Fetch + no Accept-Language + fleet UA pool = machine scraper.
    if !profile.has_sec_fetch && !profile.has_accept_lang && profile.ua_pool_size > 2 {
        return TrioClass::Parasite;
    }
    // Already classified as fleet by the main classifier
    if profile.is_fleet && !profile.is_declared_bot {
        return TrioClass::Parasite;
    }

    // Rule 3: Sovereign — full browser stack with behavioral depth.
    // Has sec-fetch (real browser) + enough requests + engagement signals.
    if profile.has_sec_fetch && profile.requests >= 3 {
        if interaction > 0.3 || (curiosity > 0.2 && profile.has_accept_lang) {
            return TrioClass::Sovereign;
        }
    }

    // Rule 4: Ghost promotion — privacy-respecting entity with depth.
    // Ghost = has browser headers but no referer. Not suspicious —
    // could be Tor, VPN, direct navigation, strict privacy settings.
    // Promotes to Sovereign after 3+ requests with behavioral evidence.
    if profile.has_sec_fetch && profile.requests >= 3 && curiosity > 0.15 {
        return TrioClass::Sovereign;
    }

    // Rule 5: Single-request with browser headers → holding state.
    // Not enough evidence to classify. Default to Commensal (benefit of doubt).
    if profile.has_sec_fetch {
        return TrioClass::Commensal;
    }

    // Rule 6: No browser headers but behavioral depth signals → Commensal.
    // An agentic entity (AI agent acting for a human) may lack Sec-Fetch
    // but shows purposeful behavior: varied paths, multiple repos, referer chains.
    if profile.requests >= 3 && (curiosity > 0.2 || interaction > 0.2) {
        return TrioClass::Commensal;
    }

    // Rule 7: No browser headers, no depth → Parasite.
    TrioClass::Parasite
}

// ── IP hashing — ZK boundary ──

/// Hash an IP address to a u64 for storage without revealing the address.
///
/// Uses SipHash (via DefaultHasher) matching bloom_sensor.rs pattern.
/// IPs remain in memory for CaddyBridge fleet blocking (iptables needs
/// real IPs) but NEVER persist to state files.
pub fn hash_ip(ip: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut h);
    h.finish()
}

// ── Epitope hashing ──

/// Compute a short BLAKE2b collision hash of behavioral invariants.
///
/// These are CONSERVED INVARIANTS — signals the entity cannot change
/// without rebuilding their infrastructure:
/// - Accept-Encoding order (HTTP library fingerprint)
/// - UA pool size (1=honest, 3-4=impersonation fleet)
/// - Blame ratio (team structure indicator)
/// - Accept header value (client configuration)
/// - Accept-Language presence (browser vs bot)
fn compute_epitope_hash(profile: &IpProfile) -> String {
    use std::hash::{Hash, Hasher};

    let ae = profile.accept_encoding.as_deref().unwrap_or("");
    let ua_bucket = if profile.ua_pool_size <= 1 {
        "1"
    } else if profile.ua_pool_size <= 3 {
        "few"
    } else {
        "many"
    };
    let blame_ratio = if profile.commit_count > 0
        && profile.blame_count as f64 / profile.commit_count as f64 > 0.2
    {
        "high"
    } else {
        "low"
    };
    let accept = profile
        .accept
        .as_deref()
        .unwrap_or("")
        .get(..20)
        .unwrap_or(profile.accept.as_deref().unwrap_or(""));
    let has_lang = if profile.has_accept_lang { "y" } else { "n" };

    let epitope_vec = format!("{}|{}|{}|{}|{}", ae, ua_bucket, blame_ratio, accept, has_lang);

    // BLAKE2b-equivalent via SipHash (fast, good collision properties)
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    epitope_vec.hash(&mut hasher);
    let hash = hasher.finish();
    format!("{:08x}", hash as u32)
}

// ── L2 collision classification ──

/// Level 2 collision class — emergent behavioral categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CollisionClass {
    /// Loads assets, has referer, multi-page session
    Genuine,
    /// Single deep hit, 200 status, possibly has sec-fetch
    Agentic,
    /// Hits same paths as other IPs within coordination window.
    /// Reserved — coordination detector (10s sliding-window path index) not yet
    /// ported from bloom_live.py Wave 165i. See BLOOM_V3_COLLISION_CLASSIFICATION_LIVE_WAVE165I.md.
    #[allow(dead_code)]
    Coordinated,
    /// Fleet-like behavior (default)
    Fleet,
}

fn classify_collision_l2(profile: &IpProfile) -> CollisionClass {
    let total: u32 = profile.statuses.values().sum();
    if total == 0 {
        return CollisionClass::Fleet;
    }

    let status_200 = profile.statuses.get(&200).copied().unwrap_or(0)
        + profile.statuses.get(&308).copied().unwrap_or(0)
        + profile.statuses.get(&301).copied().unwrap_or(0);
    let ratio_200 = status_200 as f64 / total as f64;

    // Genuine: loads assets, has referer, multi-page session
    if profile.has_assets && profile.has_referer && total > 1 && ratio_200 > 0.5 {
        return CollisionClass::Genuine;
    }

    // Agentic: single deep hit, 200 status
    if ratio_200 > 0.5 && total <= 3 {
        return CollisionClass::Agentic;
    }

    // TODO(wave-next): Port coordination detector from bloom_live.py (Wave 165i).
    // Requires: DashboardCulture.path_recent_hits: HashMap<String, Vec<(String, f64)>>
    // — 10-second sliding window of (ip, timestamp) per path.
    // When another IP hits the same path within 10s: coordination_score > 0.
    // Branch: if coordination_score > 0 && ratio_404 > 0.5 → Coordinated
    //         elif coordination_score > 0 → Coordinated

    // Fleet (default)
    CollisionClass::Fleet
}

// ── Dashboard writer ──

/// Sourdough culture — persisted across restarts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DashboardCulture {
    /// Per-IP behavioral profiles — keyed by hash_ip(ip), not raw IP.
    /// Raw IPs never persist to disk. ZK boundary enforced at serialization.
    ips: HashMap<u64, IpProfile>,
    /// Total requests since culture inception
    total_requests: u64,
    /// Fleet request count
    fleet_requests: u64,
    /// Distinct UAs seen per IP — keyed by hash_ip(ip).
    ip_uas: HashMap<u64, HashSet<String>>,
    /// Distinct hosts per IP — keyed by hash_ip(ip).
    ip_hosts: HashMap<u64, HashSet<String>>,
    /// Repo-level targeting across all IPs
    repo_totals: HashMap<String, u64>,
    /// Country estimates
    country_counts: HashMap<String, u64>,
    /// Region estimates (country:region key)
    #[serde(default)]
    region_counts: HashMap<String, u64>,
    /// City estimates (country:region:city key)
    #[serde(default)]
    city_counts: HashMap<String, u64>,
    /// ASN type counts
    #[serde(default)]
    asn_type_counts: HashMap<String, u64>,
    /// Subnet counts
    subnet_counts: HashMap<String, u64>,
    /// Timing intervals (rolling, capped at 2000)
    fleet_timing_intervals: Vec<f64>,
    /// Inception timestamp
    inception_epoch: f64,
    /// Epitope collision map: epitope_hash → set of ip_hashes
    epitope_collisions: HashMap<String, HashSet<u64>>,
}

/// Dashboard writer — fed by each caddy log entry, writes dashboard.json.
pub struct DashboardWriter {
    culture: DashboardCulture,
    output_path: PathBuf,
    state_path: PathBuf,
    /// Last fleet request timestamp (for timing intervals)
    last_fleet_ts: f64,
    /// Ingest counter for periodic flush
    ingest_count: u64,
    /// How many entries between dashboard writes
    write_interval: u64,
    /// Culture save counter
    culture_save_counter: u32,
    /// Shared epitope registry — culture-derived bot detection.
    registry: crate::epitope_registry::SharedRegistry,
    /// Shared Anderson profile — updated on flush, read by /plasmid endpoint.
    anderson_profile: crate::anderson_bridge::SharedAndersonProfile,
}

impl DashboardWriter {
    /// Create a new dashboard writer with sourdough culture.
    pub fn new(
        output_path: PathBuf,
        state_path: PathBuf,
        write_interval: u64,
        registry: crate::epitope_registry::SharedRegistry,
    ) -> Self {
        Self::with_anderson(output_path, state_path, write_interval, registry, std::sync::Arc::new(tokio::sync::RwLock::new(None)))
    }

    /// Create a new dashboard writer with shared Anderson profile output.
    pub fn with_anderson(
        output_path: PathBuf,
        state_path: PathBuf,
        write_interval: u64,
        registry: crate::epitope_registry::SharedRegistry,
        anderson_profile: crate::anderson_bridge::SharedAndersonProfile,
    ) -> Self {
        let culture = Self::load_culture(&state_path);
        let writer = Self {
            last_fleet_ts: 0.0,
            ingest_count: 0,
            write_interval,
            culture_save_counter: 0,
            output_path,
            state_path,
            culture,
            registry,
            anderson_profile,
        };
        tracing::info!(
            output = %writer.output_path.display(),
            culture = %writer.state_path.display(),
            ips = writer.culture.ips.len(),
            requests = writer.culture.total_requests,
            interval = writer.write_interval,
            "📊 dashboard writer loaded"
        );
        writer
    }

    fn load_culture(path: &Path) -> DashboardCulture {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let mut culture = match std::fs::read_to_string(path) {
            Ok(json) => match serde_json::from_str(&json) {
                Ok(culture) => {
                    let c: &DashboardCulture = &culture;
                    tracing::info!(
                        ips = c.ips.len(),
                        requests = c.total_requests,
                        path = %path.display(),
                        "🧬 dashboard culture loaded — sourdough warm start"
                    );
                    culture
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "dashboard culture corrupt — starting fresh"
                    );
                    DashboardCulture::default()
                }
            },
            Err(_) => {
                tracing::info!(
                    path = %path.display(),
                    "no dashboard culture file — first generation"
                );
                DashboardCulture::default()
            }
        };

        // Guard: inception_epoch=0.0 means the field was never set (pre-Wave 167
        // cultures or Default derive). Set to now so RPS doesn't divide by 56 years.
        if culture.inception_epoch < 1_000_000_000.0 {
            tracing::warn!(
                old_epoch = culture.inception_epoch,
                "inception_epoch missing or invalid — setting to now"
            );
            culture.inception_epoch = now;
        }

        culture
    }

    /// Ingest a parsed caddy log entry.
    pub fn ingest(&mut self, entry: &caddy::LogEntry) {
        let ip = &entry.request.remote_ip;
        let ip_h = hash_ip(ip);
        let h = &entry.request.headers;
        let uri = &entry.request.uri;
        let ua = h.user_agent.first().cloned().unwrap_or_default();
        let host = &entry.request.host;
        let ts = entry.ts;

        self.culture.total_requests += 1;

        // Per-IP profile — keyed by hash, raw IP never stored
        let profile = self.culture.ips.entry(ip_h).or_insert_with(|| IpProfile::new(ts));
        profile.requests += 1;
        profile.last_seen = ts;

        // Classification — Wave 167: three-tier (fleet / ghost / human)
        // Fleet: Chrome UA without Sec-Fetch, OR known bot UA strings
        // Ghost: has Sec-Fetch but no referer (residential proxy exits)
        // Human: has Sec-Fetch AND has referer (arrived from somewhere real)
        let has_sf = !h.sec_fetch_mode.is_empty();
        let has_referer = !h.referer.is_empty();
        let is_bot_ua = self.registry.read()
            .map(|reg| reg.is_declared_bot(&ua))
            .unwrap_or_else(|_| crate::entity_classifier::is_declared_bot(&ua));
        let is_fleet = is_bot_ua || (ua.contains("Chrome/") && !has_sf);
        let is_human = has_sf && !is_bot_ua && (has_referer || profile.has_referer);
        if is_bot_ua {
            profile.is_declared_bot = true;
        }
        if is_fleet {
            profile.is_fleet = true;
            self.culture.fleet_requests += 1;

            // Fleet timing
            if self.last_fleet_ts > 0.0 {
                let interval = ts - self.last_fleet_ts;
                if interval > 0.0 && interval < 5.0 {
                    self.culture.fleet_timing_intervals.push(interval);
                    if self.culture.fleet_timing_intervals.len() > 2000 {
                        let drain = self.culture.fleet_timing_intervals.len() - 1000;
                        self.culture.fleet_timing_intervals.drain(..drain);
                    }
                }
            }
            self.last_fleet_ts = ts;
        }
        if is_human {
            profile.is_human = true;
        }
        // Ghost: has browser headers but no referer and not a known bot.
        // Don't set is_human; don't set is_fleet. They fall into the
        // unclassified bucket until multi-request evidence promotes them.
        // If a ghost later sends a referer, is_human gets set above.

        // Status tracking
        *profile.statuses.entry(entry.status).or_insert(0) += 1;

        // Header invariants (conserved epitopes)
        if profile.accept_encoding.is_none() {
            if let Some(ae) = h.accept_encoding.first() {
                profile.accept_encoding = Some(ae.clone());
            }
        }
        if profile.accept.is_none() {
            if let Some(acc) = h.accept.first() {
                profile.accept = Some(acc.clone());
            }
        }
        if !h.accept_language.is_empty() {
            profile.has_accept_lang = true;
        }
        if has_sf {
            profile.has_sec_fetch = true;
        }
        if !h.referer.is_empty() {
            profile.has_referer = true;
        }
        if !h.cookie.is_empty() {
            profile.has_cookie = true;
        }

        // Asset detection
        if uri.ends_with(".css")
            || uri.ends_with(".js")
            || uri.ends_with(".woff2")
            || uri.ends_with(".woff")
            || uri.ends_with(".ttf")
            || uri.contains("search_index")
        {
            profile.has_assets = true;
        }

        // Path targeting
        if uri.contains("/blame/") {
            profile.blame_count += 1;
            *profile.path_types.entry("blame".to_string()).or_insert(0) += 1;
        } else if uri.contains("/commit/") || uri.contains("/commits/") {
            profile.commit_count += 1;
            *profile.path_types.entry("commit".to_string()).or_insert(0) += 1;
        } else if uri.contains("/src/") {
            *profile.path_types.entry("src".to_string()).or_insert(0) += 1;
        } else if uri.contains("/raw/") {
            *profile.path_types.entry("raw".to_string()).or_insert(0) += 1;
        } else if uri.contains("/issues") {
            *profile.path_types.entry("issues".to_string()).or_insert(0) += 1;
        } else {
            *profile.path_types.entry("other".to_string()).or_insert(0) += 1;
        }

        // Repo extraction
        if host.contains("git.primals") || host.contains("forge.primals") {
            let parts: Vec<&str> = uri.trim_matches('/').split('/').collect();
            if parts.len() >= 2 {
                let repo = format!("{}/{}", parts[0], parts[1]);
                *profile.repos.entry(repo.clone()).or_insert(0) += 1;
                *self.culture.repo_totals.entry(repo).or_insert(0) += 1;
            }
        }

        // UA pool tracking — keyed by ip hash
        if !ua.is_empty() {
            let ua_set = self.culture.ip_uas.entry(ip_h).or_default();
            ua_set.insert(ua.get(..80).unwrap_or(&ua).to_string());
            profile.ua_pool_size = ua_set.len() as u16;
        }

        // Host tracking — keyed by ip hash
        if !host.is_empty() {
            let host_set = self.culture.ip_hosts.entry(ip_h).or_default();
            host_set.insert(host.clone());
            profile.host_count = host_set.len() as u16;
        }

        // Subnet + GEO
        let subnet = {
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() == 4 {
                format!("{}.{}.{}.x", parts[0], parts[1], parts[2])
            } else {
                ip.clone()
            }
        };
        *self.culture.subnet_counts.entry(subnet).or_insert(0) += 1;
        let geo = geo_lookup(ip);
        *self.culture.country_counts.entry(geo.country.clone()).or_insert(0) += 1;
        if let Some(ref region) = geo.region {
            let key = format!("{}:{}", geo.country, region);
            *self.culture.region_counts.entry(key).or_insert(0) += 1;
        }
        if let Some(ref city) = geo.city {
            if let Some(ref region) = geo.region {
                let key = format!("{}:{}:{}", geo.country, region, city);
                *self.culture.city_counts.entry(key).or_insert(0) += 1;
            }
        }
        if let Some(ref asn_type) = geo.asn_type {
            *self.culture.asn_type_counts.entry(asn_type.clone()).or_insert(0) += 1;
        }

        // Epitope hashing (after >= 3 requests)
        if profile.requests >= 3 && profile.epitope_hash.is_none() {
            let ehash = compute_epitope_hash(profile);
            self.culture
                .epitope_collisions
                .entry(ehash.clone())
                .or_default()
                .insert(ip_h);
            profile.epitope_hash = Some(ehash);
        }

        // Periodic dashboard write
        self.ingest_count += 1;
        if self.ingest_count % self.write_interval == 0 {
            self.flush();
        }
    }

    /// Write dashboard.json + state.json + epitope_caddy.json.
    pub fn flush(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let uptime = (now - self.culture.inception_epoch).max(1.0);
        let rps = self.culture.total_requests as f64 / uptime;

        // Collect fleet + human IP counts (by hash — no raw IPs)
        let fleet_count = self.culture.ips.values().filter(|p| p.is_fleet).count();
        let human_count = self.culture.ips.values().filter(|p| p.is_human).count();
        let fleet_pct = if !self.culture.ips.is_empty() {
            fleet_count as f64 / self.culture.ips.len() as f64 * 100.0
        } else {
            0.0
        };

        // Top offenders — sorted by request count. Uses ip_hash, not raw IP.
        let mut top_offenders: Vec<_> = self.culture.ips.iter().collect();
        top_offenders.sort_by(|a, b| b.1.requests.cmp(&a.1.requests));

        let top_offenders_json: Vec<serde_json::Value> = top_offenders
            .iter()
            .take(25)
            .map(|(ip_hash, p)| {
                let top_repos: BTreeMap<String, u32> = p.repos.iter()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .take(3)
                    .map(|(k, v)| (k.clone(), *v))
                    .collect();
                let top_paths: BTreeMap<String, u32> = p.path_types.iter()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .take(3)
                    .map(|(k, v)| (k.clone(), *v))
                    .collect();
                let fmt_ts = |ts: f64| -> String {
                    chrono::DateTime::from_timestamp(ts as i64, 0)
                        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_default()
                };
                let trio = score_trio(p);
                serde_json::json!({
                    "ip_hash": format!("{:016x}", ip_hash),
                    "requests": p.requests,
                    "first_seen": fmt_ts(p.first_seen),
                    "last_seen": fmt_ts(p.last_seen),
                    "is_fleet": p.is_fleet,
                    "trio_class": trio.classification,
                    "trio_attention": (trio.attention * 100.0).round() / 100.0,
                    "trio_curiosity": (trio.curiosity * 100.0).round() / 100.0,
                    "trio_interaction": (trio.interaction * 100.0).round() / 100.0,
                    "top_repos": top_repos,
                    "top_paths": top_paths,
                })
            })
            .collect();

        // Subnets — subnet strings are kept (they're /24 prefixes, not full IPs)
        let mut subnets: Vec<_> = self.culture.subnet_counts.iter().collect();
        subnets.sort_by(|a, b| b.1.cmp(a.1));
        let subnets_json: Vec<serde_json::Value> = subnets
            .iter()
            .take(15)
            .map(|(subnet, count)| {
                let count = *count;
                let geo = geo_lookup(&subnet.replace(".x", ".0"));
                serde_json::json!({
                    "subnet": subnet,
                    "requests": count,
                    "org": geo.org,
                    "country": geo.country,
                    "region": geo.region,
                    "city": geo.city,
                    "asn_type": geo.asn_type,
                })
            })
            .collect();

        // Targets (repos)
        let mut targets: Vec<_> = self.culture.repo_totals.iter().collect();
        targets.sort_by(|a, b| b.1.cmp(a.1));
        let targets_json: Vec<serde_json::Value> = targets
            .iter()
            .take(15)
            .map(|(repo, count)| serde_json::json!({"repo": repo, "requests": count}))
            .collect();

        // Path types aggregated
        let mut path_types: HashMap<String, u64> = HashMap::new();
        for p in self.culture.ips.values() {
            for (ptype, &count) in &p.path_types {
                *path_types.entry(ptype.clone()).or_insert(0) += count as u64;
            }
        }

        // Geography — progressive subdivision
        let mut geo_sorted: Vec<_> = self.culture.country_counts.iter().collect();
        geo_sorted.sort_by(|a, b| b.1.cmp(a.1));
        let geo_json: Vec<serde_json::Value> = geo_sorted
            .iter()
            .map(|(country, count)| {
                // Collect regions within this country
                let mut regions: Vec<serde_json::Value> = self.culture.region_counts.iter()
                    .filter(|(k, _)| k.starts_with(&format!("{}:", country)))
                    .map(|(k, v)| {
                        let region = k.splitn(2, ':').nth(1).unwrap_or("??");
                        // Collect cities within this region
                        let cities: Vec<serde_json::Value> = self.culture.city_counts.iter()
                            .filter(|(ck, _)| ck.starts_with(&format!("{}:{}:", country, region)))
                            .map(|(ck, cv)| {
                                let city = ck.rsplitn(2, ':').next().unwrap_or("??");
                                serde_json::json!({"city": city, "requests": cv})
                            })
                            .collect();
                        serde_json::json!({
                            "region": region,
                            "requests": v,
                            "cities": cities,
                        })
                    })
                    .collect();
                regions.sort_by(|a, b| {
                    let ar = a["requests"].as_u64().unwrap_or(0);
                    let br = b["requests"].as_u64().unwrap_or(0);
                    br.cmp(&ar)
                });
                serde_json::json!({
                    "country": country,
                    "requests": count,
                    "regions": regions,
                })
            })
            .collect();

        // ASN type breakdown
        let asn_types: serde_json::Value = serde_json::json!(self.culture.asn_type_counts);

        // Timing analysis
        let timing = if self.culture.fleet_timing_intervals.len() > 10 {
            let intervals = &self.culture.fleet_timing_intervals;
            let sum: f64 = intervals.iter().sum();
            let mean = sum / intervals.len() as f64;
            let variance: f64 = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>()
                / intervals.len() as f64;
            let stdev = variance.sqrt();
            let cv = if mean > 0.0 { stdev / mean } else { 0.0 };
            let classification = if cv < 0.15 {
                "HIGH"
            } else if cv < 0.5 {
                "MEDIUM"
            } else {
                "LOW"
            };

            serde_json::json!({
                "avg_interval_ms": (mean * 1000.0 * 10.0).round() / 10.0,
                "cv": (cv * 1000.0).round() / 1000.0,
                "machine_confidence": classification,
            })
        } else {
            serde_json::json!({
                "avg_interval_ms": 0.0,
                "cv": 0.0,
                "machine_confidence": "LOW",
            })
        };

        // Collision layer (L2)
        let mut collision_counts: HashMap<&str, usize> = HashMap::new();
        for p in self.culture.ips.values() {
            let class = classify_collision_l2(p);
            let key = match class {
                CollisionClass::Genuine => "genuine",
                CollisionClass::Agentic => "agentic",
                CollisionClass::Coordinated => "coordinated",
                CollisionClass::Fleet => "fleet",
            };
            *collision_counts.entry(key).or_insert(0) += 1;
        }

        // Epitope clusters — keyed by ip hash, no raw IPs exposed
        let mut epitope_clusters: Vec<serde_json::Value> = self
            .culture
            .epitope_collisions
            .iter()
            .filter(|(_, ip_hashes)| !ip_hashes.is_empty())
            .map(|(hash, ip_hashes)| {
                let sample_ae = ip_hashes
                    .iter()
                    .next()
                    .and_then(|h| self.culture.ips.get(h))
                    .and_then(|p| p.accept_encoding.clone())
                    .unwrap_or_else(|| "?".to_string());
                let max_ua_pool = ip_hashes
                    .iter()
                    .filter_map(|h| self.culture.ips.get(h))
                    .map(|p| p.ua_pool_size)
                    .max()
                    .unwrap_or(0);
                let blame_total: u32 = ip_hashes
                    .iter()
                    .filter_map(|h| self.culture.ips.get(h))
                    .map(|p| p.blame_count)
                    .sum();
                let commit_total: u32 = ip_hashes
                    .iter()
                    .filter_map(|h| self.culture.ips.get(h))
                    .map(|p| p.commit_count)
                    .sum();
                let blame_ratio = if commit_total > 0 {
                    blame_total as f64 / commit_total as f64
                } else {
                    0.0
                };
                let has_lang = ip_hashes
                    .iter()
                    .any(|h| self.culture.ips.get(h).map(|p| p.has_accept_lang).unwrap_or(false));

                serde_json::json!({
                    "hash": hash,
                    "ips": ip_hashes.len(),
                    "sample_ae": sample_ae,
                    "ua_pool_size": max_ua_pool,
                    "blame_ratio": (blame_ratio * 100.0).round() / 100.0,
                    "has_lang": has_lang,
                })
            })
            .collect();
        epitope_clusters.sort_by(|a, b| {
            b.get("ips")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .cmp(&a.get("ips").and_then(|v| v.as_u64()).unwrap_or(0))
        });
        epitope_clusters.truncate(20);

        let epitope_summary = serde_json::json!({
            "total_hashed": self.culture.ips.values().filter(|p| p.epitope_hash.is_some()).count(),
            "unique_hashes": self.culture.epitope_collisions.len(),
            "largest_cluster": self.culture.epitope_collisions.values().map(|v| v.len()).max().unwrap_or(0),
            "clusters_gt1": self.culture.epitope_collisions.values().filter(|v| v.len() > 1).count(),
        });

        let dashboard = serde_json::json!({
            "ts": now,
            "utc": chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            "uptime_secs": uptime as u64,
            "total_requests": self.culture.total_requests,
            "fleet_requests": self.culture.fleet_requests,
            "rps": (rps * 10.0).round() / 10.0,
            "unique_ips": self.culture.ips.len(),
            "fleet_ips": fleet_count,
            "human_ips": human_count,
            "fleet_pct": (fleet_pct * 10.0).round() / 10.0,
            "top_offenders": top_offenders_json,
            "subnets": subnets_json,
            "targets": targets_json,
            "path_types": path_types,
            "geography": geo_json,
            "asn_types": asn_types,
            "timing": timing,
            "collision_level2": {
                "genuine": collision_counts.get("genuine").copied().unwrap_or(0),
                "agentic": collision_counts.get("agentic").copied().unwrap_or(0),
                "coordinated": collision_counts.get("coordinated").copied().unwrap_or(0),
                "fleet": collision_counts.get("fleet").copied().unwrap_or(0),
            },
            "epitope_clusters": epitope_clusters,
            "epitope_summary": epitope_summary,
        });

        // Write dashboard.json
        if let Some(parent) = self.output_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string(&dashboard) {
            Ok(json) => match std::fs::write(&self.output_path, &json) {
                Ok(()) => {
                    tracing::info!(
                        ips = self.culture.ips.len(),
                        requests = self.culture.total_requests,
                        fleet = fleet_count,
                        human = human_count,
                        bytes = json.len(),
                        "📊 dashboard.json updated"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "dashboard.json write failed");
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "dashboard serialization failed");
            }
        }

        // Write compact state.json
        let state_dir = self.output_path.parent().unwrap_or(Path::new("/tmp"));
        let state_json_path = state_dir.join("state.json");
        let state = serde_json::json!({
            "ts": now,
            "rps": (rps * 10.0).round() / 10.0,
            "fleet_ips": fleet_count,
            "human_ips": human_count,
            "total": self.culture.total_requests,
            "collision_l2": {
                "g": collision_counts.get("genuine").copied().unwrap_or(0),
                "a": collision_counts.get("agentic").copied().unwrap_or(0),
                "c": collision_counts.get("coordinated").copied().unwrap_or(0),
                "f": collision_counts.get("fleet").copied().unwrap_or(0),
            },
            "epitope": {
                "hashed": self.culture.ips.values().filter(|p| p.epitope_hash.is_some()).count(),
                "unique": self.culture.epitope_collisions.len(),
                "largest": self.culture.epitope_collisions.values().map(|v| v.len()).max().unwrap_or(0),
                "gt1": self.culture.epitope_collisions.values().filter(|v| v.len() > 1).count(),
            },
        });
        let _ = serde_json::to_string(&state).map(|s| std::fs::write(&state_json_path, s));

        // Write epitope_caddy.json (epitope_hash → ip_hash list for scatter server)
        let epitope_caddy_path = state_dir.join("epitope_caddy.json");
        let mut epitope_map: HashMap<String, Vec<String>> = HashMap::new();
        for (hash, ip_hashes) in &self.culture.epitope_collisions {
            let mut hash_list: Vec<String> = ip_hashes.iter()
                .map(|h| format!("{:016x}", h))
                .collect();
            hash_list.sort();
            epitope_map.insert(hash.clone(), hash_list);
        }
        let epitope_caddy = serde_json::json!({"ts": now, "map": epitope_map});
        let _ = serde_json::to_string(&epitope_caddy)
            .map(|s| std::fs::write(&epitope_caddy_path, s));

        // Save sourdough culture periodically
        self.culture_save_counter += 1;
        if self.culture_save_counter % 10 == 0 || self.culture_save_counter == 1 {
            self.save_culture();
        }

        // Update shared Anderson profile from population observations
        self.update_anderson_profile();
    }

    /// Compute and publish the Anderson profile from current culture data.
    fn update_anderson_profile(&self) {
        if self.culture.ips.is_empty() {
            return;
        }

        let mesh_size = 4_u32; // current operational bodies
        let membrane_thickness = 10.0; // detection rule count (L)
        let observations = crate::anderson_bridge::extract_observations(
            &self.culture.ips,
            mesh_size,
        );
        let profile = crate::anderson_bridge::compute_profile(
            &observations,
            mesh_size,
            membrane_thickness,
        );

        // Write to /run/membrane/ so the scatter server's /plasmid endpoint reads it
        if let Ok(json) = serde_json::to_string(&profile) {
            let _ = std::fs::create_dir_all("/run/membrane");
            let _ = std::fs::write("/run/membrane/anderson-profile.json", &json);
        }

        // Also update the shared profile for in-process consumers
        if let Ok(mut guard) = self.anderson_profile.try_write() {
            *guard = Some(profile);
        }
    }

    /// Persist the sourdough culture to disk.
    pub fn save_culture(&self) {
        match serde_json::to_string(&self.culture) {
            Ok(json) => {
                if let Some(parent) = self.state_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(&self.state_path, &json) {
                    tracing::warn!(error = %e, "dashboard culture save failed");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "dashboard culture serialization failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(ip: &str, uri: &str, host: &str, ua: &str, ts: f64) -> caddy::LogEntry {
        caddy::LogEntry {
            request: caddy::RequestInfo {
                remote_ip: ip.to_string(),
                host: host.to_string(),
                uri: uri.to_string(),
                method: "GET".to_string(),
                headers: caddy::Headers {
                    user_agent: vec![ua.to_string()],
                    accept_encoding: vec!["gzip, br, zstd, deflate".to_string()],
                    ..Default::default()
                },
            },
            status: 200,
            size: 1024,
            duration: 0.01,
            ts,
        }
    }

    #[test]
    fn dashboard_writer_creates_output() {
        let dir = std::env::temp_dir().join("dashboard-writer-test");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("dashboard.json");
        let state = dir.join("dashboard-culture.json");

        let registry = crate::epitope_registry::create_shared_registry(None);
        let mut writer = DashboardWriter::new(output.clone(), state.clone(), 10, registry.clone());

        for i in 0..10 {
            writer.ingest(&make_entry(
                &format!("57.141.20.{}", i),
                "/ecoPrimals/skunkBat/commit/abc123",
                "git.primals.eco",
                "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36",
                1000.0 + i as f64,
            ));
        }

        assert!(output.exists(), "dashboard.json should have been created");
        let content = std::fs::read_to_string(&output).unwrap();
        assert!(content.contains("fleet_ips"));
        assert!(content.contains("top_offenders"));
        assert!(content.contains("timing"));

        // Culture should be saved
        assert!(state.exists(), "culture file should exist");

        // Sourdough test — new writer should warm start
        let writer2 = DashboardWriter::new(output.clone(), state.clone(), 10, registry.clone());
        assert_eq!(writer2.culture.total_requests, 10);
        assert_eq!(writer2.culture.ips.len(), 10);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn epitope_hash_deterministic() {
        let mut p = IpProfile::new(1.0);
        p.accept_encoding = Some("gzip, br, zstd, deflate".to_string());
        p.ua_pool_size = 1;
        p.accept = Some("*/*".to_string());

        let h1 = compute_epitope_hash(&p);
        let h2 = compute_epitope_hash(&p);
        assert_eq!(h1, h2, "epitope hash should be deterministic");
        assert_eq!(h1.len(), 8, "epitope hash should be 8 hex chars");
    }

    #[test]
    fn collision_l2_fleet_default() {
        let p = IpProfile::new(1.0);
        assert_eq!(classify_collision_l2(&p), CollisionClass::Fleet);
    }

    #[test]
    fn collision_l2_genuine() {
        let mut p = IpProfile::new(1.0);
        p.has_assets = true;
        p.has_referer = true;
        p.statuses.insert(200, 5);
        assert_eq!(classify_collision_l2(&p), CollisionClass::Genuine);
    }

    #[test]
    fn collision_l2_agentic() {
        let mut p = IpProfile::new(1.0);
        p.statuses.insert(200, 2);
        assert_eq!(classify_collision_l2(&p), CollisionClass::Agentic);
    }

    #[test]
    fn culture_uses_hashed_ip_keys() {
        let dir = std::env::temp_dir().join("dashboard-zk-test");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("dashboard.json");
        let state = dir.join("dashboard-culture.json");

        let registry = crate::epitope_registry::create_shared_registry(None);
        let mut writer = DashboardWriter::new(output.clone(), state.clone(), 5, registry);
        for i in 0..5 {
            writer.ingest(&make_entry(
                &format!("57.141.20.{}", i),
                "/ecoPrimals/skunkBat/commit/abc123",
                "git.primals.eco",
                "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36",
                1000.0 + i as f64,
            ));
        }

        // Force culture save
        writer.save_culture();

        // Read the culture file and verify keys are u64 hashes, not raw IPs
        let culture_json = std::fs::read_to_string(&state).unwrap();
        let culture_val: serde_json::Value = serde_json::from_str(&culture_json).unwrap();
        let ips_obj = culture_val["ips"].as_object().unwrap();
        for key in ips_obj.keys() {
            assert!(
                !key.contains('.'),
                "Culture file contains raw IP '{key}' — ZK boundary violated! Keys should be u64 hashes."
            );
            // Verify key is a valid u64 numeric string
            key.parse::<u64>().unwrap_or_else(|_| {
                panic!("Culture key '{key}' is not a valid u64 hash");
            });
        }
        assert!(!ips_obj.is_empty(), "Culture should have at least one IP entry");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn state_json_created_alongside_dashboard() {
        let dir = std::env::temp_dir().join("dashboard-state-test");
        let _ = std::fs::create_dir_all(&dir);
        let output = dir.join("dashboard.json");
        let state = dir.join("dashboard-culture.json");

        let registry = crate::epitope_registry::create_shared_registry(None);
        let mut writer = DashboardWriter::new(output.clone(), state, 5, registry);
        for i in 0..5 {
            writer.ingest(&make_entry("10.0.0.1", "/", "primals.eco", "curl/7", i as f64));
        }

        let state_path = dir.join("state.json");
        assert!(state_path.exists(), "state.json should be created alongside dashboard.json");

        let epitope_path = dir.join("epitope_caddy.json");
        assert!(epitope_path.exists(), "epitope_caddy.json should be created alongside dashboard.json");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

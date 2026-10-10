// DORMANT — Wave 171 fossil. Declared but never wired to production.
// Original: skunky-ingest/src/journey_tracer.rs
// Reason: tests only, zero production refs. Wire in or delete.
// Fossilized: 2026-10-10T15:51:20Z

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Journey tracer — behavioral path topology through the evidence network.
//!
//! Visitors arrive for different reasons, traverse different paths, and leave
//! at different exit points. This module traces those paths as **epitope-sorted
//! behavioral patterns**, not identity-tracked individuals.
//!
//! # Design principles
//!
//! 1. **No identity tracking.** IPs are one-way hashed. No cookies. No
//!    fingerprinting. We observe the *shape* of a journey, not who took it.
//!
//! 2. **Epitope sorting.** Each journey is classified by its behavioral
//!    epitope — the pattern of arrival, traversal, and departure that reveals
//!    *what kind of reader* this is without revealing *which reader*.
//!
//! 3. **Traveling salesman topology.** The evidence network is a graph.
//!    Each journey is a walk through that graph. We analyze which paths are
//!    taken, which are skipped, and where visitors get stuck or leave.
//!
//! # Journey lifecycle
//!
//! ```text
//! ARRIVE → (reason: search, direct, referral, ai-agent, archive)
//!   │
//!   ├── TRAVERSE → (host₁/path₁) → (host₂/path₂) → ...
//!   │       ↕ cross-domain bridge (e.g. tuebor → detroit)
//!   │
//!   └── DEPART → (reason: bounced, exhausted, satisfied, lost)
//! ```
//!
//! # Epitope classes
//!
//! Visitors are sorted into behavioral epitopes based on their journey shape:
//!
//! - **Investigator**: deep single-site traversal (≥5 pages, 1 host)
//! - **Bridge-walker**: crosses between evidence sites (≥2 hosts)
//! - **Grazer**: reads 2–4 pages on one host, no deep dive
//! - **Bounce**: single page view, immediate departure
//! - **Scanner**: probes for vulnerabilities (.env, .git, wp-admin)
//! - **Archivist**: systematic crawl with archival user-agent or pattern
//! - **Agent**: AI retrieval pattern (llms.txt, API endpoints, structured data)
//! - **Fleet**: high-volume automated traversal (commit walks, scatter maze)

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use serde::Serialize;

use crate::bloom_sensor::{classify_referrer, classify_reader_contextual, ContentDomain,
    classify_domain, ReaderType, ReferrerSource};
use crate::caddy::LogEntry;

// ── IP hashing (same approach as bloom_sensor) ──

/// One-way hash an IP to a session key. Raw IP is never stored or logged.
fn hash_session(ip: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    // Salt so this hash isn't correlatable with bloom_sensor's hash
    "journey-salt-9f2e".hash(&mut h);
    ip.hash(&mut h);
    h.finish()
}

// ── Journey step ──

/// A single step in a visitor's journey through the evidence network.
#[derive(Debug, Clone, Serialize)]
pub struct JourneyStep {
    /// Timestamp (epoch seconds, same as Caddy log `ts`).
    pub ts: f64,
    /// Host visited.
    pub host: String,
    /// Path visited (query string stripped).
    pub path: String,
    /// Content domain classification.
    pub domain: ContentDomain,
    /// HTTP status code.
    pub status: u16,
}

// ── Arrival reason ──

/// Why did this visitor arrive?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArrivalReason {
    /// Came from a search engine (Google, Bing, DuckDuckGo).
    Search,
    /// Typed the URL directly or used a bookmark.
    Direct,
    /// Followed a link from another primals.eco site.
    Internal,
    /// Followed a link from an external site.
    Referral,
    /// AI agent or chatbot retrieval.
    AiRetrieval,
    /// Web archive crawl.
    Archive,
    /// Arrived via ChatGPT link or similar.
    AiChat,
}

impl From<ReferrerSource> for ArrivalReason {
    fn from(r: ReferrerSource) -> Self {
        match r {
            ReferrerSource::Google | ReferrerSource::Bing | ReferrerSource::DuckDuckGo => {
                ArrivalReason::Search
            }
            ReferrerSource::Direct => ArrivalReason::Direct,
            ReferrerSource::Internal => ArrivalReason::Internal,
            ReferrerSource::External => ArrivalReason::Referral,
            ReferrerSource::ChatGpt => ArrivalReason::AiChat,
        }
    }
}

// ── Departure reason ──

/// Why did this visitor leave?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DepartureReason {
    /// Single page view — bounced immediately.
    Bounced,
    /// Read a few pages, then stopped (normal exit).
    Satisfied,
    /// Deep dive — read many pages, exhausted the content.
    Exhausted,
    /// Hit a 404 or error and stopped.
    Lost,
    /// Session timed out (gap > session window).
    TimedOut,
}

// ── Behavioral epitope ──

/// Behavioral epitope — the classified shape of a journey.
///
/// Named after immunological epitopes: the surface features of a pathogen
/// that the immune system recognizes. Here, the "surface features" are
/// behavioral patterns that classify a visitor without identifying them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum JourneyEpitope {
    /// Deep single-site traversal: ≥5 content pages, 1 host.
    /// The reader who follows the thread.
    Investigator,
    /// Cross-domain walk: ≥2 evidence hosts visited.
    /// The reader who sees the network.
    BridgeWalker,
    /// 2–4 content pages on one host. Interested but not committed.
    Grazer,
    /// Single content page view. Arrived, looked, left.
    Bounce,
    /// Probes for vulnerabilities: .env, .git/config, wp-admin, etc.
    Scanner,
    /// Systematic archival crawl (Wayback Machine, archive.org).
    Archivist,
    /// AI retrieval: reads llms.txt, API endpoints, structured data.
    Agent,
    /// High-volume automated: commit walks, scatter maze traversal.
    Fleet,
}

impl JourneyEpitope {
    /// Human-readable description of this epitope.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Investigator => "Deep single-site reader — follows the evidence thread",
            Self::BridgeWalker => "Cross-domain explorer — sees the network connections",
            Self::Grazer => "Casual reader — interested but not committed",
            Self::Bounce => "Single page — arrived, looked, left",
            Self::Scanner => "Vulnerability probe — scanning for exposed files",
            Self::Archivist => "Systematic archival — preserving the record",
            Self::Agent => "AI retrieval — reading structured data for LLM context",
            Self::Fleet => "Automated fleet — high-volume traversal",
        }
    }
}

// ── Temporal tense ──

/// Temporal tense classification for the epitope sort compression.
///
/// Every observation exists in one of three temporal states. This trichotomy
/// maps to computational complexity (Paper 48):
///
/// - **Is** (present): Observable, polynomial — first-time session, state = 0
/// - **Was** (past): Recorded, polynomial — previously seen pattern, state = 1
/// - **WillBe** (future): Predicted, NP — nautilus forecast, state = null → collapsed
///
/// The tense dimension is the sharpest epitope sort because it partitions
/// the behavioral space into regions of fundamentally different computability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EpitopeTense {
    /// First observation — no prior pattern match (chain_depth == 0).
    /// State = 0. Compressible by direct measurement.
    Is,
    /// Matches a previously observed journey pattern (chain_depth > 0).
    /// State = 1. Compressible by chain_depth deduplication.
    Was,
    /// Nautilus predicted this fleet hash before observation arrived.
    /// State = null → collapsed. Compression bounded by prediction capacity.
    WillBe,
}

impl EpitopeTense {
    /// Human-readable description of this tense.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Is => "Present — first observation, no prior pattern",
            Self::Was => "Past — previously observed behavioral pattern",
            Self::WillBe => "Future — nautilus-predicted before observation",
        }
    }
}

// ── Completed journey ──

/// A completed visitor journey — the full behavioral trace.
///
/// No raw IP is stored. The `session_hash` is a one-way digest
/// used only for grouping requests within the session window.
/// It is discarded after epitope classification.
#[derive(Debug, Clone, Serialize)]
pub struct Journey {
    /// One-way session hash (not stored long-term).
    #[serde(skip)]
    pub session_hash: u64,
    /// Behavioral epitope classification.
    pub epitope: JourneyEpitope,
    /// Temporal tense — is this journey happening now, a repeat, or predicted?
    pub tense: EpitopeTense,
    /// Why the visitor arrived.
    pub arrival: ArrivalReason,
    /// Why the visitor departed.
    pub departure: DepartureReason,
    /// Reader type classification.
    pub reader_type: ReaderType,
    /// Ordered sequence of steps.
    pub steps: Vec<JourneyStep>,
    /// Unique hosts visited.
    pub hosts_visited: u32,
    /// Unique content domains touched.
    pub domains_touched: u32,
    /// Total duration (seconds) from first to last step.
    pub duration_secs: f64,
}

impl Journey {
    /// The path as a compact string: `"tuebor:/ → tuebor:/desk/ → detroit:/"`.
    pub fn path_string(&self) -> String {
        self.steps
            .iter()
            .map(|s| {
                let short_host = s.host.split('.').next().unwrap_or(&s.host);
                format!("{short_host}:{}", s.path)
            })
            .collect::<Vec<_>>()
            .join(" → ")
    }
}

// ── Journey tracer ──

/// Active session being accumulated (not yet classified).
struct ActiveSession {
    /// Reader type from first request.
    reader_type: ReaderType,
    /// Arrival reason from first request's referrer.
    arrival: ArrivalReason,
    /// Ordered steps.
    steps: Vec<JourneyStep>,
    /// Timestamp of last activity.
    last_ts: f64,
    /// Chain depth — how many previous sessions from this hash we've seen.
    /// 0 = first time (Is), >0 = repeat (Was).
    chain_depth: u32,
}

/// Population-level journey statistics (what gets emitted).
#[derive(Debug, Default, Serialize)]
pub struct JourneyObservation {
    /// Window boundaries.
    pub window_start: f64,
    pub window_end: f64,
    /// Completed journeys by epitope.
    pub by_epitope: HashMap<String, u32>,
    /// Completed journeys by arrival reason.
    pub by_arrival: HashMap<String, u32>,
    /// Completed journeys by departure reason.
    pub by_departure: HashMap<String, u32>,
    /// Average journey depth (pages per session).
    pub avg_depth: f32,
    /// Maximum journey depth observed.
    pub max_depth: u32,
    /// Bridge walks (cross-domain journeys) count.
    pub bridge_walks: u32,
    /// Total completed journeys.
    pub total_journeys: u32,
    /// Tense distribution: is (first-time), was (repeat), will_be (predicted).
    pub by_tense: HashMap<String, u32>,
    /// The journeys themselves (epitope-sorted, session hashes stripped).
    pub journeys: Vec<Journey>,
}

/// Windowed journey tracer — accumulates per-request steps into sessions,
/// classifies completed sessions into epitope-sorted journeys, and emits
/// population-level observations at window boundaries.
pub struct JourneyTracer {
    /// Session timeout — gap between requests that ends a session.
    session_timeout: Duration,
    /// Observation window — how often to emit population stats.
    window: Duration,
    /// Window start timestamp.
    window_start: f64,
    /// Active sessions keyed by hashed IP.
    sessions: HashMap<u64, ActiveSession>,
    /// Completed journeys in current window.
    completed: Vec<Journey>,
    /// Chain depth per session hash — how many completed sessions we've seen.
    /// Maps session_hash → number of previous completions.
    /// Used for tense classification: 0 = Is (first time), >0 = Was (repeat).
    chain_depths: HashMap<u64, u32>,
}

impl JourneyTracer {
    /// Create a new journey tracer.
    ///
    /// - `session_timeout`: gap between requests that ends a session (e.g. 5 minutes).
    /// - `window`: observation window for population stats (e.g. 60 seconds).
    pub fn new(session_timeout: Duration, window: Duration) -> Self {
        Self {
            session_timeout,
            window,
            window_start: 0.0,
            sessions: HashMap::new(),
            completed: Vec::new(),
            chain_depths: HashMap::new(),
        }
    }

    /// Ingest a log entry. Returns a `JourneyObservation` when the window flushes.
    pub fn ingest(&mut self, entry: &LogEntry) -> Option<JourneyObservation> {
        let ts = entry.ts;
        let host = &entry.request.host;
        let uri = entry.request.uri.split('?').next().unwrap_or(&entry.request.uri);
        let domain = classify_domain(uri);

        // Skip meta/static assets — not meaningful journey steps
        if domain == ContentDomain::Meta {
            return None;
        }

        // Initialize window
        if self.window_start == 0.0 {
            self.window_start = ts;
        }

        // Check for window boundary
        let observation = if ts - self.window_start >= self.window.as_secs_f64() {
            // Expire stale sessions before flushing
            self.expire_sessions(ts);
            let obs = self.flush_window(ts);
            self.window_start = ts;
            Some(obs)
        } else {
            None
        };

        // Classify the reader
        let ua = entry.request.headers.user_agent.first()
            .map(String::as_str).unwrap_or("");
        let ae = entry.request.headers.accept_encoding.first()
            .map(String::as_str).unwrap_or("");
        let al = entry.request.headers.accept_language.first()
            .map(String::as_str).unwrap_or("");
        let referer = entry.request.headers.referer.first()
            .map(String::as_str).unwrap_or("");

        let reader_type = classify_reader_contextual(ua, ae, al, &entry.request.remote_ip, uri);
        let referrer_source = classify_referrer(referer);

        let session_key = hash_session(&entry.request.remote_ip);

        let step = JourneyStep {
            ts,
            host: host.clone(),
            path: uri.to_string(),
            domain,
            status: entry.status,
        };

        // Update or create session
        match self.sessions.get_mut(&session_key) {
            Some(session) => {
                // Check for session timeout
                if ts - session.last_ts > self.session_timeout.as_secs_f64() {
                    // Complete the old session, start a new one
                    let old = self.sessions.remove(&session_key).unwrap();
                    self.complete_session(session_key, old);

                    let depth = self.chain_depths.get(&session_key).copied().unwrap_or(0);
                    self.sessions.insert(session_key, ActiveSession {
                        reader_type,
                        arrival: referrer_source.into(),
                        steps: vec![step],
                        last_ts: ts,
                        chain_depth: depth,
                    });
                } else {
                    session.steps.push(step);
                    session.last_ts = ts;
                }
            }
            None => {
                let depth = self.chain_depths.get(&session_key).copied().unwrap_or(0);
                self.sessions.insert(session_key, ActiveSession {
                    reader_type,
                    arrival: referrer_source.into(),
                    steps: vec![step],
                    last_ts: ts,
                    chain_depth: depth,
                });
            }
        }

        observation
    }

    /// Expire sessions that have been idle longer than the timeout.
    fn expire_sessions(&mut self, now: f64) {
        let timeout = self.session_timeout.as_secs_f64();
        let expired: Vec<u64> = self.sessions
            .iter()
            .filter(|(_, s)| now - s.last_ts > timeout)
            .map(|(&k, _)| k)
            .collect();

        for key in expired {
            if let Some(session) = self.sessions.remove(&key) {
                self.complete_session(key, session);
            }
        }
    }

    /// Classify and complete a session into a journey.
    fn complete_session(&mut self, session_key: u64, session: ActiveSession) {
        let journey = classify_journey(session);
        // Increment chain depth for this hash — next session from same hash
        // will be classified as Was instead of Is.
        *self.chain_depths.entry(session_key).or_insert(0) += 1;
        self.completed.push(journey);
    }

    /// Flush the current window and return population-level stats.
    fn flush_window(&mut self, now: f64) -> JourneyObservation {
        let journeys = std::mem::take(&mut self.completed);

        let mut by_epitope: HashMap<String, u32> = HashMap::new();
        let mut by_arrival: HashMap<String, u32> = HashMap::new();
        let mut by_departure: HashMap<String, u32> = HashMap::new();
        let mut by_tense: HashMap<String, u32> = HashMap::new();
        let mut total_depth: u32 = 0;
        let mut max_depth: u32 = 0;
        let mut bridge_walks: u32 = 0;

        for j in &journeys {
            *by_epitope.entry(format!("{:?}", j.epitope)).or_default() += 1;
            *by_arrival.entry(format!("{:?}", j.arrival)).or_default() += 1;
            *by_departure.entry(format!("{:?}", j.departure)).or_default() += 1;
            *by_tense.entry(format!("{:?}", j.tense)).or_default() += 1;

            let depth = j.steps.len() as u32;
            total_depth += depth;
            if depth > max_depth {
                max_depth = depth;
            }
            if j.hosts_visited >= 2 {
                bridge_walks += 1;
            }
        }

        let total = journeys.len() as u32;
        let avg_depth = if total > 0 {
            total_depth as f32 / total as f32
        } else {
            0.0
        };

        JourneyObservation {
            window_start: self.window_start,
            window_end: now,
            by_epitope,
            by_arrival,
            by_departure,
            avg_depth,
            max_depth,
            bridge_walks,
            total_journeys: total,
            by_tense,
            journeys,
        }
    }

    /// Flush any remaining sessions (call at shutdown).
    pub fn flush_remaining(&mut self) -> Option<JourneyObservation> {
        // Complete all active sessions
        let sessions: Vec<_> = self.sessions.drain().collect();
        for (key, session) in sessions {
            self.complete_session(key, session);
        }

        if self.completed.is_empty() {
            return None;
        }

        let now = self.completed.last().map(|j| {
            j.steps.last().map(|s| s.ts).unwrap_or(0.0)
        }).unwrap_or(0.0);

        Some(self.flush_window(now))
    }
}

// ── Journey classification ──

/// Scanner probe paths.
const SCANNER_PATHS: &[&str] = &[
    ".env", ".git/config", "wp-admin", "wp-login", ".well-known",
    "xmlrpc.php", "wp-includes", "phpinfo", "phpmyadmin",
    ".env.local", ".env.production", ".env.staging", ".env.development",
    ".env.test", ".env.remote", "config.json", ".DS_Store",
    "server-status", "debug", "trace", "actuator",
];

/// AI agent probe paths.
const AGENT_PATHS: &[&str] = &[
    "llms.txt", "llms-full.txt", ".well-known/ai-plugin.json",
    "api/", "graph.json", "sitemap.xml", "atom.xml",
    "manifest.json", "identity.json", "braids.json",
    "investigation.json", "content-manifest.toml",
];

/// Classify a completed session into a journey with epitope.
fn classify_journey(session: ActiveSession) -> Journey {
    let steps = session.steps;
    let step_count = steps.len();

    // Unique hosts
    let mut hosts: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut domains: std::collections::HashSet<&ContentDomain> = std::collections::HashSet::new();
    let mut has_scanner_path = false;
    let mut has_agent_path = false;
    let mut has_error = false;

    for step in &steps {
        hosts.insert(&step.host);
        domains.insert(&step.domain);

        if step.status >= 400 {
            has_error = true;
        }

        let path_lower = step.path.to_ascii_lowercase();
        if SCANNER_PATHS.iter().any(|p| path_lower.contains(p)) {
            has_scanner_path = true;
        }
        if AGENT_PATHS.iter().any(|p| path_lower.contains(p)) {
            has_agent_path = true;
        }
    }

    let hosts_visited = hosts.len() as u32;
    let domains_touched = domains.len() as u32;
    let duration_secs = if step_count >= 2 {
        steps.last().unwrap().ts - steps.first().unwrap().ts
    } else {
        0.0
    };

    // Classify epitope based on behavioral shape
    let epitope = match session.reader_type {
        ReaderType::Scanner => JourneyEpitope::Scanner,
        ReaderType::AiAgent => {
            if step_count > 20 {
                JourneyEpitope::Fleet
            } else {
                JourneyEpitope::Agent
            }
        }
        ReaderType::SearchCrawler => JourneyEpitope::Archivist,
        ReaderType::GitClient => JourneyEpitope::Fleet,
        ReaderType::Human => {
            if has_scanner_path {
                JourneyEpitope::Scanner
            } else if has_agent_path && step_count <= 5 {
                JourneyEpitope::Agent
            } else if hosts_visited >= 2 {
                JourneyEpitope::BridgeWalker
            } else if step_count >= 5 {
                JourneyEpitope::Investigator
            } else if step_count >= 2 {
                JourneyEpitope::Grazer
            } else {
                JourneyEpitope::Bounce
            }
        }
    };

    // Classify departure
    let departure = if step_count == 1 {
        DepartureReason::Bounced
    } else if has_error && steps.last().map_or(false, |s| s.status >= 400) {
        DepartureReason::Lost
    } else if step_count >= 8 {
        DepartureReason::Exhausted
    } else {
        DepartureReason::Satisfied
    };

    // Classify tense — the temporal dimension of this journey.
    // chain_depth == 0 means first-time (Is), > 0 means repeat (Was).
    // WillBe is reserved for nautilus predictions — not yet wired.
    let tense = if session.chain_depth == 0 {
        EpitopeTense::Is
    } else {
        EpitopeTense::Was
    };

    Journey {
        session_hash: 0, // Cleared — not stored
        epitope,
        tense,
        arrival: session.arrival,
        departure,
        reader_type: session.reader_type,
        steps,
        hosts_visited,
        domains_touched,
        duration_secs,
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caddy::{Headers, LogEntry, RequestInfo};

    fn make_entry(ts: f64, host: &str, uri: &str, ip: &str, ua: &str, referer: &str) -> LogEntry {
        LogEntry {
            request: RequestInfo {
                remote_ip: ip.to_string(),
                host: host.to_string(),
                uri: uri.to_string(),
                method: "GET".to_string(),
                headers: Headers {
                    user_agent: vec![ua.to_string()],
                    accept_encoding: vec!["gzip, deflate, br".to_string()],
                    accept_language: vec!["en-US,en;q=0.9".to_string()],
                    referer: vec![if referer.is_empty() { return LogEntry {
                        request: RequestInfo {
                            remote_ip: ip.to_string(),
                            host: host.to_string(),
                            uri: uri.to_string(),
                            method: "GET".to_string(),
                            headers: Headers {
                                user_agent: vec![ua.to_string()],
                                accept_encoding: vec!["gzip, deflate, br".to_string()],
                                accept_language: vec!["en-US,en;q=0.9".to_string()],
                                referer: vec![],
                                ..Headers::default()
                            },
                        },
                        status: 200,
                        size: 1024,
                        duration: 0.05,
                        ts,
                    }} else { referer.to_string() }],
                    ..Headers::default()
                },
            },
            status: 200,
            size: 1024,
            duration: 0.05,
            ts,
        }
    }

    fn human_entry(ts: f64, host: &str, uri: &str, ip: &str) -> LogEntry {
        make_entry(ts, host, uri, ip, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15", "")
    }

    fn search_entry(ts: f64, host: &str, uri: &str, ip: &str) -> LogEntry {
        // Note: referrer query must NOT contain primals.eco domain names
        // or "detroit"/"sporeprint" — classify_referrer checks those first.
        // See bloom_sensor::classify_referrer precedence issue.
        make_entry(ts, host, uri, ip, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15", "https://www.google.com/search?q=charter+school+fraud")
    }

    // ── Epitope classification tests ──

    #[test]
    fn investigator_epitope() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(300), Duration::from_secs(600));
        let ip = "69.244.162.196";

        // Deep single-site read: 7 pages on tuebor
        tracer.ingest(&human_entry(1000.0, "tuebor.primals.eco", "/analysis/they-banked-on-banks/", ip));
        tracer.ingest(&human_entry(1030.0, "tuebor.primals.eco", "/actors/", ip));
        tracer.ingest(&human_entry(1060.0, "tuebor.primals.eco", "/evidence/", ip));
        tracer.ingest(&human_entry(1090.0, "tuebor.primals.eco", "/analysis/", ip));
        tracer.ingest(&human_entry(1120.0, "tuebor.primals.eco", "/investigate/", ip));
        tracer.ingest(&human_entry(1150.0, "tuebor.primals.eco", "/timeline/", ip));
        tracer.ingest(&human_entry(1180.0, "tuebor.primals.eco", "/desk/", ip));

        let obs = tracer.flush_remaining().expect("should have journeys");
        assert_eq!(obs.total_journeys, 1);

        let j = &obs.journeys[0];
        assert_eq!(j.epitope, JourneyEpitope::Investigator);
        assert_eq!(j.hosts_visited, 1);
        assert_eq!(j.steps.len(), 7);
        assert_eq!(j.departure, DepartureReason::Satisfied);
    }

    #[test]
    fn bridge_walker_epitope() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(300), Duration::from_secs(600));
        let ip = "207.241.225.57";

        // Cross-domain: tuebor → detroit → sporeprint
        tracer.ingest(&human_entry(1000.0, "tuebor.primals.eco", "/", ip));
        tracer.ingest(&human_entry(1030.0, "detroit.primals.eco", "/network/actors/brian-banks/", ip));
        tracer.ingest(&human_entry(1060.0, "sporeprint.primals.eco", "/", ip));

        let obs = tracer.flush_remaining().unwrap();
        let j = &obs.journeys[0];
        assert_eq!(j.epitope, JourneyEpitope::BridgeWalker);
        assert_eq!(j.hosts_visited, 3);
        assert_eq!(obs.bridge_walks, 1);
    }

    #[test]
    fn bounce_epitope() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(300), Duration::from_secs(600));

        tracer.ingest(&human_entry(1000.0, "tuebor.primals.eco", "/", "1.2.3.4"));

        let obs = tracer.flush_remaining().unwrap();
        let j = &obs.journeys[0];
        assert_eq!(j.epitope, JourneyEpitope::Bounce);
        assert_eq!(j.departure, DepartureReason::Bounced);
    }

    #[test]
    fn scanner_epitope() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(300), Duration::from_secs(600));
        let ip = "35.214.204.78";

        tracer.ingest(&human_entry(1000.0, "primals.eco", "/", ip));
        tracer.ingest(&human_entry(1002.0, "primals.eco", "/.git/config", ip));
        tracer.ingest(&human_entry(1004.0, "primals.eco", "/.env", ip));
        tracer.ingest(&human_entry(1006.0, "primals.eco", "/.env.local", ip));

        let obs = tracer.flush_remaining().unwrap();
        let j = &obs.journeys[0];
        assert_eq!(j.epitope, JourneyEpitope::Scanner);
    }

    #[test]
    fn grazer_epitope() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(300), Duration::from_secs(600));

        tracer.ingest(&human_entry(1000.0, "sporeprint.primals.eco", "/", "5.6.7.8"));
        tracer.ingest(&human_entry(1030.0, "sporeprint.primals.eco", "/philosophy/", "5.6.7.8"));
        tracer.ingest(&human_entry(1060.0, "sporeprint.primals.eco", "/methodology/", "5.6.7.8"));

        let obs = tracer.flush_remaining().unwrap();
        let j = &obs.journeys[0];
        assert_eq!(j.epitope, JourneyEpitope::Grazer);
    }

    #[test]
    fn search_arrival() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(300), Duration::from_secs(600));

        tracer.ingest(&search_entry(1000.0, "detroit.primals.eco", "/network/actors/brian-banks/", "10.0.0.1"));

        let obs = tracer.flush_remaining().unwrap();
        let j = &obs.journeys[0];
        assert_eq!(j.arrival, ArrivalReason::Search);
    }

    #[test]
    fn session_timeout_creates_two_journeys() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(300), Duration::from_secs(3600));
        let ip = "1.2.3.4";

        // Session 1
        tracer.ingest(&human_entry(1000.0, "tuebor.primals.eco", "/", ip));
        tracer.ingest(&human_entry(1030.0, "tuebor.primals.eco", "/desk/", ip));

        // Gap > 300s — new session
        tracer.ingest(&human_entry(1400.0, "detroit.primals.eco", "/", ip));

        let obs = tracer.flush_remaining().unwrap();
        assert_eq!(obs.total_journeys, 2);
    }

    #[test]
    fn meta_assets_skipped() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(300), Duration::from_secs(600));

        tracer.ingest(&human_entry(1000.0, "tuebor.primals.eco", "/css/main.css", "1.2.3.4"));
        tracer.ingest(&human_entry(1001.0, "tuebor.primals.eco", "/favicon.ico", "1.2.3.4"));

        let obs = tracer.flush_remaining();
        assert!(obs.is_none(), "meta assets should not create journeys");
    }

    #[test]
    fn path_string_compact() {
        let j = Journey {
            session_hash: 0,
            epitope: JourneyEpitope::BridgeWalker,
            tense: EpitopeTense::Is,
            arrival: ArrivalReason::Direct,
            departure: DepartureReason::Satisfied,
            reader_type: ReaderType::Human,
            steps: vec![
                JourneyStep { ts: 0.0, host: "tuebor.primals.eco".into(), path: "/".into(), domain: ContentDomain::Homepage, status: 200 },
                JourneyStep { ts: 1.0, host: "detroit.primals.eco".into(), path: "/network/".into(), domain: ContentDomain::Network, status: 200 },
            ],
            hosts_visited: 2,
            domains_touched: 2,
            duration_secs: 1.0,
        };

        assert_eq!(j.path_string(), "tuebor:/ → detroit:/network/");
    }

    #[test]
    fn exhausted_departure_deep_read() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(300), Duration::from_secs(600));
        let ip = "99.99.99.99";

        for i in 0..10 {
            let path = format!("/analysis/page-{i}/");
            tracer.ingest(&human_entry(1000.0 + (i as f64 * 30.0), "tuebor.primals.eco", &path, ip));
        }

        let obs = tracer.flush_remaining().unwrap();
        let j = &obs.journeys[0];
        assert_eq!(j.epitope, JourneyEpitope::Investigator);
        assert_eq!(j.departure, DepartureReason::Exhausted);
    }

    #[test]
    fn observation_stats_correct() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(300), Duration::from_secs(600));

        // Bounce
        tracer.ingest(&human_entry(1000.0, "tuebor.primals.eco", "/", "1.1.1.1"));
        // Grazer
        tracer.ingest(&human_entry(1000.0, "sporeprint.primals.eco", "/", "2.2.2.2"));
        tracer.ingest(&human_entry(1030.0, "sporeprint.primals.eco", "/philosophy/", "2.2.2.2"));

        let obs = tracer.flush_remaining().unwrap();
        assert_eq!(obs.total_journeys, 2);
        assert!(obs.avg_depth > 1.0);
    }

    // ── Tense classification tests ──

    #[test]
    fn first_session_is_tense_is() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(300), Duration::from_secs(600));

        tracer.ingest(&human_entry(1000.0, "tuebor.primals.eco", "/", "42.42.42.42"));

        let obs = tracer.flush_remaining().unwrap();
        let j = &obs.journeys[0];
        assert_eq!(j.tense, EpitopeTense::Is, "first session should be tense Is");
    }

    #[test]
    fn repeat_session_is_tense_was() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(60), Duration::from_secs(3600));
        let ip = "42.42.42.42";

        // Session 1 — first visit
        tracer.ingest(&human_entry(1000.0, "tuebor.primals.eco", "/", ip));
        tracer.ingest(&human_entry(1020.0, "tuebor.primals.eco", "/desk/", ip));

        // Gap > 60s — session timeout, session 1 completes
        // Session 2 — same hash returns
        tracer.ingest(&human_entry(1200.0, "tuebor.primals.eco", "/analysis/", ip));

        let obs = tracer.flush_remaining().unwrap();
        assert_eq!(obs.total_journeys, 2);

        let first = &obs.journeys[0];
        assert_eq!(first.tense, EpitopeTense::Is, "first session = Is");

        let second = &obs.journeys[1];
        assert_eq!(second.tense, EpitopeTense::Was, "repeat session = Was");
    }

    #[test]
    fn tense_distribution_in_observation() {
        let mut tracer = JourneyTracer::new(Duration::from_secs(60), Duration::from_secs(3600));

        // Three different IPs — all first-time
        tracer.ingest(&human_entry(1000.0, "tuebor.primals.eco", "/", "1.1.1.1"));
        tracer.ingest(&human_entry(1000.0, "tuebor.primals.eco", "/", "2.2.2.2"));
        tracer.ingest(&human_entry(1000.0, "tuebor.primals.eco", "/", "3.3.3.3"));

        let obs = tracer.flush_remaining().unwrap();
        assert_eq!(obs.by_tense.get("Is"), Some(&3));
        assert_eq!(obs.by_tense.get("Was"), None);
    }
}

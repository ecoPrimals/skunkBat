// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Signal data writer — generates `signal-data.js` for the signal page.
//!
//! Replaces `gen-signal-data.py` (559 lines) which re-parsed ALL Caddy logs
//! from scratch every 15 minutes. This module accumulates data from the
//! bloom sensor's real-time stream and writes the same JS output format.
//!
//! ## Convergence
//!
//! gen-signal-data.py → skunky-ingest signal_writer:
//! - Classification engine → [`crate::bloom_sensor`] (already exists)
//! - Page exploration tracking → [`SignalAccumulator`] (this module)
//! - Cumulative history → JSON state file (this module)
//! - JS output writer → [`write_signal_data_js`] (this module)
//!
//! No more re-parsing. Signal data is a side output of the existing pipeline.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::bloom_sensor::BloomObservation;

/// How many page entries to include in the output.
const MAX_PAGES_EXPLORED: usize = 60;
/// How many historical snapshots to keep (15-min intervals → 24h).
const MAX_SNAPSHOTS: usize = 96;
/// How many top pages to keep in cumulative history.
const MAX_CUMULATIVE_PAGES: usize = 200;

/// Per-page hit counter for a site+path combo.
#[allow(dead_code)] // reserved for per-URI tracking when bloom sensor gains URI-level resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PageHit {
    site: String,
    path: String,
    hits: u32,
}

/// Per-site aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SiteStats {
    pages: u32,
    human_hits: u32,
    bot_hits: u32,
    ai_hits: u32,
}

/// Historical snapshot — one per accumulation cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Snapshot {
    ts: String,
    human: u64,
    bot: u64,
    ai: u64,
    stealth: u64,
    pages: u64,
}

/// Cumulative state persisted across restarts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CumulativeState {
    total_human_hits: u64,
    total_bot_hits: u64,
    total_ai_hits: u64,
    /// Top pages ever seen: "site/path" → hit count.
    pages_ever: HashMap<String, u64>,
    /// Sites ever seen: site → {pages, hits}.
    sites_ever: HashMap<String, (u64, u64)>,
    /// Rolling snapshot history.
    snapshots: Vec<Snapshot>,
}

/// Signal data accumulator — fed by bloom sensor observations.
pub struct SignalAccumulator {
    /// Output path for signal-data.js.
    output_path: PathBuf,
    /// State file for cumulative persistence.
    state_path: PathBuf,
    /// Current window's page hits: "site/path" → count.
    current_pages: HashMap<String, u32>,
    /// Current window's site stats.
    current_sites: HashMap<String, SiteStats>,
    /// Current window counters.
    human_hits: u64,
    bot_hits: u64,
    ai_hits: u64,
    scanner_hits: u64,
    /// Cumulative state (loaded from disk on creation).
    cumulative: CumulativeState,
    /// Observation counter — write JS every N observations.
    obs_count: u32,
    /// How many observations between JS writes.
    write_interval: u32,
}

impl SignalAccumulator {
    /// Create a new signal accumulator.
    ///
    /// Loads cumulative state from `state_path` if it exists.
    /// Writes `signal-data.js` to `output_path` every `write_interval`
    /// bloom observations.
    pub fn new(output_path: PathBuf, state_path: PathBuf, write_interval: u32) -> Self {
        let cumulative = Self::load_state(&state_path);
        tracing::info!(
            output = %output_path.display(),
            state = %state_path.display(),
            pages_ever = cumulative.pages_ever.len(),
            snapshots = cumulative.snapshots.len(),
            "📡 signal writer loaded cumulative state"
        );

        Self {
            output_path,
            state_path,
            current_pages: HashMap::new(),
            current_sites: HashMap::new(),
            human_hits: 0,
            bot_hits: 0,
            ai_hits: 0,
            scanner_hits: 0,
            cumulative,
            obs_count: 0,
            write_interval,
        }
    }

    /// Ingest a bloom observation window. Returns `true` if signal-data.js
    /// was written (every `write_interval` observations).
    pub fn ingest(&mut self, obs: &BloomObservation) -> bool {
        // Accumulate reader type counts from the observation.
        for (reader, &count) in &obs.readers {
            match reader.as_str() {
                "human" => self.human_hits += count as u64,
                "ai-agent" => self.ai_hits += count as u64,
                "search-crawler" => self.bot_hits += count as u64,
                "scanner" => self.scanner_hits += count as u64,
                "git-client" => self.bot_hits += count as u64,
                _ => {}
            }
        }

        // Accumulate per-host stats. The bloom observation has host → count,
        // but not per-page breakdowns. We track host-level for sites.
        for (host, &count) in &obs.hosts {
            let site = self.current_sites.entry(host.clone()).or_insert(SiteStats {
                pages: 0,
                human_hits: 0,
                bot_hits: 0,
                ai_hits: 0,
            });
            // Approximate: distribute hits by reader ratios from the observation.
            let total = obs.total_requests.max(1) as f64;
            let human_ratio = *obs.readers.get("human").unwrap_or(&0) as f64 / total;
            let ai_ratio = *obs.readers.get("ai-agent").unwrap_or(&0) as f64 / total;
            let bot_count = count as f64 * (1.0 - human_ratio - ai_ratio);
            site.human_hits += (count as f64 * human_ratio) as u32;
            site.ai_hits += (count as f64 * ai_ratio) as u32;
            site.bot_hits += bot_count.max(0.0) as u32;
        }

        // Accumulate domain breakdowns as pseudo-page entries.
        // The bloom sensor gives us content domains, not individual URIs.
        // We track domain-level for the signal page's "pages explored" section.
        for (domain, &count) in &obs.domains {
            // For each host in this observation, create domain entries.
            for host in obs.hosts.keys() {
                let key = format!("{host}/{domain}");
                *self.current_pages.entry(key).or_default() += count;
            }
        }

        self.obs_count += 1;

        if self.obs_count >= self.write_interval {
            self.flush();
            return true;
        }
        false
    }

    /// Flush current state: update cumulative, write JS, save state.
    pub fn flush(&mut self) {
        let now = chrono::Utc::now();
        let ts = now.format("%Y-%m-%dT%H:%M:%S%:z").to_string();

        // Update cumulative totals.
        self.cumulative.total_human_hits += self.human_hits;
        self.cumulative.total_bot_hits += self.bot_hits;
        self.cumulative.total_ai_hits += self.ai_hits;

        // Merge current pages into cumulative.
        for (key, &count) in &self.current_pages {
            *self.cumulative.pages_ever.entry(key.clone()).or_default() += count as u64;
        }

        // Merge current sites into cumulative.
        for (site, stats) in &self.current_sites {
            let entry = self.cumulative.sites_ever.entry(site.clone()).or_default();
            entry.0 += stats.pages as u64;
            entry.1 += (stats.human_hits + stats.bot_hits + stats.ai_hits) as u64;
        }

        // Trim cumulative pages to keep memory bounded.
        if self.cumulative.pages_ever.len() > MAX_CUMULATIVE_PAGES * 2 {
            let mut pages: Vec<(String, u64)> = self.cumulative.pages_ever.drain().collect();
            pages.sort_by(|a, b| b.1.cmp(&a.1));
            pages.truncate(MAX_CUMULATIVE_PAGES);
            self.cumulative.pages_ever = pages.into_iter().collect();
        }

        // Add snapshot.
        let unique_pages = self.current_pages.len() as u64;
        self.cumulative.snapshots.push(Snapshot {
            ts,
            human: self.human_hits,
            bot: self.bot_hits,
            ai: self.ai_hits,
            stealth: self.scanner_hits,
            pages: unique_pages,
        });
        if self.cumulative.snapshots.len() > MAX_SNAPSHOTS {
            let excess = self.cumulative.snapshots.len() - MAX_SNAPSHOTS;
            self.cumulative.snapshots.drain(..excess);
        }

        // Write signal-data.js.
        let generated = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
        match self.render_js(&generated) {
            Ok(js) => {
                if let Err(e) = std::fs::write(&self.output_path, &js) {
                    tracing::warn!(error = %e, "signal-data.js write failed");
                } else {
                    tracing::info!(
                        bytes = js.len(),
                        pages = self.current_pages.len(),
                        "📡 signal-data.js updated"
                    );
                }
            }
            Err(e) => tracing::warn!(error = %e, "signal-data.js render failed"),
        }

        // Save cumulative state.
        self.save_state();

        // Reset current window.
        self.current_pages.clear();
        self.current_sites.clear();
        self.human_hits = 0;
        self.bot_hits = 0;
        self.ai_hits = 0;
        self.scanner_hits = 0;
        self.obs_count = 0;
    }

    /// Render the signal-data.js content.
    fn render_js(&self, generated: &str) -> Result<String, std::fmt::Error> {
        use std::fmt::Write;
        let mut js = String::with_capacity(16384);

        writeln!(js, "// Signal exploration data v3 — generated by skunky-ingest signal_writer")?;
        writeln!(js, "// Generated: {generated}")?;
        writeln!(js, "// Real-time accumulation from bloom sensor — no log re-parsing.")?;
        writeln!(js, "// No IP addresses stored. No cookies. No tracking pixels.")?;
        writeln!(js)?;
        writeln!(js, "(function() {{")?;
        writeln!(js, "  window.SIGNAL_EXPLORATION = {{")?;
        writeln!(js, "    generated: \"{generated}\",")?;
        writeln!(js, "    lysogeny: \"active\",")?;

        // ── PAGES EXPLORED ──
        writeln!(js)?;
        writeln!(js, "    // ═══ EXPLORATION — pages with human signal ═══")?;
        writeln!(js)?;
        writeln!(js, "    pagesExplored: [")?;

        let mut pages: Vec<(&String, &u32)> = self.current_pages.iter().collect();
        pages.sort_by(|a, b| b.1.cmp(a.1));
        pages.truncate(MAX_PAGES_EXPLORED);

        for (key, hits) in &pages {
            let (site, path) = key.split_once('/').unwrap_or((key.as_str(), "/"));
            let label = path_to_label(path);
            let path_display = if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{path}")
            };
            writeln!(
                js,
                "      {{ site: \"{site}\", path: \"{path_display}\", label: \"{label}\", hits: {hits} }},"
            )?;
        }
        writeln!(js, "    ],")?;

        // ── SITES EXPLORED ──
        writeln!(js, "    sitesExplored: [")?;
        let mut sites: Vec<(&String, &SiteStats)> = self.current_sites.iter().collect();
        sites.sort_by(|a, b| b.1.human_hits.cmp(&a.1.human_hits));

        for (site, stats) in &sites {
            writeln!(
                js,
                "      {{ site: \"{site}\", pages: {}, humanHits: {}, uniqueHumans: {}, botHits: {}, aiHits: {} }},",
                stats.pages, stats.human_hits, stats.human_hits, stats.bot_hits, stats.ai_hits
            )?;
        }
        writeln!(js, "    ],")?;

        // ── HISTORY ──
        writeln!(js)?;
        writeln!(js, "    // ═══ HISTORY — cumulative memoization table ═══")?;
        writeln!(js)?;
        writeln!(js, "    history: {{")?;
        writeln!(
            js,
            "      totalHumanHitsEver: {},",
            self.cumulative.total_human_hits
        )?;
        writeln!(
            js,
            "      totalBotHitsEver: {},",
            self.cumulative.total_bot_hits
        )?;
        writeln!(
            js,
            "      totalAiHitsEver: {},",
            self.cumulative.total_ai_hits
        )?;

        // Top pages ever
        writeln!(js, "      topPagesEver: [")?;
        let mut top_ever: Vec<(&String, &u64)> = self.cumulative.pages_ever.iter().collect();
        top_ever.sort_by(|a, b| b.1.cmp(a.1));
        top_ever.truncate(30);
        for (key, count) in &top_ever {
            let (site, path) = key.split_once('/').unwrap_or((key.as_str(), "/"));
            let label = path_to_label(path);
            let path_display = if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{path}")
            };
            writeln!(
                js,
                "        {{ site: \"{site}\", path: \"{path_display}\", label: \"{label}\", totalHits: {count} }},"
            )?;
        }
        writeln!(js, "      ],")?;

        // Snapshots
        writeln!(js, "      snapshots: [")?;
        for snap in &self.cumulative.snapshots {
            writeln!(
                js,
                "        {{ ts: \"{}\", human: {}, bot: {}, ai: {}, stealth: {}, pages: {} }},",
                snap.ts, snap.human, snap.bot, snap.ai, snap.stealth, snap.pages
            )?;
        }
        writeln!(js, "      ],")?;

        // Sites ever
        writeln!(js, "      sitesEver: [")?;
        let mut sites_ever: Vec<(&String, &(u64, u64))> =
            self.cumulative.sites_ever.iter().collect();
        sites_ever.sort();
        for (site, (pages_count, total_hits)) in &sites_ever {
            writeln!(
                js,
                "        {{ site: \"{site}\", pages: {pages_count}, totalHits: {total_hits} }},"
            )?;
        }
        writeln!(js, "      ],")?;
        writeln!(js, "    }},")?;

        // ── SUMMARY ──
        writeln!(js)?;
        writeln!(js, "    summary: {{")?;
        writeln!(js, "      humanHits: {},", self.human_hits)?;
        writeln!(js, "      totalRequests: {},", self.human_hits + self.bot_hits + self.ai_hits + self.scanner_hits)?;
        writeln!(js, "      uniquePages: {},", self.current_pages.len())?;
        writeln!(js, "      crawlerHits: {},", self.bot_hits)?;
        writeln!(js, "      aiCrawlerHits: {},", self.ai_hits)?;
        writeln!(js, "      scannerHits: {},", self.scanner_hits)?;
        writeln!(
            js,
            "      allSiteHumanHits: {},",
            self.human_hits
        )?;
        writeln!(
            js,
            "      allSiteBotHits: {},",
            self.bot_hits
        )?;
        writeln!(
            js,
            "      allSiteAiHits: {},",
            self.ai_hits
        )?;
        writeln!(
            js,
            "      allSitePagesExplored: {},",
            self.current_pages.len()
        )?;
        writeln!(
            js,
            "      cumulativeHumanHitsEver: {},",
            self.cumulative.total_human_hits + self.human_hits
        )?;
        writeln!(
            js,
            "      cumulativePagesEver: {},",
            self.cumulative.pages_ever.len()
        )?;
        writeln!(
            js,
            "      cumulativeBotHitsEver: {},",
            self.cumulative.total_bot_hits + self.bot_hits
        )?;
        writeln!(
            js,
            "      cumulativeAiHitsEver: {}",
            self.cumulative.total_ai_hits + self.ai_hits
        )?;
        writeln!(js, "    }}")?;
        writeln!(js, "  }};")?;
        writeln!(js, "}})();")?;

        Ok(js)
    }

    fn load_state(path: &Path) -> CumulativeState {
        match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(state) => state,
                Err(e) => {
                    tracing::warn!(error = %e, "signal state parse failed, starting fresh");
                    CumulativeState::default()
                }
            },
            Err(_) => CumulativeState::default(),
        }
    }

    fn save_state(&self) {
        match serde_json::to_string_pretty(&self.cumulative) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.state_path, &json) {
                    tracing::warn!(error = %e, "signal state save failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "signal state serialize failed"),
        }
    }
}

/// Convert a URI path to a display label.
///
/// "/architecture/composition-patterns/" → "Composition Patterns"
/// "/commit/abc123def456" → "Abc123Def456"
fn path_to_label(path: &str) -> String {
    let clean = path.trim_matches('/');
    let segment = clean.rsplit('/').next().unwrap_or(clean);

    if segment.is_empty() {
        return "Home".to_string();
    }

    let label = segment
        .replace('-', " ")
        .replace('_', " ")
        .split_whitespace()
        .map(|w| {
            let mut chars = w.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => {
                    let upper: String = c.to_uppercase().collect();
                    format!("{upper}{}", chars.as_str())
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    if label.len() > 40 {
        format!("{}...", &label[..37])
    } else {
        label
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_from_simple_path() {
        assert_eq!(path_to_label("/about"), "About");
    }

    #[test]
    fn label_from_nested_path() {
        assert_eq!(
            path_to_label("/architecture/composition-patterns/"),
            "Composition Patterns"
        );
    }

    #[test]
    fn label_from_root() {
        assert_eq!(path_to_label("/"), "Home");
    }

    #[test]
    fn label_truncates_long() {
        let long_path = "/this-is-a-really-really-really-long-segment-name-that-exceeds-forty-characters";
        let label = path_to_label(long_path);
        assert!(label.len() <= 43); // 37 + "..."
        assert!(label.ends_with("..."));
    }

    #[test]
    fn accumulator_creates_with_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("signal-data.js");
        let state = dir.path().join("signal-state.json");
        let acc = SignalAccumulator::new(output, state, 5);
        assert_eq!(acc.obs_count, 0);
        assert!(acc.cumulative.pages_ever.is_empty());
    }

    #[test]
    fn accumulator_ingests_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("signal-data.js");
        let state = dir.path().join("signal-state.json");
        let mut acc = SignalAccumulator::new(output, state, 100);

        let mut readers = HashMap::new();
        readers.insert("human".to_string(), 10);
        readers.insert("search-crawler".to_string(), 50);
        readers.insert("ai-agent".to_string(), 3);

        let mut hosts = HashMap::new();
        hosts.insert("sporeprint.primals.eco".to_string(), 63);

        let obs = BloomObservation {
            window_start: 1000.0,
            window_end: 1060.0,
            total_requests: 63,
            unique_ips: 20,
            domains: HashMap::new(),
            readers,
            referrers: HashMap::new(),
            languages: vec![],
            cross_domain_sessions: 0,
            hosts,
        };

        acc.ingest(&obs);
        assert_eq!(acc.human_hits, 10);
        assert_eq!(acc.bot_hits, 50);
        assert_eq!(acc.ai_hits, 3);
    }

    #[test]
    fn flush_writes_js_and_state() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("signal-data.js");
        let state = dir.path().join("signal-state.json");
        let mut acc = SignalAccumulator::new(output.clone(), state.clone(), 1);

        let mut readers = HashMap::new();
        readers.insert("human".to_string(), 5);
        let obs = BloomObservation {
            window_start: 1000.0,
            window_end: 1060.0,
            total_requests: 5,
            unique_ips: 3,
            domains: HashMap::new(),
            readers,
            referrers: HashMap::new(),
            languages: vec![],
            cross_domain_sessions: 0,
            hosts: HashMap::new(),
        };

        let wrote = acc.ingest(&obs);
        assert!(wrote, "should write on first observation (interval=1)");
        assert!(output.exists(), "signal-data.js should exist");
        assert!(state.exists(), "state file should exist");

        let js = std::fs::read_to_string(&output).unwrap();
        assert!(js.contains("window.SIGNAL_EXPLORATION"));
        assert!(js.contains("lysogeny: \"active\""));
    }

    #[test]
    fn state_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("signal-data.js");
        let state = dir.path().join("signal-state.json");

        // First session — accumulate some data.
        {
            let mut acc = SignalAccumulator::new(output.clone(), state.clone(), 1);
            let mut readers = HashMap::new();
            readers.insert("human".to_string(), 100);
            readers.insert("search-crawler".to_string(), 500);
            let obs = BloomObservation {
                window_start: 1000.0,
                window_end: 1060.0,
                total_requests: 600,
                unique_ips: 50,
                domains: HashMap::new(),
                readers,
                referrers: HashMap::new(),
                languages: vec![],
                cross_domain_sessions: 0,
                hosts: HashMap::new(),
            };
            acc.ingest(&obs);
        }

        // Second session — load state and verify cumulative totals.
        let acc2 = SignalAccumulator::new(output, state, 1);
        assert_eq!(acc2.cumulative.total_human_hits, 100);
        assert_eq!(acc2.cumulative.total_bot_hits, 500);
        assert_eq!(acc2.cumulative.snapshots.len(), 1);
    }
}

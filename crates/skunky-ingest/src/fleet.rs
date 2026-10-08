// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Population-level fleet aggregation for stealth fleet detection.
//!
//! Unlike [`crate::aggregator::Aggregator`] which buckets per-IP, this
//! module analyzes the **population** of requests in a time window to
//! detect coordinated fleet patterns: UA uniformity, metronomic timing,
//! commit-level URL concentration, and IP rotation signatures.
//!
//! Emits [`FleetObservation`] when a window closes, ready for
//! `fleet.observe` JSON-RPC to skunkBat's `FleetDetector`.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use cellmembrane_types::fleet::{
    DeceptionSignals, FleetObservation, PathPattern, TimingSignature, UaFingerprint,
};

use crate::caddy::LogEntry;

/// Result from a completed fleet observation window.
pub struct FleetWindowResult {
    /// Population-level observation for skunkBat analysis.
    pub observation: FleetObservation,
    /// Unique IPs from this window (for CaddyBridge injection).
    pub ips: Vec<String>,
}

/// Population-level fleet aggregator.
///
/// Collects all requests to a target host (e.g. `git.primals.eco`) in
/// a time window and computes population statistics that reveal fleet
/// behavior invisible at the per-IP level.
pub struct FleetAggregator {
    window: Duration,
    window_start: f64,
    target_host: String,
    entries: Vec<FleetEntry>,
}

/// Minimal per-request record for fleet analysis.
struct FleetEntry {
    ua: String,
    path: String,
    ts: f64,
    status: u16,
    ip: String,
    has_referer: bool,
    accept_encoding: String,
    accept_language: String,
    /// Whether the request had Sec-Fetch-Mode header (mandatory in Chrome 76+).
    has_sec_fetch: bool,
    /// Whether the request had Sec-Ch-Ua header (mandatory in Chrome 89+).
    has_sec_ch_ua: bool,
    /// Chrome major version from UA string (0 if not Chrome).
    chrome_major: u16,
    /// Accept header value — real browsers vary per resource type.
    accept: String,
    /// Whether Connection header was present (Chrome sends keep-alive).
    has_connection: bool,
}

/// Current Chrome stable version. Update when Chrome releases new stable.
/// Chrome 155 stable: Oct 6, 2026. Two-week cadence since Chrome 153.
const CHROME_CURRENT_STABLE: u16 = 155;

/// Extract Chrome major version from a User-Agent string.
fn extract_chrome_major(ua: &str) -> u16 {
    // Look for "Chrome/NNN." pattern
    let Some(idx) = ua.find("Chrome/") else {
        return 0;
    };
    let after = &ua[idx + 7..];
    let end = after.find('.').unwrap_or(after.len());
    after[..end].parse().unwrap_or(0)
}

impl FleetAggregator {
    /// Create a new fleet aggregator for a specific host.
    pub fn new(window: Duration, target_host: String) -> Self {
        Self {
            window,
            window_start: 0.0,
            target_host,
            entries: Vec::with_capacity(256),
        }
    }

    /// Ingest a log entry. Returns a `FleetWindowResult` if the window closes.
    pub fn ingest(&mut self, entry: &LogEntry) -> Option<FleetWindowResult> {
        if !entry.request.host.contains(&self.target_host) {
            return None;
        }

        let window_secs = self.window.as_secs_f64();
        if self.window_start == 0.0 {
            self.window_start = entry.ts;
        }

        if entry.ts >= self.window_start + window_secs {
            let result = self.flush_with_ips();
            self.window_start = entry.ts;
            self.entries.clear();
            self.record(entry);
            result
        } else {
            self.record(entry);
            None
        }
    }

    /// Force-flush the current window.
    pub fn flush_remaining(&mut self) -> Option<FleetWindowResult> {
        let result = self.flush_with_ips();
        self.entries.clear();
        result
    }

    /// Flush and return both observation and unique IPs.
    fn flush_with_ips(&self) -> Option<FleetWindowResult> {
        let ips: Vec<String> = self
            .entries
            .iter()
            .map(|e| e.ip.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let observation = self.flush()?;
        Some(FleetWindowResult { observation, ips })
    }

    fn record(&mut self, entry: &LogEntry) {
        let ua = entry
            .request
            .headers
            .user_agent
            .first()
            .cloned()
            .unwrap_or_default();
        let has_referer = entry
            .request
            .headers
            .referer
            .first()
            .is_some_and(|r| !r.is_empty());
        let accept_encoding = entry
            .request
            .headers
            .accept_encoding
            .first()
            .cloned()
            .unwrap_or_default();
        let accept_language = entry
            .request
            .headers
            .accept_language
            .first()
            .cloned()
            .unwrap_or_default();
        let has_sec_fetch = !entry.request.headers.sec_fetch_mode.is_empty();
        let has_sec_ch_ua = !entry.request.headers.sec_ch_ua.is_empty();
        let chrome_major = extract_chrome_major(&ua);
        let accept = entry
            .request
            .headers
            .accept
            .first()
            .cloned()
            .unwrap_or_default();
        let has_connection = entry
            .request
            .headers
            .connection
            .first()
            .is_some_and(|c| !c.is_empty());

        self.entries.push(FleetEntry {
            ua,
            path: entry.request.uri.clone(),
            ts: entry.ts,
            status: entry.status,
            ip: entry.request.remote_ip.clone(),
            has_referer,
            accept_encoding,
            accept_language,
            has_sec_fetch,
            has_sec_ch_ua,
            chrome_major,
            accept,
            has_connection,
        });
    }

    fn flush(&self) -> Option<FleetObservation> {
        if self.entries.len() < 5 {
            return None;
        }

        let total_requests = self.entries.len() as u64;

        // UA distribution
        let mut ua_counts: HashMap<&str, u32> = HashMap::new();
        let mut platform_mac = 0u32;
        let mut platform_win = 0u32;
        let mut platform_linux = 0u32;
        for e in &self.entries {
            *ua_counts.entry(&e.ua).or_insert(0) += 1;
            let ua_lower = e.ua.to_lowercase();
            if ua_lower.contains("macintosh") {
                platform_mac += 1;
            } else if ua_lower.contains("windows") {
                platform_win += 1;
            } else if ua_lower.contains("linux") || ua_lower.contains("x11") {
                platform_linux += 1;
            }
        }
        let ua_count = ua_counts.len().min(255) as u8;
        let top_ua_count = ua_counts.values().max().copied().unwrap_or(0);
        let total_f = total_requests as f32;
        let top_ua_pct = top_ua_count as f32 / total_f;
        let platform_total = (platform_mac + platform_win + platform_linux).max(1) as f32;
        let platform_split = [
            platform_mac as f32 / platform_total,
            platform_win as f32 / platform_total,
            platform_linux as f32 / platform_total,
        ];

        // Unique IPs
        let unique_ips: HashSet<&str> = self.entries.iter().map(|e| e.ip.as_str()).collect();
        let unique_ip_count = unique_ips.len() as u32;

        // Timing analysis
        let mut timestamps: Vec<f64> = self.entries.iter().map(|e| e.ts).collect();
        timestamps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let intervals: Vec<f64> = timestamps.windows(2).map(|w| (w[1] - w[0]) * 1000.0).collect();
        let (mean_interval_ms, interval_cv) = if intervals.is_empty() {
            (0, 0.0)
        } else {
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            let variance =
                intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
            let std_dev = variance.sqrt();
            let cv = if mean > 0.0 { std_dev / mean } else { 0.0 };
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "mean_interval_ms is bounded by window size"
            )]
            (mean.min(u32::MAX as f64) as u32, cv as f32)
        };

        // Path patterns
        let commit_urls = self
            .entries
            .iter()
            .filter(|e| e.path.contains("/commit/"))
            .count();
        let commit_url_pct = commit_urls as f32 / total_f;

        // Session depth: per-IP page count
        let mut pages_per_ip: HashMap<&str, u32> = HashMap::new();
        for e in &self.entries {
            *pages_per_ip.entry(&e.ip).or_insert(0) += 1;
        }
        let single_page_ips = pages_per_ip.values().filter(|&&c| c == 1).count();
        let single_page_pct = single_page_ips as f32 / unique_ip_count.max(1) as f32;

        // Referrer presence
        let with_referer = self.entries.iter().filter(|e| e.has_referer).count();
        let has_referrer_pct = with_referer as f32 / total_f;

        // Deception signals
        let hides_identity = ua_count <= 4 && top_ua_pct > 0.3 && total_requests > 20;

        let rotates_ips = single_page_pct > 0.8 && unique_ip_count > 10;

        let rejected = self
            .entries
            .iter()
            .filter(|e| e.status == 403 || e.status == 429)
            .count();
        let rejected_ips_set: HashSet<&str> = self
            .entries
            .iter()
            .filter(|e| e.status == 403 || e.status == 429)
            .map(|e| e.ip.as_str())
            .collect();
        let ignores_rejection = rejected > 10 && rejected as f32 / total_f > 0.5;

        // Encoding uniformity
        let mut enc_counts: HashMap<&str, u32> = HashMap::new();
        let mut lang_counts: HashMap<&str, u32> = HashMap::new();
        for e in &self.entries {
            *enc_counts.entry(&e.accept_encoding).or_insert(0) += 1;
            *lang_counts.entry(&e.accept_language).or_insert(0) += 1;
        }
        let top_enc_pct = enc_counts
            .values()
            .max()
            .copied()
            .unwrap_or(0) as f32
            / total_f;
        let top_lang_pct = lang_counts
            .values()
            .max()
            .copied()
            .unwrap_or(0) as f32
            / total_f;
        let encoding_uniform = top_enc_pct > 0.9 && top_lang_pct > 0.9 && total_requests > 20;

        // Header poverty: requests with Chrome UA but missing mandatory
        // browser headers (Sec-Fetch-Mode, Sec-Ch-Ua). Chrome 145+ sends
        // 11+ headers; an HTTP client sends 3-4.
        let chrome_uas = self
            .entries
            .iter()
            .filter(|e| e.ua.contains("Chrome/"))
            .count();
        let chrome_missing_sec = self
            .entries
            .iter()
            .filter(|e| e.ua.contains("Chrome/") && !e.has_sec_fetch && !e.has_sec_ch_ua)
            .count();
        let chrome_impersonation = chrome_uas > 10
            && chrome_missing_sec as f32 / chrome_uas.max(1) as f32 > 0.8;

        // Header poverty: >80% of ALL requests lack mandatory browser
        // headers (Sec-Fetch-Mode). Any real browser (Chrome, Firefox,
        // Safari, Edge) sends Sec-Fetch headers since 2020+.
        let no_sec_fetch_count = self
            .entries
            .iter()
            .filter(|e| !e.has_sec_fetch)
            .count();
        let header_poverty =
            total_requests > 20 && no_sec_fetch_count as f32 / total_f > 0.8;

        // Stale Chrome version: >80% of Chrome-UA requests use a version
        // 5+ majors behind current stable. Real Chrome auto-updates — a
        // population stuck on one old version has hardcoded UA strings.
        let chrome_entries: Vec<u16> = self
            .entries
            .iter()
            .filter(|e| e.chrome_major > 0)
            .map(|e| e.chrome_major)
            .collect();
        let stale_chrome = if chrome_entries.len() > 10 {
            let mut version_counts: HashMap<u16, u32> = HashMap::new();
            for &v in &chrome_entries {
                *version_counts.entry(v).or_insert(0) += 1;
            }
            let top_version = version_counts
                .iter()
                .max_by_key(|&(_, &c)| c)
                .map(|(&v, _)| v)
                .unwrap_or(0);
            let top_count = version_counts.get(&top_version).copied().unwrap_or(0);
            let top_pct = top_count as f32 / chrome_entries.len() as f32;
            // Stale if: dominant version is 5+ behind stable AND >80% on one version
            top_pct > 0.8
                && CHROME_CURRENT_STABLE.saturating_sub(top_version) >= 5
        } else {
            false
        };

        // Accept monoculture: entire fleet uses one Accept value (e.g. `*/*`).
        // Real browsers vary: `text/html` for pages, `image/*` for images,
        // `application/json` for APIs. Universal `*/*` = HTTP client library.
        let mut accept_counts: HashMap<&str, u32> = HashMap::new();
        for e in &self.entries {
            *accept_counts.entry(&e.accept).or_insert(0) += 1;
        }
        let accept_monoculture = total_requests > 20 && accept_counts.len() <= 2;

        // Connection absent: real Chrome always sends `Connection: keep-alive`.
        // HTTP client libraries (reqwest, urllib, etc.) often omit it entirely.
        let no_connection_count = self
            .entries
            .iter()
            .filter(|e| !e.has_connection)
            .count();
        let connection_absent =
            total_requests > 20 && no_connection_count as f32 / total_f > 0.8;

        // Blame ratio: >10% of requests target `/blame/` paths — author
        // attribution intelligence gathering. Normal browsing has <1%.
        let blame_requests = self
            .entries
            .iter()
            .filter(|e| e.path.contains("/blame/"))
            .count();
        let blame_ratio = total_requests > 20 && blame_requests as f32 / total_f > 0.10;

        // Pagination walk: requests with `?page=N` where N > 50 — systematic
        // commit history enumeration. No human paginates through 50+ pages.
        let max_page: u32 = self
            .entries
            .iter()
            .filter_map(|e| {
                e.path
                    .find("page=")
                    .and_then(|idx| {
                        let after = &e.path[idx + 5..];
                        let end = after.find('&').unwrap_or(after.len());
                        after[..end].parse::<u32>().ok()
                    })
            })
            .max()
            .unwrap_or(0);
        let pagination_walk = total_requests > 20 && max_page > 50;

        // Depth distribution
        let d1 = pages_per_ip.values().filter(|&&c| c == 1).count() as u32;
        let d2 = pages_per_ip.values().filter(|&&c| (2..=3).contains(&c)).count() as u32;
        let d3 = pages_per_ip.values().filter(|&&c| (4..=10).contains(&c)).count() as u32;
        let d4 = pages_per_ip.values().filter(|&&c| c > 10).count() as u32;

        let ts_epoch = timestamps.last().copied().unwrap_or(0.0);
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "epoch seconds fit in u64"
        )]
        let timestamp_epoch = ts_epoch as u64;

        Some(FleetObservation {
            timestamp_epoch,
            total_requests,
            unique_ips: unique_ip_count,
            ua_fingerprint: UaFingerprint {
                ua_count,
                top_ua_pct,
                platform_split,
            },
            timing: TimingSignature {
                mean_interval_ms,
                interval_cv,
            },
            path_pattern: PathPattern {
                commit_url_pct,
                single_page_pct,
                has_referrer_pct,
            },
            deception: DeceptionSignals {
                hides_identity,
                rotates_ips,
                ignores_rejection,
                encoding_uniform,
                chrome_impersonation,
                header_poverty,
                stale_chrome,
                accept_monoculture,
                connection_absent,
                blame_ratio,
                pagination_walk,
            },
            depth_distribution: [d1, d2, d3, d4],
            rejected_ips: rejected_ips_set.len() as u32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caddy::{Headers, RequestInfo};

    fn make_fleet_entry(ip: &str, ua: &str, path: &str, status: u16, ts: f64) -> LogEntry {
        LogEntry {
            request: RequestInfo {
                remote_ip: ip.to_string(),
                host: "git.primals.eco".to_string(),
                uri: path.to_string(),
                method: "GET".to_string(),
                headers: Headers {
                    user_agent: vec![ua.to_string()],
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
            status,
            size: 512,
            duration: 0.01,
            ts,
        }
    }

    #[test]
    fn fleet_aggregator_detects_stealth_fleet() {
        let mut agg = FleetAggregator::new(Duration::from_secs(60), "git.primals".to_string());

        let mac_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";
        let win_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

        // Simulate 30 fleet requests: rotating IPs, 2 UAs, commit URLs, metronomic
        for i in 0..30 {
            let ip = format!("57.141.20.{}", i);
            let ua = if i % 2 == 0 { mac_ua } else { win_ua };
            let path = format!(
                "/ecoPrimals/wateringHole/src/commit/{:040x}/file",
                i as u64
            );
            agg.ingest(&make_fleet_entry(&ip, ua, &path, 403, 100.0 + f64::from(i) * 2.0));
        }

        // Close the window
        let result = agg
            .ingest(&make_fleet_entry("1.2.3.4", mac_ua, "/", 200, 200.0))
            .expect("should produce observation");
        let obs = &result.observation;

        assert_eq!(obs.total_requests, 30);
        assert_eq!(obs.unique_ips, 30);
        assert_eq!(obs.ua_fingerprint.ua_count, 2);
        assert!(obs.ua_fingerprint.top_ua_pct > 0.49);
        assert!(obs.path_pattern.commit_url_pct > 0.9);
        assert!(obs.path_pattern.single_page_pct > 0.9);
        assert!(obs.deception.hides_identity);
        assert!(obs.deception.rotates_ips);
        assert!(obs.deception.ignores_rejection);
        assert_eq!(result.ips.len(), 30, "should have 30 unique fleet IPs");
    }

    #[test]
    fn fleet_aggregator_ignores_other_hosts() {
        let mut agg = FleetAggregator::new(Duration::from_secs(60), "git.primals".to_string());

        let mut entry = make_fleet_entry("1.2.3.4", "Mozilla/5.0", "/", 200, 100.0);
        entry.request.host = "detroit.primals.eco".to_string();
        assert!(agg.ingest(&entry).is_none());
    }

    #[test]
    fn fleet_aggregator_flush_remaining() {
        let mut agg = FleetAggregator::new(Duration::from_secs(60), "git.primals".to_string());
        for i in 0..10 {
            agg.ingest(&make_fleet_entry(
                &format!("10.0.0.{i}"),
                "Mozilla/5.0",
                "/",
                200,
                100.0 + f64::from(i),
            ));
        }
        let result = agg.flush_remaining().expect("should flush");
        assert_eq!(result.observation.total_requests, 10);
        assert_eq!(result.ips.len(), 10);
    }
}

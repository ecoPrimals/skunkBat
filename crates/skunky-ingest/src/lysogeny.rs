// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Lysogeny sentinel — detects foreign integration into self.
//!
//! In biology, lysogeny occurs when a bacteriophage integrates its genome
//! into the host chromosome. The host cell reproduces normally but now
//! carries foreign genetic material. The prophage can remain dormant or
//! activate under stress, hijacking the host's machinery.
//!
//! For the immune system, lysogeny detection means:
//!
//! 1. **Genome integrity** — hash critical config files (our "genome") and
//!    detect unauthorized mutations. If someone modifies the Caddyfile or
//!    self-IPs list outside skunky-ingest, that's potential prophage insertion.
//!
//! 2. **Process parasitism** — monitor for stuck/zombie processes that consume
//!    resources without producing useful work. The stuck `serv key-10`
//!    processes that OOM'd Forgejo are an example — foreign (or broken)
//!    processes draining self's resources.
//!
//! 3. **Self-behavioral anomaly** — track self-IP request patterns. If a
//!    known self-IP starts acting like fleet (commit scraping, high rate,
//!    no cookies), that gate may be compromised — lysogeny activated.
//!
//! The sentinel runs periodically and emits [`LysogenyAlert`] events when
//! anomalies are detected. It does NOT store IP addresses — it stores only
//! behavioral counters and hashes.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::caddy::LogEntry;

// ── Alert types ──────────────────────────────────────────────────────────

/// A lysogeny alert — something foreign has been detected in self.
#[derive(Debug, Clone)]
pub struct LysogenyAlert {
    /// What triggered the alert.
    pub kind: AlertKind,
    /// How severe the alert is.
    pub severity: Severity,
    /// Human-readable description.
    pub message: String,
}

/// What triggered the alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertKind {
    /// Config file hash changed without us writing it.
    GenomeMutation {
        /// Which file was mutated.
        file: String,
    },
    /// Self-IP is exhibiting fleet-like behavior.
    SelfBehavioralAnomaly,
    /// Process watchdog detected resource parasitism.
    ProcessParasitism {
        /// Diagnostic details (memory %, stuck count, etc.).
        detail: String,
    },
}

/// Alert severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Something unusual but possibly benign (e.g., config edited by admin).
    Warning,
    /// Strong evidence of compromise or foreign integration.
    Critical,
}

// ── Genome integrity ─────────────────────────────────────────────────────

/// A tracked config file ("gene").
struct GenomeGene {
    path: PathBuf,
    /// Marker pair to exclude from hashing (dynamic regions).
    /// Content between start_marker..end_marker is replaced with a
    /// fixed placeholder before hashing so that fleet IP changes
    /// don't trigger false positives.
    exclude_markers: Option<(String, String)>,
    /// SHA-256 of the static content at last known-good state.
    baseline_hash: Option<String>,
    /// When the baseline was last set (by us or at startup).
    baseline_set_at: Option<Instant>,
}

impl GenomeGene {
    fn new(path: PathBuf, exclude_markers: Option<(String, String)>) -> Self {
        Self {
            path,
            exclude_markers,
            baseline_hash: None,
            baseline_set_at: None,
        }
    }

    /// Compute hash of file content, excluding dynamic marker regions.
    fn current_hash(&self) -> Option<String> {
        let content = std::fs::read_to_string(&self.path).ok()?;
        let hashable = match &self.exclude_markers {
            Some((start, end)) => {
                // Replace content between markers with fixed placeholder
                if let (Some(s), Some(e)) = (content.find(start.as_str()), content.find(end.as_str())) {
                    let end_of_end = content[e..].find('\n').map_or(content.len(), |i| e + i + 1);
                    format!(
                        "{}<<DYNAMIC_REGION>>{}",
                        &content[..s],
                        &content[end_of_end..]
                    )
                } else {
                    content
                }
            }
            None => content,
        };

        let mut hasher = Sha256::new();
        hasher.update(hashable.as_bytes());
        Some(format!("{:x}", hasher.finalize()))
    }

    /// Set or refresh the baseline from the current file state.
    fn refresh_baseline(&mut self) {
        self.baseline_hash = self.current_hash();
        self.baseline_set_at = Some(Instant::now());
        if let Some(ref hash) = self.baseline_hash {
            tracing::info!(
                file = %self.path.display(),
                hash = &hash[..16],
                "genome baseline set"
            );
        }
    }

    /// Check if the current hash matches the baseline.
    /// Returns `Some(alert)` if mutation detected.
    fn check(&self) -> Option<LysogenyAlert> {
        let Some(ref baseline) = self.baseline_hash else {
            return None; // No baseline yet
        };
        let Some(current) = self.current_hash() else {
            return Some(LysogenyAlert {
                kind: AlertKind::GenomeMutation {
                    file: self.path.display().to_string(),
                },
                severity: Severity::Critical,
                message: format!(
                    "genome file unreadable: {} — may have been deleted or permissions changed",
                    self.path.display()
                ),
            });
        };

        if current != *baseline {
            Some(LysogenyAlert {
                kind: AlertKind::GenomeMutation {
                    file: self.path.display().to_string(),
                },
                severity: Severity::Warning,
                message: format!(
                    "genome mutation detected: {} — hash changed from {}.. to {}.. (external modification?)",
                    self.path.display(),
                    &baseline[..16],
                    &current[..16],
                ),
            })
        } else {
            None
        }
    }
}

// ── Self-behavioral anomaly ──────────────────────────────────────────────

/// Per-self-IP behavioral counters for the current window.
/// NOTE: We do NOT store the IP itself in alerts — only counters.
#[derive(Debug, Default)]
struct SelfIpBehavior {
    /// Total requests in the current window.
    request_count: u32,
    /// Requests to deep content paths (commit, src, raw, etc.).
    deep_content_requests: u32,
    /// Requests without session cookies.
    cookieless_requests: u32,
    /// Distinct paths accessed.
    unique_paths: HashSet<String>,
}

impl SelfIpBehavior {
    /// Does this self-IP's behavior look fleet-like?
    fn is_anomalous(&self) -> bool {
        // Thresholds: if a self-IP makes >50 requests/window AND
        // >80% are deep content AND >90% are cookieless → suspicious
        self.request_count > 50
            && self.deep_content_requests as f32 / self.request_count.max(1) as f32 > 0.8
            && self.cookieless_requests as f32 / self.request_count.max(1) as f32 > 0.9
    }
}

/// Deep content path segments that indicate extraction attempts.
const DEEP_CONTENT_SEGMENTS: &[&str] = &[
    "/src/", "/raw/", "/commit/", "/blame/", "/wiki/",
    "/issues/", "/milestones/", "/releases/", "/activity/",
    "/graph/", "/compare/", "/diff/", "/labels/", "/projects/",
];

/// Check if a URI targets deep content.
fn is_deep_content_path(uri: &str) -> bool {
    DEEP_CONTENT_SEGMENTS.iter().any(|seg| uri.contains(seg))
}

// NOTE: Session cookie detection is deferred — Caddy structured logs
// may not include Cookie headers by default. The behavioral detector
// relies on deep_content_requests ratio instead, which is sufficient
// for detecting fleet-like access patterns from self-IPs.

// ── Process watchdog ─────────────────────────────────────────────────────

/// Check for stuck Forgejo serv processes and cgroup memory pressure.
/// Returns alerts if anomalies are found.
fn check_process_health() -> Vec<LysogenyAlert> {
    let mut alerts = Vec::new();

    // Check Forgejo cgroup memory
    if let Ok(current) = std::fs::read_to_string("/sys/fs/cgroup/system.slice/forgejo.service/memory.current") {
        if let Ok(max) = std::fs::read_to_string("/sys/fs/cgroup/system.slice/forgejo.service/memory.max") {
            let current_bytes: u64 = current.trim().parse().unwrap_or(0);
            let max_bytes: u64 = max.trim().parse().unwrap_or(u64::MAX);
            if max_bytes > 0 && max_bytes != u64::MAX {
                let pct = current_bytes * 100 / max_bytes;
                if pct > 85 {
                    alerts.push(LysogenyAlert {
                        kind: AlertKind::ProcessParasitism {
                            detail: format!("memory_pct={pct}"),
                        },
                        severity: if pct > 95 { Severity::Critical } else { Severity::Warning },
                        message: format!(
                            "Forgejo memory pressure: {pct}% of cgroup max ({} / {} MB)",
                            current_bytes / 1_048_576,
                            max_bytes / 1_048_576,
                        ),
                    });
                }
            }
        }
    }

    // Count stuck serv processes (> 5 min old)
    let max_age_secs = 300;
    let mut stuck_count = 0u32;
    if let Ok(entries) = std::fs::read_dir("/proc") {
        let now = std::time::SystemTime::now();
        for entry in entries.flatten() {
            let Ok(pid_str) = entry.file_name().into_string() else { continue };
            if pid_str.parse::<u32>().is_err() { continue; }

            let cmdline_path = entry.path().join("cmdline");
            if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                if cmdline.contains("forgejo") && cmdline.contains("serv") {
                    // Check age via /proc/PID/stat starttime or file metadata
                    if let Ok(meta) = std::fs::metadata(&cmdline_path) {
                        if let Ok(age) = now.duration_since(meta.modified().unwrap_or(now)) {
                            if age.as_secs() > max_age_secs {
                                stuck_count += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    if stuck_count > 0 {
        alerts.push(LysogenyAlert {
            kind: AlertKind::ProcessParasitism {
                detail: format!("stuck_serv={stuck_count}"),
            },
            severity: if stuck_count > 5 { Severity::Critical } else { Severity::Warning },
            message: format!(
                "Forgejo has {stuck_count} stuck serv process(es) older than {max_age_secs}s — resource parasitism"
            ),
        });
    }

    alerts
}

// ── Sentinel ─────────────────────────────────────────────────────────────

/// Configuration for the lysogeny sentinel.
#[derive(Debug, Clone)]
pub struct LysogenyConfig {
    /// Paths to config files to monitor for integrity.
    pub genome_files: Vec<(PathBuf, Option<(String, String)>)>,
    /// Self-IPs to monitor for behavioral anomalies.
    pub self_ips: HashSet<String>,
    /// How often to run integrity checks (seconds).
    pub check_interval_secs: u64,
    /// Behavioral anomaly window (seconds).
    pub behavioral_window_secs: u64,
}

/// The lysogeny sentinel — watches for foreign integration into self.
pub struct LysogenySentinel {
    genome: Vec<GenomeGene>,
    self_ips: HashSet<String>,
    self_behavior: HashMap<String, SelfIpBehavior>,
    behavioral_window: Duration,
    behavioral_window_start: Instant,
    check_interval: Duration,
    last_check: Instant,
    /// Total alerts emitted (monotonic counter).
    pub alert_count: u64,
}

impl LysogenySentinel {
    /// Create a new lysogeny sentinel.
    pub fn new(config: LysogenyConfig) -> Self {
        let mut genome: Vec<GenomeGene> = config
            .genome_files
            .into_iter()
            .map(|(path, markers)| GenomeGene::new(path, markers))
            .collect();

        // Set initial baselines
        for gene in &mut genome {
            gene.refresh_baseline();
        }

        let now = Instant::now();
        Self {
            genome,
            self_ips: config.self_ips,
            self_behavior: HashMap::new(),
            behavioral_window: Duration::from_secs(config.behavioral_window_secs),
            behavioral_window_start: now,
            check_interval: Duration::from_secs(config.check_interval_secs),
            last_check: now,
            alert_count: 0,
        }
    }

    /// Feed a log entry to the sentinel for self-behavioral tracking.
    /// Only processes entries from self-IPs; ignores everything else.
    pub fn observe(&mut self, entry: &LogEntry) {
        if !self.self_ips.contains(&entry.request.remote_ip) {
            return;
        }

        let behavior = self
            .self_behavior
            .entry(entry.request.remote_ip.clone())
            .or_default();

        behavior.request_count += 1;
        if is_deep_content_path(&entry.request.uri) {
            behavior.deep_content_requests += 1;
        }
        // For now, count all requests as "cookieless" since we don't
        // have cookie headers in structured logs. This makes the
        // behavioral detector rely on deep_content_requests ratio instead.
        behavior.cookieless_requests += 1;
        behavior.unique_paths.insert(entry.request.uri.clone());
    }

    /// Run periodic checks. Call this regularly (e.g., every second).
    /// Returns alerts if anomalies are detected.
    pub fn tick(&mut self) -> Vec<LysogenyAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Check if behavioral window has closed
        if now.duration_since(self.behavioral_window_start) >= self.behavioral_window {
            for (_ip, behavior) in &self.self_behavior {
                if behavior.is_anomalous() {
                    alerts.push(LysogenyAlert {
                        kind: AlertKind::SelfBehavioralAnomaly,
                        severity: Severity::Critical,
                        message: format!(
                            "self-IP exhibiting fleet behavior: {} requests, {:.0}% deep content, {} unique paths — potential lysogeny activation",
                            behavior.request_count,
                            behavior.deep_content_requests as f32 / behavior.request_count.max(1) as f32 * 100.0,
                            behavior.unique_paths.len(),
                        ),
                    });
                }
            }
            self.self_behavior.clear();
            self.behavioral_window_start = now;
        }

        // Periodic integrity + process checks
        if now.duration_since(self.last_check) >= self.check_interval {
            // Genome integrity
            for gene in &self.genome {
                if let Some(alert) = gene.check() {
                    alerts.push(alert);
                }
            }

            // Process health
            alerts.extend(check_process_health());

            self.last_check = now;
        }

        self.alert_count += alerts.len() as u64;
        alerts
    }

    /// Notify the sentinel that WE just wrote a config file.
    /// Refreshes the baseline hash so our own writes don't trigger alerts.
    pub fn notify_self_write(&mut self, path: &Path) {
        for gene in &mut self.genome {
            if gene.path == path {
                gene.refresh_baseline();
                tracing::debug!(
                    file = %path.display(),
                    "genome baseline refreshed after self-write"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caddy::{Headers, LogEntry, RequestInfo};

    fn make_entry(ip: &str, uri: &str, status: u16) -> LogEntry {
        LogEntry {
            request: RequestInfo {
                remote_ip: ip.to_string(),
                host: "git.primals.eco".to_string(),
                uri: uri.to_string(),
                method: "GET".to_string(),
                headers: Headers::default(),
            },
            status,
            size: 0,
            duration: 0.01,
            ts: 1000.0,
        }
    }

    #[test]
    fn genome_hash_detects_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("test.conf");
        std::fs::write(&config_file, "original content\n").unwrap();

        let mut gene = GenomeGene::new(config_file.clone(), None);
        gene.refresh_baseline();

        // No mutation
        assert!(gene.check().is_none());

        // Mutate the file
        std::fs::write(&config_file, "MODIFIED content\n").unwrap();
        let alert = gene.check().expect("should detect mutation");
        assert!(matches!(alert.kind, AlertKind::GenomeMutation { .. }));
        assert_eq!(alert.severity, Severity::Warning);
    }

    #[test]
    fn genome_hash_excludes_dynamic_region() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("Caddyfile");
        std::fs::write(
            &config_file,
            "# static header\n# ~~START~~\ndynamic content\n# ~~END~~\n# static footer\n",
        )
        .unwrap();

        let mut gene = GenomeGene::new(
            config_file.clone(),
            Some(("~~START~~".to_string(), "~~END~~".to_string())),
        );
        gene.refresh_baseline();

        // Change only the dynamic region → should NOT trigger
        std::fs::write(
            &config_file,
            "# static header\n# ~~START~~\nNEW dynamic content\n# ~~END~~\n# static footer\n",
        )
        .unwrap();
        assert!(gene.check().is_none(), "dynamic region change should not trigger alert");

        // Change the static region → SHOULD trigger
        std::fs::write(
            &config_file,
            "# MODIFIED header\n# ~~START~~\nNEW dynamic content\n# ~~END~~\n# static footer\n",
        )
        .unwrap();
        assert!(gene.check().is_some(), "static region change should trigger alert");
    }

    #[test]
    fn genome_deleted_file_is_critical() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("test.conf");
        std::fs::write(&config_file, "content").unwrap();

        let mut gene = GenomeGene::new(config_file.clone(), None);
        gene.refresh_baseline();

        std::fs::remove_file(&config_file).unwrap();
        let alert = gene.check().expect("should detect deletion");
        assert_eq!(alert.severity, Severity::Critical);
    }

    #[test]
    fn self_behavioral_anomaly_detection() {
        let self_ips: HashSet<String> = ["10.13.37.2"].iter().map(|s| s.to_string()).collect();
        let config = LysogenyConfig {
            genome_files: vec![],
            self_ips,
            check_interval_secs: 3600, // long interval so only behavioral check fires
            behavioral_window_secs: 0, // immediate window close
        };
        let mut sentinel = LysogenySentinel::new(config);

        // Simulate a self-IP doing fleet-like behavior
        for i in 0..60 {
            sentinel.observe(&make_entry(
                "10.13.37.2",
                &format!("/ecoPrimals/repo/commit/{i:040x}"),
                200,
            ));
        }

        // Wait a tiny bit so the window closes
        std::thread::sleep(Duration::from_millis(10));
        let alerts = sentinel.tick();

        let anomaly = alerts.iter().find(|a| a.kind == AlertKind::SelfBehavioralAnomaly);
        assert!(anomaly.is_some(), "should detect self-behavioral anomaly");
    }

    #[test]
    fn non_self_ip_ignored() {
        let self_ips: HashSet<String> = ["10.13.37.2"].iter().map(|s| s.to_string()).collect();
        let config = LysogenyConfig {
            genome_files: vec![],
            self_ips,
            check_interval_secs: 3600,
            behavioral_window_secs: 0,
        };
        let mut sentinel = LysogenySentinel::new(config);

        // External IP does fleet-like stuff → should NOT trigger
        for i in 0..60 {
            sentinel.observe(&make_entry(
                "57.141.20.1",
                &format!("/ecoPrimals/repo/commit/{i:040x}"),
                200,
            ));
        }

        std::thread::sleep(Duration::from_millis(10));
        let alerts = sentinel.tick();
        let anomaly = alerts.iter().find(|a| a.kind == AlertKind::SelfBehavioralAnomaly);
        assert!(anomaly.is_none(), "non-self IP should not trigger anomaly");
    }

    #[test]
    fn normal_self_traffic_not_anomalous() {
        let self_ips: HashSet<String> = ["10.13.37.2"].iter().map(|s| s.to_string()).collect();
        let config = LysogenyConfig {
            genome_files: vec![],
            self_ips,
            check_interval_secs: 3600,
            behavioral_window_secs: 0,
        };
        let mut sentinel = LysogenySentinel::new(config);

        // Self-IP doing normal browsing (not deep content)
        for i in 0..20 {
            sentinel.observe(&make_entry("10.13.37.2", &format!("/explore/repos?page={i}"), 200));
        }

        std::thread::sleep(Duration::from_millis(10));
        let alerts = sentinel.tick();
        let anomaly = alerts.iter().find(|a| a.kind == AlertKind::SelfBehavioralAnomaly);
        assert!(anomaly.is_none(), "normal browsing should not trigger anomaly");
    }

    #[test]
    fn deep_content_path_detection() {
        assert!(is_deep_content_path("/ecoPrimals/repo/src/branch/main/file.rs"));
        assert!(is_deep_content_path("/ecoPrimals/repo/commit/abc123"));
        assert!(is_deep_content_path("/ecoPrimals/repo/raw/branch/main/file"));
        assert!(is_deep_content_path("/ecoPrimals/repo/blame/branch/main/file"));
        assert!(is_deep_content_path("/ecoPrimals/repo/wiki/page"));
        assert!(is_deep_content_path("/ecoPrimals/repo/issues/42"));
        assert!(!is_deep_content_path("/"));
        assert!(!is_deep_content_path("/explore/repos"));
        assert!(!is_deep_content_path("/ecoPrimals/repo"));
    }

    #[test]
    fn notify_self_write_prevents_false_positive() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("test.conf");
        std::fs::write(&config_file, "original").unwrap();

        let config = LysogenyConfig {
            genome_files: vec![(config_file.clone(), None)],
            self_ips: HashSet::new(),
            check_interval_secs: 0,
            behavioral_window_secs: 3600,
        };
        let mut sentinel = LysogenySentinel::new(config);

        // We write the file ourselves
        std::fs::write(&config_file, "updated by skunky-ingest").unwrap();
        sentinel.notify_self_write(&config_file);

        // Should NOT trigger because we refreshed the baseline
        std::thread::sleep(Duration::from_millis(10));
        let alerts = sentinel.tick();
        let mutations: Vec<_> = alerts
            .iter()
            .filter(|a| matches!(a.kind, AlertKind::GenomeMutation { .. }))
            .collect();
        assert!(mutations.is_empty(), "self-write should not trigger genome mutation alert");
    }
}

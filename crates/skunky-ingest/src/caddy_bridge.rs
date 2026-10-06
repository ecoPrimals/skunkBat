// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Caddy bridge — writes fleet-matched IPs into Caddyfile for blocking.
//!
//! Replaces the Python `fleet-pressure.py` daemon with Rust-driven
//! antibody-based IP injection. The bridge:
//!
//! 1. Receives `FleetObservation` from the `FleetAggregator`
//! 2. Queries skunkBat `fleet.match` to check against stored antibodies
//! 3. On match: collects IPs from the observation window
//! 4. Writes matched IPs into the Caddyfile between markers
//! 5. Reloads Caddy
//!
//! ## IP Lifecycle
//!
//! IPs are ephemeral routing decisions — they are NOT stored in antibodies.
//! The antibody stores the behavioral shape. The bridge translates
//! "this observation matches antibody X" → "these IPs are fleet members
//! right now" → write to Caddy for immediate blocking.
//!
//! IPs expire after `ip_ttl` seconds without a new match.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use cellmembrane_types::fleet::DefensePosture;

/// Configuration for the Caddy bridge.
#[derive(Debug, Clone)]
pub struct CaddyBridgeConfig {
    /// Path to the Caddyfile to modify.
    pub caddyfile_path: PathBuf,
    /// Command to reload Caddy.
    pub caddy_reload_cmd: String,
    /// How long matched IPs stay in the block list (seconds).
    pub ip_ttl_secs: u64,
    /// Start marker in the Caddyfile.
    pub start_marker: String,
    /// End marker in the Caddyfile.
    pub end_marker: String,
}

impl Default for CaddyBridgeConfig {
    fn default() -> Self {
        Self {
            caddyfile_path: PathBuf::from("/etc/membrane/Caddyfile"),
            caddy_reload_cmd: "/opt/membrane/caddy reload --config /etc/membrane/Caddyfile --address localhost:2019".to_string(),
            ip_ttl_secs: 3600,
            start_marker: "~~FLEET_PRESSURE_START~~".to_string(),
            end_marker: "~~FLEET_PRESSURE_END~~".to_string(),
        }
    }
}

/// Tracked fleet IP with expiry and defense posture.
#[derive(Debug, Clone)]
struct TrackedIp {
    last_seen: SystemTime,
    posture: DefensePosture,
}

/// Caddy bridge state.
pub struct CaddyBridge {
    config: CaddyBridgeConfig,
    tracked_ips: HashMap<String, TrackedIp>,
    last_written: Vec<String>,
    /// Negative selection: IPs that must never be blocked (self-tolerance).
    /// Loaded from a file at startup. Any IP in this set is silently
    /// filtered from `add_fleet_ips` — the thymus catches autoimmune
    /// antibodies before they can attack self.
    self_ips: HashSet<String>,
}

/// Load self-IPs from a file (one IP per line, `#` comments, blank lines OK).
///
/// This is the negative selection step: any IP listed here will never be
/// added to fleet block lists, preventing autoimmune responses against
/// known infrastructure.
///
/// # Errors
///
/// Returns an error if the file cannot be read (missing file returns empty set).
pub fn load_self_ips(path: &Path) -> HashSet<String> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let ips: HashSet<String> = content
                .lines()
                .map(|line| line.split('#').next().unwrap_or("").trim())
                .filter(|ip| !ip.is_empty())
                .map(String::from)
                .collect();
            tracing::info!(
                count = ips.len(),
                path = %path.display(),
                "thymic negative selection loaded — {} self-IPs protected",
                ips.len()
            );
            ips
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "self-IPs file not found — negative selection disabled (all IPs vulnerable)"
            );
            HashSet::new()
        }
    }
}

impl CaddyBridge {
    /// Create a new Caddy bridge with self-tolerance (negative selection).
    ///
    /// `self_ips` contains IPs that must never be blocked. Pass an empty set
    /// to disable negative selection (not recommended in production).
    #[must_use]
    pub fn new(config: CaddyBridgeConfig, self_ips: HashSet<String>) -> Self {
        Self {
            config,
            tracked_ips: HashMap::new(),
            last_written: Vec::new(),
            self_ips,
        }
    }

    /// Add fleet IPs that matched an antibody with a specific defense posture.
    ///
    /// Called when `fleet.match` returns matching antibody IDs. The posture
    /// determines what Caddy directive is written (403/429/scatter/abort).
    /// Escalates posture if the same IP is already tracked at a lower level.
    ///
    /// **Negative selection**: Any IP in the `self_ips` set is silently
    /// filtered — the thymus catches autoimmune antibodies before they
    /// can attack self.
    pub fn add_fleet_ips(&mut self, ips: &[String], posture: DefensePosture) {
        let now = SystemTime::now();
        let mut self_filtered = 0u32;
        for ip in ips {
            // Negative selection — protect self
            if self.self_ips.contains(ip.as_str()) {
                self_filtered += 1;
                continue;
            }
            self.tracked_ips
                .entry(ip.clone())
                .and_modify(|t| {
                    t.last_seen = now;
                    if posture > t.posture {
                        t.posture = posture;
                    }
                })
                .or_insert(TrackedIp {
                    last_seen: now,
                    posture,
                });
        }
        if self_filtered > 0 {
            tracing::info!(
                filtered = self_filtered,
                "🧬 negative selection: {} self-IP(s) protected from fleet antibodies",
                self_filtered
            );
        }
    }

    /// Expire old IPs and write to Caddyfile if changed.
    ///
    /// Returns `Ok(true)` if the Caddyfile was updated and Caddy reloaded.
    /// Returns `Ok(false)` if no changes were needed.
    ///
    /// # Errors
    ///
    /// Returns an error if file I/O or Caddy reload fails.
    pub fn sync(&mut self) -> Result<bool, std::io::Error> {
        self.expire_stale_ips();

        let mut active_ips: Vec<String> = self.tracked_ips.keys().cloned().collect();
        active_ips.sort();

        if active_ips == self.last_written {
            return Ok(false);
        }

        self.write_caddyfile()?;
        self.reload_caddy()?;
        self.last_written = active_ips;

        Ok(true)
    }

    /// Get the current set of blocked IPs.
    #[must_use]
    pub fn active_ips(&self) -> Vec<String> {
        let mut ips: Vec<String> = self.tracked_ips.keys().cloned().collect();
        ips.sort();
        ips
    }

    /// Number of currently tracked IPs.
    #[must_use]
    pub fn tracked_count(&self) -> usize {
        self.tracked_ips.len()
    }

    /// Path to the Caddyfile being managed.
    #[must_use]
    pub fn caddyfile_path(&self) -> &Path {
        &self.config.caddyfile_path
    }

    fn expire_stale_ips(&mut self) {
        let ttl = Duration::from_secs(self.config.ip_ttl_secs);
        let now = SystemTime::now();
        self.tracked_ips.retain(|_ip, tracked| {
            now.duration_since(tracked.last_seen)
                .map_or(true, |age| age < ttl)
        });
    }

    /// Group tracked IPs by their defense posture.
    fn ips_by_posture(&self) -> HashMap<DefensePosture, Vec<String>> {
        let mut groups: HashMap<DefensePosture, Vec<String>> = HashMap::new();
        for (ip, tracked) in &self.tracked_ips {
            // Observe means no directive — skip
            if tracked.posture == DefensePosture::Observe {
                continue;
            }
            groups
                .entry(tracked.posture)
                .or_default()
                .push(ip.clone());
        }
        for ips in groups.values_mut() {
            ips.sort();
        }
        groups
    }

    /// Generate Caddy directives for a specific posture + IP set.
    fn posture_directive(posture: DefensePosture, ips: &[String]) -> String {
        if ips.is_empty() {
            return String::new();
        }
        let ip_list = ips.join(" ");
        match posture {
            DefensePosture::Observe => String::new(),

            DefensePosture::WarnRoute => format!(
                "\t@fleet_warn remote_ip {ip_list}\n\
                 \thandle @fleet_warn {{\n\
                 \t\trespond 403 {{\n\
                 \t\t\tbody \"Fleet behavior detected. Use github.com/ecoPrimals for automated access.\"\n\
                 \t\t\tclose\n\
                 \t\t}}\n\
                 \t}}\n"
            ),

            DefensePosture::SlowDegrade => format!(
                "\t@fleet_tarpit remote_ip {ip_list}\n\
                 \thandle @fleet_tarpit {{\n\
                 \t\trewrite * /tarpit{{uri}}\n\
                 \t\treverse_proxy localhost:9753 {{\n\
                 \t\t\theader_up X-Real-IP {{remote_host}}\n\
                 \t\t}}\n\
                 \t}}\n"
            ),

            DefensePosture::Scatter => format!(
                "\t@fleet_scatter remote_ip {ip_list}\n\
                 \thandle @fleet_scatter {{\n\
                 \t\treverse_proxy localhost:9753 {{\n\
                 \t\t\theader_up X-Real-IP {{remote_host}}\n\
                 \t\t}}\n\
                 \t}}\n"
            ),

            DefensePosture::Vanish => format!(
                "\t@fleet_vanish remote_ip {ip_list}\n\
                 \thandle @fleet_vanish {{\n\
                 \t\tabort\n\
                 \t}}\n"
            ),

            DefensePosture::Disperse => format!(
                "\t@fleet_disperse remote_ip {ip_list}\n\
                 \thandle @fleet_disperse {{\n\
                 \t\trewrite * /disperse{{uri}}\n\
                 \t\treverse_proxy localhost:9753 {{\n\
                 \t\t\theader_up X-Real-IP {{remote_host}}\n\
                 \t\t}}\n\
                 \t}}\n"
            ),
        }
    }

    fn write_caddyfile(&self) -> Result<(), std::io::Error> {
        let content = std::fs::read_to_string(&self.config.caddyfile_path)?;

        let start_idx = content.find(&self.config.start_marker);
        let end_idx = content.find(&self.config.end_marker);

        let (Some(start), Some(end)) = (start_idx, end_idx) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Caddyfile markers not found: {} / {}",
                    self.config.start_marker, self.config.end_marker
                ),
            ));
        };

        let start_line_end = content[start..]
            .find('\n')
            .map_or(content.len(), |i| start + i + 1);

        // Find the beginning of the line containing the end marker
        // (preserves any `\t# ` prefix so the marker stays commented)
        let end_line_start = content[..end].rfind('\n').map_or(0, |i| i + 1);

        let groups = self.ips_by_posture();

        // Build directive blocks in escalation order (most aggressive first —
        // Caddy evaluates matchers top-to-bottom, first match wins)
        let mut ip_block = String::new();
        for posture in [
            DefensePosture::Disperse,
            DefensePosture::Vanish,
            DefensePosture::Scatter,
            DefensePosture::SlowDegrade,
            DefensePosture::WarnRoute,
        ] {
            if let Some(ips) = groups.get(&posture) {
                ip_block.push_str(&Self::posture_directive(posture, ips));
            }
        }

        let new_content = format!(
            "{}{}{}",
            &content[..start_line_end],
            ip_block,
            &content[end_line_start..]
        );

        std::fs::write(&self.config.caddyfile_path, new_content)?;

        let total: usize = groups.values().map(Vec::len).sum();
        let summary: Vec<String> = groups
            .iter()
            .map(|(p, ips)| format!("{p}:{}", ips.len()))
            .collect();
        tracing::info!(
            total,
            postures = %summary.join(" "),
            path = %self.config.caddyfile_path.display(),
            "Caddyfile updated with posture-aware fleet directives"
        );

        Ok(())
    }

    fn reload_caddy(&self) -> Result<(), std::io::Error> {
        let parts: Vec<&str> = self.config.caddy_reload_cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty caddy reload command",
            ));
        }

        let output = std::process::Command::new(parts[0])
            .args(&parts[1..])
            .output()?;

        if output.status.success() {
            tracing::info!("Caddy reloaded successfully");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!(stderr = %stderr, "Caddy reload failed");
            Err(std::io::Error::other(format!("Caddy reload failed: {stderr}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_caddyfile_content() -> String {
        "git.primals.eco {\n\t# ~~FLEET_PRESSURE_START~~\n\t# ~~FLEET_PRESSURE_END~~\n\troot * /opt/ecoPrimals/gitea-data\n}\n".to_string()
    }

    fn test_config(caddyfile: PathBuf) -> CaddyBridgeConfig {
        CaddyBridgeConfig {
            caddyfile_path: caddyfile,
            caddy_reload_cmd: "true".to_string(),
            ip_ttl_secs: 3600,
            start_marker: "~~FLEET_PRESSURE_START~~".to_string(),
            end_marker: "~~FLEET_PRESSURE_END~~".to_string(),
        }
    }

    #[test]
    fn add_and_track_ips() {
        let config = CaddyBridgeConfig {
            caddyfile_path: PathBuf::from("/tmp/nonexistent"),
            caddy_reload_cmd: "echo reload".to_string(),
            ip_ttl_secs: 3600,
            ..Default::default()
        };
        let mut bridge = CaddyBridge::new(config, HashSet::new());

        bridge.add_fleet_ips(
            &["57.141.20.1".to_string(), "57.141.20.2".to_string()],
            DefensePosture::WarnRoute,
        );

        assert_eq!(bridge.tracked_count(), 2);
        let ips = bridge.active_ips();
        assert!(ips.contains(&"57.141.20.1".to_string()));
        assert!(ips.contains(&"57.141.20.2".to_string()));
    }

    #[test]
    fn posture_escalation_on_same_ip() {
        let mut bridge = CaddyBridge::new(CaddyBridgeConfig {
            caddyfile_path: PathBuf::from("/tmp/nonexistent"),
            caddy_reload_cmd: "true".to_string(),
            ..Default::default()
        }, HashSet::new());

        bridge.add_fleet_ips(&["1.2.3.4".to_string()], DefensePosture::WarnRoute);
        assert_eq!(bridge.tracked_ips["1.2.3.4"].posture, DefensePosture::WarnRoute);

        bridge.add_fleet_ips(&["1.2.3.4".to_string()], DefensePosture::Scatter);
        assert_eq!(bridge.tracked_ips["1.2.3.4"].posture, DefensePosture::Scatter);

        // Lower posture should NOT de-escalate
        bridge.add_fleet_ips(&["1.2.3.4".to_string()], DefensePosture::WarnRoute);
        assert_eq!(bridge.tracked_ips["1.2.3.4"].posture, DefensePosture::Scatter);
    }

    #[test]
    fn expire_stale_ips() {
        let config = CaddyBridgeConfig {
            caddyfile_path: PathBuf::from("/tmp/nonexistent"),
            caddy_reload_cmd: "echo reload".to_string(),
            ip_ttl_secs: 0,
            ..Default::default()
        };
        let mut bridge = CaddyBridge::new(config, HashSet::new());

        bridge.add_fleet_ips(&["1.2.3.4".to_string()], DefensePosture::WarnRoute);
        std::thread::sleep(Duration::from_millis(10));
        bridge.expire_stale_ips();

        assert_eq!(bridge.tracked_count(), 0);
    }

    #[test]
    fn write_warn_route_directive() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        {
            let mut f = std::fs::File::create(&caddyfile).unwrap();
            f.write_all(test_caddyfile_content().as_bytes()).unwrap();
        }

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(
            &["57.141.20.1".to_string(), "57.141.20.2".to_string()],
            DefensePosture::WarnRoute,
        );
        bridge.write_caddyfile().unwrap();

        let content = std::fs::read_to_string(&caddyfile).unwrap();
        assert!(content.contains("@fleet_warn"));
        assert!(content.contains("57.141.20.1"));
        assert!(content.contains("respond 403"));
        assert!(content.contains("~~FLEET_PRESSURE_END~~"));
    }

    #[test]
    fn write_tarpit_directive() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.1".to_string()], DefensePosture::SlowDegrade);
        bridge.write_caddyfile().unwrap();

        let content = std::fs::read_to_string(&caddyfile).unwrap();
        assert!(content.contains("@fleet_tarpit"));
        assert!(content.contains("/tarpit{uri}"));
        assert!(content.contains("reverse_proxy localhost:9753"));
    }

    #[test]
    fn write_scatter_directive() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.2".to_string()], DefensePosture::Scatter);
        bridge.write_caddyfile().unwrap();

        let content = std::fs::read_to_string(&caddyfile).unwrap();
        assert!(content.contains("@fleet_scatter"));
        assert!(content.contains("reverse_proxy localhost:9753"));
    }

    #[test]
    fn write_vanish_directive() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.3".to_string()], DefensePosture::Vanish);
        bridge.write_caddyfile().unwrap();

        let content = std::fs::read_to_string(&caddyfile).unwrap();
        assert!(content.contains("@fleet_vanish"));
        assert!(content.contains("abort"));
    }

    #[test]
    fn write_multi_posture_ordering() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.1".to_string()], DefensePosture::WarnRoute);
        bridge.add_fleet_ips(&["10.0.0.2".to_string()], DefensePosture::Vanish);
        bridge.add_fleet_ips(&["10.0.0.3".to_string()], DefensePosture::Scatter);
        bridge.write_caddyfile().unwrap();

        let content = std::fs::read_to_string(&caddyfile).unwrap();
        // Vanish should appear before Scatter, Scatter before WarnRoute
        let vanish_pos = content.find("@fleet_vanish").unwrap();
        let scatter_pos = content.find("@fleet_scatter").unwrap();
        let warn_pos = content.find("@fleet_warn").unwrap();
        assert!(vanish_pos < scatter_pos, "vanish should come before scatter");
        assert!(scatter_pos < warn_pos, "scatter should come before warn");
    }

    #[test]
    fn observe_posture_produces_no_directives() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.1".to_string()], DefensePosture::Observe);
        bridge.write_caddyfile().unwrap();

        let content = std::fs::read_to_string(&caddyfile).unwrap();
        assert!(!content.contains("@fleet_"));
    }

    #[test]
    fn sync_no_change_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile), HashSet::new());
        let changed = bridge.sync().unwrap();
        assert!(!changed);
    }

    #[test]
    fn negative_selection_filters_self_ips() {
        let self_ips: HashSet<String> =
            ["10.13.37.1", "162.226.225.148"].iter().map(|s| s.to_string()).collect();
        let mut bridge = CaddyBridge::new(
            CaddyBridgeConfig {
                caddyfile_path: PathBuf::from("/tmp/nonexistent"),
                caddy_reload_cmd: "true".to_string(),
                ..Default::default()
            },
            self_ips,
        );

        bridge.add_fleet_ips(
            &[
                "57.141.20.1".to_string(),  // fleet — should be tracked
                "162.226.225.148".to_string(),  // self — should be filtered
                "10.13.37.1".to_string(),  // self — should be filtered
                "57.141.20.2".to_string(),  // fleet — should be tracked
            ],
            DefensePosture::Vanish,
        );

        assert_eq!(bridge.tracked_count(), 2);
        assert!(bridge.tracked_ips.contains_key("57.141.20.1"));
        assert!(bridge.tracked_ips.contains_key("57.141.20.2"));
        assert!(!bridge.tracked_ips.contains_key("162.226.225.148"));
        assert!(!bridge.tracked_ips.contains_key("10.13.37.1"));
    }

    #[test]
    #[test]
    fn negative_selection_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let self_file = dir.path().join("self-ips.txt");
        std::fs::write(
            &self_file,
            "# Known infrastructure\n\
             162.226.225.148  # sporeGate WAN\n\
             10.13.37.1       # golgiBody wg0\n\
             \n\
             # golgiBody\n\
             157.230.3.183    # this server\n",
        )
        .unwrap();

        let self_ips = load_self_ips(&self_file);
        assert_eq!(self_ips.len(), 3);
        assert!(self_ips.contains("162.226.225.148"));
        assert!(self_ips.contains("10.13.37.1"));
        assert!(self_ips.contains("157.230.3.183"));
    }

    #[test]
    fn sync_with_new_ips_returns_true() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile), HashSet::new());
        bridge.add_fleet_ips(&["57.141.20.1".to_string()], DefensePosture::WarnRoute);
        let changed = bridge.sync().unwrap();
        assert!(changed);
    }
}

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

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

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

/// Tracked fleet IP with expiry.
#[derive(Debug, Clone)]
struct TrackedIp {
    last_seen: SystemTime,
}

/// Caddy bridge state.
pub struct CaddyBridge {
    config: CaddyBridgeConfig,
    tracked_ips: HashMap<String, TrackedIp>,
    last_written: Vec<String>,
}

impl CaddyBridge {
    /// Create a new Caddy bridge.
    #[must_use]
    pub fn new(config: CaddyBridgeConfig) -> Self {
        Self {
            config,
            tracked_ips: HashMap::new(),
            last_written: Vec::new(),
        }
    }

    /// Add fleet IPs that matched an antibody.
    ///
    /// Called when `fleet.match` returns matching antibody IDs.
    pub fn add_fleet_ips(&mut self, ips: &[String]) {
        let now = SystemTime::now();
        for ip in ips {
            self.tracked_ips
                .entry(ip.clone())
                .and_modify(|t| t.last_seen = now)
                .or_insert(TrackedIp { last_seen: now });
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

        self.write_caddyfile(&active_ips)?;
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

    fn expire_stale_ips(&mut self) {
        let ttl = Duration::from_secs(self.config.ip_ttl_secs);
        let now = SystemTime::now();
        self.tracked_ips.retain(|_ip, tracked| {
            now.duration_since(tracked.last_seen)
                .map_or(true, |age| age < ttl)
        });
    }

    fn write_caddyfile(&self, ips: &[String]) -> Result<(), std::io::Error> {
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

        let start_line_end = content[start..].find('\n').map_or(content.len(), |i| start + i + 1);

        let ip_block = if ips.is_empty() {
            String::new()
        } else {
            format!(
                "    @fleet_pressure_ip remote_ip {}\n    route @fleet_pressure_ip {{\n        respond 403 {{\n            body \"Fleet behavior detected. Use github.com/ecoPrimals for automated access.\"\n            close\n        }}\n    }}\n",
                ips.join(" ")
            )
        };

        let new_content = format!(
            "{}{}{}",
            &content[..start_line_end],
            ip_block,
            &content[end..]
        );

        std::fs::write(&self.config.caddyfile_path, new_content)?;

        tracing::info!(
            ips = ips.len(),
            path = %self.config.caddyfile_path.display(),
            "Caddyfile updated with fleet IPs"
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
        [
            "git.primals.eco {",
            "    # ~~FLEET_PRESSURE_START~~",
            "    # ~~FLEET_PRESSURE_END~~",
            "    root * /opt/ecoPrimals/gitea-data",
            "}",
        ]
        .join("\n")
    }

    #[test]
    fn add_and_track_ips() {
        let config = CaddyBridgeConfig {
            caddyfile_path: PathBuf::from("/tmp/nonexistent"),
            caddy_reload_cmd: "echo reload".to_string(),
            ip_ttl_secs: 3600,
            ..Default::default()
        };
        let mut bridge = CaddyBridge::new(config);

        bridge.add_fleet_ips(&[
            "57.141.20.1".to_string(),
            "57.141.20.2".to_string(),
        ]);

        assert_eq!(bridge.tracked_count(), 2);
        let ips = bridge.active_ips();
        assert!(ips.contains(&"57.141.20.1".to_string()));
        assert!(ips.contains(&"57.141.20.2".to_string()));
    }

    #[test]
    fn expire_stale_ips() {
        let config = CaddyBridgeConfig {
            caddyfile_path: PathBuf::from("/tmp/nonexistent"),
            caddy_reload_cmd: "echo reload".to_string(),
            ip_ttl_secs: 0,
            ..Default::default()
        };
        let mut bridge = CaddyBridge::new(config);

        bridge.add_fleet_ips(&["1.2.3.4".to_string()]);
        std::thread::sleep(Duration::from_millis(10));
        bridge.expire_stale_ips();

        assert_eq!(bridge.tracked_count(), 0);
    }

    #[test]
    fn write_caddyfile_injects_ips() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        {
            let mut f = std::fs::File::create(&caddyfile).unwrap();
            f.write_all(test_caddyfile_content().as_bytes()).unwrap();
        }

        let config = CaddyBridgeConfig {
            caddyfile_path: caddyfile.clone(),
            caddy_reload_cmd: "true".to_string(),
            ip_ttl_secs: 3600,
            start_marker: "~~FLEET_PRESSURE_START~~".to_string(),
            end_marker: "~~FLEET_PRESSURE_END~~".to_string(),
        };

        let bridge = CaddyBridge::new(config);
        bridge
            .write_caddyfile(&["57.141.20.1".to_string(), "57.141.20.2".to_string()])
            .unwrap();

        let content = std::fs::read_to_string(&caddyfile).unwrap();
        assert!(content.contains("57.141.20.1"));
        assert!(content.contains("57.141.20.2"));
        assert!(content.contains("@fleet_pressure_ip"));
        assert!(content.contains("~~FLEET_PRESSURE_END~~"));
    }

    #[test]
    fn sync_no_change_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let config = CaddyBridgeConfig {
            caddyfile_path: caddyfile,
            caddy_reload_cmd: "true".to_string(),
            ip_ttl_secs: 3600,
            start_marker: "~~FLEET_PRESSURE_START~~".to_string(),
            end_marker: "~~FLEET_PRESSURE_END~~".to_string(),
        };

        let mut bridge = CaddyBridge::new(config);
        let changed = bridge.sync().unwrap();
        assert!(!changed);
    }

    #[test]
    fn sync_with_new_ips_returns_true() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let config = CaddyBridgeConfig {
            caddyfile_path: caddyfile,
            caddy_reload_cmd: "true".to_string(),
            ip_ttl_secs: 3600,
            start_marker: "~~FLEET_PRESSURE_START~~".to_string(),
            end_marker: "~~FLEET_PRESSURE_END~~".to_string(),
        };

        let mut bridge = CaddyBridge::new(config);
        bridge.add_fleet_ips(&["57.141.20.1".to_string()]);
        let changed = bridge.sync().unwrap();
        assert!(changed);
    }
}

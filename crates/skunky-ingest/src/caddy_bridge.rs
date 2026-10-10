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
    /// Path to the Caddyfile (used for reload command, NOT written to).
    pub caddyfile_path: PathBuf,
    /// Command to reload Caddy.
    pub caddy_reload_cmd: String,
    /// How long matched IPs stay in the block list (seconds).
    pub ip_ttl_secs: u64,
    /// Start marker in the Caddyfile (legacy — used only for one-time migration).
    pub start_marker: String,
    /// End marker in the Caddyfile (legacy — used only for one-time migration).
    pub end_marker: String,
    /// Directory for import snippet files. caddy-bridge writes fleet matchers
    /// here instead of injecting into the Caddyfile. The Caddyfile uses
    /// `import /path/to/fleet.snippet` to include them.
    ///
    /// This is the vacuole fix: the Caddyfile was 78% fleet IP data (294KB
    /// of 378KB) because caddy-bridge rewrote the entire file every sync.
    /// Now the Caddyfile is static config and snippets are the ephemeral
    /// routing layer.
    pub snippet_dir: PathBuf,
}

impl Default for CaddyBridgeConfig {
    fn default() -> Self {
        Self {
            caddyfile_path: PathBuf::from("/etc/membrane/Caddyfile"),
            caddy_reload_cmd: "/opt/membrane/caddy reload --config /etc/membrane/Caddyfile --address localhost:2019".to_string(),
            ip_ttl_secs: 3600,
            start_marker: "~~FLEET_PRESSURE_START~~".to_string(),
            end_marker: "~~FLEET_PRESSURE_END~~".to_string(),
            snippet_dir: PathBuf::from("/opt/membrane/fleet-imports"),
        }
    }
}

/// Tracked fleet IP with expiry, defense posture, and behavioral hash.
#[derive(Debug, Clone)]
struct TrackedIp {
    last_seen: SystemTime,
    posture: DefensePosture,
    /// Behavioral hash of the fleet this IP belongs to.
    /// When present, Caddy passes it as `X-Fleet-Hash` to scatter_server
    /// so scatter can use per-hash adaptive amplification from OpsonizeCache.
    behavioral_hash: Option<String>,
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
    ///
    /// **Sourdough bootstrapping**: On creation, the bridge reads the
    /// fleet snippet file to restore `tracked_ips`. Falls back to parsing
    /// Caddyfile markers for backward compatibility during migration.
    /// The snippet file is the durable state.
    #[must_use]
    pub fn new(config: CaddyBridgeConfig, self_ips: HashSet<String>) -> Self {
        // Ensure snippet directory exists
        if let Err(e) = std::fs::create_dir_all(&config.snippet_dir) {
            tracing::warn!(
                error = %e,
                dir = %config.snippet_dir.display(),
                "could not create snippet directory"
            );
        }

        // Try snippet files first, fall back to Caddyfile markers
        let tracked_ips = {
            let snippet_path = config.snippet_dir.join("fleet.snippet");
            let from_snippets = Self::restore_from_snippet(&snippet_path);
            if from_snippets.is_empty() {
                // Backward compat: try legacy Caddyfile markers
                let from_legacy = Self::restore_from_caddyfile(&config);
                if !from_legacy.is_empty() {
                    tracing::info!(
                        restored = from_legacy.len(),
                        "🫓 sourdough: migrated {} fleet IPs from legacy Caddyfile markers",
                        from_legacy.len()
                    );
                }
                from_legacy
            } else {
                tracing::info!(
                    restored = from_snippets.len(),
                    "🫓 sourdough: restored {} fleet IPs from snippet file",
                    from_snippets.len()
                );
                from_snippets
            }
        };

        let mut last_written: Vec<String> = tracked_ips.keys().cloned().collect();
        last_written.sort();

        Self {
            config,
            tracked_ips,
            last_written,
            self_ips,
        }
    }

    /// Parse fleet directives from a snippet file.
    ///
    /// Reads `@fleet_{posture} remote_ip {ip_list}` lines and reconstructs
    /// TrackedIp entries. The snippet file is the sourdough starter.
    fn restore_from_snippet(path: &Path) -> HashMap<String, TrackedIp> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };
        Self::parse_fleet_directives(&content)
    }

    /// Parse existing fleet directives from the Caddyfile between markers.
    /// Legacy method — used only for backward-compatible migration.
    fn restore_from_caddyfile(config: &CaddyBridgeConfig) -> HashMap<String, TrackedIp> {
        let content = match std::fs::read_to_string(&config.caddyfile_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "sourdough: could not read Caddyfile for restoration"
                );
                return HashMap::new();
            }
        };

        let start_idx = content.find(&config.start_marker);
        let end_idx = content.find(&config.end_marker);
        let (Some(start), Some(end)) = (start_idx, end_idx) else {
            return HashMap::new();
        };

        Self::parse_fleet_directives(&content[start..end])
    }

    /// Shared parser for fleet directives — works on snippet content or
    /// Caddyfile marker sections. Extracts @fleet_* matchers and X-Fleet-Hash
    /// headers into TrackedIp entries.
    fn parse_fleet_directives(content: &str) -> HashMap<String, TrackedIp> {
        let mut tracked: HashMap<String, TrackedIp> = HashMap::new();
        let now = SystemTime::now();
        let mut last_parsed_ips: Vec<String> = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("header_up X-Fleet-Hash") {
                if let Some(hash) = trimmed
                    .split("X-Fleet-Hash")
                    .nth(1)
                    .map(|v| v.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty())
                {
                    for ip in &last_parsed_ips {
                        if let Some(t) = tracked.get_mut(ip) {
                            t.behavioral_hash = Some(hash.clone());
                        }
                    }
                }
                continue;
            }

            let posture = if trimmed.starts_with("@fleet_disperse") {
                DefensePosture::Disperse
            } else if trimmed.starts_with("@fleet_vanish") {
                DefensePosture::Vanish
            } else if trimmed.starts_with("@fleet_scatter") {
                DefensePosture::Scatter
            } else if trimmed.starts_with("@fleet_tarpit") {
                DefensePosture::SlowDegrade
            } else if trimmed.starts_with("@fleet_warn") {
                DefensePosture::WarnRoute
            } else {
                continue;
            };

            last_parsed_ips.clear();
            if let Some(ip_part) = trimmed.split("remote_ip").nth(1) {
                for ip in ip_part.split_whitespace() {
                    last_parsed_ips.push(ip.to_string());
                    tracked.insert(
                        ip.to_string(),
                        TrackedIp {
                            last_seen: now,
                            posture,
                            behavioral_hash: None,
                        },
                    );
                }
            }
        }

        tracked
    }

    /// Add fleet IPs that matched an antibody with a specific defense posture.
    ///
    /// Called when `fleet.match` returns matching antibody IDs. The posture
    /// determines what Caddy directive is written (403/429/scatter/abort).
    /// Escalates posture if the same IP is already tracked at a lower level.
    ///
    /// When `behavioral_hash` is provided, Caddy passes it as `X-Fleet-Hash`
    /// to scatter_server, enabling per-hash adaptive amplification from
    /// the OpsonizeCache. This closes the hash loop:
    /// log → fleet observation → behavioral_hash → Caddy header → scatter → adaptive poison.
    ///
    /// **Negative selection**: Any IP in the `self_ips` set is silently
    /// filtered — the thymus catches autoimmune antibodies before they
    /// can attack self.
    pub fn add_fleet_ips(&mut self, ips: &[String], posture: DefensePosture) {
        self.add_fleet_ips_with_hash(ips, posture, None);
    }

    /// Add fleet IPs with an associated behavioral hash.
    pub fn add_fleet_ips_with_hash(
        &mut self,
        ips: &[String],
        posture: DefensePosture,
        behavioral_hash: Option<&str>,
    ) {
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
                    // Update hash if we have a newer/better one
                    if behavioral_hash.is_some() {
                        t.behavioral_hash = behavioral_hash.map(String::from);
                    }
                })
                .or_insert(TrackedIp {
                    last_seen: now,
                    posture,
                    behavioral_hash: behavioral_hash.map(String::from),
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

    /// Group tracked IPs by their defense posture and behavioral hash.
    ///
    /// IPs with different hashes in the same posture are grouped by hash
    /// so each reverse_proxy block can pass the correct `X-Fleet-Hash`.
    /// IPs with no hash are grouped under `None`.
    fn ips_by_posture_and_hash(&self) -> HashMap<DefensePosture, Vec<(Option<String>, Vec<String>)>> {
        // First pass: group by (posture, hash)
        let mut raw: HashMap<(DefensePosture, Option<String>), Vec<String>> = HashMap::new();
        for (ip, tracked) in &self.tracked_ips {
            if tracked.posture == DefensePosture::Observe {
                continue;
            }
            raw.entry((tracked.posture, tracked.behavioral_hash.clone()))
                .or_default()
                .push(ip.clone());
        }
        for ips in raw.values_mut() {
            ips.sort();
        }
        // Second pass: regroup by posture
        let mut result: HashMap<DefensePosture, Vec<(Option<String>, Vec<String>)>> = HashMap::new();
        for ((posture, hash), ips) in raw {
            result.entry(posture).or_default().push((hash, ips));
        }
        // Sort sub-groups by first IP for deterministic output
        for groups in result.values_mut() {
            groups.sort_by(|a, b| {
                a.1.first().map(String::as_str).cmp(&b.1.first().map(String::as_str))
            });
        }
        result
    }

    /// Backward-compatible grouping (ignores hash). Used by sync() for change detection.
    fn ips_by_posture(&self) -> HashMap<DefensePosture, Vec<String>> {
        let mut groups: HashMap<DefensePosture, Vec<String>> = HashMap::new();
        for (ip, tracked) in &self.tracked_ips {
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

    /// Generate Caddy directives for a posture + hash group.
    ///
    /// When `behavioral_hash` is `Some`, the reverse_proxy block includes
    /// `header_up X-Fleet-Hash {hash}` so scatter_server can use
    /// per-hash adaptive amplification from the OpsonizeCache.
    fn posture_directive(
        posture: DefensePosture,
        ips: &[String],
        behavioral_hash: Option<&str>,
        idx: usize,
    ) -> String {
        if ips.is_empty() {
            return String::new();
        }
        let ip_list = ips.join(" ");
        // Use idx suffix to make matcher names unique when same posture has multiple hash groups
        let suffix = if idx > 0 { format!("_{idx}") } else { String::new() };

        let hash_header = behavioral_hash
            .map(|h| format!("\t\t\theader_up X-Fleet-Hash \"{h}\"\n"))
            .unwrap_or_default();

        match posture {
            DefensePosture::Observe => String::new(),

            DefensePosture::WarnRoute => format!(
                "\t@fleet_warn{suffix} remote_ip {ip_list}\n\
                 \thandle @fleet_warn{suffix} {{\n\
                 \t\trespond 403 {{\n\
                 \t\t\tbody \"Fleet behavior detected. Use github.com/ecoPrimals for automated access.\"\n\
                 \t\t\tclose\n\
                 \t\t}}\n\
                 \t}}\n"
            ),

            DefensePosture::SlowDegrade => format!(
                "\t@fleet_tarpit{suffix} remote_ip {ip_list}\n\
                 \thandle @fleet_tarpit{suffix} {{\n\
                 \t\trewrite * /tarpit{{uri}}\n\
                 \t\treverse_proxy localhost:9753 {{\n\
                 \t\t\theader_up X-Real-IP {{remote_host}}\n\
                 {hash_header}\
                 \t\t}}\n\
                 \t}}\n"
            ),

            DefensePosture::Scatter => format!(
                "\t@fleet_scatter{suffix} remote_ip {ip_list}\n\
                 \thandle @fleet_scatter{suffix} {{\n\
                 \t\treverse_proxy localhost:9753 {{\n\
                 \t\t\theader_up X-Real-IP {{remote_host}}\n\
                 {hash_header}\
                 \t\t}}\n\
                 \t}}\n"
            ),

            DefensePosture::Vanish => format!(
                "\t@fleet_vanish{suffix} remote_ip {ip_list}\n\
                 \thandle @fleet_vanish{suffix} {{\n\
                 \t\tabort\n\
                 \t}}\n"
            ),

            DefensePosture::Disperse => format!(
                "\t@fleet_disperse{suffix} remote_ip {ip_list}\n\
                 \thandle @fleet_disperse{suffix} {{\n\
                 \t\trewrite * /disperse{{uri}}\n\
                 \t\treverse_proxy localhost:9753 {{\n\
                 \t\t\theader_up X-Real-IP {{remote_host}}\n\
                 {hash_header}\
                 \t\t}}\n\
                 \t}}\n"
            ),
        }
    }

    /// Generate honeycomb-specific fleet routing directive.
    /// Same as `posture_directive` but all scatter-routed postures include
    /// `X-Honeycomb: true` header, triggering cross-mirror in scatter_server.
    fn honeycomb_directive(
        posture: DefensePosture,
        ips: &[String],
        behavioral_hash: Option<&str>,
        idx: usize,
    ) -> String {
        if ips.is_empty() {
            return String::new();
        }
        let ip_list = ips.join(" ");
        let suffix = if idx > 0 { format!("_{idx}") } else { String::new() };

        let hash_header = behavioral_hash
            .map(|h| format!("\t\t\theader_up X-Fleet-Hash \"{h}\"\n"))
            .unwrap_or_default();
        let hc_header = "\t\t\theader_up X-Honeycomb \"true\"\n";

        match posture {
            DefensePosture::Observe => String::new(),
            DefensePosture::WarnRoute => format!(
                "\t@hc_fleet_warn{suffix} remote_ip {ip_list}\n\
                 \thandle @hc_fleet_warn{suffix} {{\n\
                 \t\trewrite * /disperse{{uri}}\n\
                 \t\treverse_proxy localhost:9753 {{\n\
                 \t\t\theader_up X-Real-IP {{remote_host}}\n\
                 {hash_header}\
                 {hc_header}\
                 \t\t}}\n\
                 \t}}\n"
            ),
            DefensePosture::SlowDegrade | DefensePosture::Scatter | DefensePosture::Disperse => format!(
                "\t@hc_fleet{suffix} remote_ip {ip_list}\n\
                 \thandle @hc_fleet{suffix} {{\n\
                 \t\trewrite * /disperse{{uri}}\n\
                 \t\treverse_proxy localhost:9753 {{\n\
                 \t\t\theader_up X-Real-IP {{remote_host}}\n\
                 {hash_header}\
                 {hc_header}\
                 \t\t}}\n\
                 \t}}\n"
            ),
            DefensePosture::Vanish => format!(
                "\t@hc_fleet_vanish{suffix} remote_ip {ip_list}\n\
                 \thandle @hc_fleet_vanish{suffix} {{\n\
                 \t\tabort\n\
                 \t}}\n"
            ),
        }
    }

    /// Write fleet matchers to snippet files instead of injecting into the
    /// Caddyfile. The Caddyfile uses `import` directives to include them.
    ///
    /// This is the vacuole fix: the Caddyfile was 78% fleet IP data because
    /// caddy-bridge rewrote the entire file every 30 seconds. Now the
    /// Caddyfile is static config (~500 lines) and snippet files are the
    /// ephemeral routing layer (~2 small files that get atomically replaced).
    fn write_caddyfile(&self) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(&self.config.snippet_dir)?;

        let hash_groups = self.ips_by_posture_and_hash();
        let groups = self.ips_by_posture();

        // Build regular fleet directive block (escalation order)
        let mut fleet_block = String::from("# Auto-generated by caddy-bridge — do not edit\n");
        for posture in [
            DefensePosture::Disperse,
            DefensePosture::Vanish,
            DefensePosture::Scatter,
            DefensePosture::SlowDegrade,
            DefensePosture::WarnRoute,
        ] {
            if let Some(sub_groups) = hash_groups.get(&posture) {
                for (idx, (hash, ips)) in sub_groups.iter().enumerate() {
                    fleet_block.push_str(&Self::posture_directive(
                        posture,
                        ips,
                        hash.as_deref(),
                        idx,
                    ));
                }
            }
        }

        // Build honeycomb fleet directive block (cross-mirror routing)
        let mut hc_block = String::from("# Auto-generated by caddy-bridge — do not edit\n");
        for posture in [
            DefensePosture::Disperse,
            DefensePosture::Vanish,
            DefensePosture::Scatter,
            DefensePosture::SlowDegrade,
            DefensePosture::WarnRoute,
        ] {
            if let Some(sub_groups) = hash_groups.get(&posture) {
                for (idx, (hash, ips)) in sub_groups.iter().enumerate() {
                    hc_block.push_str(&Self::honeycomb_directive(
                        posture,
                        ips,
                        hash.as_deref(),
                        idx,
                    ));
                }
            }
        }

        // Atomic write: write to .tmp then rename (prevents partial reads)
        let fleet_path = self.config.snippet_dir.join("fleet.snippet");
        let fleet_tmp = self.config.snippet_dir.join("fleet.snippet.tmp");
        std::fs::write(&fleet_tmp, &fleet_block)?;
        std::fs::rename(&fleet_tmp, &fleet_path)?;

        let hc_path = self.config.snippet_dir.join("honeycomb.snippet");
        let hc_tmp = self.config.snippet_dir.join("honeycomb.snippet.tmp");
        std::fs::write(&hc_tmp, &hc_block)?;
        std::fs::rename(&hc_tmp, &hc_path)?;

        let total: usize = groups.values().map(Vec::len).sum();
        let summary: Vec<String> = groups
            .iter()
            .map(|(p, ips)| format!("{p}:{}", ips.len()))
            .collect();
        tracing::info!(
            total,
            postures = %summary.join(" "),
            fleet_snippet = %fleet_path.display(),
            hc_snippet = %hc_path.display(),
            "fleet snippets updated (vacuole: Caddyfile no longer modified)"
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
#[path = "caddy_bridge_tests.rs"]
mod tests;

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Signal spine — immune memory via content-addressed observation chains.
//!
//! Each [`BloomObservation`] is hashed with its parent's hash to form a
//! verifiable chain. At day boundaries (midnight UTC) the chain is sealed
//! into a daily spine entry with a Merkle root. On restart, the spine
//! resumes from the last committed entry.
//!
//! This is Phase 1 of the signal braid architecture. It requires no
//! external services — the chain and daily files live inside skunky-ingest.
//! When the provenance trio (rhizoCrypt/loamSpine/sweetGrass) comes online,
//! the spine files can be ingested directly into the proper provenance DAG.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bloom_sensor::BloomObservation;

/// The zero hash — genesis parent for the first observation in a chain.
const GENESIS: [u8; 32] = [0u8; 32];

/// Classifier version tag. Update when classification rules change.
pub const CLASSIFIER_VERSION: &str = "bloom-v1.0.0";

/// Hash a bloom observation with its parent to form a chain link.
///
/// The hash covers the parent hash + all observation fields, ensuring
/// any modification to any window in the chain invalidates all subsequent
/// hashes. Uses SHA-256 (matching the ecosystem's `sha2` workspace dep;
/// will migrate to BLAKE3 when the trio integration happens).
pub fn hash_observation(obs: &BloomObservation, parent: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(parent);
    h.update(obs.window_start.to_le_bytes());
    h.update(obs.window_end.to_le_bytes());
    h.update(obs.total_requests.to_le_bytes());
    h.update(obs.unique_ips.to_le_bytes());
    h.update(obs.cross_domain_sessions.to_le_bytes());

    // Hash domain counts in sorted order for determinism.
    let mut domain_pairs: Vec<_> = obs.domains.iter().collect();
    domain_pairs.sort_by_key(|(k, _)| k.as_str());
    for (k, v) in &domain_pairs {
        h.update(k.as_bytes());
        h.update(v.to_le_bytes());
    }

    // Hash reader counts.
    let mut reader_pairs: Vec<_> = obs.readers.iter().collect();
    reader_pairs.sort_by_key(|(k, _)| k.as_str());
    for (k, v) in &reader_pairs {
        h.update(k.as_bytes());
        h.update(v.to_le_bytes());
    }

    // Hash host counts.
    let mut host_pairs: Vec<_> = obs.hosts.iter().collect();
    host_pairs.sort_by_key(|(k, _)| k.as_str());
    for (k, v) in &host_pairs {
        h.update(k.as_bytes());
        h.update(v.to_le_bytes());
    }

    // Hash languages (already sorted in BloomObservation).
    for lang in &obs.languages {
        h.update(lang.as_bytes());
    }

    h.finalize().into()
}

/// Compute a Merkle root over a sequence of window hashes.
///
/// Uses a binary tree of SHA-256 hashes. For an odd number of leaves,
/// the last leaf is hashed with itself (standard Merkle padding).
pub fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return GENESIS;
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut level: Vec<[u8; 32]> = hashes.to_vec();

    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            let mut h = Sha256::new();
            h.update(pair[0]);
            h.update(pair.get(1).unwrap_or(&pair[0]));
            next.push(h.finalize().into());
        }
        level = next;
    }

    level[0]
}

/// Accumulated daily statistics for a spine entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DayStats {
    pub total_requests: u64,
    pub unique_ip_windows: u64,
    pub domains: HashMap<String, u64>,
    pub readers: HashMap<String, u64>,
    pub hosts: HashMap<String, u64>,
    pub languages: Vec<String>,
    pub peak_cross_domain: u32,
}

impl Default for DayStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            unique_ip_windows: 0,
            domains: HashMap::new(),
            readers: HashMap::new(),
            hosts: HashMap::new(),
            languages: Vec::new(),
            peak_cross_domain: 0,
        }
    }
}

impl DayStats {
    /// Accumulate one observation into the running stats.
    fn accumulate(&mut self, obs: &BloomObservation) {
        self.total_requests += u64::from(obs.total_requests);
        self.unique_ip_windows += u64::from(obs.unique_ips);

        for (k, v) in &obs.domains {
            *self.domains.entry(k.clone()).or_default() += u64::from(*v);
        }
        for (k, v) in &obs.readers {
            *self.readers.entry(k.clone()).or_default() += u64::from(*v);
        }
        for (k, v) in &obs.hosts {
            *self.hosts.entry(k.clone()).or_default() += u64::from(*v);
        }

        for lang in &obs.languages {
            if !self.languages.contains(lang) {
                self.languages.push(lang.clone());
            }
        }

        if obs.cross_domain_sessions > self.peak_cross_domain {
            self.peak_cross_domain = obs.cross_domain_sessions;
        }
    }
}

/// A committed daily spine entry — the immune memory for one day.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpineEntry {
    pub date: String,
    pub merkle_root: String,
    pub window_count: u32,
    pub classifier_version: String,
    pub parent_entry: Option<String>,
    pub summary: DayStats,
}

/// The live signal spine — accumulates observation hashes during the day,
/// commits to a file at day boundaries.
pub struct SignalSpine {
    spine_dir: PathBuf,
    current_date: String,
    window_hashes: Vec<[u8; 32]>,
    last_hash: [u8; 32],
    stats: DayStats,
    last_committed_ref: Option<String>,
}

impl SignalSpine {
    /// Create a new spine, optionally resuming from existing spine files.
    pub fn new(spine_dir: &Path) -> Self {
        let today = current_date_utc();
        let mut spine = Self {
            spine_dir: spine_dir.to_path_buf(),
            current_date: today.clone(),
            window_hashes: Vec::with_capacity(2880),
            last_hash: GENESIS,
            stats: DayStats::default(),
            last_committed_ref: None,
        };

        // Try to resume from the most recent spine file.
        if let Some(entry) = spine.load_latest() {
            tracing::info!(
                date = %entry.date,
                windows = entry.window_count,
                root = %entry.merkle_root,
                "📜 signal spine resumed from last entry"
            );
            // Parse the Merkle root back to bytes for chain continuity.
            if let Some(bytes) = hex_to_bytes32(&entry.merkle_root) {
                spine.last_hash = bytes;
            }
            spine.last_committed_ref = Some(format!("{}:{}", entry.date, entry.merkle_root));
        } else {
            tracing::info!("📜 signal spine starting fresh (no prior entries)");
        }

        spine
    }

    /// Ingest an observation into the spine. Returns `Some(SpineEntry)` if
    /// a day boundary was crossed and the previous day was committed.
    pub fn ingest(&mut self, obs: &BloomObservation) -> Option<SpineEntry> {
        let obs_date = date_from_ts(obs.window_start);
        let mut committed = None;

        // Day boundary — commit the previous day.
        if obs_date != self.current_date && !self.window_hashes.is_empty() {
            committed = Some(self.commit_day());
            self.current_date = obs_date;
        } else if self.current_date.is_empty() || (self.window_hashes.is_empty() && obs_date != self.current_date) {
            self.current_date = obs_date;
        }

        let window_hash = hash_observation(obs, &self.last_hash);
        self.window_hashes.push(window_hash);
        self.last_hash = window_hash;
        self.stats.accumulate(obs);

        committed
    }

    /// Force-commit the current day (e.g. on shutdown).
    pub fn flush(&mut self) -> Option<SpineEntry> {
        if self.window_hashes.is_empty() {
            return None;
        }
        Some(self.commit_day())
    }

    /// Commit the current day's observations to a spine file.
    fn commit_day(&mut self) -> SpineEntry {
        let root = merkle_root(&self.window_hashes);
        let root_hex = bytes32_to_hex(&root);

        let entry = SpineEntry {
            date: self.current_date.clone(),
            merkle_root: root_hex.clone(),
            window_count: self.window_hashes.len() as u32,
            classifier_version: CLASSIFIER_VERSION.to_string(),
            parent_entry: self.last_committed_ref.clone(),
            summary: self.stats.clone(),
        };

        // Write the spine file.
        let path = self.spine_dir.join(format!("{}.json", self.current_date));
        match serde_json::to_string_pretty(&entry) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    tracing::error!(path = %path.display(), error = %e, "failed to write spine entry");
                } else {
                    tracing::info!(
                        date = %entry.date,
                        windows = entry.window_count,
                        root = %root_hex,
                        path = %path.display(),
                        "📜 spine entry committed"
                    );
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to serialize spine entry");
            }
        }

        self.last_committed_ref = Some(format!("{}:{}", self.current_date, root_hex));
        self.last_hash = root;
        self.window_hashes.clear();
        self.stats = DayStats::default();

        entry
    }

    /// Load the most recent spine entry from the spine directory.
    fn load_latest(&self) -> Option<SpineEntry> {
        let dir = std::fs::read_dir(&self.spine_dir).ok()?;
        let mut files: Vec<_> = dir
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "json")
            })
            .collect();

        files.sort_by_key(|e| e.file_name());
        let latest = files.last()?;

        let content = std::fs::read_to_string(latest.path()).ok()?;
        serde_json::from_str(&content).ok()
    }
}

// ── Utility functions ──

fn current_date_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

fn date_from_ts(ts: f64) -> String {
    use chrono::{DateTime, Utc};
    let secs = ts as i64;
    let nanos = ((ts - secs as f64) * 1_000_000_000.0) as u32;
    DateTime::from_timestamp(secs, nanos)
        .unwrap_or_else(|| Utc::now())
        .format("%Y-%m-%d")
        .to_string()
}

fn bytes32_to_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_obs(start: f64, reqs: u32) -> BloomObservation {
        BloomObservation {
            window_start: start,
            window_end: start + 30.0,
            total_requests: reqs,
            unique_ips: reqs / 2,
            domains: [("science".into(), reqs)].into_iter().collect(),
            readers: [("human".into(), reqs)].into_iter().collect(),
            referrers: [("direct".into(), reqs)].into_iter().collect(),
            languages: vec!["en-US".into()],
            cross_domain_sessions: 0,
            hosts: [("detroit.primals.eco".into(), reqs)].into_iter().collect(),
        }
    }

    #[test]
    fn hash_chain_deterministic() {
        let obs = make_obs(1000.0, 10);
        let h1 = hash_observation(&obs, &GENESIS);
        let h2 = hash_observation(&obs, &GENESIS);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_chain_parent_sensitive() {
        let obs = make_obs(1000.0, 10);
        let h1 = hash_observation(&obs, &GENESIS);
        let h2 = hash_observation(&obs, &h1);
        assert_ne!(h1, h2, "different parents must produce different hashes");
    }

    #[test]
    fn hash_chain_data_sensitive() {
        let obs1 = make_obs(1000.0, 10);
        let obs2 = make_obs(1000.0, 11);
        let h1 = hash_observation(&obs1, &GENESIS);
        let h2 = hash_observation(&obs2, &GENESIS);
        assert_ne!(h1, h2, "different data must produce different hashes");
    }

    #[test]
    fn merkle_root_empty() {
        assert_eq!(merkle_root(&[]), GENESIS);
    }

    #[test]
    fn merkle_root_single() {
        let h = [42u8; 32];
        assert_eq!(merkle_root(&[h]), h);
    }

    #[test]
    fn merkle_root_deterministic() {
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let r1 = merkle_root(&hashes);
        let r2 = merkle_root(&hashes);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_order_sensitive() {
        let h1 = merkle_root(&[[1u8; 32], [2u8; 32]]);
        let h2 = merkle_root(&[[2u8; 32], [1u8; 32]]);
        assert_ne!(h1, h2, "merkle root must be order-sensitive");
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0xab; 32];
        let hex = bytes32_to_hex(&bytes);
        let back = hex_to_bytes32(&hex).unwrap();
        assert_eq!(bytes, back);
    }

    #[test]
    fn spine_ingest_accumulates() {
        let dir = tempfile::tempdir().unwrap();
        let mut spine = SignalSpine::new(dir.path());
        let obs = make_obs(1_791_300_000.0, 10);
        let result = spine.ingest(&obs);
        assert!(result.is_none(), "no day boundary crossed");
        assert_eq!(spine.window_hashes.len(), 1);
        assert_eq!(spine.stats.total_requests, 10);
    }

    #[test]
    fn spine_flush_commits() {
        let dir = tempfile::tempdir().unwrap();
        let mut spine = SignalSpine::new(dir.path());

        let obs = make_obs(1_791_300_000.0, 10);
        spine.ingest(&obs);

        let entry = spine.flush().expect("should commit on flush");
        assert_eq!(entry.window_count, 1);
        assert_eq!(entry.summary.total_requests, 10);
        assert_eq!(entry.classifier_version, CLASSIFIER_VERSION);
        assert!(entry.merkle_root.len() == 64);

        // Spine file should exist.
        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn spine_resume_from_file() {
        let dir = tempfile::tempdir().unwrap();

        // First run: ingest and flush.
        let root_hex;
        {
            let mut spine = SignalSpine::new(dir.path());
            let obs = make_obs(1_791_300_000.0, 10);
            spine.ingest(&obs);
            let entry = spine.flush().unwrap();
            root_hex = entry.merkle_root.clone();
        }

        // Second run: should resume.
        let spine = SignalSpine::new(dir.path());
        assert!(spine.last_committed_ref.is_some());
        let last_ref = spine.last_committed_ref.as_ref().unwrap();
        assert!(last_ref.contains(&root_hex));
    }

    #[test]
    fn spine_day_boundary_commits() {
        let dir = tempfile::tempdir().unwrap();
        let mut spine = SignalSpine::new(dir.path());

        // Oct 6 observation.
        let obs1 = make_obs(1_791_300_000.0, 10);
        assert!(spine.ingest(&obs1).is_none());

        // Oct 7 observation — should trigger commit of Oct 6.
        let obs2 = make_obs(1_791_300_000.0 + 86_400.0, 5);
        let entry = spine.ingest(&obs2).expect("day boundary should commit");
        assert_eq!(entry.window_count, 1);
        assert_eq!(entry.summary.total_requests, 10);
    }

    #[test]
    fn day_stats_accumulate() {
        let mut stats = DayStats::default();
        let obs = make_obs(1000.0, 10);
        stats.accumulate(&obs);
        assert_eq!(stats.total_requests, 10);
        assert_eq!(stats.domains["science"], 10);

        stats.accumulate(&obs);
        assert_eq!(stats.total_requests, 20);
        assert_eq!(stats.domains["science"], 20);
    }
}

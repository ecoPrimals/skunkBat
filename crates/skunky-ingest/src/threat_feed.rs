// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Threat intelligence feed — MHC presentation layer.
//!
//! ## Biological Parallel: Major Histocompatibility Complex
//!
//! MHC molecules display fragments of pathogens on the cell surface so
//! other immune cells (and other organisms) can recognize the threat.
//! The pathogen is not shared — only its *signature*.
//!
//! The threat feed publishes behavioral fingerprints from the signal
//! spine and fleet detection systems. The feed contains NO IP addresses,
//! user agents, or personally identifiable information — only statistical
//! signatures of scanning behavior that other defenders can match against
//! their own logs.
//!
//! Served as a static JSON file at `detroit.primals.eco/defense/feed.json`.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::signal_spine::SpineEntry;

/// A single threat indicator — a behavioral fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    /// SHA-256 behavioral hash (from fleet aggregator opsonize pipeline).
    pub behavioral_hash: String,
    /// Which detection heuristics fired on this fleet.
    pub detectors: Vec<String>,
    /// Confidence level (0.0 - 1.0).
    pub confidence: f64,
    /// Scanner probe paths observed (what they were looking for).
    pub probe_paths: Vec<String>,
    /// Timing signature description.
    pub timing_signature: String,
    /// Estimated fleet size (unique IPs in observation window).
    pub estimated_fleet_size: u32,
    /// First observed date (ISO 8601).
    pub first_observed: String,
    /// Last observed date (ISO 8601).
    pub last_observed: String,
}

/// The published threat intelligence feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    /// Feed format version.
    pub version: String,
    /// Feed generation timestamp (ISO 8601).
    pub generated_at: String,
    /// Spine merkle root — cryptographic proof of observation integrity.
    pub spine_merkle_root: String,
    /// Classifier version that produced the observations.
    pub classifier_version: String,
    /// Privacy notice — what this feed does NOT contain.
    pub privacy_notice: String,
    /// Active threat indicators.
    pub indicators: Vec<ThreatIndicator>,
    /// Summary statistics.
    pub summary: FeedSummary,
}

/// Summary statistics for the threat feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSummary {
    /// Total unique behavioral hashes observed.
    pub total_behavioral_hashes: u32,
    /// Total estimated scanner IPs across all fleets.
    pub total_estimated_ips: u32,
    /// Date range covered by this feed.
    pub date_range: String,
    /// Number of observation windows analyzed.
    pub observation_windows: u32,
}

/// Generate a threat feed from a spine entry and accumulated indicators.
pub fn generate_feed(
    spine_entry: &SpineEntry,
    indicators: &[ThreatIndicator],
) -> ThreatFeed {
    let total_ips: u32 = indicators.iter().map(|i| i.estimated_fleet_size).sum();

    ThreatFeed {
        version: "1.0.0".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        spine_merkle_root: spine_entry.merkle_root.clone(),
        classifier_version: spine_entry.classifier_version.clone(),
        privacy_notice: "This feed contains NO IP addresses, user agents, or personally \
            identifiable information. All indicators are behavioral fingerprints — \
            statistical signatures of scanning behavior that can be matched against \
            your own logs without sharing any visitor data."
            .to_string(),
        summary: FeedSummary {
            total_behavioral_hashes: indicators.len() as u32,
            total_estimated_ips: total_ips,
            date_range: spine_entry.date.clone(),
            observation_windows: spine_entry.window_count,
        },
        indicators: indicators.to_vec(),
    }
}

/// Write the threat feed to a JSON file.
pub fn write_feed(feed: &ThreatFeed, output_path: &Path) -> Result<(), std::io::Error> {
    let json = serde_json::to_string_pretty(feed)
        .map_err(|e| std::io::Error::other(format!("feed serialization failed: {e}")))?;
    std::fs::write(output_path, json)?;
    tracing::info!(
        path = %output_path.display(),
        indicators = feed.indicators.len(),
        merkle_root = %feed.spine_merkle_root,
        "📡 threat intelligence feed published"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal_spine::{DayStats, SpineEntry, CLASSIFIER_VERSION};

    fn test_spine_entry() -> SpineEntry {
        SpineEntry {
            date: "2026-10-06".to_string(),
            merkle_root: "abcdef0123456789".repeat(4),
            window_count: 2880,
            classifier_version: CLASSIFIER_VERSION.to_string(),
            parent_entry: None,
            summary: DayStats::default(),
        }
    }

    #[test]
    fn generate_feed_with_indicators() {
        let spine = test_spine_entry();
        let indicators = vec![ThreatIndicator {
            behavioral_hash: "abc123def456".to_string(),
            detectors: vec!["content_gate".to_string(), "stealth_ua".to_string()],
            confidence: 0.75,
            probe_paths: vec!["/commit/".to_string()],
            timing_signature: "metronomic".to_string(),
            estimated_fleet_size: 1200,
            first_observed: "2026-10-05".to_string(),
            last_observed: "2026-10-06".to_string(),
        }];

        let feed = generate_feed(&spine, &indicators);
        assert_eq!(feed.version, "1.0.0");
        assert_eq!(feed.indicators.len(), 1);
        assert_eq!(feed.summary.total_estimated_ips, 1200);
        assert_eq!(feed.summary.total_behavioral_hashes, 1);
        assert!(feed.privacy_notice.contains("NO IP addresses"));
    }

    #[test]
    fn generate_empty_feed() {
        let spine = test_spine_entry();
        let feed = generate_feed(&spine, &[]);
        assert_eq!(feed.indicators.len(), 0);
        assert_eq!(feed.summary.total_estimated_ips, 0);
        assert_eq!(feed.spine_merkle_root, spine.merkle_root);
    }

    #[test]
    fn write_and_read_feed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed.json");

        let spine = test_spine_entry();
        let feed = generate_feed(&spine, &[]);
        write_feed(&feed, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: ThreatFeed = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.version, "1.0.0");
        assert_eq!(parsed.indicators.len(), 0);
        assert_eq!(parsed.classifier_version, CLASSIFIER_VERSION);
    }

    #[test]
    fn feed_contains_no_real_infrastructure() {
        let spine = test_spine_entry();
        let indicators = vec![ThreatIndicator {
            behavioral_hash: "deadbeef01234567".to_string(),
            detectors: vec!["ip_rotation".to_string()],
            confidence: 1.0,
            probe_paths: vec!["/src/".to_string()],
            timing_signature: "burst-cluster".to_string(),
            estimated_fleet_size: 500,
            first_observed: "2026-10-06".to_string(),
            last_observed: "2026-10-06".to_string(),
        }];

        let feed = generate_feed(&spine, &indicators);
        let json = serde_json::to_string(&feed).unwrap();

        assert!(!json.contains("57.141"), "leaked fleet IP range");
        assert!(!json.contains("10.13.37"), "leaked WireGuard range");
        assert!(!json.contains("162.226"), "leaked WAN IP");
        assert!(!json.contains("golgiBody"), "leaked hostname");
    }

    #[test]
    fn multiple_indicators_sum_ips() {
        let spine = test_spine_entry();
        let indicators = vec![
            ThreatIndicator {
                behavioral_hash: "aaa".to_string(),
                detectors: vec![],
                confidence: 0.5,
                probe_paths: vec![],
                timing_signature: "metronomic".to_string(),
                estimated_fleet_size: 800,
                first_observed: "2026-10-06".to_string(),
                last_observed: "2026-10-06".to_string(),
            },
            ThreatIndicator {
                behavioral_hash: "bbb".to_string(),
                detectors: vec![],
                confidence: 0.9,
                probe_paths: vec![],
                timing_signature: "varied".to_string(),
                estimated_fleet_size: 1200,
                first_observed: "2026-10-06".to_string(),
                last_observed: "2026-10-06".to_string(),
            },
        ];

        let feed = generate_feed(&spine, &indicators);
        assert_eq!(feed.summary.total_estimated_ips, 2000);
        assert_eq!(feed.summary.total_behavioral_hashes, 2);
    }
}

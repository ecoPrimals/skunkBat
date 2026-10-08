// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 ecoPrimals
//
// Epitope Inversion Tracker — the immune system's outward eye.
//
// Instead of only watching what comes TO us, we publish epitope signatures
// and consume feeds from peer forges to reconstruct fleet movement patterns
// across the entire mesh. Every spy hole, every contact point, all at once.
//
// The inversion:
//   Traditional: "who is crawling ME?" → one view, one target
//   Inverted:    "where is THIS FLEET crawling?" → all views, all targets
//
// When an epitope hash (behavioral fingerprint) appears in feeds from
// multiple forges, we can reconstruct the fleet's full crawl graph.
// Combined with gravitational mesh routing (swarmVine), the forges
// closest to a fleet (highest gravity) contribute the most signal.
//
// Data flow:
//   1. bloom_live.py generates local epitope clusters → epitope-feed.json
//   2. scatter_server serves /epitope-feed.json
//   3. gossip.inject pushes clusters into swarmVine (topic: defense)
//   4. gossip.pool merges all mesh feeds into communal immunity surface
//   5. THIS MODULE correlates epitope hashes across all sources
//      to build fleet movement timelines and crawl graphs

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A sighting of an epitope hash at a specific forge.
#[derive(Debug, Clone)]
pub struct EpitopeSighting {
    /// Which forge observed this epitope (node_id from epitope feed)
    pub forge_id: String,
    /// When this feed was generated (epoch seconds)
    pub observed_epoch: u64,
    /// Cluster size (number of IPs sharing this fingerprint at this forge)
    pub cluster_size: u32,
    /// UA rotation pool size (behavioral invariant)
    pub ua_pool_size: u32,
    /// Blame ratio (attribution extraction signature)
    pub blame_ratio: f64,
    /// Accept-Encoding fingerprint
    pub accept_encoding: String,
    /// Whether Accept-Language header is present
    pub has_accept_language: bool,
}

/// Cross-forge movement pattern for a single epitope hash.
#[derive(Debug, Clone)]
pub struct FleetMovement {
    /// The epitope hash (behavioral DNA)
    pub epitope_hash: String,
    /// All forges where this epitope has been sighted
    pub sightings: Vec<EpitopeSighting>,
    /// First observed (earliest epoch across all forges)
    pub first_seen: u64,
    /// Last observed (latest epoch)
    pub last_seen: u64,
    /// Movement velocity: forges-per-hour
    pub velocity: f64,
}

/// The inversion tracker — correlates epitope hashes across forges.
#[derive(Debug, Clone)]
pub struct InversionTracker {
    /// epitope_hash → list of sightings from different forges
    sightings: Arc<RwLock<HashMap<String, Vec<EpitopeSighting>>>>,
    /// Our own node ID for self-identification
    our_node_id: String,
}

impl InversionTracker {
    pub fn new(node_id: String) -> Self {
        Self {
            sightings: Arc::new(RwLock::new(HashMap::new())),
            our_node_id: node_id,
        }
    }

    /// Ingest an epitope feed from a peer forge (or ourselves).
    ///
    /// Extracts each cluster's hash and records a sighting, building
    /// the cross-forge movement graph over time.
    pub async fn ingest_feed(&self, feed: &serde_json::Value) {
        let forge_id = feed
            .get("node_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let generated_epoch = feed
            .get("generated_epoch")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let clusters = match feed.get("epitope_clusters").and_then(|v| v.as_array()) {
            Some(c) => c,
            None => return,
        };

        let mut sightings = self.sightings.write().await;

        for cluster in clusters {
            let hash = match cluster.get("hash").and_then(|v| v.as_str()) {
                Some(h) => h.to_string(),
                None => continue,
            };

            let sighting = EpitopeSighting {
                forge_id: forge_id.clone(),
                observed_epoch: generated_epoch,
                cluster_size: cluster
                    .get("cluster_size")
                    .or_else(|| cluster.get("ips"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                ua_pool_size: cluster
                    .get("ua_pool_size")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                blame_ratio: cluster
                    .get("blame_ratio")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0),
                accept_encoding: cluster
                    .get("accept_encoding")
                    .or_else(|| cluster.get("sample_ae"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                has_accept_language: cluster
                    .get("has_accept_language")
                    .or_else(|| cluster.get("has_lang"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            };

            let entry = sightings.entry(hash).or_default();

            // Deduplicate: don't store multiple sightings from the same forge
            // in the same epoch window (5-minute dedup)
            let dominated = entry.iter().any(|s| {
                s.forge_id == sighting.forge_id
                    && s.observed_epoch.abs_diff(sighting.observed_epoch) < 300
            });

            if !dominated {
                entry.push(sighting);
            }

            // Retention: keep at most 100 sightings per hash
            if entry.len() > 100 {
                entry.drain(..entry.len() - 100);
            }
        }
    }

    /// Build the fleet movement graph — which epitopes are seen at multiple forges.
    ///
    /// This is the inversion in action: instead of "who is crawling me?" we ask
    /// "where is this fleet crawling?" and reconstruct their movement pattern
    /// across every spy hole in the mesh.
    pub async fn fleet_movements(&self) -> Vec<FleetMovement> {
        let sightings = self.sightings.read().await;

        let mut movements: Vec<FleetMovement> = Vec::new();

        for (hash, sights) in sightings.iter() {
            if sights.is_empty() {
                continue;
            }

            let first_seen = sights.iter().map(|s| s.observed_epoch).min().unwrap_or(0);
            let last_seen = sights.iter().map(|s| s.observed_epoch).max().unwrap_or(0);

            // Count unique forges
            let mut unique_forges: std::collections::HashSet<&str> =
                std::collections::HashSet::new();
            for s in sights {
                unique_forges.insert(&s.forge_id);
            }

            // Movement velocity: unique forges seen per hour of observation window
            let window_hours = (last_seen.saturating_sub(first_seen)) as f64 / 3600.0;
            let velocity = if window_hours > 0.0 {
                unique_forges.len() as f64 / window_hours
            } else {
                0.0
            };

            movements.push(FleetMovement {
                epitope_hash: hash.clone(),
                sightings: sights.clone(),
                first_seen,
                last_seen,
                velocity,
            });
        }

        // Sort by number of unique forges (most distributed fleets first)
        movements.sort_by(|a, b| {
            let a_forges: std::collections::HashSet<&str> =
                a.sightings.iter().map(|s| s.forge_id.as_str()).collect();
            let b_forges: std::collections::HashSet<&str> =
                b.sightings.iter().map(|s| s.forge_id.as_str()).collect();
            b_forges.len().cmp(&a_forges.len())
                .then(b.sightings.len().cmp(&a.sightings.len()))
        });

        movements
    }

    /// Export the inversion graph as JSON for the /epitope-inversion.json endpoint.
    pub async fn export_json(&self) -> serde_json::Value {
        let movements = self.fleet_movements().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let total_epitopes = movements.len();
        let multi_forge = movements.iter().filter(|m| {
            let forges: std::collections::HashSet<&str> =
                m.sightings.iter().map(|s| s.forge_id.as_str()).collect();
            forges.len() > 1
        }).count();

        let mut entries: Vec<serde_json::Value> = Vec::new();
        for m in &movements {
            let forges: std::collections::HashSet<&str> =
                m.sightings.iter().map(|s| s.forge_id.as_str()).collect();

            let sighting_entries: Vec<serde_json::Value> = m.sightings.iter().map(|s| {
                serde_json::json!({
                    "forge": s.forge_id,
                    "epoch": s.observed_epoch,
                    "cluster_size": s.cluster_size,
                    "ua_pool_size": s.ua_pool_size,
                    "blame_ratio": (s.blame_ratio * 1000.0).round() / 1000.0,
                })
            }).collect();

            entries.push(serde_json::json!({
                "epitope_hash": m.epitope_hash,
                "forges_observed": forges.len(),
                "forge_list": forges.into_iter().collect::<Vec<&str>>(),
                "total_sightings": m.sightings.len(),
                "first_seen": m.first_seen,
                "last_seen": m.last_seen,
                "velocity_forges_per_hour": (m.velocity * 100.0).round() / 100.0,
                "sightings": sighting_entries,
            }));
        }

        serde_json::json!({
            "schema": "ecoPrimals/epitope-inversion/v1",
            "node_id": self.our_node_id,
            "generated_epoch": now,
            "total_tracked_epitopes": total_epitopes,
            "multi_forge_epitopes": multi_forge,
            "fleet_movements": entries,
            "usage": "Epitopes observed at multiple forges reveal fleet crawl patterns. \
                      Higher forges_observed = more distributed fleet. High velocity = \
                      rapid-scan fleet. Cross-reference with communal immunity pool for \
                      mesh-confirmed signatures.",
        })
    }

    /// Ingest all defense-topic gossip entries (from gossip.pool result).
    ///
    /// This is called periodically to pull all epitope feeds from the mesh
    /// and build the inversion graph.
    pub async fn ingest_pool(&self, pool_result: &serde_json::Value) {
        let clusters = match pool_result.get("merged_clusters").and_then(|v| v.as_array()) {
            Some(c) => c,
            None => return,
        };

        // Group by origin_node to reconstruct per-forge feeds
        let mut by_node: HashMap<String, Vec<&serde_json::Value>> = HashMap::new();
        for cluster in clusters {
            let node = cluster
                .get("origin_node")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            by_node.entry(node).or_default().push(cluster);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (node_id, clusters) in &by_node {
            // Synthesize a feed-like structure from the pool entries
            let feed = serde_json::json!({
                "node_id": node_id,
                "generated_epoch": now,
                "epitope_clusters": clusters,
            });
            self.ingest_feed(&feed).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ingest_and_movement() {
        let tracker = InversionTracker::new("test-node".to_string());

        let feed_a = serde_json::json!({
            "node_id": "forge-alpha",
            "generated_epoch": 1000,
            "epitope_clusters": [
                {"hash": "aabb1122", "cluster_size": 5, "ua_pool_size": 9, "blame_ratio": 0.55},
                {"hash": "ccdd3344", "cluster_size": 2, "ua_pool_size": 1, "blame_ratio": 0.0},
            ]
        });

        let feed_b = serde_json::json!({
            "node_id": "forge-beta",
            "generated_epoch": 1500,
            "epitope_clusters": [
                {"hash": "aabb1122", "cluster_size": 8, "ua_pool_size": 9, "blame_ratio": 0.60},
            ]
        });

        tracker.ingest_feed(&feed_a).await;
        tracker.ingest_feed(&feed_b).await;

        let movements = tracker.fleet_movements().await;

        // aabb1122 should be seen at 2 forges
        let multi = movements.iter().find(|m| m.epitope_hash == "aabb1122").unwrap();
        let forges: std::collections::HashSet<&str> =
            multi.sightings.iter().map(|s| s.forge_id.as_str()).collect();
        assert_eq!(forges.len(), 2);
        assert!(forges.contains("forge-alpha"));
        assert!(forges.contains("forge-beta"));

        // ccdd3344 should be seen at only 1 forge
        let single = movements.iter().find(|m| m.epitope_hash == "ccdd3344").unwrap();
        let forges: std::collections::HashSet<&str> =
            single.sightings.iter().map(|s| s.forge_id.as_str()).collect();
        assert_eq!(forges.len(), 1);
    }

    #[tokio::test]
    async fn test_dedup_same_forge_same_window() {
        let tracker = InversionTracker::new("test-node".to_string());

        let feed1 = serde_json::json!({
            "node_id": "forge-alpha",
            "generated_epoch": 1000,
            "epitope_clusters": [{"hash": "aabb1122", "cluster_size": 5}]
        });
        let feed2 = serde_json::json!({
            "node_id": "forge-alpha",
            "generated_epoch": 1100, // within 300s dedup window
            "epitope_clusters": [{"hash": "aabb1122", "cluster_size": 6}]
        });

        tracker.ingest_feed(&feed1).await;
        tracker.ingest_feed(&feed2).await;

        let movements = tracker.fleet_movements().await;
        let m = movements.iter().find(|m| m.epitope_hash == "aabb1122").unwrap();
        assert_eq!(m.sightings.len(), 1); // deduplicated
    }

    #[tokio::test]
    async fn test_export_json() {
        let tracker = InversionTracker::new("sporeGate".to_string());

        let feed = serde_json::json!({
            "node_id": "forge-alpha",
            "generated_epoch": 1000,
            "epitope_clusters": [
                {"hash": "aabb1122", "cluster_size": 5, "ua_pool_size": 9, "blame_ratio": 0.55},
            ]
        });
        tracker.ingest_feed(&feed).await;

        let export = tracker.export_json().await;
        assert_eq!(export["schema"], "ecoPrimals/epitope-inversion/v1");
        assert_eq!(export["total_tracked_epitopes"], 1);
    }
}

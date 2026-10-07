// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Plasmid federation — Merge conserved plasmids from all golgi layers.
//!
//! Replaces `plasmid-federation.sh` + its embedded Python merger.
//! Runs on golgiBody (central). Fetches `/plasmid` from each layer,
//! merges epitopes weighted by observation count, and publishes the
//! federated threat intelligence feed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A layer in the federation mesh.
#[derive(Debug, Clone)]
pub struct LayerEntry {
    pub name: String,
    pub url: String,
    pub provider: String,
    pub location: String,
    pub jurisdiction: String,
}

/// Configuration for the federation task.
#[derive(Debug, Clone)]
pub struct FederationConfig {
    pub layers: Vec<LayerEntry>,
    pub feed_dir: PathBuf,
    pub work_dir: PathBuf,
    pub fetch_timeout: Duration,
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            layers: vec![LayerEntry {
                name: "golgiBody".into(),
                url: "http://localhost:9753/plasmid".into(),
                provider: "DigitalOcean".into(),
                location: "NYC, US".into(),
                jurisdiction: "US federal".into(),
            }],
            feed_dir: PathBuf::from("/opt/ecoPrimals/signal/site/public/feed"),
            work_dir: PathBuf::from("/run/membrane/plasmid-sync"),
            fetch_timeout: Duration::from_secs(10),
        }
    }
}

// ── Wire types for layer /plasmid response ──

#[derive(Debug, Deserialize)]
struct LayerPlasmid {
    layer: Option<String>,
    population: Option<LayerPopulation>,
    timing: Option<LayerTiming>,
    conserved_epitopes: Option<Vec<LayerEpitope>>,
    behavioral_hashes: Option<Vec<LayerHash>>,
}

#[derive(Debug, Deserialize)]
struct LayerPopulation {
    total_subgroups: Option<u64>,
    total_observations: Option<u64>,
    mean_confidence: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct LayerTiming {
    observation_window_secs: Option<u64>,
    aggregate_velocity_per_hour: Option<f64>,
    total_match_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct LayerEpitope {
    name: Option<String>,
    subgroups_matching: Option<u64>,
    frequency_pct: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct LayerHash {
    hash: Option<String>,
    confidence: Option<f64>,
    match_count: Option<u64>,
    velocity_per_hour: Option<f64>,
    last_seen: Option<u64>,
    gate_count: Option<u64>,
    detectors: Option<Vec<String>>,
}

// ── Output types ──

#[derive(Debug, Serialize)]
pub struct FederatedFeed {
    pub schema: String,
    pub generated: u64,
    pub generated_iso: String,
    pub license: String,
    pub source: String,
    pub description: String,
    pub federation: FederationMeta,
    pub population: FederatedPopulation,
    pub conserved_epitopes: Vec<FederatedEpitope>,
    pub behavioral_hashes_summary: HashSummary,
    pub detection_rules: DetectionRules,
    pub attribution: Attribution,
}

#[derive(Debug, Serialize)]
pub struct FederationMeta {
    pub layer_count: usize,
    pub layers: Vec<LayerMeta>,
}

#[derive(Debug, Serialize)]
pub struct LayerMeta {
    pub name: String,
    pub subgroups: u64,
    pub observations: u64,
    pub mean_confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_window_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_velocity_per_hour: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_match_count: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct FederatedPopulation {
    pub total_subgroups: u64,
    pub total_observations: u64,
    pub mean_confidence: f64,
}

#[derive(Debug, Serialize)]
pub struct FederatedEpitope {
    pub name: String,
    pub frequency_pct: u64,
    pub layers_observed: usize,
    pub layers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HashSummary {
    pub total_unique: usize,
    pub multi_layer: usize,
}

#[derive(Debug, Serialize)]
pub struct DetectionRules {
    pub description: String,
    pub rules: Vec<String>,
    pub threshold: u32,
}

#[derive(Debug, Serialize)]
pub struct Attribution {
    pub primary_entity: String,
    pub whois_confirmed_blocks: Vec<WhoisBlock>,
}

#[derive(Debug, Serialize)]
pub struct WhoisBlock {
    pub cidr: String,
    pub netname: String,
    pub org: String,
    pub country: String,
}

/// Federated hash entry (internal, not in final feed — just summary).
#[derive(Debug)]
struct MergedHash {
    max_conf: f64,
    total_matches: u64,
    max_velocity: f64,
    latest_seen: u64,
    gate_count: u64,
    detectors: BTreeSet<String>,
    layers: BTreeSet<String>,
}

/// Run one federation cycle: fetch → merge → publish.
///
/// Returns the path to the published feed, or an error.
pub async fn run_once(config: &FederationConfig) -> Result<PathBuf, FederationError> {
    tokio::fs::create_dir_all(&config.work_dir).await?;
    tokio::fs::create_dir_all(&config.feed_dir).await?;

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(config.fetch_timeout)
        .build()
        .map_err(|e| FederationError::Http(e.to_string()))?;

    // ── Fetch from each layer ──
    let mut fetched: Vec<(String, LayerPlasmid)> = Vec::new();
    for layer in &config.layers {
        match client.get(&layer.url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<LayerPlasmid>().await {
                    Ok(mut data) => {
                        if data.layer.is_none() {
                            data.layer = Some(layer.name.clone());
                        }
                        tracing::info!(layer = %layer.name, provider = %layer.provider, "✓ plasmid fetched");
                        fetched.push((layer.name.clone(), data));
                    }
                    Err(e) => {
                        tracing::warn!(layer = %layer.name, error = %e, "✗ plasmid parse failed");
                    }
                }
            }
            Ok(resp) => {
                tracing::warn!(layer = %layer.name, status = %resp.status(), "✗ plasmid fetch non-200");
            }
            Err(e) => {
                tracing::warn!(layer = %layer.name, error = %e, "✗ plasmid unreachable");
            }
        }
    }

    if fetched.is_empty() {
        return Err(FederationError::NoLayers);
    }

    // ── Merge ──
    let feed = merge_plasmids(&fetched);

    // ── Publish ──
    let output_path = config.feed_dir.join("conserved-plasmid.json");
    let json = serde_json::to_string_pretty(&feed)?;
    tokio::fs::write(&output_path, &json).await?;

    tracing::info!(
        layers = fetched.len(),
        epitopes = feed.conserved_epitopes.len(),
        hashes = feed.behavioral_hashes_summary.total_unique,
        path = %output_path.display(),
        "🧬 plasmid federation published"
    );

    Ok(output_path)
}

fn merge_plasmids(layers: &[(String, LayerPlasmid)]) -> FederatedFeed {
    let mut all_epitopes: HashMap<String, (u64, u64, Vec<String>)> = HashMap::new();
    let mut all_hashes: BTreeMap<String, MergedHash> = BTreeMap::new();
    let mut total_subgroups: u64 = 0;
    let mut total_observations: u64 = 0;
    let mut weighted_confidence: f64 = 0.0;
    let mut layer_metadata: Vec<LayerMeta> = Vec::new();

    for (name, data) in layers {
        let pop = data.population.as_ref();
        let subs = pop.and_then(|p| p.total_subgroups).unwrap_or(0);
        let obs = pop.and_then(|p| p.total_observations).unwrap_or(0);
        let conf = pop.and_then(|p| p.mean_confidence).unwrap_or(0.0);

        total_subgroups += subs;
        total_observations += obs;
        weighted_confidence += conf * subs as f64;

        let timing = data.timing.as_ref();
        layer_metadata.push(LayerMeta {
            name: name.clone(),
            subgroups: subs,
            observations: obs,
            mean_confidence: (conf * 1000.0).round() / 1000.0,
            observation_window_secs: timing.and_then(|t| t.observation_window_secs),
            aggregate_velocity_per_hour: timing.and_then(|t| t.aggregate_velocity_per_hour),
            total_match_count: timing.and_then(|t| t.total_match_count),
        });

        // Merge epitopes
        if let Some(epitopes) = &data.conserved_epitopes {
            for epi in epitopes {
                let ename = epi.name.as_deref().unwrap_or("").to_string();
                let freq = epi.subgroups_matching.or(epi.frequency_pct).unwrap_or(0);
                let entry = all_epitopes.entry(ename).or_insert((0, 0, Vec::new()));
                entry.0 += freq;
                entry.1 += subs;
                entry.2.push(name.clone());
            }
        }

        // Merge behavioral hashes
        if let Some(hashes) = &data.behavioral_hashes {
            for h in hashes {
                let hid = h.hash.as_deref().unwrap_or("").to_string();
                if hid.is_empty() {
                    continue;
                }
                let entry = all_hashes.entry(hid).or_insert(MergedHash {
                    max_conf: 0.0,
                    total_matches: 0,
                    max_velocity: 0.0,
                    latest_seen: 0,
                    gate_count: 0,
                    detectors: BTreeSet::new(),
                    layers: BTreeSet::new(),
                });
                entry.max_conf = entry.max_conf.max(h.confidence.unwrap_or(0.0));
                entry.total_matches += h.match_count.unwrap_or(0);
                entry.max_velocity = entry.max_velocity.max(h.velocity_per_hour.unwrap_or(0.0));
                entry.latest_seen = entry.latest_seen.max(h.last_seen.unwrap_or(0));
                entry.gate_count = entry.gate_count.max(h.gate_count.unwrap_or(0));
                if let Some(dets) = &h.detectors {
                    entry.detectors.extend(dets.iter().cloned());
                }
                entry.layers.insert(name.clone());
            }
        }
    }

    // Build sorted epitopes
    let mut federated_epitopes: Vec<FederatedEpitope> = all_epitopes
        .into_iter()
        .map(|(name, (freq, pop, layers))| {
            let pct = if pop > 0 { freq * 100 / pop } else { 0 };
            FederatedEpitope {
                name,
                frequency_pct: pct,
                layers_observed: layers.len(),
                layers,
            }
        })
        .collect();
    federated_epitopes.sort_by(|a, b| b.frequency_pct.cmp(&a.frequency_pct));

    let multi_layer_count = all_hashes.values().filter(|h| h.layers.len() > 1).count();

    let mean_conf = if total_subgroups > 0 {
        (weighted_confidence / total_subgroups as f64 * 1000.0).round() / 1000.0
    } else {
        0.0
    };

    let now = chrono::Utc::now();

    FederatedFeed {
        schema: "ecoPrimals/conserved-plasmid/v2".into(),
        generated: now.timestamp() as u64,
        generated_iso: now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        license: "CC-BY-SA-4.0".into(),
        source: "signal.primals.eco".into(),
        description: "Federated behavioral threat intelligence from multiple observation layers. Published for community immunity.".into(),
        federation: FederationMeta {
            layer_count: layers.len(),
            layers: layer_metadata,
        },
        population: FederatedPopulation {
            total_subgroups,
            total_observations,
            mean_confidence: mean_conf,
        },
        conserved_epitopes: federated_epitopes,
        behavioral_hashes_summary: HashSummary {
            total_unique: all_hashes.len(),
            multi_layer: multi_layer_count,
        },
        detection_rules: DetectionRules {
            description: "Any system exhibiting 4 or more of these rules simultaneously is this fleet.".into(),
            rules: vec![
                "User-Agent contains 'Chrome/' but Sec-Fetch-Mode header is ABSENT".into(),
                "User-Agent contains 'Chrome/' but Sec-Ch-Ua header is ABSENT".into(),
                "Connection header is ABSENT".into(),
                "Accept header is exactly '*/*'".into(),
                "Chrome major version is 5+ behind current stable".into(),
                "Accept-Encoding is identical across >90% of population".into(),
                "Accept-Language is identical across >90% of population".into(),
                ">50% of requests target /commit/, /src/, /raw/, /blame/ paths".into(),
                "Inter-request timing coefficient of variation < 0.15".into(),
                ">80% of IPs make exactly 1 request (single-page rotation)".into(),
                ">10% of requests target /blame/ paths (author attribution)".into(),
                "Requests continue after 403 response".into(),
            ],
            threshold: 4,
        },
        attribution: Attribution {
            primary_entity: "Meta Platforms, Inc.".into(),
            whois_confirmed_blocks: vec![
                WhoisBlock {
                    cidr: "57.141.0.0/13".into(),
                    netname: "FB-BLOCK".into(),
                    org: "Meta Platforms Ireland Limited".into(),
                    country: "IE".into(),
                },
                WhoisBlock {
                    cidr: "173.252.0.0/16".into(),
                    netname: "FACEBOOK-INC".into(),
                    org: "Facebook, Inc.".into(),
                    country: "US".into(),
                },
            ],
        },
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    #[error("no layers reachable")]
    NoLayers,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP: {0}")]
    Http(String),
}

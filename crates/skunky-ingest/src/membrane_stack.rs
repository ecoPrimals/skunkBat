// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Membrane stack — nested membrane observer from core to heliosphere.
//!
//! Converged from `membrane-breathe.py` (jellystein, Wave 171).
//! Fetches live data from public feeds and local sensors, computes
//! a 7-layer Anderson-like profile, writes `membrane-stack.json`.
//!
//! ## Layers (inside → outside)
//!
//! | # | Name | Source | Feed |
//! |---|------|--------|------|
//! | 0 | gAIa | bloom sensor + anderson bridge | local |
//! | 1 | Mycelium | inferred (future: soil sensor) | none |
//! | 2 | Earth's Crust | USGS earthquake feed | HTTPS |
//! | 3 | Atmosphere | inferred from climate data | none |
//! | 4 | Magnetosphere | NOAA SWPC Kp index | HTTPS |
//! | 5 | Heliosphere | NOAA DSCOVR solar wind | HTTPS |
//! | 6 | Deep Space | inferred — cosmic ray background | none |
//!
//! ## Convergence
//!
//! This module replaces `membrane-breathe.py`. The jellystein version
//! is fossilized in `fossilRecord/membrane-stack/`.

use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::Utc;
use serde::{Deserialize, Serialize};

// ── Types ──

/// A single membrane layer observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembraneLayer {
    pub name: String,
    pub scale: String,
    pub depth: String,
    pub source: String,
    pub data: serde_json::Value,
    /// 0.0 (opaque) to 1.0 (transparent)
    pub permeability: f64,
    /// Anderson disorder / filtering strength
    pub anderson_w: f64,
    /// Qualitative breathing state
    pub breathing: String,
    pub alive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Aggregate statistics for the full stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackAggregate {
    pub alive_layers: usize,
    pub total_layers: usize,
    pub mean_permeability: f64,
    pub mean_anderson_w: f64,
}

/// The complete membrane stack snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembraneStack {
    pub timestamp: String,
    pub wave: u32,
    pub layers: Vec<MembraneLayer>,
    pub aggregate: StackAggregate,
    pub elapsed_secs: f64,
    pub motto: String,
}

/// Configuration for the membrane stack observer.
#[derive(Debug, Clone)]
pub struct MembraneStackConfig {
    pub output_path: PathBuf,
    pub bloom_path: PathBuf,
    pub anderson_path: PathBuf,
    pub http_timeout_secs: u64,
}

impl Default for MembraneStackConfig {
    fn default() -> Self {
        Self {
            output_path: PathBuf::from("/opt/membrane/live-terminal/membrane-stack.json"),
            bloom_path: PathBuf::from("/run/membrane/bloom.signal"),
            anderson_path: PathBuf::from("/run/membrane/anderson-profile.json"),
            http_timeout_secs: 10,
        }
    }
}

// ── USGS types ──

#[derive(Debug, Deserialize)]
struct UsgsFeatureCollection {
    features: Vec<UsgsFeature>,
}

#[derive(Debug, Deserialize)]
struct UsgsFeature {
    properties: UsgsProperties,
}

#[derive(Debug, Deserialize)]
struct UsgsProperties {
    mag: Option<f64>,
    place: Option<String>,
}

// ── NOAA types ──

#[derive(Debug, Deserialize)]
struct NoaaKpEntry {
    #[serde(rename = "Kp")]
    kp: Option<f64>,
    time_tag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NoaaScaleEntry {
    #[serde(rename = "Scale")]
    scale: Option<String>,
    #[serde(rename = "Text")]
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NoaaScales {
    #[serde(rename = "G")]
    g: Option<NoaaScaleEntry>,
}

#[derive(Debug, Deserialize)]
struct NoaaSolarWindSpeed {
    proton_speed: Option<f64>,
    time_tag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NoaaSolarWindMag {
    bt: Option<f64>,
    bz_gsm: Option<f64>,
    time_tag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NoaaFlux {
    flux: Option<f64>,
}

// ── Data fetching ──

async fn fetch_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
) -> Option<T> {
    client
        .get(url)
        .header("User-Agent", "ecoPrimal-artisan/2.0 membrane-stack-rust")
        .send()
        .await
        .ok()?
        .json::<T>()
        .await
        .ok()
}

fn read_local_json(path: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

// ── Layer builders ──

fn layer_gaia(config: &MembraneStackConfig) -> MembraneLayer {
    let bloom = read_local_json(&config.bloom_path);
    let anderson = read_local_json(&config.anderson_path);

    if let (Some(bloom), Some(anderson)) = (bloom, anderson) {
        let total = bloom
            .get("total_requests")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let readers = bloom.get("readers").cloned().unwrap_or_default();
        let human = readers
            .get("human")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let ai = readers
            .get("ai-agent")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let scanner = readers
            .get("scanner")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let p = if total > 0.0 { human / total } else { 0.0 };
        let w = anderson
            .get("w_population")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let selectivity = anderson
            .get("selectivity_observed")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        MembraneLayer {
            name: "gAIa".into(),
            scale: "digital membrane".into(),
            depth: "0 (you are here)".into(),
            source: "bloom sensor + anderson bridge".into(),
            data: serde_json::json!({
                "requests_per_window": total,
                "human": human,
                "ai_agent": ai,
                "scanner": scanner,
                "selectivity": (selectivity * 1000.0).round() / 1000.0,
            }),
            permeability: (p * 10000.0).round() / 10000.0,
            anderson_w: (w * 100.0).round() / 100.0,
            breathing: if total > 0.0 { "ticking" } else { "dormant" }.into(),
            alive: true,
            error: None,
        }
    } else {
        MembraneLayer {
            name: "gAIa".into(),
            scale: "digital membrane".into(),
            depth: "0 (you are here)".into(),
            source: "bloom sensor + anderson bridge".into(),
            data: serde_json::Value::Null,
            permeability: 0.0,
            anderson_w: 0.0,
            breathing: String::new(),
            alive: false,
            error: Some("no bloom/anderson data".into()),
        }
    }
}

fn layer_mycelium() -> MembraneLayer {
    MembraneLayer {
        name: "Mycelium".into(),
        scale: "0 to -1 m".into(),
        depth: "soil rhizosphere".into(),
        source: "inferred (no direct sensor yet)".into(),
        data: serde_json::json!({
            "note": "200m hyphae per gram. 90% of plants connected. Seasonal permeability."
        }),
        permeability: 0.7,
        anderson_w: 5.0,
        breathing: "seasonal".into(),
        alive: true,
        error: None,
    }
}

async fn layer_seismic(client: &reqwest::Client) -> MembraneLayer {
    let url = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_hour.geojson";
    let data: Option<UsgsFeatureCollection> = fetch_json(client, url).await;

    if let Some(fc) = data {
        let count = fc.features.len();
        let max_mag = fc
            .features
            .iter()
            .filter_map(|f| f.properties.mag)
            .fold(0.0_f64, f64::max);
        let locations: Vec<String> = fc
            .features
            .iter()
            .take(3)
            .filter_map(|f| f.properties.place.clone())
            .collect();

        let p = (count as f64 / 20.0).min(1.0);
        let w = (15.0 - max_mag * 2.0).max(1.0);

        let breathing = if count > 5 {
            "active"
        } else if count > 0 {
            "quiet"
        } else {
            "silent"
        };

        MembraneLayer {
            name: "Earth's Crust".into(),
            scale: "0 to -70 km".into(),
            depth: "Mohorovičić discontinuity".into(),
            source: "USGS earthquake feed".into(),
            data: serde_json::json!({
                "quakes_last_hour": count,
                "max_magnitude": (max_mag * 10.0).round() / 10.0,
                "locations": locations,
            }),
            permeability: (p * 1000.0).round() / 1000.0,
            anderson_w: (w * 10.0).round() / 10.0,
            breathing: breathing.into(),
            alive: true,
            error: None,
        }
    } else {
        MembraneLayer {
            name: "Earth's Crust".into(),
            scale: "0 to -70 km".into(),
            depth: "Mohorovičić discontinuity".into(),
            source: "USGS earthquake feed".into(),
            data: serde_json::Value::Null,
            permeability: 0.0,
            anderson_w: 0.0,
            breathing: String::new(),
            alive: false,
            error: Some("USGS unreachable".into()),
        }
    }
}

fn layer_atmosphere() -> MembraneLayer {
    MembraneLayer {
        name: "Atmosphere".into(),
        scale: "0 to 50 km".into(),
        depth: "tropopause + stratopause + W-layer".into(),
        source: "inferred from climate data".into(),
        data: serde_json::json!({
            "tropopause_km": 12,
            "stratopause_km": 50,
            "stratopause_trend": "cooling 0.5-1K/decade, dropping 300-500m/decade",
            "w_layer": "newly discovered — suppresses entrainment at cloud tops",
        }),
        permeability: 0.4,
        anderson_w: 8.0,
        breathing: "seasonal + anthropogenic drift".into(),
        alive: true,
        error: None,
    }
}

async fn layer_magnetosphere(client: &reqwest::Client) -> MembraneLayer {
    let kp_url = "https://services.swpc.noaa.gov/products/noaa-planetary-k-index.json";
    let scales_url = "https://services.swpc.noaa.gov/products/noaa-scales.json";

    let kp_data: Option<Vec<NoaaKpEntry>> = fetch_json(client, kp_url).await;
    let scales_raw: Option<serde_json::Value> = fetch_json(client, scales_url).await;

    if let Some(kp_entries) = kp_data {
        if let Some(latest) = kp_entries.last() {
            let kp = latest.kp.unwrap_or(0.0);
            let kp_time = latest.time_tag.clone().unwrap_or_default();

            let (g_scale, g_text) = scales_raw
                .as_ref()
                .and_then(|s| s.get("0"))
                .and_then(|z| {
                    let g = z.get("G")?;
                    let scale = g.get("Scale")?.as_str()?.to_string();
                    let text = g.get("Text")?.as_str()?.to_string();
                    Some((scale, text))
                })
                .unwrap_or(("0".into(), "none".into()));

            let p = (kp / 9.0).min(1.0);
            let w = (15.0 - kp * 1.5).max(1.0);

            let breathing = if kp >= 5.0 {
                "storming"
            } else if kp >= 3.0 {
                "flexing"
            } else {
                "quiet"
            };

            return MembraneLayer {
                name: "Magnetosphere".into(),
                scale: "100 to 60,000 km".into(),
                depth: "Van Allen belts + magnetopause".into(),
                source: "NOAA SWPC".into(),
                data: serde_json::json!({
                    "kp_index": kp,
                    "kp_time": kp_time,
                    "geomagnetic_storm": format!("G{g_scale} ({g_text})"),
                }),
                permeability: (p * 1000.0).round() / 1000.0,
                anderson_w: (w * 10.0).round() / 10.0,
                breathing: breathing.into(),
                alive: true,
                error: None,
            };
        }
    }

    MembraneLayer {
        name: "Magnetosphere".into(),
        scale: "100 to 60,000 km".into(),
        depth: "Van Allen belts + magnetopause".into(),
        source: "NOAA SWPC".into(),
        data: serde_json::Value::Null,
        permeability: 0.0,
        anderson_w: 0.0,
        breathing: String::new(),
        alive: false,
        error: Some("NOAA unreachable".into()),
    }
}

async fn layer_heliosphere(client: &reqwest::Client) -> MembraneLayer {
    let speed: Option<Vec<NoaaSolarWindSpeed>> =
        fetch_json(client, "https://services.swpc.noaa.gov/products/summary/solar-wind-speed.json")
            .await;
    let mag: Option<Vec<NoaaSolarWindMag>> =
        fetch_json(client, "https://services.swpc.noaa.gov/products/summary/solar-wind-mag-field.json")
            .await;
    let flux: Option<Vec<NoaaFlux>> =
        fetch_json(client, "https://services.swpc.noaa.gov/products/summary/10cm-flux.json")
            .await;

    if let (Some(speed_data), Some(mag_data)) = (speed, mag) {
        let sw_speed = speed_data
            .first()
            .and_then(|s| s.proton_speed)
            .unwrap_or(0.0);
        let sw_bt = mag_data.first().and_then(|m| m.bt).unwrap_or(0.0);
        let sw_bz = mag_data.first().and_then(|m| m.bz_gsm).unwrap_or(0.0);
        let sw_time = speed_data
            .first()
            .and_then(|s| s.time_tag.clone())
            .unwrap_or_default();
        let radio_flux = flux
            .and_then(|f| f.first().and_then(|x| x.flux))
            .unwrap_or(0.0);

        let p = ((700.0 - sw_speed) / 500.0).clamp(0.0, 1.0);
        let w = sw_bt.max(1.0);

        let breathing = if sw_bz < -5.0 {
            "reconnecting"
        } else if sw_speed > 500.0 {
            "expanding"
        } else if sw_speed > 350.0 {
            "steady"
        } else {
            "contracting"
        };

        MembraneLayer {
            name: "Heliosphere".into(),
            scale: "1 AU to ~120 AU".into(),
            depth: "termination shock + heliopause".into(),
            source: "NOAA DSCOVR (L1 Lagrange point)".into(),
            data: serde_json::json!({
                "solar_wind_speed_km_s": sw_speed,
                "magnetic_field_bt_nT": sw_bt,
                "magnetic_field_bz_nT": sw_bz,
                "radio_flux_sfu": radio_flux,
                "time": sw_time,
            }),
            permeability: (p * 1000.0).round() / 1000.0,
            anderson_w: (w * 10.0).round() / 10.0,
            breathing: breathing.into(),
            alive: true,
            error: None,
        }
    } else {
        MembraneLayer {
            name: "Heliosphere".into(),
            scale: "1 AU to ~120 AU".into(),
            depth: "termination shock + heliopause".into(),
            source: "NOAA DSCOVR (L1 Lagrange point)".into(),
            data: serde_json::Value::Null,
            permeability: 0.0,
            anderson_w: 0.0,
            breathing: String::new(),
            alive: false,
            error: Some("NOAA solar wind unreachable".into()),
        }
    }
}

fn layer_deep_space() -> MembraneLayer {
    MembraneLayer {
        name: "Deep Space".into(),
        scale: "120+ AU".into(),
        depth: "interstellar medium".into(),
        source: "inferred — galactic cosmic ray background".into(),
        data: serde_json::json!({
            "planet_nine": "unconfirmed — signal in null space at ~225 AU",
            "pluto": "liquid N₂ rising through cracks in Sputnik Planitia (Aug 2026)",
            "voyager_1": "interstellar space since 2012",
            "new_horizons": "58 AU, approaching termination shock (2029-2040)",
        }),
        permeability: 0.9,
        anderson_w: 2.0,
        breathing: "galactic timescale".into(),
        alive: true,
        error: None,
    }
}

// ── Stack computation ──

/// Compute the full 7-layer membrane stack.
///
/// Fetches live data from USGS, NOAA, and local sensors.
/// Returns the complete stack snapshot.
pub async fn compute_stack(config: &MembraneStackConfig) -> MembraneStack {
    let start = Instant::now();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.http_timeout_secs))
        .build()
        .unwrap_or_default();

    // Fetch remote layers concurrently
    let (seismic, magneto, helio) = tokio::join!(
        layer_seismic(&client),
        layer_magnetosphere(&client),
        layer_heliosphere(&client),
    );

    let layers = vec![
        layer_gaia(config),
        layer_mycelium(),
        seismic,
        layer_atmosphere(),
        magneto,
        helio,
        layer_deep_space(),
    ];

    let alive_count = layers.iter().filter(|l| l.alive).count();
    let (sum_p, sum_w) = layers
        .iter()
        .filter(|l| l.alive)
        .fold((0.0, 0.0), |(sp, sw), l| {
            (sp + l.permeability, sw + l.anderson_w)
        });
    let n = alive_count.max(1) as f64;

    let elapsed = start.elapsed().as_secs_f64();

    MembraneStack {
        timestamp: Utc::now().to_rfc3339(),
        wave: 171,
        layers,
        aggregate: StackAggregate {
            alive_layers: alive_count,
            total_layers: 7,
            mean_permeability: (sum_p / n * 1000.0).round() / 1000.0,
            mean_anderson_w: (sum_w / n * 10.0).round() / 10.0,
        },
        elapsed_secs: (elapsed * 1000.0).round() / 1000.0,
        motto: "membranes all the way down, membranes all the way up".into(),
    }
}

/// Compute and write the membrane stack to disk.
pub async fn breathe(config: &MembraneStackConfig) -> Result<MembraneStack, std::io::Error> {
    let stack = compute_stack(config).await;

    if let Some(parent) = config.output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(&stack)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&config.output_path, json)?;

    tracing::info!(
        layers_alive = stack.aggregate.alive_layers,
        mean_p = stack.aggregate.mean_permeability,
        mean_w = stack.aggregate.mean_anderson_w,
        elapsed = stack.elapsed_secs,
        "membrane stack breath complete"
    );

    Ok(stack)
}

/// Run the membrane stack observer as a repeating loop.
pub async fn breathe_loop(config: MembraneStackConfig, interval_secs: u64) {
    tracing::info!(
        interval = interval_secs,
        output = %config.output_path.display(),
        "membrane stack observer starting"
    );

    // Initial warmup delay
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;

    loop {
        match breathe(&config).await {
            Ok(stack) => {
                let alive = stack.aggregate.alive_layers;
                let total = stack.aggregate.total_layers;
                tracing::info!(
                    alive,
                    total,
                    mean_p = stack.aggregate.mean_permeability,
                    mean_w = stack.aggregate.mean_anderson_w,
                    "gAIa breathes — {alive}/{total} layers"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "membrane stack breath failed");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}

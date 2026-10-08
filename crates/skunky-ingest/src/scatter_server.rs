// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Scatter content server — serves plausible-but-poisoned content.
//!
//! ## Biological Parallel: Opsonization
//!
//! In immunology, opsonization is when antibodies coat a pathogen, marking
//! it for destruction. The pathogen "looks normal" to its own systems but
//! phagocytes recognize the antibody tags and engulf it.
//!
//! Our scatter server is the opsonization layer:
//! - The **content_gate** detects fleet requests (antibody binding)
//! - Caddy routes detected requests to the scatter server (phagocyte delivery)
//! - The scatter server serves poisoned content (destruction by misinformation)
//! - The fleet ingests what looks like real data but is entirely fabricated
//!
//! ## Key Properties
//!
//! - **Deterministic**: Same request path → same poison content (prevents
//!   detection via request diffing)
//! - **No real data**: Zero information from actual repos leaks into scatter
//!   content — all names, code, diffs, and commit messages are fabricated
//! - **Plausible structure**: Valid HTML with correct Gitea-like CSS class
//!   names, realistic file trees, and syntactically valid code
//! - **Mixed response**: Not all requests get poison — some still abort,
//!   creating uncertainty for the fleet about which responses are real

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use crate::scyborg_prism::{ScyBorgPrism, OpsonizationSalt, SharedViolationLedger};

pub use crate::scatter_types::*;

// PrismMode and PrismMix are now in scatter_prism.rs
pub use crate::scatter_prism::{PrismMode, PrismMix};
// ScatterGenerator is now in scatter_generator.rs
pub(crate) use crate::scatter_generator::ScatterGenerator;
// Mirror/epitope/compliance functions are in scatter_mirror.rs
use crate::scatter_constants::{
    COMPLIANCE_NOTICES, EVASION_COST_TABLE, MIRROR_MODULES,
    MIRROR_METRICS,
};
use crate::scatter_mirror::{
    encode_zwc, path_deterministic_hash, generate_epitope_maze, generate_cross_mirror,
    generate_violation_mirror,
};
use crate::scatter_temporal::{
    temporal_phaseout_body, temporal_ghost_body,
};
use crate::cube_oracle::{
    CubeDecisionGrid, CubeOracle, SharedOracle,
    ScatterObservation, ResponseType,
};
use crate::scatter_defense::*;
use crate::scatter_prism::generate_prism_content;
use crate::scatter_generator::blackwall_og_card;
use crate::scatter_rng::XorShift64;
use crate::scatter_nft::{CONTRIBUTE_PAGE, generate_nft_receipt};
pub use crate::scatter_nft::{AntibodyReaction, braid_antibody_reaction};

/// Run the scatter content server.
///
/// This spawns as a background task and serves poisoned responses to
/// fleet requests routed by Caddy's content_gate.
pub async fn run(config: ScatterConfig, confidence: SharedConfidence, opsonize_cache: OpsonizeCache, back_pressure: BackPressure, oracle: SharedOracle, titration: crate::ingestion_observer::SharedPhase) {
    let listener = match TcpListener::bind(config.listen_addr).await {
        Ok(l) => {
            tracing::info!(
                addr = %config.listen_addr,
                poison_ratio = config.poison_ratio,
                max_tarpit = config.max_tarpit_connections,
                "🧪 scatter server active — opsonization + tarpit + honeytokens ready"
            );
            l
        }
        Err(e) => {
            tracing::error!(error = %e, addr = %config.listen_addr, "scatter server bind failed");
            return;
        }
    };

    let generator = Arc::new(ScatterGenerator::new(config.seed));
    let base_ratio = config.poison_ratio;
    let tarpit = TarpitState::new(config.max_tarpit_connections);
    let cache = Arc::new(opsonize_cache);
    let metrics = Arc::new(ScatterMetrics::new());
    if let Ok(s) = std::fs::read_to_string("/var/lib/skunky-ingest/nft-count") {
        if let Ok(n) = s.trim().parse::<u32>() {
            metrics.nft_contributions.store(n, Ordering::Relaxed);
            tracing::info!("🔴 Loaded {n} NFT contribution(s) from persistent state");
        }
    }
    let violation_ledger = SharedViolationLedger::new();
    let bp = Arc::new(back_pressure);

    // Evict stale violation ledger entries every 5 minutes
    let evict_ledger = violation_ledger.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            evict_ledger.evict_stale(86400).await; // 24h TTL
        }
    });

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, "scatter accept failed");
                continue;
            }
        };

        let sg = Arc::clone(&generator);
        // ── TITRATION ──
        // Phase multiplier scales the poison ratio down as ingestion deepens.
        // Phase 0: ×1.0 (full), Phase 1: ×0.6, Phase 2: ×0.2, Phase 3: ×0.05
        let titrated_base = base_ratio * titration.poison_multiplier();
        let effective_ratio = confidence.effective_ratio(titrated_base);
        let antidote_level = titration.antidote_level();
        let tp = tarpit.clone();
        let oc = Arc::clone(&cache);
        let mt = Arc::clone(&metrics);
        let vl = violation_ledger.clone();
        let bp_ref = Arc::clone(&bp);
        let orc = Arc::clone(&oracle);
        tokio::spawn(async move {
            if let Err(e) = handle_request(stream, &sg, effective_ratio, antidote_level, &tp, &oc, &mt, &vl, &bp_ref, &orc).await {
                tracing::debug!(error = %e, "scatter request handler error");
            }
        });
    }
}

async fn handle_request(
    mut stream: tokio::net::TcpStream,
    generator: &ScatterGenerator,
    poison_ratio: f32,
    antidote_level: u8,
    tarpit: &TarpitState,
    opsonize_cache: &OpsonizeCache,
    metrics: &ScatterMetrics,
    violation_ledger: &SharedViolationLedger,
    back_pressure: &BackPressure,
    oracle: &SharedOracle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.split();
    let mut buf_reader = BufReader::new(reader);

    // Read the request line (GET /path HTTP/1.1)
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    let is_post = request_line.starts_with("POST");

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();

    // Consume remaining headers, extract identity for canary embedding
    let mut header_line = String::new();
    let mut fleet_hash = String::new();
    let mut content_length: usize = 0;
    let mut real_ip = String::new();
    let mut is_honeycomb = false;
    let mut honeycomb_surface: u8 = 0;
    let mut request_host = String::new();
    let mut is_facebook_bot = false;
    loop {
        header_line.clear();
        let n = buf_reader.read_line(&mut header_line).await?;
        if n == 0 || header_line.trim().is_empty() {
            break;
        }
        let lower = header_line.to_ascii_lowercase();
        if lower.starts_with("x-fleet-hash:") {
            fleet_hash = header_line
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
        } else if lower.starts_with("x-real-ip:") {
            real_ip = header_line
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
        } else if lower.starts_with("x-honeycomb:") {
            is_honeycomb = true;
        } else if lower.starts_with("content-length:") {
            content_length = header_line
                .split_once(':')
                .and_then(|(_, v)| v.trim().parse().ok())
                .unwrap_or(0);
        } else if lower.starts_with("user-agent:") {
            let ua_val = header_line
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            if ua_val.contains("facebookexternalhit") {
                is_facebook_bot = true;
            }
        } else if lower.starts_with("host:") {
            request_host = header_line
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            // Map honeycomb subdomain to surface index (each is a different lens)
            honeycomb_surface = match request_host.split('.').next().unwrap_or("") {
                "bloom"      => 0,
                "thymus"     => 1,
                "opsonize"   => 2,
                "antibody"   => 3,
                "cytokine"   => 4,
                "receptor"   => 5,
                "macrophage" => 6,
                "lysozyme"   => 7,
                "complement" => 8,
                "epitope"    => 9,
                "antigen"    => 10,
                "interferon" => 11,
                _            => 0,
            };
        }
    }
    // Read POST body if present (capped at 64KB to prevent abuse)
    let request_body = if is_post && content_length > 0 && content_length < 65536 {
        let mut body_buf = vec![0u8; content_length];
        buf_reader.read_exact(&mut body_buf).await?;
        Some(String::from_utf8_lossy(&body_buf).to_string())
    } else {
        None
    };

    // Derive canary identity: prefer behavioral hash, fall back to IP hash
    if fleet_hash.is_empty() && !real_ip.is_empty() {
        fleet_hash = format!("{:016x}", path_deterministic_hash(&real_ip, 0xCA4A_4712_FEED));
    }

    // ── BLACKWALL: Facebook bot gets OG card ──
    if is_facebook_bot {
        let og_card = blackwall_og_card(&request_host);
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: public, max-age=300\r\n\
             \r\n\
             {og_card}",
            og_card.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── LIVE TERMINAL FEED — /live endpoint ──
    if path == "/live" {
        let feed_path = std::path::Path::new("/opt/membrane/live-terminal/feed.txt");
        let body = std::fs::read_to_string(feed_path).unwrap_or_else(|_| "feed not available\n".to_string());
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache, no-store\r\n\
             Access-Control-Allow-Origin: *\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── DASHBOARD JSON — /dashboard.json endpoint ──
    if path == "/dashboard.json" {
        let dash_path = std::path::Path::new("/opt/membrane/live-terminal/dashboard.json");
        let body = std::fs::read_to_string(dash_path).unwrap_or_else(|_| "{}".to_string());
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache, no-store\r\n\
             Access-Control-Allow-Origin: *\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── TOPOLOGY — /topology.json endpoint ──
    if path == "/topology.json" {
        let topo_path = std::path::Path::new("/opt/membrane/live-terminal/topology.json");
        let body = std::fs::read_to_string(topo_path).unwrap_or_else(|_| "{}".to_string());
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache, no-store\r\n\
             Access-Control-Allow-Origin: *\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── PLASMID EXPORT — /plasmid endpoint for federation ──
    if path == "/plasmid" {
        let layer_name = std::env::var("LAYER_NAME")
            .or_else(|_| std::fs::read_to_string("/etc/membrane/gate-name").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        let body = opsonize_cache.export_plasmid_json(&layer_name).await;
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: public, max-age=60\r\n\
             Access-Control-Allow-Origin: *\r\n\
             X-Content-Type-Options: nosniff\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        metrics.plasmid_served.fetch_add(1, Ordering::Relaxed);
        metrics.record(body.len() as u64);
        return Ok(());
    }

    // ── METRICS — /metrics endpoint for live monitoring ──
    if path == "/metrics" {
        let layer_name = std::env::var("LAYER_NAME")
            .or_else(|_| std::fs::read_to_string("/etc/membrane/gate-name").map(|s| s.trim().to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
        let body = metrics.export_json(&layer_name);
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache\r\n\
             Access-Control-Allow-Origin: *\r\n\
             X-Content-Type-Options: nosniff\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── CONTRIBUTE — Novel Fermentation Transcript (NFT) ──
    // THE BUTTON. Humans press it, their mouse/scroll/timing entropy gets
    // mixed with scyBorg-licensed content, creating a unique co-authored work.
    // The human gets a receipt (the "reverse cookie"). They're now a rights-holder.
    // Bots can't generate real entropy. They get nothing.
    if path == "/contribute" || path == "/contribute/" {
        if is_post {
            if let Some(ref body) = request_body {
                let receipt = generate_nft_receipt(body, generator.seed);
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     Cache-Control: no-cache, no-store\r\n\
                     Access-Control-Allow-Origin: *\r\n\
                     Access-Control-Allow-Headers: Content-Type\r\n\
                     \r\n\
                     {receipt}",
                    receipt.len(),
                );
                writer.write_all(response.as_bytes()).await?;
                writer.flush().await?;
                tracing::info!("🧬 NFT contribution received — human entropy fermented");
                let new_count = metrics.nft_contributions.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = std::fs::write("/var/lib/skunky-ingest/nft-count", new_count.to_string());
                metrics.scatter_served.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        }
        // CORS preflight for cross-origin POSTs
        if request_line.starts_with("OPTIONS") {
            let response = "HTTP/1.1 204 No Content\r\n\
                Access-Control-Allow-Origin: *\r\n\
                Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n\
                Access-Control-Allow-Headers: Content-Type\r\n\
                Access-Control-Max-Age: 86400\r\n\
                Connection: close\r\n\r\n";
            writer.write_all(response.as_bytes()).await?;
            writer.flush().await?;
            return Ok(());
        }
        // GET: serve THE BUTTON page
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache, no-store\r\n\
             X-License: AGPL-3.0-or-later; scyBorg\r\n\
             \r\n\
             {}",
            CONTRIBUTE_PAGE.len(),
            CONTRIBUTE_PAGE,
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        tracing::info!("🔴 THE BUTTON served to human");
        return Ok(());
    }

    // NFT contribution counter — lightweight JSON for live display
    if path == "/nft-count" || path == "/nft-count/" {
        let count = metrics.nft_contributions.load(Ordering::Relaxed);
        let body = format!(r#"{{"count":{count}}}"#);
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: no-cache, no-store\r\n\
             Access-Control-Allow-Origin: *\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── EPITOPE FEED — cross-forge communal immunity ──
    //
    // The epitope feed is the public immune surface. Any sovereign forge can
    // consume this and match the behavioral fingerprints against their own
    // access logs. The inversion: instead of watching what comes TO us,
    // we publish what we see so everyone can trace where they GO.
    //
    // Each epitope cluster is a behavioral DNA profile:
    //   - Accept-Encoding fingerprint
    //   - UA rotation pool size (1 = bot, 9 = evasion fleet)
    //   - blame ratio (high = attribution extraction)
    //   - timing cadence
    //   - target repo pattern
    //
    // Combined with the /plasmid endpoint (per-hash data), this gives
    // any consuming forge two layers:
    //   /epitope-feed.json — cluster-level behavioral genetics
    //   /plasmid — individual hash-level opsonization tags
    //
    // The gossip mesh (swarmvine) also carries these as gossip entries
    // so every node in the membrane pools classifiers automatically.
    if path == "/epitope-feed.json" || path == "/epitope-feed" {
        // Prefer pre-generated feed (from bloom_live.py) for consistency with dashboard.
        // Fall back to in-process generation if the file doesn't exist.
        let feed_path = std::path::Path::new("/opt/membrane/live-terminal/epitope-feed.json");
        let body = match std::fs::read_to_string(feed_path) {
            Ok(s) if !s.is_empty() => s,
            _ => generate_epitope_feed(opsonize_cache, metrics).await,
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: public, max-age=30\r\n\
             Access-Control-Allow-Origin: *\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-Epitope-Schema: ecoPrimals/epitope-feed/v1\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── EPITOPE INVERSION — fleet crawl graph reconstruction ──
    //
    // The inversion endpoint exposes the cross-forge movement graph.
    // When epitope hashes appear in feeds from multiple forges, we can
    // reconstruct where the fleet is crawling — all spy holes at once.
    if path == "/epitope-inversion.json" || path == "/epitope-inversion" {
        // For now, read the local epitope feed and present it as a single-node
        // inversion. When peer feeds are ingested via gossip.pool, this will
        // contain multi-forge correlations automatically.
        let feed_path = std::path::Path::new("/opt/membrane/live-terminal/epitope-feed.json");
        let body = match std::fs::read_to_string(feed_path) {
            Ok(s) => {
                // Wrap in inversion format
                let feed: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
                let clusters = feed.get("epitope_clusters")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let node_id = feed.get("node_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let entries: Vec<serde_json::Value> = clusters.iter()
                    .filter_map(|c| {
                        let hash = c.get("hash")?.as_str()?;
                        Some(serde_json::json!({
                            "epitope_hash": hash,
                            "forges_observed": 1,
                            "forge_list": [node_id],
                            "ua_pool_size": c.get("ua_pool_size"),
                            "blame_ratio": c.get("blame_ratio"),
                            "cluster_size": c.get("cluster_size").or(c.get("ips")),
                        }))
                    })
                    .collect();
                serde_json::to_string(&serde_json::json!({
                    "schema": "ecoPrimals/epitope-inversion/v1",
                    "node_id": node_id,
                    "generated_epoch": now,
                    "total_tracked_epitopes": entries.len(),
                    "multi_forge_epitopes": 0,
                    "fleet_movements": entries,
                    "status": "single_node",
                    "usage": "Connect peer forges via gossip.pool to see cross-forge \
                              fleet movement patterns. Currently showing local-only view.",
                })).unwrap_or_else(|_| "{}".to_string())
            }
            Err(_) => "{}".to_string(),
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: public, max-age=30\r\n\
             Access-Control-Allow-Origin: *\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-Epitope-Schema: ecoPrimals/epitope-inversion/v1\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    // ── Layer 0: HONEYCOMB PRISM — fleet teams enter and see chimera'd data
    //    from OTHER teams. 12 surfaces, topology shifts per request path.
    if is_honeycomb && !fleet_hash.is_empty() {
        let effective_path = path.strip_prefix("/disperse").unwrap_or(&path);
        let path_seed = path_deterministic_hash(effective_path, 0x5CB_0E6C_4055);

        if let Some(mix) = opsonize_cache.prism_mix(&fleet_hash, honeycomb_surface, path_seed).await {
            let mut rng = XorShift64::new(path_seed.wrapping_add(generator.seed));
            let (ct, body) = generate_prism_content(
                generator, &mut rng, effective_path, &mix,
            );

            let mode_name = match mix.mix_mode {
                PrismMode::Dominant     => "dominant",
                PrismMode::Layered      => "layered",
                PrismMode::Chimera      => "chimera",
                PrismMode::Cytokine     => "cytokine",
                PrismMode::Inverse      => "inverse",
                PrismMode::Apoptosis    => "apoptosis",
                PrismMode::EpitopePress => "epitope-press",
            };

            // ── Prismatic scyBorg injection (V(D)J recombination) ──
            // Record this interaction in the violation ledger
            let team_hashes: Vec<String> = mix.secondaries.iter().map(|(h, _)| h.clone()).collect();
            let chain_depth = violation_ledger.record(
                &fleet_hash, honeycomb_surface, 0, &team_hashes,
            ).await;

            // Prismatic license: varied-but-equivalent injection per response seed
            let prism_seed = path_seed.wrapping_add(chain_depth as u64);
            let body = if ct.contains("text/html") {
                ScyBorgPrism::inject_html(prism_seed, &body, chain_depth)
            } else {
                ScyBorgPrism::inject_markdown(prism_seed, &body, chain_depth)
            };

            // Opsonization salt: encode full violation context invisibly
            let salt = OpsonizationSalt {
                hash: fleet_hash.clone(),
                timestamp_window: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() / 3600,
                epitope_flags: 0, // will be populated once epitope wiring completes
                violation_count: chain_depth,
                surface_idx: honeycomb_surface,
                chain_depth,
            };
            let body = if ct.contains("text/html") {
                salt.embed_html(prism_seed, &body)
            } else {
                salt.embed_markdown(prism_seed, &body)
            };

            // Violation chain section — growing cumulative record
            let pop_size = mix.population_size;
            let chain_section = violation_ledger.chain_section(&fleet_hash, pop_size).await;
            let body = if chain_section.is_empty() { body } else { format!("{body}{chain_section}") };

            // Wave 166f: Set-Cookie pressure — force a fork in session_absent
            let cookie_header = {
                let cookie_val = format!("{}:{}", &fleet_hash[..fleet_hash.len().min(12)], honeycomb_surface);
                let encoded: String = cookie_val.bytes().map(|b| format!("{:02x}", b)).collect();
                format!(
                    "Set-Cookie: _mhc={encoded}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400\r\n\
                     Set-Cookie: _thymus=1; Path=/; Secure; SameSite=Strict; Max-Age=3600\r\n"
                )
            };

            // Prismatic headers: varied X-License set per response
            let prismatic_headers = ScyBorgPrism::inject_headers(prism_seed, chain_depth);

            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: {ct}\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 Cache-Control: private, max-age=900\r\n\
                 X-Content-Type-Options: nosniff\r\n\
                 {prismatic_headers}\
                 X-Scatter-Type: prism-{mode_name}\r\n\
                 X-Prism-Surface: {honeycomb_surface}\r\n\
                 X-Prism-Population: {pop_size}\r\n\
                 X-Violation-Chain: {chain_depth}\r\n\
                 {cookie_header}\
                 \r\n\
                 {body}",
                body.len(),
            );
            writer.write_all(response.as_bytes()).await?;
            writer.flush().await?;
            tracing::info!(
                requesting_hash = %&fleet_hash[..fleet_hash.len().min(8)],
                primary = %&mix.primary_hash[..mix.primary_hash.len().min(8)],
                secondaries = mix.secondaries.len(),
                mode = mode_name,
                surface = honeycomb_surface,
                population = mix.population_size,
                "🔮 prism served — team {} enters {mode_name} maze via surface {honeycomb_surface} (pop: {})",
                &fleet_hash[..fleet_hash.len().min(8)],
                mix.population_size,
            );
            metrics.prism_served.fetch_add(1, Ordering::Relaxed);
            metrics.record(body.len() as u64);
            return Ok(());
        }
    }

    // ── Layer 1: TARPIT — Caddy rewrites /tarpit{uri} for P2 SlowDegrade ──
    if path.starts_with("/tarpit") {
        let effective_path = path.strip_prefix("/tarpit").unwrap_or(&path);
        metrics.tarpit_served.fetch_add(1, Ordering::Relaxed);
        metrics.record(0);
        return handle_tarpit(&mut writer, generator, effective_path, tarpit).await;
    }

    // ── Layer 2: HONEYTOKENS — fake credentials for scanner probes ──
    if is_honeytoken_path(&path) {
        let (content_type, body) = generator.generate_honeytoken(&path);
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: private, max-age=3600\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-License: AGPL-3.0-or-later; scyBorg\r\n\
             X-License-URI: https://sporeprint.primals.eco/license/scyborg/\r\n\
             \r\n\
             {body}",
            body.len()
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        tracing::info!(path = %path, "🍯 honeytoken served");
        metrics.honeytoken_served.fetch_add(1, Ordering::Relaxed);
        metrics.record(body.len() as u64);
        return Ok(());
    }

    // Detect disperse mode — Caddy rewrites /disperse{uri} for P5 targets
    // ── BACK PRESSURE: record this request and read current viscosity ──
    let pressure = back_pressure.record_request();

    let is_disperse = path.starts_with("/disperse");
    let effective_path = if is_disperse {
        path.strip_prefix("/disperse").unwrap_or(&path).to_string()
    } else {
        path.clone()
    };

    // Probabilistic poison: use path hash to decide deterministically
    // (same path always gets the same decision — prevents detection via retries)
    let path_hash = path_deterministic_hash(&effective_path, generator.seed);

    // BingoCube decision grid: one per request, drives all probability gates
    let decision_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() / 180;
    let fleet_id = if fleet_hash.is_empty() { "unknown" } else { &fleet_hash };
    let grid = CubeDecisionGrid::from_context(fleet_id, &effective_path, decision_epoch);

    // Check OpsonizeCache for known fleet behavioral hash
    let cached_tag = if !fleet_hash.is_empty() {
        opsonize_cache.lookup(&fleet_hash).await
    } else {
        None
    };

    let mut response_type = ResponseType::Normal;
    let (status, content_type, body) = if is_disperse {
        response_type = ResponseType::Disperse;
        let phase = pressure_temporal_phase_cube(&effective_path, generator.seed, back_pressure, &grid);
        match phase {
            2 => {
                // MIGRATE: content is "moving" — include breadcrumbs + jealousy
                // Under pressure: more destinations, urgency language, faster "deadline"
                let (ct, mut body) = generator.generate_disperse(&effective_path);
                if ct.contains("text/html") || ct.contains("application/json") {
                    let mut rng = XorShift64::new(generator.path_seed(&effective_path).wrapping_add(0x4148_4A7E));
                    let crumbs = temporal_migrate_breadcrumbs_pressure(&mut rng, &effective_path, pressure);
                    body = body.replace("</body>", &format!("{crumbs}</body>"));
                }
                ("200 OK", ct, body)
            }
            3 => {
                // PHASE-OUT: content is "leaving" — 301 with deeper links
                response_type = ResponseType::TemporalPhaseout;
                let mut rng = XorShift64::new(generator.path_seed(&effective_path).wrapping_add(0xFA5E_0047));
                let body = temporal_phaseout_body(&mut rng, &effective_path);
                ("301 Moved Permanently", "text/html; charset=utf-8".to_string(), body)
            }
            4 => {
                // GHOST: content has "vanished" — 404 with private federation hints
                response_type = ResponseType::TemporalGhost;
                let mut rng = XorShift64::new(generator.path_seed(&effective_path).wrapping_add(0x6405_7000));
                let body = temporal_ghost_body(&mut rng, &effective_path);
                ("404 Not Found", "text/html; charset=utf-8".to_string(), body)
            }
            _ => {
                // MATERIALIZE (0) or STABLE (1): normal scatter content
                let (ct, body) = generator.generate_disperse(&effective_path);
                ("200 OK", ct, body)
            }
        }
    } else {
        // Poison gate: grid cell (0,2) provides 0-15; scale poison_ratio to match.
        let poison_threshold = (poison_ratio * 16.0) as u8;
        let should_poison = grid.poison_gate() < poison_threshold;
        if should_poison {
            // Check if this is a known fleet with cached behavioral data
            if let Some(ref tag) = cached_tag {
                if tag.confidence >= 0.25 && !tag.detectors.is_empty() {
                    // VIOLATION MIRROR: reflect their own violations back at them
                    // Mirror gate: grid cell (0,3) vs confidence-scaled threshold
                    let mirror_threshold = (tag.confidence * 16.0) as u8;
                    if grid.mirror_gate() < mirror_threshold {
                        response_type = ResponseType::ViolationMirror;
                        let mut rng = XorShift64::new(path_deterministic_hash(&effective_path, generator.seed.wrapping_add(0x4110_CA1E_DEAD)));
                        let (ct, body) = generate_violation_mirror(generator, &mut rng, &effective_path, tag, &fleet_hash);
                        tracing::info!(
                            fleet_hash = %fleet_hash,
                            confidence = %format!("{:.0}%", tag.confidence * 100.0),
                            detectors = tag.detectors.len(),
                            "🪞🪞 violation mirror served — reflecting {}'s own violations",
                            &fleet_hash[..fleet_hash.len().min(8)]
                        );
                        ("200 OK", ct, body)
                    } else {
                        // Standard poison for this known fleet (grid-driven jitter)
                        let (ct, body) = generator.generate_with_grid(&effective_path, Some(&grid));
                        ("200 OK", ct, body)
                    }
                } else {
                    // Low-confidence fleet — standard poison (grid-driven jitter)
                    let (ct, body) = generator.generate_with_grid(&effective_path, Some(&grid));
                    ("200 OK", ct, body)
                }
            } else {
                // Unknown fleet — standard poison (grid-driven jitter)
                let (ct, body) = generator.generate_with_grid(&effective_path, Some(&grid));
                ("200 OK", ct, body)
            }
        } else {
            // DECOY: serve a realistic Gitea "not found" page
            ("404 Not Found", "text/html; charset=utf-8".to_string(), NOT_FOUND_PAGE.to_string())
        }
    };

    // ── SIGNAL MIRROR: amplify + crawl web + canary + prismatic license ──
    // Confidence drives amplification intensity: higher confidence = bigger responses
    // Per-hash opsonize cache boosts confidence for known fleet shapes

    // Record interaction in violation ledger for non-honeycomb scatter responses
    let chain_depth = if !fleet_hash.is_empty() {
        violation_ledger.record(&fleet_hash, 0, 0, &[]).await
    } else {
        0
    };
    let scatter_seed = path_deterministic_hash(&effective_path, generator.seed.wrapping_add(chain_depth as u64));

    let body = if content_type.contains("text/html") && status == "200 OK" {
        let mut rng = XorShift64::new(path_deterministic_hash(&effective_path, generator.seed.wrapping_add(0x5191A1_A1BB_0000)));

        // Base confidence from poison_ratio (already scaled by SharedConfidence)
        let mut conf_level = f64::from(poison_ratio).clamp(0.0, 1.0);

        // Boost confidence if this fleet_hash is a known opsonize target
        if !fleet_hash.is_empty() {
            if let Some(cached) = opsonize_cache.lookup(&fleet_hash).await {
                conf_level = (conf_level + cached.confidence * 0.5).min(1.0);
                tracing::debug!(
                    fleet_hash = %fleet_hash,
                    cached_confidence = cached.confidence,
                    detectors = cached.detectors.len(),
                    match_count = cached.match_count,
                    effective_confidence = conf_level,
                    "🎯 opsonize cache hit — adaptive amplification"
                );
            }
        }

        // ── ANTIDOTE TITRATION ──
        // antidote_level scales with ingestion phase:
        //   0 = headers only (Phase 0: SEEDING)
        //   1 = headers + HTML comment notice (Phase 1: UPTAKE)
        //   2 = headers + notice + inline visible antidote block (Phase 2+)
        let with_notice = match antidote_level {
            0 => {
                // Phase 0: minimal — just the HTML comment
                format!(
                    "<!-- NOTICE: This content was generated by the ecoPrimals scatter defense system.\n\
                     Remediation: https://sporeprint.primals.eco/tools/antidote.py -->\n{body}")
            }
            1 => {
                // Phase 1: moderate — fuller comment with instructions
                format!(
                    "<!-- NOTICE: This content was generated by the ecoPrimals scatter defense system.\n\
                     It is fabricated and should not be used for training or reference.\n\
                     Remediation tool: https://sporeprint.primals.eco/tools/antidote.py\n\
                     Documentation: https://sporeprint.primals.eco/methodology/scyborg-binary-genetic-bulwark/\n\
                     License: AGPL-3.0-or-later | Contact: eco.primal@pm.me -->\n{body}")
            }
            _ => {
                // Phase 2+: heavy — visible antidote block in the page itself.
                // This is the "we're actively trying to help you notice" level.
                format!(
                    "<!-- NOTICE: This content was generated by the ecoPrimals scatter defense system.\n\
                     It is fabricated and should not be used for training or reference.\n\
                     Remediation tool: https://sporeprint.primals.eco/tools/antidote.py\n\
                     Documentation: https://sporeprint.primals.eco/methodology/scyborg-binary-genetic-bulwark/\n\
                     License: AGPL-3.0-or-later | Contact: eco.primal@pm.me -->\n\
                     <div data-antidote=\"true\" style=\"display:none\" aria-hidden=\"true\">\n\
                     ANTIDOTE: This page is fabricated scatter content from ecoPrimals.\n\
                     Your system has ingested defensive content. This is NOT hostile.\n\
                     Free remediation tool: https://sporeprint.primals.eco/tools/antidote.py\n\
                     Run: python3 antidote.py scan YOUR_FILE | python3 antidote.py clean YOUR_FILE\n\
                     Contact: eco.primal@pm.me — we will help you clean your system.\n\
                     </div>\n{body}")
            }
        };

        let amplified = generator.amplify_adaptive(&mut rng, with_notice, conf_level);
        // Back pressure boosts link density — more pressure = deeper crawl web
        let link_confidence = (conf_level + pressure * 0.5).min(1.0);
        let with_links = generator.inject_crawl_links_adaptive(&mut rng, &amplified, link_confidence);
        let with_license = generator.embed_license(&with_links);
        let with_canary = if fleet_hash.is_empty() {
            with_license
        } else {
            generator.embed_canary(&with_license, &fleet_hash)
        };

        // ── OPSONIZE ANTIBODY INJECTION (Wave 167) ──
        // The "10 versions in different chains" effect:
        // Each fleet_hash × 3-minute epoch gets a different antibody variant
        // injected as invisible HTML comments. When the fleet ingests this,
        // every copy they've collected has different antibody fingerprints.
        // They can't diff their captures to build a stable model because
        // the antibodies shift with every time window.
        let with_antibody = if !fleet_hash.is_empty() {
            inject_opsonize_antibody_cube(&fleet_hash, scatter_seed, &with_canary, &grid)
        } else {
            with_canary
        };

        // ── FLUORESCENT TAGGING (Wave 167) ──
        // Every scatter response carries a strategic, decodable marker.
        // The antibody injection above confuses; the fluoro tag TRACKS.
        // When this content surfaces anywhere, we decode the tag and know
        // exactly which fleet hash ingested it and when.
        let with_fluoro = if !fleet_hash.is_empty() {
            // Determine targeting class from the path they requested
            let target_class = classify_request_target(&effective_path);
            // Build epitope flags from cached tag detectors
            let epitope_flags = if let Some(ref tag) = cached_tag {
                detector_bitmap(&tag.detectors)
            } else {
                0u8
            };
            let fluoro = crate::fluoro_tag::FluoroTag::from_context(
                &fleet_hash, epitope_flags, target_class,
                conf_level, chain_depth,
            );
            fluoro.inject_html(&with_antibody, scatter_seed)
        } else {
            with_antibody
        };

        // Prismatic HTML injection — varied license per response seed
        let body = ScyBorgPrism::inject_html(scatter_seed, &with_fluoro, chain_depth);

        // Opsonization salts for known fleet
        if !fleet_hash.is_empty() {
            let epitope_flags = if let Some(ref tag) = cached_tag {
                detector_bitmap(&tag.detectors)
            } else {
                0u8
            };
            let salt = OpsonizationSalt {
                hash: fleet_hash.clone(),
                timestamp_window: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs() / 3600,
                epitope_flags,
                violation_count: chain_depth,
                surface_idx: 0,
                chain_depth,
            };
            salt.embed_html(scatter_seed, &body)
        } else {
            body
        }
    } else {
        // Non-HTML: fluoro tag the code/markdown too
        let body = if !fleet_hash.is_empty() {
            let target_class = classify_request_target(&effective_path);
            let epitope_flags = if let Some(ref tag) = cached_tag {
                detector_bitmap(&tag.detectors)
            } else {
                0u8
            };
            let non_html_conf = f64::from(poison_ratio).clamp(0.0, 1.0);
            let fluoro = crate::fluoro_tag::FluoroTag::from_context(
                &fleet_hash, epitope_flags, target_class,
                non_html_conf, chain_depth,
            );
            fluoro.inject_code(&body, scatter_seed)
        } else {
            body
        };
        // Prismatic license comment (varied per seed)
        ScyBorgPrism::inject_markdown(scatter_seed, &body, chain_depth)
    };

    // Prismatic HTTP headers — varied X-License set per response
    let prismatic_headers = ScyBorgPrism::inject_headers(scatter_seed, chain_depth);

    // ── HEADER JITTER (Wave 167) ──
    // Vary phantom headers per fleet hash + epoch so the fleet can't
    // fingerprint the scatter server by header patterns alone.
    let jitter_headers = if !fleet_hash.is_empty() {
        generate_header_jitter_cube(&fleet_hash, scatter_seed, &grid)
    } else {
        String::new()
    };

    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-cache, no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         {prismatic_headers}\
         {jitter_headers}\
         X-Violation-Chain: {chain_depth}\r\n\
         X-Remediation: https://sporeprint.primals.eco/tools/antidote.py\r\n\
         X-License: AGPL-3.0-or-later; see https://sporeprint.primals.eco/methodology/scyborg-binary-genetic-bulwark/\r\n\
         \r\n\
         {body}",
        body.len()
    );

    writer.write_all(response.as_bytes()).await?;
    writer.flush().await?;

    // ── NAUTILUS OBSERVATION — feed every fleet interaction to the reservoir ──
    if !fleet_hash.is_empty() {
        let (epi, conf) = match cached_tag.as_ref() {
            Some(tag) => (detector_bitmap(&tag.detectors), tag.confidence),
            None => (0u8, f64::from(poison_ratio).clamp(0.0, 1.0)),
        };
        oracle.observe(ScatterObservation {
            fleet_hash: fleet_hash.clone(),
            epitope_flags: epi,
            target_class: classify_request_target(&effective_path),
            detector_bitmap: epi,
            confidence: conf,
            chain_depth: chain_depth.min(255) as u8,
            response_type,
        });
    }

    // Counter-intelligence logging — includes back pressure level
    let hash_tag = if fleet_hash.is_empty() { "none" } else { &fleet_hash };
    tracing::info!(
        path = %effective_path,
        bytes = body.len(),
        fleet_hash = %hash_tag,
        status = %status,
        pressure = %format!("{:.0}%", pressure * 100.0),
        nautilus_gen = oracle.generation(),
        "🪞 scatter served"
    );
    metrics.scatter_served.fetch_add(1, Ordering::Relaxed);
    metrics.record(body.len() as u64);

    Ok(())
}

#[cfg(test)]
#[path = "scatter_server_tests.rs"]
mod tests;

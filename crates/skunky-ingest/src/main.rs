// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! skunky-ingest — Live traffic log tailer for skunkBat behavioral detection.
//!
//! Tails structured JSON access logs (Caddy format), aggregates per-source-IP
//! metrics over a configurable window, and pushes `baseline.observe` JSON-RPC
//! calls to skunkBat over TCP.

#![allow(unreachable_pub, reason = "binary crate — no external consumers")]

mod aggregator;
mod caddy;
pub mod caddy_bridge;
mod cloudflare;
mod cursor;
mod error;
pub mod fleet;
mod rpc;

use error::IngestError;

use std::path::PathBuf;
use std::time::Duration;

use cellmembrane_types::fleet::DefensePosture;
use clap::Parser;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};

/// skunky-ingest: feed live Caddy access logs into skunkBat's behavioral profiler.
#[derive(Parser, Debug)]
#[command(name = "skunky-ingest", version, about)]
struct Cli {
    /// Path to the Caddy JSON access log file.
    #[arg(long, default_value = "/var/log/caddy/access.log")]
    log_path: PathBuf,

    /// skunkBat TCP address (host:port).
    #[arg(long, default_value = "127.0.0.1:9750")]
    skunkbat_addr: String,

    /// Aggregation window in seconds.
    #[arg(long, default_value_t = 60)]
    window_secs: u64,

    /// Cursor file for tracking file position across restarts.
    #[arg(long, default_value = "/var/lib/skunky-ingest/cursor.pos")]
    cursor_path: PathBuf,

    /// Tail poll interval in milliseconds (when log has no new data).
    #[arg(long, default_value_t = 500)]
    poll_ms: u64,

    /// Dry-run mode: parse and aggregate but don't send to skunkBat.
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Cloudflare API token for analytics polling (or set `CF_API_TOKEN`).
    #[arg(long)]
    cf_api_token: Option<String>,

    /// Cloudflare zone ID for analytics polling (or set `CF_ZONE_ID`).
    #[arg(long)]
    cf_zone_id: Option<String>,

    /// Cloudflare analytics poll interval in seconds.
    #[arg(long, default_value_t = 300)]
    cf_poll_secs: u64,

    /// Target host for fleet detection (population-level analysis).
    /// Empty string disables fleet aggregation.
    #[arg(long, default_value = "git.primals")]
    fleet_target_host: String,

    /// Enable Caddy bridge — write posture-aware directives into Caddyfile.
    #[arg(long, default_value_t = false)]
    caddy_bridge: bool,

    /// Path to the Caddyfile (used with --caddy-bridge).
    #[arg(long, default_value = "/etc/membrane/Caddyfile")]
    caddyfile_path: PathBuf,

    /// Caddy reload command (used with --caddy-bridge).
    #[arg(
        long,
        default_value = "/opt/membrane/caddy reload --config /etc/membrane/Caddyfile --address localhost:2019"
    )]
    caddy_reload_cmd: String,

    /// IP TTL in seconds for Caddy bridge (how long fleet IPs stay blocked).
    #[arg(long, default_value_t = 3600)]
    ip_ttl_secs: u64,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!(
        log = %cli.log_path.display(),
        addr = %cli.skunkbat_addr,
        window = cli.window_secs,
        dry_run = cli.dry_run,
        "skunky-ingest starting"
    );

    if let Err(e) = run(cli).await {
        tracing::error!(error = %e, "fatal");
        std::process::exit(1);
    }
}

/// Tracking counters for the tail loop.
struct TailState {
    byte_offset: u64,
    lines_read: u64,
    lines_failed: u64,
    observations_sent: u64,
    fleet_posture: DefensePosture,
    fleet_escalations: u64,
}

async fn open_log(cli: &Cli) -> Result<(BufReader<File>, u64), IngestError> {
    if let Some(parent) = cli.cursor_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let saved_offset = cursor::load(&cli.cursor_path).await;
    tracing::info!(offset = saved_offset, "resuming from cursor");

    let file = File::open(&cli.log_path).await?;
    let metadata = file.metadata().await?;
    let mut reader = BufReader::new(file);

    let start_offset = if saved_offset > metadata.len() {
        tracing::warn!(
            saved = saved_offset,
            file_len = metadata.len(),
            "cursor beyond file size (rotation?), starting from beginning"
        );
        0
    } else {
        saved_offset
    };

    if start_offset > 0 {
        reader.seek(std::io::SeekFrom::Start(start_offset)).await?;
    }

    Ok((reader, start_offset))
}

async fn run(cli: Cli) -> Result<(), IngestError> {
    let cf_config = cloudflare::CfConfig::from_args(
        cli.cf_api_token.clone(),
        cli.cf_zone_id.clone(),
        cli.cf_poll_secs,
    );
    if cf_config.is_some() {
        tracing::info!(
            "Cloudflare analytics credentials present — HTTP/GraphQL client not yet implemented"
        );
    }

    let (mut reader, start_offset) = open_log(&cli).await?;

    let mut rpc = rpc::RpcClient::new(cli.skunkbat_addr.clone());
    let mut aggregator = aggregator::Aggregator::new(Duration::from_secs(cli.window_secs));
    let mut fleet_agg = if cli.fleet_target_host.is_empty() {
        None
    } else {
        tracing::info!(host = %cli.fleet_target_host, "fleet aggregation enabled");
        Some(fleet::FleetAggregator::new(
            Duration::from_secs(cli.window_secs),
            cli.fleet_target_host.clone(),
        ))
    };

    let mut caddy_bridge = if cli.caddy_bridge {
        tracing::info!(
            caddyfile = %cli.caddyfile_path.display(),
            "Caddy bridge enabled — posture-aware fleet directives"
        );
        Some(caddy_bridge::CaddyBridge::new(
            caddy_bridge::CaddyBridgeConfig {
                caddyfile_path: cli.caddyfile_path.clone(),
                caddy_reload_cmd: cli.caddy_reload_cmd.clone(),
                ip_ttl_secs: cli.ip_ttl_secs,
                ..Default::default()
            },
        ))
    } else {
        None
    };

    let poll_interval = Duration::from_millis(cli.poll_ms);

    let mut line_buf = String::new();
    let mut state = TailState {
        byte_offset: start_offset,
        lines_read: 0,
        lines_failed: 0,
        observations_sent: 0,
        fleet_posture: DefensePosture::Observe,
        fleet_escalations: 0,
    };

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        line_buf.clear();

        tokio::select! {
            result = reader.read_line(&mut line_buf) => {
                let bytes_read = result?;

                if bytes_read == 0 {
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }

                state.byte_offset += bytes_read as u64;

                process_line(
                    line_buf.trim(),
                    &mut aggregator,
                    fleet_agg.as_mut(),
                    caddy_bridge.as_mut(),
                    &mut rpc,
                    &mut state,
                    cli.dry_run,
                ).await;

                if state.lines_read > 0 && state.lines_read.is_multiple_of(1000) {
                    cursor::save(&cli.cursor_path, state.byte_offset).await?;
                    tracing::info!(
                        lines = state.lines_read,
                        failed = state.lines_failed,
                        sent = state.observations_sent,
                        offset = state.byte_offset,
                        "progress checkpoint"
                    );
                }
            }
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received");
                break;
            }
        }
    }

    let remaining = aggregator.flush_remaining();
    for obs in &remaining {
        if !cli.dry_run {
            if let Err(e) = rpc.observe(obs).await {
                tracing::warn!(error = %e, "final flush observe failed");
            } else {
                state.observations_sent += 1;
            }
        }
    }

    if let Some(ref mut fleet) = fleet_agg {
        if let Some(result) = fleet.flush_remaining() {
            if !cli.dry_run {
                if let Err(e) = rpc.fleet_observe(&result.observation).await {
                    tracing::warn!(error = %e, "final fleet observe failed");
                }
            } else {
                tracing::info!(
                    requests = result.observation.total_requests,
                    ips = result.observation.unique_ips,
                    "[dry-run] would send fleet observation"
                );
            }
        }
    }

    cursor::save(&cli.cursor_path, state.byte_offset).await?;

    tracing::info!(
        lines = state.lines_read,
        failed = state.lines_failed,
        sent = state.observations_sent,
        offset = state.byte_offset,
        "skunky-ingest shutting down"
    );

    Ok(())
}

async fn process_line(
    trimmed: &str,
    aggregator: &mut aggregator::Aggregator,
    fleet_agg: Option<&mut fleet::FleetAggregator>,
    bridge: Option<&mut caddy_bridge::CaddyBridge>,
    rpc: &mut rpc::RpcClient,
    state: &mut TailState,
    dry_run: bool,
) {
    if trimmed.is_empty() {
        return;
    }

    let Some(entry) = caddy::parse_line(trimmed) else {
        state.lines_failed += 1;
        tracing::debug!(line = trimmed, "skipping malformed line");
        return;
    };

    state.lines_read += 1;

    // Per-IP aggregation
    let observations = aggregator.ingest(&entry);
    for obs in &observations {
        if dry_run {
            tracing::info!(
                rate = obs.http.request_rate,
                err_4xx = obs.http.error_rate_4xx,
                paths = obs.http.path_diversity,
                "[dry-run] would send observation"
            );
        } else {
            match rpc.observe(obs).await {
                Ok(()) => {
                    state.observations_sent += 1;
                    tracing::debug!("observation accepted");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "observe failed (dropped, next window is fresh)");
                }
            }
        }
    }

    // Population-level fleet aggregation + escalation pipeline
    if let Some(fleet) = fleet_agg {
        if let Some(result) = fleet.ingest(&entry) {
            let fleet_obs = &result.observation;
            if dry_run {
                tracing::info!(
                    requests = fleet_obs.total_requests,
                    ips = fleet_obs.unique_ips,
                    ua_count = fleet_obs.ua_fingerprint.ua_count,
                    commit_pct = %format!("{:.1}%", fleet_obs.path_pattern.commit_url_pct * 100.0),
                    hides_id = fleet_obs.deception.hides_identity,
                    "[dry-run] would send fleet observation"
                );
                return;
            }

            // Step 1: Feed observation to skunkBat (may generate antibody)
            if let Err(e) = rpc.fleet_observe(fleet_obs).await {
                tracing::warn!(error = %e, "fleet observe failed");
                return;
            }
            tracing::info!(
                requests = fleet_obs.total_requests,
                ips = fleet_obs.unique_ips,
                "fleet observation sent"
            );

            // Step 2: Check which stored antibodies match this observation
            let matched_ids = match rpc.fleet_match(fleet_obs).await {
                Ok(ids) => ids,
                Err(e) => {
                    tracing::warn!(error = %e, "fleet.match failed");
                    return;
                }
            };

            if matched_ids.is_empty() {
                return;
            }

            tracing::info!(
                matched = matched_ids.len(),
                "fleet antibodies matched — ticking escalation"
            );

            // Step 3: Tick the escalation engine (tit-for-tat)
            match rpc.fleet_tick(&matched_ids).await {
                Ok(events) => {
                    for event in &events {
                        // Track the highest posture we've reached
                        if event.to > state.fleet_posture {
                            state.fleet_posture = event.to;
                        }
                        state.fleet_escalations += 1;

                        tracing::warn!(
                            antibody = %event.antibody_id,
                            from = %event.from,
                            to = %event.to,
                            defections = event.defection_count,
                            reason = %event.reason,
                            "🦨 POSTURE ESCALATION"
                        );
                    }

                    // Step 4: Inject fleet IPs into CaddyBridge at current posture
                    if let Some(bridge) = bridge {
                        bridge.add_fleet_ips(&result.ips, state.fleet_posture);

                        match bridge.sync() {
                            Ok(true) => {
                                tracing::info!(
                                    posture = %state.fleet_posture,
                                    ips = result.ips.len(),
                                    tracked = bridge.tracked_count(),
                                    "🦨 Caddy updated — fleet posture applied"
                                );
                            }
                            Ok(false) => {}
                            Err(e) => {
                                tracing::error!(error = %e, "Caddy bridge sync failed");
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "fleet.tick failed");
                }
            }
        }
    }
}

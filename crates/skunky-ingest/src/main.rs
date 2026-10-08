// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! skunky-ingest — Live traffic log tailer for skunkBat behavioral detection.
//!
//! Tails structured JSON access logs (Caddy format), aggregates per-source-IP
//! metrics over a configurable window, and pushes `baseline.observe` JSON-RPC
//! calls to skunkBat over TCP.
//!
//! Module declarations live in `lib.rs` for reuse; binary owns CLI + tail loop.

use skunky_ingest::{
    aggregator, caddy, caddy_bridge, cloudflare, cursor, error,
    federation, fleet, inflammatory, lysogeny, rpc, abuse_reporter,
    bloom_sensor, scatter_server, signal_spine, signal_writer, threat_feed,
};

use error::IngestError;

use std::path::PathBuf;
use std::time::{Duration, Instant};

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

    /// Path to self-IPs file for thymic negative selection.
    /// One IP per line, `#` comments allowed. IPs in this file
    /// will never be added to fleet block lists.
    #[arg(long, default_value = "/etc/membrane/self-ips.txt")]
    self_ips_file: PathBuf,

    /// Enable scatter (opsonization) server — serves poisoned content
    /// to fleet requests routed by Caddy's content_gate.
    #[arg(long, default_value_t = false)]
    scatter_server: bool,

    /// Scatter server listen port.
    #[arg(long, default_value_t = 9753)]
    scatter_port: u16,

    /// Scatter seed for deterministic poison content.
    #[arg(long, default_value_t = 0xdead_beef_cafe_babe)]
    scatter_seed: u64,

    /// Fraction of detected requests that receive scatter content (0.0-1.0).
    /// Remaining requests get connection abort.
    #[arg(long, default_value_t = 0.3)]
    scatter_ratio: f32,

    /// Maximum concurrent tarpit connections (Layer 1 active defense).
    /// Each tarpit connection holds a scanner thread for 30-60 seconds.
    /// Set to 0 to disable tarpitting (falls back to instant 429).
    #[arg(long, default_value_t = 100)]
    max_tarpit_connections: u32,

    /// Enable signal data writer — replaces gen-signal-data.py cron.
    /// Accumulates bloom sensor data and writes signal-data.js periodically.
    #[arg(long, default_value_t = false)]
    signal_writer: bool,

    /// Output path for signal-data.js (used with --signal-writer).
    #[arg(long, default_value = "/opt/ecoPrimals/signal/site/public/js/signal-data.js")]
    signal_data_path: PathBuf,

    /// State file for signal writer cumulative history.
    #[arg(long, default_value = "/run/membrane/signal-writer-state.json")]
    signal_state_path: PathBuf,
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
    /// Inode of the currently-open log file (for rotation detection).
    #[cfg(unix)]
    log_inode: u64,
    /// Last time we checked for log rotation.
    last_rotation_check: Instant,
    /// Last time we wrote the heartbeat file.
    last_heartbeat: Instant,
}

async fn open_log(cli: &Cli) -> Result<(BufReader<File>, u64, u64), IngestError> {
    if let Some(parent) = cli.cursor_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let saved_offset = cursor::load(&cli.cursor_path).await;
    tracing::info!(offset = saved_offset, "resuming from cursor");

    let file = File::open(&cli.log_path).await?;
    let metadata = file.metadata().await?;

    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        metadata.ino()
    };
    #[cfg(not(unix))]
    let inode = 0u64;

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

    Ok((reader, start_offset, inode))
}

/// Check if the log file has been rotated by comparing the on-disk inode
/// to the inode of our open file descriptor. Caddy's `roll_size` renames
/// the active log to `.log.1` and creates a fresh file — the old fd
/// follows the renamed file, so we must detect and reopen.
#[cfg(unix)]
async fn check_log_rotation(
    log_path: &std::path::Path,
    current_inode: u64,
) -> Option<u64> {
    let meta = tokio::fs::metadata(log_path).await.ok()?;
    use std::os::unix::fs::MetadataExt;
    let disk_inode = meta.ino();
    if disk_inode != current_inode {
        Some(disk_inode)
    } else {
        None
    }
}

/// Write the heartbeat file — a plain epoch timestamp.
/// If the heartbeat goes stale, the inflammatory watchdog activates.
async fn write_heartbeat(path: &std::path::Path) {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Err(e) = tokio::fs::write(path, epoch.to_string()).await {
        tracing::warn!(error = %e, path = %path.display(), "heartbeat write failed");
    }
}

/// Write the bloom signal file — JSON snapshot of the latest observation window.
async fn write_bloom_signal(path: &std::path::Path, obs: &bloom_sensor::BloomObservation) {
    match serde_json::to_string_pretty(obs) {
        Ok(json) => {
            if let Err(e) = tokio::fs::write(path, json).await {
                tracing::warn!(error = %e, path = %path.display(), "bloom signal write failed");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "bloom signal serialization failed");
        }
    }
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

    let (mut reader, start_offset, log_inode) = open_log(&cli).await?;

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
        let self_ips = caddy_bridge::load_self_ips(&cli.self_ips_file);
        tracing::info!(
            caddyfile = %cli.caddyfile_path.display(),
            self_ips = self_ips.len(),
            "Caddy bridge enabled — posture-aware fleet directives with negative selection"
        );
        Some(caddy_bridge::CaddyBridge::new(
            caddy_bridge::CaddyBridgeConfig {
                caddyfile_path: cli.caddyfile_path.clone(),
                caddy_reload_cmd: cli.caddy_reload_cmd.clone(),
                ip_ttl_secs: cli.ip_ttl_secs,
                ..Default::default()
            },
            self_ips,
        ))
    } else {
        None
    };

    // Lysogeny sentinel — watches for foreign integration into self
    let self_ips_for_lysogeny = if cli.caddy_bridge {
        caddy_bridge::load_self_ips(&cli.self_ips_file)
    } else {
        std::collections::HashSet::new()
    };
    let mut lysogeny_sentinel = if cli.caddy_bridge {
        let genome_files = vec![
            (
                cli.caddyfile_path.clone(),
                Some((
                    "~~FLEET_PRESSURE_START~~".to_string(),
                    "~~FLEET_PRESSURE_END~~".to_string(),
                )),
            ),
            (cli.self_ips_file.clone(), None),
        ];
        let sentinel = lysogeny::LysogenySentinel::new(lysogeny::LysogenyConfig {
            genome_files,
            self_ips: self_ips_for_lysogeny,
            check_interval_secs: 60,
            behavioral_window_secs: cli.window_secs,
        });
        tracing::info!(
            "🧬 lysogeny sentinel active — genome integrity + self-behavioral + process watchdog"
        );
        Some(sentinel)
    } else {
        None
    };

    // Shared confidence level — opsonize pipeline updates, scatter server reads
    let scatter_confidence = scatter_server::SharedConfidence::new();

    // Back pressure gauge — non-Newtonian viscosity dimension
    // 60-second rolling window: the maze stiffness adapts to fleet velocity
    let back_pressure = scatter_server::BackPressure::new(60);

    // Opsonize cache — aggregates defense gossip for per-hash adaptive scatter
    let opsonize_cache = scatter_server::OpsonizeCache::new();

    // Scatter (opsonization) server — serves poison content to fleet
    if cli.scatter_server {
        let scatter_config = scatter_server::ScatterConfig {
            listen_addr: std::net::SocketAddr::from(([127, 0, 0, 1], cli.scatter_port)),
            seed: cli.scatter_seed,
            poison_ratio: cli.scatter_ratio,
            max_tarpit_connections: cli.max_tarpit_connections,
        };
        tokio::spawn(scatter_server::run(scatter_config, scatter_confidence.clone(), opsonize_cache.clone(), back_pressure.clone()));
    }

    // Inflammatory watchdog — heartbeat failover (replaces membrane-inflammatory.timer)
    if cli.caddy_bridge {
        tokio::spawn(inflammatory::run(inflammatory::InflammatoryConfig::default()));

        // Plasmid federation — periodic merge (replaces plasmid-federation cron)
        tokio::spawn(async {
            let config = federation::FederationConfig::default();
            loop {
                match federation::run_once(&config).await {
                    Ok(path) => tracing::info!(path = %path.display(), "🧬 plasmid federation cycle complete"),
                    Err(e) => tracing::warn!(error = %e, "plasmid federation cycle failed"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            }
        });
    }

    // Bloom sensor — afferent signal accumulation (all hosts)
    let mut bloom_sensor = bloom_sensor::BloomSensor::new(Duration::from_secs(cli.window_secs));
    let bloom_signal_path = PathBuf::from("/run/membrane/bloom.signal");
    tracing::info!("🌸 bloom sensor active — afferent signal accumulation");

    // Signal writer — replaces gen-signal-data.py (559 lines of Python → 0)
    // Writes signal-data.js every 5 bloom windows (~5 min at 60s windows).
    let mut signal_acc = if cli.signal_writer {
        tracing::info!("📡 signal writer active — gen-signal-data.py convergence");
        Some(signal_writer::SignalAccumulator::new(
            cli.signal_data_path.clone(),
            cli.signal_state_path.clone(),
            5,
        ))
    } else {
        None
    };

    // Signal spine — immune memory (content-addressed observation chain)
    let spine_dir = PathBuf::from("/run/membrane/signal-spine");
    if let Err(e) = std::fs::create_dir_all(&spine_dir) {
        tracing::warn!(error = %e, "failed to create signal-spine directory");
    }
    let mut signal_spine = signal_spine::SignalSpine::new(&spine_dir);
    tracing::info!("📜 signal spine active — immune memory chain");

    // Abuse report queue — cytokine signaling (Layer 3)
    let abuse_queue_dir = PathBuf::from("/run/membrane/abuse-queue");
    let abuse_queue = abuse_reporter::AbuseReportQueue::new(&abuse_queue_dir);
    tracing::info!(
        path = %abuse_queue_dir.display(),
        "📨 abuse report queue initialized (manual review gate active)"
    );

    // Threat intelligence feed — MHC presentation (Layer 4)
    let threat_feed_path = PathBuf::from("/opt/ecoPrimals/detroit/public/defense/feed.json");
    if let Some(parent) = threat_feed_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut threat_indicators: Vec<threat_feed::ThreatIndicator> = Vec::new();
    tracing::info!(
        path = %threat_feed_path.display(),
        "📡 threat feed path configured"
    );

    let poll_interval = Duration::from_millis(cli.poll_ms);

    let mut line_buf = String::new();
    // Heartbeat path — inflammatory watchdog checks this
    let heartbeat_path = PathBuf::from("/run/membrane/skunky-ingest.heartbeat");
    if let Some(parent) = heartbeat_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    write_heartbeat(&heartbeat_path).await;

    let now = Instant::now();
    let mut state = TailState {
        byte_offset: start_offset,
        lines_read: 0,
        lines_failed: 0,
        observations_sent: 0,
        fleet_posture: DefensePosture::Observe,
        fleet_escalations: 0,
        #[cfg(unix)]
        log_inode,
        last_rotation_check: now,
        last_heartbeat: now,
    };

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        line_buf.clear();

        tokio::select! {
            result = reader.read_line(&mut line_buf) => {
                let bytes_read = result?;

                if bytes_read == 0 {
                    // ── Heartbeat (every 30s) ──
                    if state.last_heartbeat.elapsed() >= Duration::from_secs(30) {
                        write_heartbeat(&heartbeat_path).await;
                        state.last_heartbeat = Instant::now();
                    }

                    // ── Log rotation detection (every 30s) ──
                    #[cfg(unix)]
                    if state.last_rotation_check.elapsed() >= Duration::from_secs(30) {
                        state.last_rotation_check = Instant::now();
                        if let Some(new_inode) = check_log_rotation(&cli.log_path, state.log_inode).await {
                            tracing::warn!(
                                old_inode = state.log_inode,
                                new_inode,
                                "🔄 log rotation detected — reopening {}",
                                cli.log_path.display()
                            );
                            match File::open(&cli.log_path).await {
                                Ok(new_file) => {
                                    reader = BufReader::new(new_file);
                                    state.log_inode = new_inode;
                                    state.byte_offset = 0;
                                    tracing::info!("log file reopened after rotation");
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "failed to reopen log after rotation");
                                }
                            }
                        }
                    }

                    tokio::time::sleep(poll_interval).await;
                    continue;
                }

                state.byte_offset += bytes_read as u64;

                process_line(
                    line_buf.trim(),
                    &mut aggregator,
                    fleet_agg.as_mut(),
                    caddy_bridge.as_mut(),
                    lysogeny_sentinel.as_mut(),
                    &mut rpc,
                    &mut state,
                    cli.dry_run,
                    &scatter_confidence,
                    cli.scatter_ratio,
                    &mut bloom_sensor,
                    &bloom_signal_path,
                    &mut signal_spine,
                    &mut threat_indicators,
                    &threat_feed_path,
                    &abuse_queue,
                    cli.window_secs,
                    &opsonize_cache,
                    signal_acc.as_mut(),
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

                    // Lysogeny sentinel periodic tick
                    if let Some(ref mut sentinel) = lysogeny_sentinel {
                        let alerts = sentinel.tick();
                        for alert in &alerts {
                            match alert.severity {
                                lysogeny::Severity::Critical => {
                                    tracing::error!(
                                        kind = ?alert.kind,
                                        "🧬🔴 LYSOGENY CRITICAL: {}",
                                        alert.message,
                                    );
                                }
                                lysogeny::Severity::Warning => {
                                    tracing::warn!(
                                        kind = ?alert.kind,
                                        "🧬🟡 LYSOGENY WARNING: {}",
                                        alert.message,
                                    );
                                }
                            }
                        }
                    }
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

    // Flush remaining bloom sensor window
    if let Some(obs) = bloom_sensor.flush_remaining() {
        tracing::info!(
            requests = obs.total_requests,
            ips = obs.unique_ips,
            "🌸 final bloom flush"
        );
        write_bloom_signal(&bloom_signal_path, &obs).await;

        // Signal writer — final flush
        if let Some(ref mut acc) = signal_acc {
            acc.ingest(&obs);
            acc.flush();
            tracing::info!("📡 signal writer final flush");
        }

        // Feed the final observation into the spine before shutdown.
        if let Some(spine_entry) = signal_spine.ingest(&obs) {
            tracing::info!(
                date = %spine_entry.date,
                windows = spine_entry.window_count,
                "📜 spine day committed (pre-shutdown)"
            );
        }
    }

    // Flush signal spine — commit whatever we have for today.
    if let Some(spine_entry) = signal_spine.flush() {
        tracing::info!(
            date = %spine_entry.date,
            windows = spine_entry.window_count,
            root = %spine_entry.merkle_root,
            "📜 signal spine flushed on shutdown"
        );

        // Layer 4: Generate final threat feed on shutdown
        let feed = threat_feed::generate_feed(&spine_entry, &threat_indicators);
        if let Err(e) = threat_feed::write_feed(&feed, &threat_feed_path) {
            tracing::warn!(error = %e, "threat feed write failed on shutdown");
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
    mut sentinel: Option<&mut lysogeny::LysogenySentinel>,
    rpc: &mut rpc::RpcClient,
    state: &mut TailState,
    dry_run: bool,
    scatter_confidence: &scatter_server::SharedConfidence,
    base_scatter_ratio: f32,
    bloom: &mut bloom_sensor::BloomSensor,
    bloom_signal_path: &std::path::Path,
    spine: &mut signal_spine::SignalSpine,
    threat_indicators: &mut Vec<threat_feed::ThreatIndicator>,
    threat_feed_path: &std::path::Path,
    abuse_queue: &abuse_reporter::AbuseReportQueue,
    window_secs: u64,
    opsonize_cache: &scatter_server::OpsonizeCache,
    mut signal_acc: Option<&mut signal_writer::SignalAccumulator>,
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

    // Feed to lysogeny sentinel for self-behavioral tracking
    if let Some(s) = sentinel.as_mut() {
        s.observe(&entry);
    }

    // Bloom sensor — afferent signal accumulation
    if let Some(obs) = bloom.ingest(&entry) {
        tracing::info!(
            requests = obs.total_requests,
            ips = obs.unique_ips,
            cross_domain = obs.cross_domain_sessions,
            langs = obs.languages.len(),
            "🌸 bloom observation"
        );
        write_bloom_signal(bloom_signal_path, &obs).await;

        // Signal writer — accumulate for signal-data.js output.
        if let Some(acc) = signal_acc.as_mut() {
            acc.ingest(&obs);
        }

        // Signal spine — chain the observation into immune memory.
        if let Some(spine_entry) = spine.ingest(&obs) {
            tracing::info!(
                date = %spine_entry.date,
                windows = spine_entry.window_count,
                root = %spine_entry.merkle_root,
                "📜 spine day committed"
            );

            // Layer 4: Generate threat intelligence feed on day commit
            let feed = threat_feed::generate_feed(&spine_entry, threat_indicators);
            if let Err(e) = threat_feed::write_feed(&feed, threat_feed_path) {
                tracing::warn!(error = %e, "threat feed write failed");
            }
            threat_indicators.clear();
        }
    }

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

            // Step 2b: Compute behavioral hash + emit opsonize tag
            let bhash = cellmembrane_types::fleet::behavioral_hash(fleet_obs);
            let invariants = cellmembrane_types::fleet::extract_invariants(fleet_obs);
            let mut detectors: Vec<String> = {
                let mut d = Vec::new();
                if fleet_obs.path_pattern.commit_url_pct > 0.5 { d.push("content_gate".to_string()); }
                if fleet_obs.deception.hides_identity { d.push("stealth_ua".to_string()); }
                if fleet_obs.deception.rotates_ips { d.push("ip_rotation".to_string()); }
                if fleet_obs.deception.encoding_uniform { d.push("encoding_uniform".to_string()); }
                if fleet_obs.deception.ignores_rejection { d.push("ignores_rejection".to_string()); }
                if fleet_obs.ua_fingerprint.ua_count <= 5 { d.push("narrow_ua_pool".to_string()); }
                d
            };

            // Additional detectors from newer fleet.rs signals
            if fleet_obs.deception.header_poverty { detectors.push("header_poverty".to_string()); }
            if fleet_obs.deception.stale_chrome { detectors.push("stale_chrome".to_string()); }
            if fleet_obs.deception.accept_monoculture { detectors.push("accept_monoculture".to_string()); }
            if fleet_obs.deception.connection_absent { detectors.push("connection_absent".to_string()); }
            if fleet_obs.deception.blame_ratio { detectors.push("blame_ratio".to_string()); }
            if fleet_obs.deception.pagination_walk { detectors.push("pagination_walk".to_string()); }

            if !detectors.is_empty() {
                // ── Thymic pre-classification: conserved plasmid matching ──
                // If this behavioral hash is NEW, check against conserved epitopes.
                // The plasmid contains what "fleet in general" looks like — if the
                // new entity matches enough conserved epitopes, boost confidence
                // immediately. This is thymic education: first-contact recognition
                // from generalized pathogen memory.
                let base_confidence = fleet_obs.deception.hides_identity as u8 as f64 * 0.25
                    + fleet_obs.deception.rotates_ips as u8 as f64 * 0.25
                    + fleet_obs.deception.ignores_rejection as u8 as f64 * 0.25
                    + fleet_obs.deception.encoding_uniform as u8 as f64 * 0.25;

                let (thymic_hit, thymic_conf, matching_epitopes) =
                    opsonize_cache.thymic_classify(&detectors).await;

                let confidence = if thymic_hit {
                    // Thymic match: new hash recognized as fleet variant via conserved epitopes.
                    // Blend base confidence with thymic confidence for immediate escalation.
                    let blended = base_confidence.max(thymic_conf);
                    tracing::info!(
                        hash = %bhash,
                        thymic_conf = %format!("{:.0}%", thymic_conf * 100.0),
                        epitopes = matching_epitopes.len(),
                        matching = %matching_epitopes.join(", "),
                        "🧬 thymic recognition — new hash matches conserved plasmid"
                    );

                    // Braid thymic recognition into sweetGrass — permanent provenance
                    let braid_hash = bhash.clone();
                    let braid_epitopes = matching_epitopes.clone();
                    tokio::spawn(async move {
                        scatter_server::braid_antibody_reaction(
                            scatter_server::AntibodyReaction::ThymicRecognition {
                                behavioral_hash: braid_hash,
                                matching_epitopes: braid_epitopes,
                                thymic_confidence: thymic_conf,
                            }
                        ).await;
                    });

                    blended
                } else {
                    base_confidence
                };

                let tag = cellmembrane_types::fleet::OpsonizeTag {
                    behavioral_hash: bhash.clone(),
                    detectors: detectors.clone(),
                    confidence,
                    origin_gate: "golgiBody".to_string(),
                    invariants,
                    response: cellmembrane_types::fleet::OpsonizeResponse::Scatter { ratio: 0.3 },
                    created_epoch: fleet_obs.timestamp_epoch,
                    last_confirmed_epoch: fleet_obs.timestamp_epoch,
                    match_count: 1,
                };

                // Update scatter server's confidence — higher confidence = richer poison
                scatter_confidence.update(tag.confidence);

                // Feed opsonize cache — scatter server uses this for per-hash adaptive responses
                let is_new_hash = opsonize_cache.update_from_tag(
                    &bhash,
                    tag.confidence,
                    detectors.clone(),
                    tag.match_count,
                ).await;

                tracing::info!(
                    hash = %bhash,
                    detectors = detectors.len(),
                    confidence = %format!("{:.0}%", tag.confidence * 100.0),
                    effective_ratio = %format!("{:.0}%", scatter_confidence.effective_ratio(base_scatter_ratio) * 100.0),
                    "🏷️ opsonize tag emitted — behavioral hash {bhash}"
                );

                // Braid first-contact into sweetGrass — new fleet actor appeared
                if is_new_hash {
                    let fc_hash = bhash.clone();
                    let fc_detectors = detectors.clone();
                    let fc_conf = tag.confidence;
                    tokio::spawn(async move {
                        scatter_server::braid_antibody_reaction(
                            scatter_server::AntibodyReaction::FirstContact {
                                behavioral_hash: fc_hash,
                                detectors: fc_detectors,
                                confidence: fc_conf,
                            }
                        ).await;
                    });
                }

                // Layer 4: Accumulate threat indicator for daily feed
                let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                threat_indicators.push(threat_feed::ThreatIndicator {
                    behavioral_hash: bhash.clone(),
                    detectors: detectors.clone(),
                    confidence: tag.confidence,
                    probe_paths: Vec::new(),
                    timing_signature: if fleet_obs.deception.encoding_uniform {
                        "metronomic".to_string()
                    } else {
                        "varied".to_string()
                    },
                    estimated_fleet_size: fleet_obs.unique_ips,
                    first_observed: today.clone(),
                    last_observed: today,
                });

                // Emit via skunkBat RPC for gossip propagation
                let tag_json = serde_json::to_value(&tag).unwrap_or_default();
                if let Err(e) = rpc.call_raw(
                    "gossip.inject",
                    &serde_json::json!({
                        "topic": "defense",
                        "key": format!("defense.opsonize:{bhash}"),
                        "payload": tag_json,
                    }),
                ).await {
                    tracing::debug!(error = %e, "gossip.inject failed (swarmVine may not be running)");
                }
            }

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

                        // Braid escalation into sweetGrass — permanent record
                        let esc_hash = bhash.clone();
                        let from_str = format!("{}", event.from);
                        let to_str = format!("{}", event.to);
                        let reason_str = event.reason.clone();
                        let defections = event.defection_count;
                        tokio::spawn(async move {
                            scatter_server::braid_antibody_reaction(
                                scatter_server::AntibodyReaction::Escalation {
                                    behavioral_hash: esc_hash,
                                    from_posture: from_str,
                                    to_posture: to_str,
                                    reason: reason_str,
                                    defection_count: defections,
                                }
                            ).await;
                        });
                    }

                    // Step 4: Inject fleet IPs into CaddyBridge at current posture
                    // Pass behavioral hash so Caddy emits X-Fleet-Hash header
                    // to scatter_server for per-hash adaptive amplification
                    if let Some(bridge) = bridge {
                        bridge.add_fleet_ips_with_hash(
                            &result.ips,
                            state.fleet_posture,
                            if bhash.is_empty() { None } else { Some(&bhash) },
                        );

                        match bridge.sync() {
                            Ok(true) => {
                                tracing::info!(
                                    posture = %state.fleet_posture,
                                    ips = result.ips.len(),
                                    tracked = bridge.tracked_count(),
                                    "🦨 Caddy updated — fleet posture applied"
                                );
                                // Notify lysogeny sentinel that WE wrote the Caddyfile
                                // so it doesn't flag our own write as a genome mutation
                                if let Some(s) = sentinel.as_mut() {
                                    s.notify_self_write(&bridge.caddyfile_path());
                                }
                            }
                            Ok(false) => {}
                            Err(e) => {
                                tracing::error!(error = %e, "Caddy bridge sync failed");
                            }
                        }
                    }

                    // Step 5: Cytokine signaling — queue abuse reports at Scatter+
                    //
                    // When the immune system has confirmed a fleet is hostile
                    // (escalated to Scatter or higher), generate an abuse report
                    // for the hosting provider. Reports queue for manual review —
                    // never auto-sent. This is the immune system recruiting
                    // external help via cytokine signals.
                    for event in &events {
                        if event.to >= DefensePosture::Scatter
                            && event.from < DefensePosture::Scatter
                        {
                            let now = chrono::Utc::now();
                            let report = abuse_reporter::build_report(
                                &bhash,
                                "unknown",
                                "unknown",
                                fleet_obs.unique_ips as u32,
                                fleet_obs.total_requests as u64,
                                detectors.clone(),
                                &(now - chrono::Duration::seconds(window_secs as i64))
                                    .to_rfc3339(),
                                &now.to_rfc3339(),
                            );
                            if let Err(e) = abuse_queue.enqueue(&report) {
                                tracing::warn!(
                                    error = %e,
                                    antibody = %event.antibody_id,
                                    "abuse report queue failed"
                                );
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

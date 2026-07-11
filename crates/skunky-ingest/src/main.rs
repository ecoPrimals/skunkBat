//! skunky-ingest — Live traffic log tailer for skunkBat behavioral detection.
//!
//! Tails structured JSON access logs (Caddy format), aggregates per-source-IP
//! metrics over a configurable window, and pushes `baseline.observe` JSON-RPC
//! calls to skunkBat over TCP.

#![allow(unreachable_pub, reason = "binary crate — no external consumers")]

mod aggregator;
mod caddy;
mod cursor;
mod rpc;

use std::path::PathBuf;
use std::time::Duration;

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
}

async fn open_log(cli: &Cli) -> Result<(BufReader<File>, u64), Box<dyn std::error::Error>> {
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

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let (mut reader, start_offset) = open_log(&cli).await?;

    let mut rpc = rpc::RpcClient::new(cli.skunkbat_addr.clone());
    let mut aggregator = aggregator::Aggregator::new(Duration::from_secs(cli.window_secs));
    let poll_interval = Duration::from_millis(cli.poll_ms);

    let mut line_buf = String::new();
    let mut state = TailState {
        byte_offset: start_offset,
        lines_read: 0,
        lines_failed: 0,
        observations_sent: 0,
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
                    tracing::warn!(error = %e, "observe failed, will retry next window");
                }
            }
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! skunkBat `UniBin` — single binary, multiple modes.
//!
//! Implements BTSP Phase 1 (socket naming, `FAMILY_ID` guard) and
//! Primal IPC Protocol v3.1 (standalone startup, `--port` + `--bind` convention).

mod ipc;

use clap::{Parser, Subcommand};
use skunk_bat_core::PrimalLifecycle;
use skunk_bat_core::{SkunkBat, SkunkBatConfig};
use tracing_subscriber::EnvFilter;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Default TCP port for JSON-RPC when `SKUNKBAT_PORT` is unset.
const DEFAULT_PORT: u16 = 9140;

fn default_port() -> u16 {
    std::env::var("SKUNKBAT_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

fn default_bind() -> String {
    std::env::var("SKUNKBAT_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1".to_owned())
}

/// skunkBat — Reconnaissance & Automated Defense
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the IPC server (JSON-RPC 2.0 over UDS + TCP).
    Server {
        /// TCP listen address.
        ///
        /// Override with `SKUNKBAT_LISTEN_ADDR` env var or `--bind`.
        /// Defaults to `127.0.0.1` (localhost-only). Use `0.0.0.0`
        /// to expose on all interfaces.
        #[arg(long, default_value_t = default_bind())]
        bind: String,

        /// TCP port to bind for JSON-RPC (newline-delimited).
        ///
        /// Override with `SKUNKBAT_PORT` env var or `--port`.
        #[arg(long, default_value_t = default_port())]
        port: u16,

        /// Disable Unix domain socket listener.
        #[arg(long)]
        no_uds: bool,
    },

    /// One-shot health check (exits 0 if healthy).
    Health,

    /// One-shot network scan (prints JSON to stdout).
    Scan,

    /// One-shot threat detection (prints JSON to stdout).
    Detect,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // BTSP Phase 1 guard: refuse to start if FAMILY_ID + BIOMEOS_INSECURE conflict
    if let Err(e) = ipc::transport::BtspConfig::from_env() {
        tracing::error!("{e}");
        std::process::exit(1);
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Server { bind, port, no_uds } => run_server(&bind, port, no_uds).await,
        Commands::Health => run_health().await,
        Commands::Scan => run_scan().await,
        Commands::Detect => run_detect().await,
    }
}

async fn run_server(bind: &str, port: u16, no_uds: bool) -> Result<(), BoxError> {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    tracing::info!("skunkBat server starting on {bind}:{port}");

    ipc::serve(skunkbat, bind.to_owned(), port, no_uds).await
}

async fn run_health() -> Result<(), BoxError> {
    use skunk_bat_core::PrimalHealth;

    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    let report = skunkbat.health_check().await?;
    println!("{}", serde_json::to_string_pretty(&report)?);

    skunkbat.stop().await?;
    Ok(())
}

async fn run_scan() -> Result<(), BoxError> {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    let scan = skunkbat.scan_network().await?;
    println!("{}", serde_json::to_string_pretty(&scan)?);

    skunkbat.stop().await?;
    Ok(())
}

async fn run_detect() -> Result<(), BoxError> {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    let threats = skunkbat.detect_threats().await?;
    println!("{}", serde_json::to_string_pretty(&threats)?);

    skunkbat.stop().await?;
    Ok(())
}

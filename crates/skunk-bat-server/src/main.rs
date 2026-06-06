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

/// Default TCP port for JSON-RPC (aligned with `ports.env`).
const DEFAULT_PORT: u16 = 9750;

fn default_port() -> u16 {
    std::env::var(skunk_bat_core::env_keys::SKUNKBAT_PORT)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

fn default_bind() -> String {
    std::env::var(skunk_bat_core::env_keys::SKUNKBAT_LISTEN_ADDR)
        .unwrap_or_else(|_| "127.0.0.1".to_owned())
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

        /// Explicit UDS socket path (overrides BTSP-derived path).
        ///
        /// Implies `--no-tcp` (port-free deployment) matching the ecosystem
        /// convention. Add `--port` to re-enable TCP alongside UDS.
        ///
        /// Example: `--socket /run/membrane/skunkbat.sock`
        #[arg(long)]
        socket: Option<String>,

        /// Disable Unix domain socket listener.
        #[arg(long)]
        no_uds: bool,

        /// Disable TCP listener (port-free deployment).
        ///
        /// Implied automatically when `--socket` is provided.
        /// Requires UDS to be active.
        #[arg(long)]
        no_tcp: bool,
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
        Commands::Server {
            bind,
            port,
            socket,
            no_uds,
            no_tcp,
        } => run_server(&bind, port, socket.as_deref(), no_uds, no_tcp).await,
        Commands::Health => run_health().await,
        Commands::Scan => run_scan().await,
        Commands::Detect => run_detect().await,
    }
}

async fn run_server(
    bind: &str,
    port: u16,
    socket: Option<&str>,
    no_uds: bool,
    no_tcp: bool,
) -> Result<(), BoxError> {
    // Ecosystem pattern: --socket implies UDS-only (port-free) unless
    // TCP was explicitly requested via --port or --bind differs from default.
    let no_tcp = no_tcp || (socket.is_some() && !no_uds);

    if no_tcp && no_uds {
        return Err("cannot disable both TCP and UDS — no listeners would be active".into());
    }

    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    if no_tcp {
        tracing::info!("skunkBat server starting (port-free UDS mode)");
    } else {
        tracing::info!("skunkBat server starting on {bind}:{port}");
    }

    ipc::serve(skunkbat, bind.to_owned(), port, socket, no_uds, no_tcp).await
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

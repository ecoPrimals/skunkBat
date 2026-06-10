// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! skunkBat `UniBin` — single binary, multiple modes.
//!
//! Implements BTSP Phase 1 (socket naming, `FAMILY_ID` guard) and
//! Primal IPC Protocol v3.1 (standalone startup, `--port` + `--bind` convention).
//!
//! Supports `TRANSPORT_ENDPOINT` env var for launcher-injected transport binding
//! (sourDough `TransportEndpoint` standard, Wave 100+).

mod ipc;

use clap::{Parser, Subcommand};
use skunk_bat_core::PrimalLifecycle;
use skunk_bat_core::{SkunkBat, SkunkBatConfig};
use skunk_bat_integrations::TransportEndpoint;
use tracing_subscriber::EnvFilter;

/// Typed error for the server binary — replaces `Box<dyn Error>`.
#[derive(Debug, thiserror::Error)]
enum ServerError {
    #[error("config: {0}")]
    Config(String),

    #[error("{0}")]
    Primal(#[from] skunk_bat_core::PrimalError),

    #[error("{0}")]
    SkunkBat(#[from] skunk_bat_core::SkunkBatError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("{0}")]
    Transport(#[from] ipc::transport::TransportError),
}

/// Default TCP port for JSON-RPC (Tier 5 fallback only).
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

/// Check if TCP fallback mode is enabled via `PRIMAL_BIND_MODE`.
fn tcp_fallback_enabled() -> bool {
    std::env::var(skunk_bat_core::env_keys::PRIMAL_BIND_MODE)
        .map(|v| v.eq_ignore_ascii_case("fallback"))
        .unwrap_or(false)
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
    /// Start the IPC server (JSON-RPC 2.0, UDS-only by default).
    Server {
        /// TCP listen address (Tier 5 fallback — requires `PRIMAL_BIND_MODE=fallback`
        /// or explicit `--port` to activate TCP).
        ///
        /// Override with `SKUNKBAT_LISTEN_ADDR` env var or `--bind`.
        /// Defaults to `127.0.0.1` (localhost-only).
        #[arg(long, default_value_t = default_bind())]
        bind: String,

        /// TCP port — activates TCP listener as Tier 5 fallback.
        ///
        /// TCP is disabled by default (zero-port standard). Passing `--port`
        /// explicitly enables TCP alongside UDS. Also enabled by
        /// `PRIMAL_BIND_MODE=fallback` env var.
        #[arg(long)]
        port: Option<u16>,

        /// Explicit UDS socket path (overrides BTSP-derived path).
        ///
        /// Example: `--socket /run/membrane/skunkbat.sock`
        #[arg(long)]
        socket: Option<String>,

        /// Disable Unix domain socket listener (requires TCP fallback active).
        #[arg(long)]
        no_uds: bool,

        /// Disable TCP listener (explicit — TCP is already off by default).
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
async fn main() -> Result<(), ServerError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

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

        Commands::Health => {
            use skunk_bat_core::PrimalHealth;
            let mut sb = started_instance().await?;
            let v = serde_json::to_value(&sb.health_check().await?)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            sb.stop().await?;
            Ok(())
        }
        Commands::Scan => {
            let mut sb = started_instance().await?;
            let v = serde_json::to_value(&sb.scan_network().await?)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            sb.stop().await?;
            Ok(())
        }
        Commands::Detect => {
            let mut sb = started_instance().await?;
            let v = serde_json::to_value(&sb.detect_threats().await?)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            sb.stop().await?;
            Ok(())
        }
    }
}

/// Create and start a `SkunkBat` instance for one-shot commands.
async fn started_instance() -> Result<SkunkBat, ServerError> {
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;
    Ok(skunkbat)
}

async fn run_server(
    bind: &str,
    port: Option<u16>,
    socket: Option<&str>,
    no_uds: bool,
    no_tcp: bool,
) -> Result<(), ServerError> {
    // TRANSPORT_ENDPOINT env var: launcher-injected transport (sourDough standard).
    // Overrides CLI flags when set.
    let (socket, no_uds, mut no_tcp, port) = match TransportEndpoint::from_env() {
        Some(TransportEndpoint::Uds { ref path }) => {
            tracing::info!("TRANSPORT_ENDPOINT: UDS at {path}");
            (Some(path.clone()), false, true, port)
        }
        Some(TransportEndpoint::Tcp { ref host, port: ep_port }) => {
            tracing::info!("TRANSPORT_ENDPOINT: TCP at {host}:{ep_port}");
            (socket.map(ToOwned::to_owned), true, false, Some(ep_port))
        }
        Some(TransportEndpoint::MeshRelay { .. }) => {
            return Err(ServerError::Config(
                "mesh_relay transport not supported for server binding".into(),
            ));
        }
        None => (socket.map(ToOwned::to_owned), no_uds, no_tcp, port),
    };

    // Zero-port standard: TCP is off by default.
    // TCP activates only when:
    //   1. --port is explicitly passed, OR
    //   2. PRIMAL_BIND_MODE=fallback, OR
    //   3. TRANSPORT_ENDPOINT specifies TCP (handled above)
    let tcp_requested = port.is_some() || tcp_fallback_enabled();
    if !tcp_requested {
        no_tcp = true;
    }

    let effective_port = port.unwrap_or_else(default_port);

    if no_tcp && no_uds {
        return Err(ServerError::Config(
            "cannot disable both TCP and UDS — no listeners would be active".into(),
        ));
    }

    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    if no_tcp {
        tracing::info!("skunkBat server starting (UDS-only, zero-port standard)");
    } else {
        tracing::info!("skunkBat server starting on {bind}:{effective_port} (TCP fallback)");
    }

    ipc::serve(skunkbat, bind.to_owned(), effective_port, socket.as_deref(), no_uds, no_tcp).await?;
    Ok(())
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

#![expect(
    unreachable_pub,
    reason = "transport types used by main.rs via re-export"
)]
//! IPC layer — JSON-RPC 2.0 over newline-delimited streams.
//!
//! Implements the Primal IPC Protocol v3.1:
//! - Newline-delimited JSON-RPC 2.0 over TCP and UDS
//! - Semantic method naming (`security.scan`, `health.liveness`, etc.)
//! - Standalone startup (degrades gracefully without ecosystem)

mod dispatch;
mod dispatch_composable;
mod dispatch_security;
mod jsonrpc;
mod method_gate;
#[allow(
    dead_code,
    reason = "client-side API (to_wire, from_wire, negotiate_client) used in tests"
)]
mod protocol_negotiation;
mod registration;
mod server;
mod tarpc_uds;
pub mod transport;

use skunk_bat_core::PrimalLifecycle;
use skunk_bat_core::SkunkBat;
use skunk_bat_integrations::TransportEndpoint;
use skunk_bat_integrations::forwarding::{self, ForwardingConfig};
use skunk_bat_integrations::verifier::RuntimeVerifier;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use transport::SessionRegistry;

/// Concrete `SkunkBat` type used by the server — runtime-discovered verifier.
pub type App = SkunkBat<RuntimeVerifier>;

/// Background service handles — aborted on shutdown.
struct BackgroundTasks {
    register: JoinHandle<()>,
    announce: JoinHandle<()>,
    forwarding: JoinHandle<()>,
    federation: JoinHandle<()>,
    session_sweep: JoinHandle<()>,
}

impl BackgroundTasks {
    fn abort_all(&self) {
        self.register.abort();
        self.announce.abort();
        self.forwarding.abort();
        self.federation.abort();
        self.session_sweep.abort();
    }
}

/// Session TTL — connections older than this are evicted by the sweep task.
/// Configurable via `SKUNKBAT_SESSION_TTL` (seconds).
fn session_ttl() -> std::time::Duration {
    std::env::var(skunk_bat_core::env_keys::SKUNKBAT_SESSION_TTL)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(
            std::time::Duration::from_hours(1),
            std::time::Duration::from_secs,
        )
}

/// Interval between session TTL sweeps.
/// Configurable via `SKUNKBAT_SESSION_SWEEP` (seconds).
fn session_sweep_interval() -> std::time::Duration {
    std::env::var(skunk_bat_core::env_keys::SKUNKBAT_SESSION_SWEEP)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(
            std::time::Duration::from_mins(5),
            std::time::Duration::from_secs,
        )
}

/// Spawn all background services (registration, announcement, forwarding, federation, session sweep).
async fn spawn_background(
    state: &Arc<RwLock<App>>,
    sessions: &Arc<SessionRegistry>,
    socket_path: Option<&String>,
    port: u16,
) -> BackgroundTasks {
    let register_endpoint = socket_path.map_or_else(
        || format!("tcp://0.0.0.0:{port}"),
        |p| format!("unix://{p}"),
    );
    let register = tokio::spawn(registration::self_register(register_endpoint));

    let announce_socket = socket_path
        .cloned()
        .unwrap_or_else(|| format!("tcp://127.0.0.1:{port}"));
    let announce = tokio::spawn(async move {
        registration::neural_announce(&announce_socket).await;
    });

    let audit_log = state.read().await.audit_log().clone();
    let forwarding = tokio::spawn(forwarding::run_forwarding_loop(
        audit_log.clone(),
        ForwardingConfig::from_env(),
    ));

    let federation_client = skunk_bat_integrations::songbird::FederationClient::from_env();
    let federation = tokio::spawn(skunk_bat_integrations::songbird::run_federation_loop(
        audit_log,
        federation_client,
    ));

    let sweep_sessions = Arc::clone(sessions);
    let ttl = session_ttl();
    let sweep_interval = session_sweep_interval();
    let session_sweep = tokio::spawn(async move {
        loop {
            tokio::time::sleep(sweep_interval).await;
            let evicted = sweep_sessions.sweep_expired(ttl).await;
            if evicted > 0 {
                let active = sweep_sessions.len().await;
                tracing::debug!(active, "session sweep complete");
            }
        }
    });

    BackgroundTasks {
        register,
        announce,
        forwarding,
        federation,
        session_sweep,
    }
}

/// Start IPC listeners and serve until shutdown signal.
///
/// Uses G66 transport abstraction: binds [`transport::TransportListener`]s from
/// [`TransportEndpoint`]s, then runs unified accept loops.
/// Traps `SIGINT`/`SIGTERM` for graceful lifecycle stop and socket cleanup.
pub async fn serve(
    skunkbat: App,
    addr: String,
    port: u16,
    socket_override: Option<&str>,
    no_uds: bool,
    no_tcp: bool,
) -> Result<(), transport::TransportError> {
    let state = Arc::new(RwLock::new(skunkbat));
    let sessions = Arc::new(SessionRegistry::new());

    let btsp_config = transport::BtspHandshakeConfig::from_env().map(Arc::new);
    if let Some(ref cfg) = btsp_config {
        tracing::info!("BTSP Phase 2 active: provider={:?}", cfg.provider_endpoint);
    }

    let socket_path = if no_uds {
        None
    } else if let Some(path) = socket_override {
        Some(path.to_owned())
    } else {
        transport::BtspConfig::from_env()
            .ok()
            .map(|c| c.socket_path())
    };

    // G66: bind listeners from TransportEndpoints
    let tcp_handle = if no_tcp {
        None
    } else {
        let ep = TransportEndpoint::Tcp { host: addr, port };
        let listener = transport::bind_transport(&ep).await?;
        tracing::info!("TCP listening on 0.0.0.0:{port}");
        Some(tokio::spawn(transport::serve_listener(
            listener,
            Arc::clone(&state),
            Arc::clone(&sessions),
            btsp_config.clone(),
        )))
    };

    let uds_handle = if no_uds {
        None
    } else if let Some(ref path) = socket_path {
        let ep = TransportEndpoint::Uds { path: path.clone() };
        let listener = transport::bind_transport(&ep).await?;
        tracing::info!("UDS listening on {path}");
        create_capability_symlink(path);
        Some(tokio::spawn(transport::serve_listener(
            listener,
            Arc::clone(&state),
            Arc::clone(&sessions),
            btsp_config.clone(),
        )))
    } else {
        None
    };

    // C2 dual-socket: tarpc binary UDS alongside JSON-RPC (Unix only — retained as fallback).
    // On non-Unix, G65 protocol negotiation on TransportStream handles tarpc.
    let tarpc_shutdown = spawn_tarpc_dual_socket(no_uds, socket_path.as_ref(), &state);

    tracing::info!(
        "skunkBat IPC ready (TCP: {}, UDS: {}, tarpc: {}, G66: transport-agnostic)",
        !no_tcp,
        !no_uds,
        tarpc_shutdown.is_some(),
    );

    let bg = spawn_background(&state, &sessions, socket_path.as_ref(), port).await;

    wait_for_shutdown(tcp_handle, uds_handle).await?;

    if let Some(ref tx) = tarpc_shutdown {
        let _ = tx.send(true);
    }

    bg.abort_all();

    {
        let mut sb = state.write().await;
        if let Err(e) = sb.stop().await {
            tracing::warn!("lifecycle stop error: {e}");
        }
    }

    if let Some(ref path) = socket_path {
        tokio::fs::remove_file(path).await.ok();
        let jsonrpc_path = std::path::Path::new(path);
        let symlink = jsonrpc_path.parent().map(|p| p.join("security.sock"));
        if let Some(s) = symlink {
            tokio::fs::remove_file(s).await.ok();
        }
        let tarpc_path = skunk_bat_core::tarpc_service::tarpc_socket_from_jsonrpc(jsonrpc_path);
        tokio::fs::remove_file(tarpc_path).await.ok();
        tracing::info!("cleaned up socket files");
    }

    Ok(())
}

/// Create capability-domain symlink: `security.sock` → `skunkbat[-{fid}].sock`
///
/// Uses G68 [`platform_link`](skunk_bat_core::platform_substrate::platform_link)
/// instead of raw `std::os::unix::fs::symlink` — works on all platforms.
fn create_capability_symlink(socket_path: &str) {
    let socket_name = std::path::Path::new(socket_path).file_name().map_or_else(
        || "skunkbat.sock".to_owned(),
        |n| n.to_string_lossy().into_owned(),
    );
    let symlink_path = std::path::Path::new(socket_path).parent().map_or_else(
        || std::path::PathBuf::from("security.sock"),
        |p| p.join("security.sock"),
    );

    std::fs::remove_file(&symlink_path).ok();
    match skunk_bat_core::platform_substrate::platform_link(
        std::path::Path::new(&socket_name),
        &symlink_path,
    ) {
        Ok(()) => tracing::info!("Capability symlink: security.sock -> {socket_name}"),
        Err(e) => tracing::warn!("Failed to create capability symlink: {e}"),
    }
}

/// Spawn the C2 dual-socket tarpc UDS server (Unix only).
///
/// On non-Unix, returns `None` — tarpc is served via G65 protocol negotiation
/// on `TransportStream` instead.
#[cfg(unix)]
fn spawn_tarpc_dual_socket(
    no_uds: bool,
    socket_path: Option<&String>,
    state: &Arc<RwLock<App>>,
) -> Option<tokio::sync::watch::Sender<bool>> {
    if no_uds {
        return None;
    }
    let tarpc_path = socket_path.map_or_else(
        || {
            let btsp = transport::BtspConfig::from_env().ok();
            let jsonrpc = btsp.map_or_else(
                || std::path::PathBuf::from("/tmp/biomeos/skunkbat.sock"),
                |c| std::path::PathBuf::from(c.socket_path()),
            );
            skunk_bat_core::tarpc_service::tarpc_socket_from_jsonrpc(&jsonrpc)
        },
        |p| skunk_bat_core::tarpc_service::tarpc_socket_from_jsonrpc(std::path::Path::new(p)),
    );

    let server = tarpc_uds::TarpcUdsServer::new(Arc::clone(state), tarpc_path);
    let shutdown = server.shutdown_sender();
    tokio::spawn(async move {
        if let Err(e) = server.serve().await {
            tracing::error!("tarpc UDS server error: {e}");
        }
    });
    Some(shutdown)
}

#[cfg(not(unix))]
fn spawn_tarpc_dual_socket(
    _no_uds: bool,
    _socket_path: Option<&String>,
    _state: &Arc<RwLock<App>>,
) -> Option<tokio::sync::watch::Sender<bool>> {
    None
}

#[cfg(unix)]
async fn wait_for_shutdown(
    tcp_handle: Option<JoinHandle<Result<(), transport::TransportError>>>,
    uds_handle: Option<JoinHandle<Result<(), transport::TransportError>>>,
) -> Result<(), transport::TransportError> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        result = async {
            match tcp_handle {
                Some(h) => h.await,
                None => std::future::pending().await,
            }
        } => {
            result??;
        }
        result = async {
            match uds_handle {
                Some(h) => h.await,
                None => std::future::pending().await,
            }
        } => {
            result??;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("SIGINT received, stopping skunkBat");
        }
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received, stopping skunkBat");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_shutdown(
    tcp_handle: Option<JoinHandle<Result<(), transport::TransportError>>>,
    _uds_handle: Option<JoinHandle<Result<(), transport::TransportError>>>,
) -> Result<(), transport::TransportError> {
    tokio::select! {
        result = async {
            match tcp_handle {
                Some(h) => h.await,
                None => std::future::pending().await,
            }
        } => {
            result??;
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl+C received, stopping skunkBat");
        }
    }
    Ok(())
}

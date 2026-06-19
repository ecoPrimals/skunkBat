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
mod jsonrpc;
mod method_gate;
mod registration;
mod server;
pub mod transport;

use skunk_bat_core::PrimalLifecycle;
use skunk_bat_core::SkunkBat;
use skunk_bat_integrations::forwarding::{self, ForwardingConfig};
use std::sync::Arc;
use tokio::sync::RwLock;
use transport::SessionRegistry;

/// Start IPC listeners and serve until shutdown signal.
///
/// Traps `SIGINT`/`SIGTERM` for graceful lifecycle stop and UDS socket cleanup.
pub async fn serve(
    skunkbat: SkunkBat,
    addr: String,
    port: u16,
    socket_override: Option<&str>,
    no_uds: bool,
    no_tcp: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(RwLock::new(skunkbat));
    let sessions = Arc::new(SessionRegistry::new());

    let socket_path = if no_uds {
        None
    } else if let Some(path) = socket_override {
        Some(path.to_owned())
    } else {
        transport::BtspConfig::from_env()
            .ok()
            .map(|c| c.socket_path())
    };

    let tcp_handle = if no_tcp {
        None
    } else {
        Some(tokio::spawn(transport::serve_tcp(
            Arc::clone(&state),
            Arc::clone(&sessions),
            addr,
            port,
        )))
    };

    let uds_handle = if no_uds {
        None
    } else {
        Some(tokio::spawn(transport::serve_uds(
            Arc::clone(&state),
            Arc::clone(&sessions),
        )))
    };

    tracing::info!(
        "skunkBat IPC ready (TCP: {}, UDS: {})",
        !no_tcp,
        !no_uds,
    );

    let register_endpoint = socket_path.as_ref().map_or_else(
        || format!("tcp://0.0.0.0:{port}"),
        |p| format!("unix://{p}"),
    );
    let register_handle = tokio::spawn(registration::self_register(register_endpoint));

    let announce_socket = socket_path
        .clone()
        .unwrap_or_else(|| format!("tcp://127.0.0.1:{port}"));
    let announce_handle = tokio::spawn(async move {
        registration::neural_announce(&announce_socket).await;
    });

    let audit_log = state.read().await.audit_log().clone();
    let forwarding_handle = tokio::spawn(forwarding::run_forwarding_loop(
        audit_log,
        ForwardingConfig::default(),
    ));

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

    register_handle.abort();
    announce_handle.abort();
    forwarding_handle.abort();

    {
        let mut sb = state.write().await;
        if let Err(e) = sb.stop().await {
            tracing::warn!("lifecycle stop error: {e}");
        }
    }

    if let Some(ref path) = socket_path {
        tokio::fs::remove_file(path).await.ok();
        let symlink = std::path::Path::new(path)
            .parent()
            .map(|p| p.join("security.sock"));
        if let Some(s) = symlink {
            tokio::fs::remove_file(s).await.ok();
        }
        tracing::info!("cleaned up socket files");
    }

    Ok(())
}

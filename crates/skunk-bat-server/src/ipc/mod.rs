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
mod server;
pub mod transport;

use skunk_bat_core::PrimalLifecycle;
use skunk_bat_core::SkunkBat;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Start IPC listeners and serve until shutdown signal.
///
/// Traps `SIGINT`/`SIGTERM` for graceful lifecycle stop and UDS socket cleanup.
pub async fn serve(
    skunkbat: SkunkBat,
    port: u16,
    no_uds: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(RwLock::new(skunkbat));

    let socket_path = if no_uds {
        None
    } else {
        transport::BtspConfig::from_env()
            .ok()
            .map(|c| c.socket_path())
    };

    let tcp_handle = tokio::spawn(transport::serve_tcp(Arc::clone(&state), port));

    let uds_handle = if no_uds {
        None
    } else {
        Some(tokio::spawn(transport::serve_uds(Arc::clone(&state))))
    };

    tracing::info!("skunkBat IPC ready (TCP :{port}, UDS: {})", !no_uds);

    tokio::select! {
        result = tcp_handle => {
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
            tracing::info!("shutdown signal received, stopping skunkBat");
        }
    }

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

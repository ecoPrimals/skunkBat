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

use skunk_bat_core::SkunkBat;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Start IPC listeners and serve until shutdown.
pub async fn serve(
    skunkbat: SkunkBat,
    port: u16,
    no_uds: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(RwLock::new(skunkbat));

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
    }

    Ok(())
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Transport layer — TCP and Unix domain socket listeners.
//!
//! Implements BTSP Phase 1 (socket naming with `FAMILY_ID` awareness),
//! Phase 2 (`BearDog`-delegated handshake on both TCP and UDS), and
//! Primal IPC Protocol v3.1 (filesystem sockets in `$BIOMEOS_SOCKET_DIR`).
//!
//! Both TCP and UDS use first-byte peek to auto-detect protocol:
//! `{` → plain JSON-RPC (biomeOS composition bypass), otherwise BTSP
//! framed handshake. TCP uses native `TcpStream::peek`; UDS uses
//! `PeekedStream` (read-one-byte + replay) since `UnixStream` lacks peek.

mod btsp;
mod config;
mod error;
pub mod negotiate;
#[cfg(test)]
mod negotiate_tests;
mod peek;
mod sys;

pub use error::TransportError;

pub use btsp::{read_frame, write_frame};
pub use config::{BtspConfig, BtspHandshakeConfig};
pub use negotiate::SessionRegistry;

use btsp::perform_server_handshake;
use negotiate::SessionRegistry as BtspSessionRegistry;
use peek::PeekedStream;
use skunk_bat_core::SkunkBat;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use super::method_gate::CallerContext;
use super::server::handle_connection;

/// Bind TCP and accept connections with optional BTSP handshake.
///
/// TCP uses the same first-byte peek as `BearDog`: `{` → plain JSON-RPC
/// (biomeOS composition), otherwise BTSP framed handshake.
pub async fn serve_tcp(
    state: Arc<RwLock<SkunkBat>>,
    sessions: Arc<BtspSessionRegistry>,
    addr: String,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let listener = TcpListener::bind((&*addr, port)).await?;
    tracing::info!("TCP JSON-RPC listening on {addr}:{port}");

    let btsp_config = BtspHandshakeConfig::from_env().map(Arc::new);
    if let Some(ref cfg) = btsp_config {
        tracing::info!(
            "BTSP Phase 2 active on TCP: provider={}",
            cfg.provider_socket.display()
        );
    }

    loop {
        let (mut stream, addr) = listener.accept().await?;
        tracing::debug!("TCP connection from {addr}");
        let state = Arc::clone(&state);
        let btsp = btsp_config.clone();
        let sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            let caller = if addr.ip().is_loopback() {
                CallerContext::loopback()
            } else {
                CallerContext::remote()
            };
            if let Some(ref cfg) = btsp {
                let mut peek_buf = [0u8; 1];
                let n = stream.peek(&mut peek_buf).await.unwrap_or(0);
                if n > 0 && peek_buf[0] != b'{' {
                    match perform_server_handshake(&mut stream, cfg).await {
                        Ok(result) => {
                            tracing::debug!(
                                "BTSP authenticated TCP {addr}: session={}",
                                result.session_id
                            );
                            sessions
                                .insert(result.session_id, result.handshake_key)
                                .await;
                        }
                        Err(e) => {
                            tracing::warn!("BTSP handshake failed TCP {addr}: {e}");
                            return;
                        }
                    }
                }
            }
            handle_connection(state, sessions, stream, caller).await;
        });
    }
}

/// Bind UDS and accept connections per BTSP Phase 1 naming + Phase 2 handshake.
///
/// Uses first-byte peek (via `PeekedStream`) to auto-detect protocol:
/// `{` → plain JSON-RPC (biomeOS composition), otherwise BTSP framed
/// handshake. Matches the TCP behavior exactly.
#[cfg(unix)]
pub async fn serve_uds(
    state: Arc<RwLock<SkunkBat>>,
    sessions: Arc<BtspSessionRegistry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixListener;

    let btsp = BtspConfig::from_env()?;
    btsp.log_mode();

    let socket_path = btsp.socket_path();

    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    tokio::fs::remove_file(&socket_path).await.ok();
    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!("UDS JSON-RPC listening on {socket_path}");

    create_capability_symlink(&btsp);

    let btsp_config = BtspHandshakeConfig::from_env().map(Arc::new);
    if let Some(ref cfg) = btsp_config {
        tracing::info!(
            "BTSP Phase 2 active on UDS (first-byte peek): provider={}",
            cfg.provider_socket.display()
        );
    }

    loop {
        let (mut stream, _addr) = listener.accept().await?;
        tracing::debug!("UDS connection accepted");
        let state = Arc::clone(&state);
        let btsp = btsp_config.clone();
        let sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            if let Some(ref cfg) = btsp {
                let mut first = [0u8; 1];
                let n = stream.read(&mut first).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                let mut peeked = PeekedStream {
                    peeked: Some(first[0]),
                    inner: stream,
                };
                if first[0] != b'{' {
                    match perform_server_handshake(&mut peeked, cfg).await {
                        Ok(result) => {
                            tracing::debug!(
                                "BTSP authenticated UDS: session={}",
                                result.session_id
                            );
                            sessions
                                .insert(result.session_id, result.handshake_key)
                                .await;
                        }
                        Err(e) => {
                            tracing::warn!("BTSP handshake failed UDS: {e}");
                            return;
                        }
                    }
                }
                handle_connection(state, sessions, peeked, CallerContext::unix()).await;
            } else {
                handle_connection(state, sessions, stream, CallerContext::unix()).await;
            }
        });
    }
}

#[cfg(not(unix))]
pub async fn serve_uds(
    _state: Arc<RwLock<SkunkBat>>,
    _sessions: Arc<BtspSessionRegistry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    tracing::warn!("Unix domain sockets not available on this platform");
    std::future::pending().await
}

/// Create capability-domain symlink: `security.sock` → `skunkbat[-{fid}].sock`
#[cfg(unix)]
fn create_capability_symlink(btsp: &BtspConfig) {
    let symlink_path = btsp.capability_symlink_path();
    let socket_name = std::path::Path::new(&btsp.socket_path())
        .file_name()
        .map_or_else(
            || "skunkbat.sock".to_owned(),
            |n| n.to_string_lossy().into_owned(),
        );

    std::fs::remove_file(&symlink_path).ok();
    match std::os::unix::fs::symlink(&socket_name, &symlink_path) {
        Ok(()) => tracing::info!("Capability symlink: security.sock -> {socket_name}"),
        Err(e) => tracing::warn!("Failed to create capability symlink: {e}"),
    }
}

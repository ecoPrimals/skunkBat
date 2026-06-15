// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Transport layer — TCP and Unix domain socket listeners.
//!
//! Implements riboCipher signal detection (Wave 111+ standard),
//! BTSP Phase 1 (socket naming with `FAMILY_ID` awareness),
//! Phase 2 (`BearDog`-delegated handshake on both TCP and UDS), and
//! Primal IPC Protocol v3.1 (filesystem sockets in `$BIOMEOS_SOCKET_DIR`).
//!
//! riboCipher: clients send a 2-byte signal `[0xEC, protocol_type]` before
//! any payload. The accept loop consumes this envelope and routes to the
//! correct handler. Unsignalled connections fall back to legacy peek logic
//! with a WARN log (hard-cut scheduled for Wave 114).
//!
//! Protocol types: `0x00` = probe, `0x01` = NDJSON JSON-RPC, `0x02` = BTSP
//! binary, `0x03` = BTSP JSON-line, `0x04` = HTTP/1.1, `0x05` = encrypted
//! resume.

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

/// riboCipher clear-signal prefix byte.
const RIBOCIPHER_CLEAR: u8 = 0xEC;

/// riboCipher protocol type: NDJSON JSON-RPC.
const PROTO_NDJSON: u8 = 0x01;
/// riboCipher protocol type: BTSP binary handshake.
const PROTO_BTSP_BINARY: u8 = 0x02;
/// riboCipher protocol type: lightweight probe.
const PROTO_PROBE: u8 = 0x00;

/// Bind TCP and accept connections with riboCipher signal detection.
///
/// Connections starting with `0xEC` are routed via the riboCipher protocol
/// type table. Unsignalled connections fall back to legacy peek logic with
/// a deprecation warning.
pub async fn serve_tcp(
    state: Arc<RwLock<SkunkBat>>,
    sessions: Arc<BtspSessionRegistry>,
    addr: String,
    port: u16,
) -> Result<(), TransportError> {
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

            let mut peek_buf = [0u8; 2];
            let n = stream.peek(&mut peek_buf).await.unwrap_or(0);

            if n >= 1 && peek_buf[0] == RIBOCIPHER_CLEAR {
                handle_ribocipher_tcp(stream, state, sessions, caller).await;
                return;
            }

            // Legacy unsignalled path — log deprecation warning.
            if n > 0 && peek_buf[0] != b'{' && peek_buf[0] != b'[' {
                tracing::warn!(
                    first_byte = peek_buf[0],
                    "DEPRECATED: unsignalled connection from {addr} — \
                     riboCipher signal required in future waves"
                );
            }

            if let Some(ref cfg) = btsp
                && n > 0
                && peek_buf[0] != b'{'
            {
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
            handle_connection(state, sessions, stream, caller).await;
        });
    }
}

/// Handle a riboCipher-signalled TCP connection.
///
/// Consumes the 2-byte `[0xEC, protocol_type]` envelope, then routes
/// to the appropriate handler based on the protocol type.
async fn handle_ribocipher_tcp(
    mut stream: tokio::net::TcpStream,
    state: Arc<RwLock<SkunkBat>>,
    sessions: Arc<BtspSessionRegistry>,
    caller: CallerContext,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut signal = [0u8; 2];
    if stream.read_exact(&mut signal).await.is_err() {
        return;
    }

    let protocol_type = signal[1];
    tracing::debug!(protocol_type, "riboCipher clear signal accepted (TCP)");

    match protocol_type {
        PROTO_NDJSON => {
            handle_connection(state, sessions, stream, caller).await;
        }
        PROTO_PROBE => {
            let probe_response = serde_json::json!({
                "status": "ok",
                "primal": skunk_bat_core::PRIMAL_ID,
                "version": env!("CARGO_PKG_VERSION")
            });
            let mut bytes = serde_json::to_vec(&probe_response).unwrap_or_default();
            bytes.push(b'\n');
            let _ = stream.write_all(&bytes).await;
            let _ = stream.flush().await;
        }
        PROTO_BTSP_BINARY => {
            tracing::debug!("riboCipher routed to BTSP binary (TCP) — not yet wired");
        }
        other => {
            tracing::warn!(
                protocol_type = other,
                "riboCipher: unknown protocol type — closing connection"
            );
        }
    }
}

/// Bind UDS and accept connections with riboCipher signal detection.
///
/// Connections starting with `0xEC` are routed via the riboCipher protocol
/// type table. Unsignalled connections fall back to legacy peek logic with
/// a deprecation warning.
///
/// When `socket_override` is provided (via `--socket` CLI flag), it takes
/// priority over the BTSP-derived path — enabling launcher-injected paths
/// like `/run/membrane/skunkbat.sock` for port-free deployment.
#[cfg(unix)]
pub async fn serve_uds(
    state: Arc<RwLock<SkunkBat>>,
    sessions: Arc<BtspSessionRegistry>,
    socket_override: Option<String>,
) -> Result<(), TransportError> {
    use tokio::net::UnixListener;

    let has_override = socket_override.is_some();
    let btsp = BtspConfig::from_env().ok();

    let socket_path = socket_override.unwrap_or_else(|| {
        btsp.as_ref().map_or_else(
            || "/tmp/biomeos/skunkbat.sock".to_owned(),
            BtspConfig::socket_path,
        )
    });

    if has_override {
        tracing::info!("UDS: launcher-injected socket path: {socket_path}");
    } else if let Some(ref cfg) = btsp {
        cfg.log_mode();
    } else {
        tracing::info!("UDS: standalone mode, socket={socket_path}");
    }

    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    tokio::fs::remove_file(&socket_path).await.ok();
    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!("UDS JSON-RPC listening on {socket_path}");

    if has_override {
        create_standalone_symlink(&socket_path);
    } else if let Some(ref cfg) = btsp {
        create_capability_symlink(cfg);
    } else {
        create_standalone_symlink(&socket_path);
    }

    let btsp_config = BtspHandshakeConfig::from_env().map(Arc::new);
    if let Some(ref cfg) = btsp_config {
        tracing::info!(
            "BTSP Phase 2 active on UDS (first-byte peek): provider={}",
            cfg.provider_socket.display()
        );
    }

    loop {
        let (stream, _addr) = listener.accept().await?;
        tracing::debug!("UDS connection accepted");
        let state = Arc::clone(&state);
        let btsp = btsp_config.clone();
        let sessions = Arc::clone(&sessions);
        tokio::spawn(handle_uds_connection(stream, state, sessions, btsp));
    }
}

/// Handle a single UDS connection with riboCipher detection.
#[cfg(unix)]
async fn handle_uds_connection(
    mut stream: tokio::net::UnixStream,
    state: Arc<RwLock<SkunkBat>>,
    sessions: Arc<BtspSessionRegistry>,
    btsp: Option<Arc<BtspHandshakeConfig>>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut first = [0u8; 1];
    let n = stream.read(&mut first).await.unwrap_or(0);
    if n == 0 {
        return;
    }

    if first[0] == RIBOCIPHER_CLEAR {
        let mut proto = [0u8; 1];
        if stream.read(&mut proto).await.unwrap_or(0) == 0 {
            return;
        }
        tracing::debug!(
            protocol_type = proto[0],
            "riboCipher clear signal accepted (UDS)"
        );

        match proto[0] {
            PROTO_NDJSON => {
                handle_connection(state, sessions, stream, CallerContext::unix()).await;
            }
            PROTO_PROBE => {
                let resp = serde_json::json!({
                    "status": "ok",
                    "primal": skunk_bat_core::PRIMAL_ID,
                    "version": env!("CARGO_PKG_VERSION")
                });
                let mut bytes = serde_json::to_vec(&resp).unwrap_or_default();
                bytes.push(b'\n');
                let _ = stream.write_all(&bytes).await;
                let _ = stream.flush().await;
            }
            PROTO_BTSP_BINARY => {
                if let Some(ref cfg) = btsp {
                    match perform_server_handshake(&mut stream, cfg).await {
                        Ok(result) => {
                            tracing::debug!(
                                "BTSP authenticated UDS (riboCipher): session={}",
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
                handle_connection(state, sessions, stream, CallerContext::unix()).await;
            }
            other => {
                tracing::warn!(
                    protocol_type = other,
                    "riboCipher: unknown protocol type — closing UDS connection"
                );
            }
        }
        return;
    }

    // Legacy unsignalled path with deprecation warning.
    if first[0] != b'{' && first[0] != b'[' {
        tracing::warn!(
            first_byte = first[0],
            "DEPRECATED: unsignalled UDS connection — \
             riboCipher signal required in future waves"
        );
    }

    let mut peeked = PeekedStream {
        peeked: Some(first[0]),
        inner: stream,
    };

    if let Some(ref cfg) = btsp
        && first[0] != b'{'
    {
        match perform_server_handshake(&mut peeked, cfg).await {
            Ok(result) => {
                tracing::debug!("BTSP authenticated UDS: session={}", result.session_id);
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
}

#[cfg(not(unix))]
pub async fn serve_uds(
    _state: Arc<RwLock<SkunkBat>>,
    _sessions: Arc<BtspSessionRegistry>,
    _socket_override: Option<String>,
) -> Result<(), TransportError> {
    tracing::warn!("Unix domain sockets not available on this platform");
    std::future::pending().await
}

/// Create capability-domain symlink when using `--socket` override (no `BtspConfig`).
#[cfg(unix)]
fn create_standalone_symlink(socket_path: &str) {
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        let symlink_path = parent.join("security.sock");
        let socket_name = std::path::Path::new(socket_path).file_name().map_or_else(
            || "skunkbat.sock".to_owned(),
            |n| n.to_string_lossy().into_owned(),
        );
        std::fs::remove_file(&symlink_path).ok();
        match std::os::unix::fs::symlink(&socket_name, &symlink_path) {
            Ok(()) => tracing::info!("Capability symlink: security.sock -> {socket_name}"),
            Err(e) => tracing::warn!("Failed to create capability symlink: {e}"),
        }
    }
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

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Transport layer — TCP and Unix domain socket listeners.
//!
//! Implements BTSP Phase 1 (socket naming with `FAMILY_ID` awareness),
//! Phase 2 (`BearDog`-delegated handshake on both TCP and UDS), and
//! Primal IPC Protocol v3.1 (filesystem sockets in `$BIOMEOS_SOCKET_DIR`).
//!
//! Protocol detection uses riboCipher signal-first accept (Wave 111+).
//! The server reads the first byte to classify the connection:
//!
//! | First byte | Action |
//! |------------|--------|
//! | `0xEC`     | Clear riboCipher — read 2nd byte for protocol type |
//! | `0xED`     | Mito-obfuscated riboCipher — not yet implemented, reject |
//! | `0xEE`     | Nuclear-sealed riboCipher — not yet implemented, reject |
//! | other      | Legacy (deprecated) — log warning, fall back to old peek logic |
//!
//! Protocol types (after `0xEC`):
//!
//! | Byte   | Protocol        |
//! |--------|-----------------|
//! | `0x00` | Probe           |
//! | `0x01` | NDJSON JSON-RPC |
//! | `0x02` | BTSP binary     |
//! | `0x03` | BTSP JSON-line  |

mod btsp;
mod config;
mod error;
pub mod frame;
pub mod negotiate;
mod peek;

pub use error::TransportError;

pub use btsp::{read_frame, write_frame};
pub use config::{BtspConfig, BtspHandshakeConfig};
pub use negotiate::SessionRegistry;

use btsp::perform_server_handshake;
use negotiate::SessionRegistry as BtspSessionRegistry;
use peek::PeekedStream;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use super::App;
use super::method_gate::CallerContext;
use super::protocol_negotiation::{self, IpcProtocol};
use super::server::handle_connection;

/// riboCipher signal prefix bytes (Wave 111+ standard).
const RIBOCIPHER_CLEAR: u8 = 0xEC;
const RIBOCIPHER_MITO: u8 = 0xED;
const RIBOCIPHER_NUCLEAR: u8 = 0xEE;

/// Protocol type byte values carried after a riboCipher signal.
mod protocol_type {
    pub const PROBE: u8 = 0x00;
    pub const NDJSON_JSONRPC: u8 = 0x01;
    pub const BTSP_BINARY: u8 = 0x02;
    pub const BTSP_JSONLINE: u8 = 0x03;
}

/// Classified intent of an incoming connection after reading the signal.
enum ConnectionIntent {
    /// NDJSON JSON-RPC (signal consumed — stream is ready for JSON lines).
    NdjsonJsonRpc,
    /// BTSP handshake (signal consumed — stream is ready for handshake frames).
    BtspHandshake,
    /// Lightweight health probe — respond and close.
    Probe,
    /// G65 protocol negotiation — first byte `P` consumed, rest of `PROTOCOLS:` line pending.
    ProtocolNegotiation,
    /// Legacy unsignalled connection — first byte must be replayed.
    Legacy { first_byte: u8 },
    /// Connection should be rejected (unknown tier / protocol).
    Reject,
}

/// Read riboCipher signal from a stream and classify the connection intent.
///
/// Consumes the signal bytes (1–2 bytes for clear tier) so the stream is
/// positioned at the start of protocol-specific data. For legacy connections
/// the first byte is returned so the caller can replay it.
async fn classify_connection<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<ConnectionIntent> {
    use tokio::io::AsyncReadExt;

    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;

    match first[0] {
        RIBOCIPHER_CLEAR => {
            let mut pt = [0u8; 1];
            stream.read_exact(&mut pt).await?;
            match pt[0] {
                protocol_type::NDJSON_JSONRPC => Ok(ConnectionIntent::NdjsonJsonRpc),
                protocol_type::BTSP_BINARY | protocol_type::BTSP_JSONLINE => {
                    Ok(ConnectionIntent::BtspHandshake)
                }
                protocol_type::PROBE => Ok(ConnectionIntent::Probe),
                other => {
                    tracing::warn!("Unknown riboCipher protocol type 0x{other:02x}");
                    Ok(ConnectionIntent::Reject)
                }
            }
        }
        RIBOCIPHER_MITO | RIBOCIPHER_NUCLEAR => {
            tracing::warn!(
                "riboCipher tier {tier} not yet implemented — rejecting",
                tier = if first[0] == RIBOCIPHER_MITO {
                    "mito (0xED)"
                } else {
                    "nuclear (0xEE)"
                },
            );
            Ok(ConnectionIntent::Reject)
        }
        b'P' => {
            tracing::debug!("G65 protocol negotiation candidate (first byte 'P')");
            Ok(ConnectionIntent::ProtocolNegotiation)
        }
        other => {
            tracing::warn!("DEPRECATED: unsignalled connection (first byte 0x{other:02x})");
            Ok(ConnectionIntent::Legacy {
                first_byte: first[0],
            })
        }
    }
}

/// Complete a BTSP handshake and register the session.
///
/// Returns the session ID on success. Updates `caller` with the bearer token.
async fn complete_btsp_handshake<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &BtspHandshakeConfig,
    sessions: &BtspSessionRegistry,
    caller: &mut CallerContext,
    label: &str,
) -> Result<String, TransportError> {
    let result = perform_server_handshake(stream, cfg).await?;
    tracing::debug!("BTSP authenticated {label}: session={}", result.session_id);
    let sid = result.session_id.clone();
    caller.bearer_token = Some(format!("btsp:{}", result.session_id));
    sessions
        .insert(result.session_id, result.handshake_key)
        .await;
    Ok(sid)
}

/// Handle G65 protocol negotiation on a stream where `P` was already consumed.
///
/// Negotiates the protocol and routes to tarpc or JSON-RPC accordingly.
async fn handle_g65<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    mut stream: S,
    state: Arc<RwLock<App>>,
    sessions: Arc<BtspSessionRegistry>,
    caller: CallerContext,
    label: &str,
) {
    let supported = IpcProtocol::all_supported();
    match protocol_negotiation::negotiate_server_after_p(&mut stream, &supported).await {
        Ok(IpcProtocol::Tarpc) => {
            tracing::info!("G65 → tarpc on {label}");
            super::tarpc_uds::serve_tarpc_stream(state, stream).await;
        }
        Ok(IpcProtocol::JsonRpc) | Err(_) => {
            handle_connection(state, sessions, stream, caller, None).await;
        }
    }
}

/// Bind TCP and accept connections with riboCipher signal routing.
#[expect(
    clippy::too_many_lines,
    reason = "accept loop with protocol-dispatch arms"
)]
pub async fn serve_tcp(
    state: Arc<RwLock<App>>,
    sessions: Arc<BtspSessionRegistry>,
    addr: String,
    port: u16,
) -> Result<(), TransportError> {
    let listener = TcpListener::bind((&*addr, port)).await?;
    tracing::info!("TCP JSON-RPC listening on {addr}:{port}");

    let btsp_config = BtspHandshakeConfig::from_env().map(Arc::new);
    if let Some(ref cfg) = btsp_config {
        tracing::info!(
            "BTSP Phase 2 active on TCP: provider={:?}",
            cfg.provider_endpoint
        );
    }

    loop {
        let (mut stream, addr) = listener.accept().await?;
        tracing::debug!("TCP connection from {addr}");
        let state = Arc::clone(&state);
        let btsp = btsp_config.clone();
        let sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            let mut caller = if addr.ip().is_loopback() {
                CallerContext::loopback()
            } else {
                CallerContext::remote_with_addr(addr.to_string())
            };

            let intent = match classify_connection(&mut stream).await {
                Ok(i) => i,
                Err(e) => {
                    tracing::debug!("TCP {addr}: failed to read signal: {e}");
                    return;
                }
            };

            let label = format!("TCP {addr}");
            match intent {
                ConnectionIntent::NdjsonJsonRpc => {
                    handle_connection(state, sessions, stream, caller, None).await;
                }
                ConnectionIntent::BtspHandshake => {
                    let sid = if let Some(ref cfg) = btsp {
                        match complete_btsp_handshake(
                            &mut stream,
                            cfg,
                            &sessions,
                            &mut caller,
                            &label,
                        )
                        .await
                        {
                            Ok(sid) => {
                                record_transport_path(&state, &caller).await;
                                Some(sid)
                            }
                            Err(e) => {
                                tracing::warn!("BTSP handshake failed {label}: {e}");
                                return;
                            }
                        }
                    } else {
                        None
                    };
                    handle_connection(state, sessions, stream, caller, sid).await;
                }
                ConnectionIntent::Probe => {
                    tracing::debug!("riboCipher probe from {label}");
                    respond_to_probe(&mut stream).await;
                }
                ConnectionIntent::ProtocolNegotiation => {
                    handle_g65(stream, state, sessions, caller, &label).await;
                }
                ConnectionIntent::Legacy { first_byte } => {
                    if first_byte != b'{' {
                        if let Some(ref cfg) = btsp {
                            let mut ps = PeekedStream {
                                peeked: Some(first_byte),
                                inner: stream,
                            };
                            match complete_btsp_handshake(
                                &mut ps,
                                cfg,
                                &sessions,
                                &mut caller,
                                &label,
                            )
                            .await
                            {
                                Ok(sid) => {
                                    handle_connection(state, sessions, ps, caller, Some(sid)).await;
                                }
                                Err(e) => tracing::warn!("BTSP handshake failed {label}: {e}"),
                            }
                        }
                        return;
                    }
                    let peeked = PeekedStream {
                        peeked: Some(first_byte),
                        inner: stream,
                    };
                    handle_connection(state, sessions, peeked, caller, None).await;
                }
                ConnectionIntent::Reject => {}
            }
        });
    }
}

/// Set up the UDS listener: create directory, clean stale socket, bind, create symlink.
#[cfg(unix)]
async fn setup_uds_listener()
-> Result<(tokio::net::UnixListener, Option<Arc<BtspHandshakeConfig>>), TransportError> {
    let btsp = BtspConfig::from_env()?;
    btsp.log_mode();

    let socket_path = btsp.socket_path();

    if let Some(parent) = std::path::Path::new(&socket_path).parent()
        && let Err(e) = tokio::fs::create_dir_all(parent).await
    {
        tracing::warn!(
            "Failed to create UDS socket directory {}: {e}",
            parent.display()
        );
    }

    if let Err(e) = tokio::fs::remove_file(&socket_path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!("Failed to remove stale UDS socket {socket_path}: {e}");
    }

    let listener = tokio::net::UnixListener::bind(&socket_path)?;
    tracing::info!("UDS JSON-RPC listening on {socket_path}");

    create_capability_symlink(&btsp);

    let btsp_config = BtspHandshakeConfig::from_env().map(Arc::new);
    if let Some(ref cfg) = btsp_config {
        tracing::info!(
            "BTSP Phase 2 active on UDS (riboCipher signal): provider={:?}",
            cfg.provider_endpoint
        );
    }

    Ok((listener, btsp_config))
}

/// Bind UDS and accept connections per BTSP Phase 1 naming + riboCipher routing.
#[cfg(unix)]
pub async fn serve_uds(
    state: Arc<RwLock<App>>,
    sessions: Arc<BtspSessionRegistry>,
) -> Result<(), TransportError> {
    let (listener, btsp_config) = setup_uds_listener().await?;

    loop {
        let (mut stream, _addr) = listener.accept().await?;
        tracing::debug!("UDS connection accepted");
        let state = Arc::clone(&state);
        let btsp = btsp_config.clone();
        let sessions = Arc::clone(&sessions);
        tokio::spawn(async move {
            let intent = match classify_connection(&mut stream).await {
                Ok(i) => i,
                Err(e) => {
                    tracing::debug!("UDS: failed to read signal: {e}");
                    return;
                }
            };

            let mut caller = CallerContext::unix();
            let label = "UDS";

            match intent {
                ConnectionIntent::NdjsonJsonRpc => {
                    handle_connection(state, sessions, stream, caller, None).await;
                }
                ConnectionIntent::BtspHandshake => {
                    let sid = if let Some(ref cfg) = btsp {
                        match complete_btsp_handshake(
                            &mut stream,
                            cfg,
                            &sessions,
                            &mut caller,
                            label,
                        )
                        .await
                        {
                            Ok(sid) => Some(sid),
                            Err(e) => {
                                tracing::warn!("BTSP handshake failed {label}: {e}");
                                return;
                            }
                        }
                    } else {
                        None
                    };
                    handle_connection(state, sessions, stream, caller, sid).await;
                }
                ConnectionIntent::Probe => {
                    tracing::debug!("riboCipher probe from {label}");
                    respond_to_probe(&mut stream).await;
                }
                ConnectionIntent::ProtocolNegotiation => {
                    handle_g65(stream, state, sessions, caller, label).await;
                }
                ConnectionIntent::Legacy { first_byte } => {
                    if first_byte != b'{' {
                        if let Some(ref cfg) = btsp {
                            let mut ps = PeekedStream {
                                peeked: Some(first_byte),
                                inner: stream,
                            };
                            match complete_btsp_handshake(
                                &mut ps,
                                cfg,
                                &sessions,
                                &mut caller,
                                label,
                            )
                            .await
                            {
                                Ok(sid) => {
                                    handle_connection(state, sessions, ps, caller, Some(sid)).await;
                                }
                                Err(e) => tracing::warn!("BTSP handshake failed {label}: {e}"),
                            }
                        }
                        return;
                    }
                    let peeked = PeekedStream {
                        peeked: Some(first_byte),
                        inner: stream,
                    };
                    handle_connection(state, sessions, peeked, caller, None).await;
                }
                ConnectionIntent::Reject => {}
            }
        });
    }
}

#[cfg(not(unix))]
pub async fn serve_uds(
    _state: Arc<RwLock<App>>,
    _sessions: Arc<BtspSessionRegistry>,
) -> Result<(), TransportError> {
    tracing::warn!("Unix domain sockets not available on this platform");
    std::future::pending().await
}

/// Respond to a riboCipher probe with a minimal JSON health payload, then close.
///
/// Probes are used by `ToadStool` and other discovery agents to check liveness
/// without establishing a full IPC session.
async fn respond_to_probe<S: tokio::io::AsyncWrite + Unpin>(stream: &mut S) {
    use tokio::io::AsyncWriteExt;
    let payload = format!(
        "{{\"primal\":\"{}\",\"status\":\"alive\"}}\n",
        skunk_bat_core::PRIMAL_ID
    );
    if let Err(e) = stream.write_all(payload.as_bytes()).await {
        tracing::debug!("Probe response write failed: {e}");
        return;
    }
    if let Err(e) = stream.flush().await {
        tracing::debug!("Probe response flush failed: {e}");
    }
}

/// Record transport layer path for topology validation.
///
/// Encodes the connection transport as a layer-traversal path:
/// - `[0]`: Unix domain socket (local)
/// - `[1]`: TCP loopback
/// - `[2]`: TCP remote (unauthenticated)
/// - `[2, 3]`: TCP remote + BTSP authenticated
async fn record_transport_path(state: &Arc<RwLock<App>>, caller: &CallerContext) {
    use super::method_gate::ConnectionOrigin;
    let path = match caller.origin {
        ConnectionOrigin::Unix => vec![0],
        ConnectionOrigin::Loopback => vec![1],
        ConnectionOrigin::Remote => vec![2, 3],
    };
    state.read().await.record_connection_path(path);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cursor_stream(data: &[u8]) -> std::io::Cursor<Vec<u8>> {
        std::io::Cursor::new(data.to_vec())
    }

    #[tokio::test]
    async fn classify_clear_ndjson() {
        let mut s = cursor_stream(&[0xEC, 0x01]);
        let intent = classify_connection(&mut s).await.unwrap();
        assert!(matches!(intent, ConnectionIntent::NdjsonJsonRpc));
    }

    #[tokio::test]
    async fn classify_clear_btsp_binary() {
        let mut s = cursor_stream(&[0xEC, 0x02]);
        let intent = classify_connection(&mut s).await.unwrap();
        assert!(matches!(intent, ConnectionIntent::BtspHandshake));
    }

    #[tokio::test]
    async fn classify_clear_btsp_jsonline() {
        let mut s = cursor_stream(&[0xEC, 0x03]);
        let intent = classify_connection(&mut s).await.unwrap();
        assert!(matches!(intent, ConnectionIntent::BtspHandshake));
    }

    #[tokio::test]
    async fn classify_clear_probe() {
        let mut s = cursor_stream(&[0xEC, 0x00]);
        let intent = classify_connection(&mut s).await.unwrap();
        assert!(matches!(intent, ConnectionIntent::Probe));
    }

    #[tokio::test]
    async fn classify_clear_unknown_protocol() {
        let mut s = cursor_stream(&[0xEC, 0xFF]);
        let intent = classify_connection(&mut s).await.unwrap();
        assert!(matches!(intent, ConnectionIntent::Reject));
    }

    #[tokio::test]
    async fn classify_mito_rejects() {
        let mut s = cursor_stream(&[0xED, 0x00, 0x00, 0x00, 0x00]);
        let intent = classify_connection(&mut s).await.unwrap();
        assert!(matches!(intent, ConnectionIntent::Reject));
    }

    #[tokio::test]
    async fn classify_nuclear_rejects() {
        let mut s = cursor_stream(&[0xEE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let intent = classify_connection(&mut s).await.unwrap();
        assert!(matches!(intent, ConnectionIntent::Reject));
    }

    #[tokio::test]
    async fn classify_g65_negotiation() {
        let mut s = cursor_stream(b"PROTOCOLS: tarpc,jsonrpc\n");
        let intent = classify_connection(&mut s).await.unwrap();
        assert!(matches!(intent, ConnectionIntent::ProtocolNegotiation));
    }

    #[tokio::test]
    async fn classify_legacy_json_brace() {
        let mut s = cursor_stream(b"{");
        let intent = classify_connection(&mut s).await.unwrap();
        assert!(matches!(
            intent,
            ConnectionIntent::Legacy { first_byte: b'{' }
        ));
    }

    #[tokio::test]
    async fn classify_legacy_btsp_arbitrary() {
        let mut s = cursor_stream(&[0x42]);
        let intent = classify_connection(&mut s).await.unwrap();
        assert!(matches!(
            intent,
            ConnectionIntent::Legacy { first_byte: 0x42 }
        ));
    }

    #[tokio::test]
    async fn classify_empty_stream_errors() {
        let mut s = cursor_stream(&[]);
        assert!(classify_connection(&mut s).await.is_err());
    }

    #[tokio::test]
    async fn classify_clear_truncated_errors() {
        let mut s = cursor_stream(&[0xEC]);
        assert!(classify_connection(&mut s).await.is_err());
    }
}

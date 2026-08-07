// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Transport layer — G66 transport abstraction + riboCipher routing.
//!
//! ## G66 Transport Abstraction
//!
//! [`TransportStream`] and [`TransportListener`] eliminate silicon deism:
//! all `#[cfg(unix)]` for stream/listener variants lives here, not in
//! business logic. IPC modules operate on transport-agnostic types.
//!
//! ## Protocol Detection (riboCipher)
//!
//! | First byte | Action |
//! |------------|--------|
//! | `P` (0x50) | G65 protocol negotiation (`PROTOCOLS: ...`) |
//! | `0xEC`     | Clear riboCipher — read 2nd byte for protocol type |
//! | `0xED`     | Mito-obfuscated riboCipher — not yet implemented, reject |
//! | `0xEE`     | Nuclear-sealed riboCipher — not yet implemented, reject |
//! | other      | Legacy (deprecated) — log warning, fall back to old peek logic |

mod btsp;
mod config;
mod error;
pub mod frame;
pub mod listener;
pub mod negotiate;
mod peek;
pub mod stream;

pub use error::TransportError;

pub use btsp::{read_frame, write_frame};
pub use config::{BtspConfig, BtspHandshakeConfig};
pub use listener::{TransportListener, bind_transport};
pub use negotiate::SessionRegistry;
pub use stream::TransportStream;

use btsp::perform_server_handshake;
use negotiate::SessionRegistry as BtspSessionRegistry;
use peek::PeekedStream;
use std::sync::Arc;
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

/// Construct a [`CallerContext`] from a [`TransportStream`]'s metadata.
fn caller_from_stream(stream: &TransportStream) -> CallerContext {
    match stream {
        #[cfg(unix)]
        TransportStream::Unix(_) => CallerContext::unix(),
        TransportStream::Tcp(s) => match s.peer_addr() {
            Ok(addr) if addr.ip().is_loopback() => CallerContext::loopback(),
            Ok(addr) => CallerContext::remote_with_addr(addr.to_string()),
            Err(_) => CallerContext::remote_with_addr("unknown".to_owned()),
        },
    }
}

/// Unified accept loop — transport-agnostic (G66).
///
/// Accepts connections on any [`TransportListener`], classifies via
/// riboCipher signal + G65 negotiation, and dispatches to the appropriate
/// handler.
pub async fn serve_listener(
    listener: TransportListener,
    state: Arc<RwLock<App>>,
    sessions: Arc<BtspSessionRegistry>,
    btsp_config: Option<Arc<BtspHandshakeConfig>>,
) -> Result<(), TransportError> {
    tracing::info!(
        transport = listener.transport_name(),
        "IPC listener ready (G66)"
    );

    loop {
        let mut stream = listener.accept().await?;
        let label = stream.peer_label();
        tracing::debug!("{label} connection accepted");

        let state = Arc::clone(&state);
        let btsp = btsp_config.clone();
        let sessions = Arc::clone(&sessions);

        tokio::spawn(async move {
            let intent = match classify_connection(&mut stream).await {
                Ok(i) => i,
                Err(e) => {
                    tracing::debug!("{label}: failed to read signal: {e}");
                    return;
                }
            };

            let mut caller = caller_from_stream(&stream);

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

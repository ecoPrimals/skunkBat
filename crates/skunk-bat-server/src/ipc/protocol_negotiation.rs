// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! G65 Protocol Negotiation — single-socket protocol selection.
//!
//! Enables automatic protocol selection between JSON-RPC and tarpc at connection
//! time. Phase 3 of cephalization: a single socket serves both protocols via a
//! text-line handshake, eliminating the C2 dual-socket pattern.
//!
//! ## Wire Protocol
//!
//! ```text
//! Client → Server: "PROTOCOLS: tarpc,jsonrpc\n"
//! Server → Client: "PROTOCOL: tarpc\n"
//! [Connection proceeds with selected protocol]
//! ```
//!
//! ## Backward Compatibility
//!
//! If the first byte is NOT `P` (the start of `PROTOCOLS:`), the connection
//! falls through to riboCipher classification. Legacy clients need zero changes.

use serde::{Deserialize, Serialize};
use std::fmt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};

/// RPC protocol variants for protocol negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum IpcProtocol {
    /// JSON-RPC 2.0 — text-based, backward-compatible default.
    #[default]
    JsonRpc,
    /// tarpc — binary, type-safe, high-performance intra-gate protocol.
    Tarpc,
}

impl fmt::Display for IpcProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

impl IpcProtocol {
    /// Wire name used in `PROTOCOLS:` / `PROTOCOL:` lines.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::JsonRpc => "jsonrpc",
            Self::Tarpc => "tarpc",
        }
    }

    /// Parse from wire name (case-insensitive, aliases accepted).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "jsonrpc" | "json-rpc" | "json_rpc" => Some(Self::JsonRpc),
            "tarpc" | "binary" => Some(Self::Tarpc),
            _ => None,
        }
    }

    /// All protocols this build supports (tarpc preferred).
    #[must_use]
    pub fn all_supported() -> Vec<Self> {
        vec![Self::Tarpc, Self::JsonRpc]
    }
}

/// Client's protocol negotiation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationRequest {
    /// Protocols the client supports, in preference order.
    pub supported: Vec<IpcProtocol>,
}

impl NegotiationRequest {
    /// Serialize to wire format: `"PROTOCOLS: tarpc,jsonrpc\n"`
    #[must_use]
    pub fn to_wire(&self) -> String {
        let names: Vec<&str> = self
            .supported
            .iter()
            .copied()
            .map(IpcProtocol::wire_name)
            .collect();
        format!("PROTOCOLS: {}\n", names.join(","))
    }

    /// Parse from wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if the line doesn't start with `PROTOCOLS: ` or has no valid protocols.
    pub fn from_wire(line: &str) -> Result<Self, NegotiationError> {
        let body = line
            .trim()
            .strip_prefix("PROTOCOLS: ")
            .ok_or(NegotiationError::InvalidRequest)?;

        let supported: Vec<IpcProtocol> = body
            .split(',')
            .filter_map(|s| IpcProtocol::parse(s.trim()))
            .collect();

        if supported.is_empty() {
            return Err(NegotiationError::NoValidProtocols);
        }

        Ok(Self { supported })
    }
}

/// Server's protocol selection response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiationResponse {
    /// The protocol the server selected.
    pub selected: IpcProtocol,
}

impl NegotiationResponse {
    /// Serialize to wire format: `"PROTOCOL: tarpc\n"`
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("PROTOCOL: {}\n", self.selected.wire_name())
    }

    /// Parse from wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if the line doesn't match the expected format.
    pub fn from_wire(line: &str) -> Result<Self, NegotiationError> {
        let name = line
            .trim()
            .strip_prefix("PROTOCOL: ")
            .ok_or(NegotiationError::InvalidResponse)?;

        let selected = IpcProtocol::parse(name).ok_or(NegotiationError::UnknownProtocol)?;
        Ok(Self { selected })
    }
}

/// Errors during protocol negotiation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NegotiationError {
    /// Line does not start with `PROTOCOLS: `.
    #[error("invalid negotiation request (expected PROTOCOLS: ...)")]
    InvalidRequest,
    /// Line does not start with `PROTOCOL: `.
    #[error("invalid negotiation response (expected PROTOCOL: ...)")]
    InvalidResponse,
    /// None of the listed protocols are recognized.
    #[error("no valid protocols in request")]
    NoValidProtocols,
    /// Protocol name not recognized.
    #[error("unknown protocol name")]
    UnknownProtocol,
    /// I/O error during negotiation.
    #[error("negotiation I/O error: {0}")]
    Io(String),
}

/// Select the best protocol: first from `client_prefs` that `server_supports` also contains.
///
/// Falls back to `JsonRpc` if no intersection.
#[must_use]
pub fn select_protocol(
    client_prefs: &[IpcProtocol],
    server_supports: &[IpcProtocol],
) -> IpcProtocol {
    for proto in client_prefs {
        if server_supports.contains(proto) {
            return *proto;
        }
    }
    IpcProtocol::JsonRpc
}

/// Complete G65 server-side negotiation on a stream where `P` was already consumed.
///
/// Reads the rest of the `PROTOCOLS:` line (the `P` has been consumed by the
/// connection classifier), sends back `PROTOCOL: <selected>\n`, and returns
/// the selected protocol.
///
/// # Errors
///
/// Returns `NegotiationError` on I/O failure or malformed request.
pub async fn negotiate_server_after_p<S>(
    stream: &mut S,
    server_supported: &[IpcProtocol],
) -> Result<IpcProtocol, NegotiationError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(&mut *stream);
    let mut rest = String::new();

    let read_result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        reader.read_line(&mut rest),
    )
    .await;

    match read_result {
        Ok(Ok(n)) if n > 0 => {
            let full_line = format!("P{rest}");
            let trimmed = full_line.trim();

            if trimmed.starts_with("PROTOCOLS: ") {
                let request = NegotiationRequest::from_wire(&full_line)?;
                let selected = select_protocol(&request.supported, server_supported);

                let response = NegotiationResponse { selected };
                debug!("G65 negotiated: {selected}");

                stream
                    .write_all(response.to_wire().as_bytes())
                    .await
                    .map_err(|e| NegotiationError::Io(e.to_string()))?;
                stream
                    .flush()
                    .await
                    .map_err(|e| NegotiationError::Io(e.to_string()))?;

                info!("G65 protocol selected: {selected}");
                Ok(selected)
            } else {
                warn!("G65: first byte was 'P' but line is not PROTOCOLS: {trimmed}");
                Ok(IpcProtocol::JsonRpc)
            }
        }
        Ok(Err(e)) => {
            warn!("G65 negotiation read error: {e}");
            Ok(IpcProtocol::JsonRpc)
        }
        _ => {
            debug!("G65 negotiation timed out — fallback to JSON-RPC");
            Ok(IpcProtocol::JsonRpc)
        }
    }
}

/// Client-side negotiation: send preferences, receive server's selection.
///
/// # Errors
///
/// Returns `NegotiationError` on I/O failure or invalid response.
pub async fn negotiate_client<T>(
    transport: &mut T,
    supported: &[IpcProtocol],
) -> Result<IpcProtocol, NegotiationError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = NegotiationRequest {
        supported: supported.to_vec(),
    };
    let wire = request.to_wire();

    debug!("G65 client sending: {:?}", wire.trim());
    transport
        .write_all(wire.as_bytes())
        .await
        .map_err(|e| NegotiationError::Io(e.to_string()))?;
    transport
        .flush()
        .await
        .map_err(|e| NegotiationError::Io(e.to_string()))?;

    let mut reader = BufReader::new(transport);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|e| NegotiationError::Io(e.to_string()))?;

    let response = NegotiationResponse::from_wire(&line)?;
    info!("G65 negotiated: {}", response.selected);
    Ok(response.selected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_protocol_display() {
        assert_eq!(IpcProtocol::JsonRpc.to_string(), "jsonrpc");
        assert_eq!(IpcProtocol::Tarpc.to_string(), "tarpc");
    }

    #[test]
    fn ipc_protocol_parse() {
        assert_eq!(IpcProtocol::parse("jsonrpc"), Some(IpcProtocol::JsonRpc));
        assert_eq!(IpcProtocol::parse("json-rpc"), Some(IpcProtocol::JsonRpc));
        assert_eq!(IpcProtocol::parse("json_rpc"), Some(IpcProtocol::JsonRpc));
        assert_eq!(IpcProtocol::parse("tarpc"), Some(IpcProtocol::Tarpc));
        assert_eq!(IpcProtocol::parse("binary"), Some(IpcProtocol::Tarpc));
        assert_eq!(IpcProtocol::parse("unknown"), None);
    }

    #[test]
    fn ipc_protocol_serde_roundtrip() {
        for proto in [IpcProtocol::JsonRpc, IpcProtocol::Tarpc] {
            let json = serde_json::to_string(&proto).unwrap();
            let back: IpcProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(proto, back);
        }
    }

    #[test]
    fn request_wire_roundtrip() {
        let req = NegotiationRequest {
            supported: vec![IpcProtocol::Tarpc, IpcProtocol::JsonRpc],
        };
        let wire = req.to_wire();
        assert_eq!(wire, "PROTOCOLS: tarpc,jsonrpc\n");
        let parsed = NegotiationRequest::from_wire(&wire).unwrap();
        assert_eq!(req, parsed);
    }

    #[test]
    fn request_single_protocol() {
        let req = NegotiationRequest {
            supported: vec![IpcProtocol::JsonRpc],
        };
        assert_eq!(req.to_wire(), "PROTOCOLS: jsonrpc\n");
    }

    #[test]
    fn request_invalid_prefix() {
        let err = NegotiationRequest::from_wire("INVALID: foo\n").unwrap_err();
        assert_eq!(err, NegotiationError::InvalidRequest);
    }

    #[test]
    fn request_no_valid_protocols() {
        let err = NegotiationRequest::from_wire("PROTOCOLS: foo,bar\n").unwrap_err();
        assert_eq!(err, NegotiationError::NoValidProtocols);
    }

    #[test]
    fn response_wire_roundtrip() {
        let resp = NegotiationResponse {
            selected: IpcProtocol::Tarpc,
        };
        let wire = resp.to_wire();
        assert_eq!(wire, "PROTOCOL: tarpc\n");
        let parsed = NegotiationResponse::from_wire(&wire).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn response_invalid() {
        let err = NegotiationResponse::from_wire("STATUS: ok\n").unwrap_err();
        assert_eq!(err, NegotiationError::InvalidResponse);
    }

    #[test]
    fn select_protocol_prefers_client_order() {
        let client = &[IpcProtocol::Tarpc, IpcProtocol::JsonRpc];
        let server = &[IpcProtocol::Tarpc, IpcProtocol::JsonRpc];
        assert_eq!(select_protocol(client, server), IpcProtocol::Tarpc);
    }

    #[test]
    fn select_protocol_server_only_jsonrpc() {
        let client = &[IpcProtocol::Tarpc, IpcProtocol::JsonRpc];
        let server = &[IpcProtocol::JsonRpc];
        assert_eq!(select_protocol(client, server), IpcProtocol::JsonRpc);
    }

    #[test]
    fn select_protocol_no_intersection_falls_back() {
        let client = &[IpcProtocol::Tarpc];
        let server = &[IpcProtocol::JsonRpc];
        assert_eq!(select_protocol(client, server), IpcProtocol::JsonRpc);
    }

    #[tokio::test]
    async fn negotiate_duplex_tarpc_preferred() {
        let (mut client_stream, mut server_stream) = tokio::io::duplex(4096);

        let server_supported = IpcProtocol::all_supported();
        let server_task = tokio::spawn(async move {
            let mut line = String::new();
            let mut reader = BufReader::new(&mut server_stream);
            reader.read_line(&mut line).await.unwrap();

            let request = NegotiationRequest::from_wire(&line).unwrap();
            let selected = select_protocol(&request.supported, &server_supported);
            let response = NegotiationResponse { selected };
            server_stream
                .write_all(response.to_wire().as_bytes())
                .await
                .unwrap();
            server_stream.flush().await.unwrap();
            selected
        });

        let client_result = negotiate_client(
            &mut client_stream,
            &[IpcProtocol::Tarpc, IpcProtocol::JsonRpc],
        )
        .await
        .unwrap();
        assert_eq!(client_result, IpcProtocol::Tarpc);

        let server_result = server_task.await.unwrap();
        assert_eq!(server_result, IpcProtocol::Tarpc);
    }

    #[tokio::test]
    async fn negotiate_duplex_jsonrpc_only_server() {
        let (mut client_stream, mut server_stream) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut line = String::new();
            let mut reader = BufReader::new(&mut server_stream);
            reader.read_line(&mut line).await.unwrap();

            let request = NegotiationRequest::from_wire(&line).unwrap();
            let selected = select_protocol(&request.supported, &[IpcProtocol::JsonRpc]);
            let response = NegotiationResponse { selected };
            server_stream
                .write_all(response.to_wire().as_bytes())
                .await
                .unwrap();
            server_stream.flush().await.unwrap();
            selected
        });

        let client_result = negotiate_client(
            &mut client_stream,
            &[IpcProtocol::Tarpc, IpcProtocol::JsonRpc],
        )
        .await
        .unwrap();
        assert_eq!(client_result, IpcProtocol::JsonRpc);

        let server_result = server_task.await.unwrap();
        assert_eq!(server_result, IpcProtocol::JsonRpc);
    }

    #[tokio::test]
    async fn negotiate_server_after_p_tarpc() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            negotiate_server_after_p(&mut server, &IpcProtocol::all_supported()).await
        });

        client
            .write_all(b"PROTOCOLS: tarpc,jsonrpc\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        // Server reads from after 'P' — simulate by sending the full line
        // and having the server reconstruct. In production, classify_connection
        // consumes the 'P' and the server reads "ROTOCOLS: tarpc,jsonrpc\n".
        // For this test, we write the full line and the server wraps with 'P'.
        // Actually, negotiate_server_after_p expects 'P' already consumed:
        // it reads "ROTOCOLS: tarpc,jsonrpc\n" and prepends 'P'.

        // Re-do: write without the 'P'
        drop(client);
        drop(server_task);

        let (mut client2, mut server2) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            negotiate_server_after_p(&mut server2, &IpcProtocol::all_supported()).await
        });

        client2
            .write_all(b"ROTOCOLS: tarpc,jsonrpc\n")
            .await
            .unwrap();
        client2.flush().await.unwrap();

        let result = task.await.unwrap().unwrap();
        assert_eq!(result, IpcProtocol::Tarpc);
    }

    #[tokio::test]
    async fn negotiate_server_after_p_jsonrpc_only() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            negotiate_server_after_p(&mut server, &[IpcProtocol::JsonRpc]).await
        });

        client
            .write_all(b"ROTOCOLS: tarpc,jsonrpc\n")
            .await
            .unwrap();
        client.flush().await.unwrap();

        let result = task.await.unwrap().unwrap();
        assert_eq!(result, IpcProtocol::JsonRpc);
    }
}

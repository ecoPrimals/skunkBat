// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! JSON-RPC connection handler with BTSP Phase 3 encrypted framing.
//!
//! Starts in NDJSON (newline-delimited) mode. When a `btsp.negotiate`
//! request produces session keys, the connection upgrades to
//! length-prefixed encrypted frames:
//! ```text
//! [4B length (big-endian u32)][12B nonce || ciphertext || 16B Poly1305 tag]
//! ```
//!
//! Supports single requests, batch requests (JSON arrays), and
//! notifications (requests without `id` — no response sent).
//!
//! **Transport upgrade rule**: `btsp.negotiate` must be sent as a standalone
//! request, not within a JSON-RPC batch array. Sending it inside a batch
//! returns an invalid-request error — transport upgrades are incompatible
//! with batch semantics (wire format changes mid-response are undefined).

use skunk_bat_core::SkunkBat;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;

use super::dispatch;
use super::jsonrpc::{self, Response};
use super::transport::negotiate::{self, SessionKeys, SessionRegistry};
use super::transport::{read_frame, write_frame};

/// Handle a single JSON-RPC connection (NDJSON → encrypted upgrade).
pub(super) async fn handle_connection<S>(
    state: Arc<RwLock<SkunkBat>>,
    sessions: Arc<SessionRegistry>,
    stream: S,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match try_negotiate_upgrade(&state, &sessions, trimmed, &mut writer).await {
            NegotiateAction::Upgrade(keys) => {
                tracing::info!("BTSP Phase 3: switching to encrypted framing");
                let buf_reader = lines.into_inner();
                if !buf_reader.buffer().is_empty() {
                    tracing::warn!(
                        "BufReader has {} leftover bytes at negotiate boundary — \
                         discarding (protocol violation: client must await response \
                         before sending encrypted frames)",
                        buf_reader.buffer().len()
                    );
                }
                let inner_reader = buf_reader.into_inner();
                run_encrypted_frame_loop(state, sessions, inner_reader, writer, &keys).await;
                return;
            }
            NegotiateAction::Handled => continue,
            NegotiateAction::NotNegotiate => {}
        }

        let first_byte = trimmed.as_bytes().first().copied();
        let response_bytes = match first_byte {
            Some(b'[') => handle_batch(&state, &sessions, trimmed).await,
            _ => handle_single(&state, &sessions, trimmed).await,
        };

        let Some(mut bytes) = response_bytes else {
            continue;
        };
        bytes.push(b'\n');

        if writer.write_all(&bytes).await.is_err() {
            break;
        }
        if writer.flush().await.is_err() {
            break;
        }
    }
}

/// Result of attempting to handle a `btsp.negotiate` request.
enum NegotiateAction {
    /// Request was not `btsp.negotiate` — process normally.
    NotNegotiate,
    /// Negotiate was handled (response sent), but no encryption — stay on NDJSON.
    Handled,
    /// Negotiate succeeded with encryption — switch to encrypted frame I/O.
    Upgrade(SessionKeys),
}

/// Check if a request is `btsp.negotiate` and handle the upgrade in-band.
///
/// Sends the negotiate response via NDJSON and returns the appropriate action:
/// - `Upgrade(keys)` → caller switches to encrypted frame loop
/// - `Handled` → response already sent, caller skips this line
/// - `NotNegotiate` → not a negotiate request, process normally
async fn try_negotiate_upgrade<W>(
    _state: &Arc<RwLock<SkunkBat>>,
    sessions: &Arc<SessionRegistry>,
    line: &str,
    writer: &mut W,
) -> NegotiateAction
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let Ok(request) = serde_json::from_str::<jsonrpc::Request>(line) else {
        return NegotiateAction::NotNegotiate;
    };

    if request.method != "btsp.negotiate" {
        return NegotiateAction::NotNegotiate;
    }

    let id = request.id_or_null();
    let outcome = negotiate::handle_negotiate(sessions, request.params).await;

    let response = if outcome.response.get("error").is_some() {
        Response::error(
            id,
            jsonrpc::INVALID_PARAMS,
            outcome.response["message"]
                .as_str()
                .unwrap_or("negotiate failed"),
        )
    } else {
        Response::success(id, outcome.response)
    };

    let mut bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
    bytes.push(b'\n');

    if writer.write_all(&bytes).await.is_err() || writer.flush().await.is_err() {
        return NegotiateAction::Handled;
    }

    outcome
        .session_keys
        .map_or(NegotiateAction::Handled, NegotiateAction::Upgrade)
}

/// Encrypted BTSP frame loop — reads length-prefixed encrypted frames,
/// decrypts, dispatches JSON-RPC, encrypts response, writes.
async fn run_encrypted_frame_loop<R, W>(
    state: Arc<RwLock<SkunkBat>>,
    sessions: Arc<SessionRegistry>,
    mut reader: R,
    mut writer: W,
    keys: &SessionKeys,
) where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
{
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                tracing::warn!("BTSP encrypted frame read error: {e}");
                break;
            }
        };

        let plaintext = match negotiate::decrypt_frame(&keys.decrypt_key, &frame) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("BTSP decrypt error: {e}");
                break;
            }
        };

        let line = match std::str::from_utf8(&plaintext) {
            Ok(s) => s.trim(),
            Err(e) => {
                tracing::warn!("BTSP decrypted frame is not valid UTF-8: {e}");
                break;
            }
        };

        let first_byte = line.as_bytes().first().copied();
        let response_bytes = match first_byte {
            Some(b'[') => handle_batch(&state, &sessions, line).await,
            _ => handle_single(&state, &sessions, line).await,
        };

        if let Some(bytes) = response_bytes {
            let encrypted = match negotiate::encrypt_frame(&keys.encrypt_key, &bytes) {
                Ok(e) => e,
                Err(err) => {
                    tracing::warn!("BTSP encrypt error: {err}");
                    break;
                }
            };
            if write_frame(&mut writer, &encrypted).await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
    }
}

/// Handle a single JSON-RPC request. Returns `None` for notifications.
///
/// `btsp.negotiate` is handled by `try_negotiate_upgrade` before this
/// function runs. If it reaches here (e.g. inside the encrypted frame
/// loop), it is processed as a regular negotiate without upgrade.
async fn handle_single(
    state: &Arc<RwLock<SkunkBat>>,
    sessions: &Arc<SessionRegistry>,
    line: &str,
) -> Option<Vec<u8>> {
    match serde_json::from_str::<jsonrpc::Request>(line) {
        Ok(request) => {
            if request.method == "btsp.negotiate" {
                let id = request.id_or_null();
                let outcome = negotiate::handle_negotiate(sessions, request.params).await;
                let response = if outcome.response.get("error").is_some() {
                    Response::error(
                        id,
                        jsonrpc::INVALID_PARAMS,
                        outcome.response["message"]
                            .as_str()
                            .unwrap_or("negotiate failed"),
                    )
                } else {
                    Response::success(id, outcome.response)
                };
                return Some(serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec()));
            }
            if request.is_notification() {
                dispatch::dispatch(state, request).await;
                return None;
            }
            let response = dispatch::dispatch(state, request).await;
            Some(serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec()))
        }
        Err(e) => Some(
            serde_json::to_vec(&Response::error(
                serde_json::Value::Null,
                jsonrpc::PARSE_ERROR,
                format!("parse error: {e}"),
            ))
            .unwrap_or_else(|_| b"{}".to_vec()),
        ),
    }
}

/// Handle a batch JSON-RPC request (array of requests).
///
/// Per JSON-RPC 2.0 spec: responses are collected and returned as a JSON
/// array. Notification responses are omitted. An empty batch returns an
/// invalid-request error. `btsp.negotiate` is rejected inside batches
/// (transport upgrades require standalone requests).
async fn handle_batch(
    state: &Arc<RwLock<SkunkBat>>,
    _sessions: &Arc<SessionRegistry>,
    line: &str,
) -> Option<Vec<u8>> {
    let requests: Vec<serde_json::Value> = match serde_json::from_str(line) {
        Ok(arr) => arr,
        Err(e) => {
            return Some(
                serde_json::to_vec(&Response::error(
                    serde_json::Value::Null,
                    jsonrpc::PARSE_ERROR,
                    format!("batch parse error: {e}"),
                ))
                .unwrap_or_else(|_| b"{}".to_vec()),
            );
        }
    };

    if requests.is_empty() {
        return Some(
            serde_json::to_vec(&Response::error(
                serde_json::Value::Null,
                jsonrpc::INVALID_REQUEST,
                "empty batch",
            ))
            .unwrap_or_else(|_| b"{}".to_vec()),
        );
    }

    let mut responses = Vec::new();

    for raw in requests {
        match serde_json::from_value::<jsonrpc::Request>(raw) {
            Ok(request) => {
                if request.method == "btsp.negotiate" {
                    let id = request.id_or_null();
                    responses.push(Response::error(
                        id,
                        jsonrpc::INVALID_REQUEST,
                        "btsp.negotiate must be sent as a standalone request, not within a batch",
                    ));
                    continue;
                }
                let is_notification = request.is_notification();
                let response = dispatch::dispatch(state, request).await;
                if !is_notification {
                    responses.push(response);
                }
            }
            Err(e) => {
                responses.push(Response::error(
                    serde_json::Value::Null,
                    jsonrpc::INVALID_REQUEST,
                    format!("invalid request in batch: {e}"),
                ));
            }
        }
    }

    if responses.is_empty() {
        return None;
    }

    Some(serde_json::to_vec(&responses).unwrap_or_else(|_| b"[]".to_vec()))
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

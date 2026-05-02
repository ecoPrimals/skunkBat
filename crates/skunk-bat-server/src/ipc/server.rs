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

        if let Some(keys) = try_negotiate_upgrade(&state, &sessions, trimmed, &mut writer).await {
            tracing::info!("BTSP Phase 3: switching to encrypted framing");
            let inner_reader = lines.into_inner().into_inner();
            run_encrypted_frame_loop(state, sessions, inner_reader, writer, &keys).await;
            return;
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

/// Check if a request is `btsp.negotiate` and handle the upgrade in-band.
///
/// Sends the negotiate response via NDJSON, then returns `Some(keys)` if
/// encryption was established so the caller can switch to frame mode.
async fn try_negotiate_upgrade<W>(
    _state: &Arc<RwLock<SkunkBat>>,
    sessions: &Arc<SessionRegistry>,
    line: &str,
    writer: &mut W,
) -> Option<SessionKeys>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let request: jsonrpc::Request = serde_json::from_str(line).ok()?;

    if request.method != "btsp.negotiate" {
        return None;
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
        return None;
    }

    outcome.session_keys
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
/// `btsp.negotiate` within a single request is handled by
/// `try_negotiate_upgrade` before this function runs. This path remains
/// as a fallback for negotiate requests inside batch arrays.
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
/// invalid-request error.
async fn handle_batch(
    state: &Arc<RwLock<SkunkBat>>,
    sessions: &Arc<SessionRegistry>,
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
                    responses.push(response);
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
mod tests {
    use super::*;
    use skunk_bat_core::SkunkBatConfig;
    use std::time::Duration;

    fn make_state() -> Arc<RwLock<SkunkBat>> {
        Arc::new(RwLock::new(SkunkBat::new(SkunkBatConfig::default())))
    }

    fn make_sessions() -> Arc<SessionRegistry> {
        Arc::new(SessionRegistry::new())
    }

    async fn roundtrip(input: &str) -> String {
        let state = make_state();
        let sessions = make_sessions();
        let (client, server) = tokio::io::duplex(4096);

        let handle = tokio::spawn(handle_connection(state, sessions, server));

        let (client_reader, mut client_writer) = tokio::io::split(client);
        client_writer
            .write_all(format!("{input}\n").as_bytes())
            .await
            .unwrap();
        client_writer.shutdown().await.unwrap();

        let mut reader = BufReader::new(client_reader);
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("timeout reading response")
            .unwrap();

        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        line
    }

    #[tokio::test]
    async fn test_single_request() {
        let line = roundtrip(r#"{"jsonrpc":"2.0","method":"health.liveness","id":1}"#).await;
        assert!(line.contains("alive"));
    }

    #[tokio::test]
    async fn test_parse_error() {
        let line = roundtrip("not json at all").await;
        assert!(line.contains("-32700"));
    }

    #[tokio::test]
    async fn test_batch_request() {
        let line = roundtrip(
            r#"[{"jsonrpc":"2.0","method":"health.liveness","id":1},{"jsonrpc":"2.0","method":"identity.get","id":2}]"#,
        )
        .await;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[tokio::test]
    async fn test_empty_batch() {
        let line = roundtrip("[]").await;
        assert!(line.contains("-32600"));
    }

    #[tokio::test]
    async fn test_notification_no_response() {
        let state = make_state();
        let sessions = make_sessions();
        let (client, server) = tokio::io::duplex(4096);

        let handle = tokio::spawn(handle_connection(state, sessions, server));

        let (client_reader, mut client_writer) = tokio::io::split(client);
        client_writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"health.liveness\"}\n")
            .await
            .unwrap();
        client_writer.shutdown().await.unwrap();

        let mut reader = BufReader::new(client_reader);
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .expect("timeout")
            .unwrap();

        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert_eq!(n, 0, "notification should produce no response");
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let line = roundtrip(r#"{"jsonrpc":"2.0","method":"bogus.call","id":99}"#).await;
        assert!(line.contains("-32601"));
    }

    #[tokio::test]
    async fn test_btsp_negotiate_no_session() {
        let line = roundtrip(
            r#"{"jsonrpc":"2.0","method":"btsp.negotiate","params":{"session_id":"fake","preferred_cipher":"chacha20-poly1305","bond_type":"Covalent"},"id":10}"#,
        ).await;
        let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert!(resp["error"].is_object());
    }

    #[tokio::test]
    async fn test_btsp_negotiate_null_cipher_session() {
        let state = make_state();
        let sessions = make_sessions();
        sessions.insert("test-session-1".into(), None).await;

        let (client, server) = tokio::io::duplex(4096);
        let handle = tokio::spawn(handle_connection(state, sessions, server));

        let (client_reader, mut client_writer) = tokio::io::split(client);
        let req = r#"{"jsonrpc":"2.0","method":"btsp.negotiate","params":{"session_id":"test-session-1","preferred_cipher":"chacha20-poly1305","bond_type":"Covalent"},"id":10}"#;
        client_writer
            .write_all(format!("{req}\n").as_bytes())
            .await
            .unwrap();
        client_writer.shutdown().await.unwrap();

        let mut reader = BufReader::new(client_reader);
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("timeout")
            .unwrap();

        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert!(resp["error"].is_null());
        let result = &resp["result"];
        assert_eq!(result["cipher"], "null");
        assert!(result["server_nonce"].is_string());
    }

    #[tokio::test]
    async fn test_btsp_negotiate_upgrade_to_encrypted() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as BASE64;
        use tokio::io::AsyncReadExt;

        let state = make_state();
        let sessions = make_sessions();
        let handshake_key = vec![0x42u8; 32];
        sessions
            .insert("enc-session".into(), Some(handshake_key.clone()))
            .await;

        let (client, server) = tokio::io::duplex(8192);
        let handle = tokio::spawn(handle_connection(state, sessions, server));

        let (client_reader, mut client_writer) = tokio::io::split(client);

        let client_nonce = [0x01u8; 16];
        let client_nonce_b64 = BASE64.encode(client_nonce);
        let negotiate_req = format!(
            r#"{{"jsonrpc":"2.0","method":"btsp.negotiate","params":{{"session_id":"enc-session","ciphers":["chacha20-poly1305"],"client_nonce":"{client_nonce_b64}"}},"id":1}}"#
        );
        client_writer
            .write_all(format!("{negotiate_req}\n").as_bytes())
            .await
            .unwrap();

        let mut reader = BufReader::new(client_reader);
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("timeout reading negotiate response")
            .unwrap();

        let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let result = &resp["result"];
        assert_eq!(result["cipher"], "chacha20-poly1305");

        let server_nonce = BASE64
            .decode(result["server_nonce"].as_str().unwrap())
            .unwrap();
        assert_eq!(server_nonce.len(), 32);

        let server_keys =
            negotiate::derive_session_keys(&handshake_key, &client_nonce, &server_nonce);

        let rpc_request = r#"{"jsonrpc":"2.0","method":"health.liveness","id":2}"#;
        let encrypted =
            negotiate::encrypt_frame(&server_keys.decrypt_key, rpc_request.as_bytes()).unwrap();

        let len = u32::try_from(encrypted.len()).unwrap();
        client_writer.write_u32(len).await.unwrap();
        client_writer.write_all(&encrypted).await.unwrap();
        client_writer.flush().await.unwrap();

        let mut inner_reader = reader.into_inner();
        let resp_len = tokio::time::timeout(Duration::from_secs(5), inner_reader.read_u32())
            .await
            .expect("timeout reading response length")
            .unwrap();
        let mut resp_buf = vec![0u8; resp_len as usize];
        inner_reader.read_exact(&mut resp_buf).await.unwrap();

        let decrypted = negotiate::decrypt_frame(&server_keys.encrypt_key, &resp_buf).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();
        assert!(
            response["result"]["status"]
                .as_str()
                .unwrap()
                .contains("alive")
        );

        drop(client_writer);
        drop(inner_reader);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
}

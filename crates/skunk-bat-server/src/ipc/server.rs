// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Newline-delimited JSON-RPC connection handler.
//!
//! Supports single requests, batch requests (JSON arrays), and
//! notifications (requests without `id` — no response sent).
//! Routes `btsp.negotiate` to the Phase 3 cipher negotiation handler.

use skunk_bat_core::SkunkBat;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;

use super::dispatch;
use super::jsonrpc::{self, Response};
use super::transport::negotiate::{self, SessionRegistry};

/// Handle a single newline-delimited JSON-RPC connection.
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

/// Handle a single JSON-RPC request. Returns `None` for notifications.
async fn handle_single(
    state: &Arc<RwLock<SkunkBat>>,
    sessions: &Arc<SessionRegistry>,
    line: &str,
) -> Option<Vec<u8>> {
    match serde_json::from_str::<jsonrpc::Request>(line) {
        Ok(request) => {
            if request.method == "btsp.negotiate" {
                let id = request.id_or_null();
                let result = negotiate::handle_negotiate(sessions, request.params).await;
                let response = if result.get("error").is_some() {
                    Response::error(
                        id,
                        jsonrpc::INVALID_PARAMS,
                        result["message"].as_str().unwrap_or("negotiate failed"),
                    )
                } else {
                    Response::success(id, result)
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
                    let result = negotiate::handle_negotiate(sessions, request.params).await;
                    let response = if result.get("error").is_some() {
                        Response::error(
                            id,
                            jsonrpc::INVALID_PARAMS,
                            result["message"].as_str().unwrap_or("negotiate failed"),
                        )
                    } else {
                        Response::success(id, result)
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
    async fn test_btsp_negotiate_with_session() {
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
}

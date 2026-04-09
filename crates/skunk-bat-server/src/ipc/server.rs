// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Newline-delimited JSON-RPC connection handler.

use skunk_bat_core::SkunkBat;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;

use super::dispatch;
use super::jsonrpc::{self, Response};

/// Handle a single newline-delimited JSON-RPC connection.
pub(super) async fn handle_connection<S>(state: Arc<RwLock<SkunkBat>>, stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<jsonrpc::Request>(&line) {
            Ok(request) => dispatch::dispatch(&state, request).await,
            Err(e) => Response::error(
                serde_json::Value::Null,
                jsonrpc::PARSE_ERROR,
                format!("parse error: {e}"),
            ),
        };

        let mut response_bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
        response_bytes.push(b'\n');

        if writer.write_all(&response_bytes).await.is_err() {
            break;
        }
        if writer.flush().await.is_err() {
            break;
        }
    }
}

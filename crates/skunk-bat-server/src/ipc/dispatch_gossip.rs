// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Gossip proxy — forwards `gossip.inject` and `gossip.query` to swarmVine UDS.
//!
//! skunkBat is a CONSUMED consumer of gossip (it calls gossip.inject on behalf
//! of skunky-ingest and its own fleet detection). The actual gossip engine lives
//! in swarmVine. This module proxies requests to the local swarmVine UDS socket.
//!
//! Pattern: fire-and-forget (borrowed from barraCuda `ipc/gossip.rs`).
//! Socket discovery: `SWARMVINE_SOCKET` env → `$XDG_RUNTIME_DIR/biomeos/swarmvine.sock`.

use super::jsonrpc;
use super::jsonrpc::Response;
use std::sync::OnceLock;
use std::time::Duration;

const SWARMVINE_SOCKET_ENV: &str = "SWARMVINE_SOCKET";
#[allow(dead_code)] // reserved for connect-with-timeout path
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const WRITE_TIMEOUT: Duration = Duration::from_millis(500);
const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Discover the swarmVine UDS path.
#[cfg(unix)]
fn discover_swarmvine_socket() -> Option<std::path::PathBuf> {
    if let Ok(path) = std::env::var(SWARMVINE_SOCKET_ENV) {
        let p = std::path::PathBuf::from(&path);
        if p.exists() {
            return Some(p);
        }
    }

    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let p = std::path::PathBuf::from(xdg).join("biomeos/swarmvine.sock");
        if p.exists() {
            return Some(p);
        }
    }

    // Production fallback: membrane runtime dir
    let membrane = std::path::PathBuf::from("/run/membrane/swarmvine.sock");
    if membrane.exists() {
        return Some(membrane);
    }

    None
}

/// Gate name for gossip origin tagging.
#[allow(dead_code)] // wired when gossip.inject carries origin metadata
fn gate_name() -> &'static str {
    static GATE: OnceLock<String> = OnceLock::new();
    GATE.get_or_init(|| {
        std::env::var("GATE_NAME").unwrap_or_else(|_| hostname())
    })
}

#[allow(dead_code)] // used by gate_name()
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".into())
}

/// Forward a JSON-RPC request to swarmVine UDS and return the response.
#[cfg(unix)]
fn forward_to_swarmvine(
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    use std::io::{BufRead, Write};
    use std::os::unix::net::UnixStream;

    let socket_path = discover_swarmvine_socket()
        .ok_or_else(|| "swarmVine socket not found".to_string())?;

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });

    let line = serde_json::to_string(&request)
        .map_err(|e| format!("serialize error: {e}"))?;

    let stream = UnixStream::connect(&socket_path)
        .map_err(|e| format!("connect to swarmVine: {e}"))?;

    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));

    let mut writer = std::io::BufWriter::new(&stream);
    writer
        .write_all(line.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    writer
        .write_all(b"\n")
        .map_err(|e| format!("write newline: {e}"))?;
    writer.flush().map_err(|e| format!("flush: {e}"))?;

    let mut reader = std::io::BufReader::new(&stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|e| format!("read response: {e}"))?;

    serde_json::from_str(&response_line)
        .map_err(|e| format!("parse response: {e}"))
}

#[cfg(not(unix))]
fn forward_to_swarmvine(
    _method: &str,
    _params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    Err("gossip proxy requires Unix (UDS)".to_string())
}

/// Fire-and-forget gossip injection — does not wait for response.
/// Used by fleet detection and escalation emission.
#[cfg(unix)]
pub(crate) fn fire_and_forget_inject(topic: &str, key: &str, payload: &serde_json::Value) -> bool {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    let Some(socket_path) = discover_swarmvine_socket() else {
        return false;
    };

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "gossip.inject",
        "params": {
            "topic": topic,
            "key": key,
            "payload": payload,
        },
        "id": null,
    });

    let Ok(line) = serde_json::to_string(&request) else {
        return false;
    };

    let Ok(stream) = UnixStream::connect(&socket_path) else {
        return false;
    };
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

    let mut writer = std::io::BufWriter::new(&stream);
    if writer.write_all(line.as_bytes()).is_err() {
        return false;
    }
    if writer.write_all(b"\n").is_err() {
        return false;
    }
    writer.flush().is_ok()
}

#[cfg(not(unix))]
pub(crate) fn fire_and_forget_inject(_topic: &str, _key: &str, _payload: &serde_json::Value) -> bool {
    false
}

/// Handle `gossip.inject` — proxy to swarmVine.
pub(super) async fn dispatch_gossip_inject(
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let params = match params {
        Some(p) => p,
        None => {
            return Response::error(id, jsonrpc::INVALID_PARAMS, "missing params".to_string());
        }
    };

    match tokio::task::spawn_blocking(move || forward_to_swarmvine("gossip.inject", &params))
        .await
    {
        Ok(Ok(result)) => Response::success(id, result),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "gossip.inject proxy failed");
            Response::error(id, jsonrpc::INTERNAL_ERROR, e)
        }
        Err(e) => Response::error(
            id,
            jsonrpc::INTERNAL_ERROR,
            format!("task join error: {e}"),
        ),
    }
}

/// Handle `gossip.query` — proxy to swarmVine.
pub(super) async fn dispatch_gossip_query(
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let params = match params {
        Some(p) => p,
        None => {
            return Response::error(id, jsonrpc::INVALID_PARAMS, "missing params".to_string());
        }
    };

    match tokio::task::spawn_blocking(move || forward_to_swarmvine("gossip.query", &params)).await
    {
        Ok(Ok(result)) => Response::success(id, result),
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "gossip.query proxy failed");
            Response::error(id, jsonrpc::INTERNAL_ERROR, e)
        }
        Err(e) => Response::error(
            id,
            jsonrpc::INTERNAL_ERROR,
            format!("task join error: {e}"),
        ),
    }
}

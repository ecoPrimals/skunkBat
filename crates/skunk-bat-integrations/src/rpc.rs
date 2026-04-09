// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Newline-delimited JSON-RPC 2.0 client for inter-primal IPC.
//!
//! Follows the Primal IPC Protocol v3.1 wire format (newline-delimited
//! JSON over UDS or TCP) and BTSP Phase 1 socket naming conventions.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
    id: u64,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcResponseError>,
}

#[derive(Debug, Deserialize)]
struct RpcResponseError {
    code: i32,
    message: String,
}

/// Resolve the BIOMEOS socket directory from environment.
///
/// Priority: `BIOMEOS_SOCKET_DIR` → `$XDG_RUNTIME_DIR/biomeos` → `/run/user/{uid}/biomeos`.
#[must_use]
pub fn socket_dir() -> String {
    std::env::var("BIOMEOS_SOCKET_DIR").unwrap_or_else(|_| {
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
            .unwrap_or_else(|_| format!("/run/user/{}", proc_uid()));
        format!("{runtime_dir}/biomeos")
    })
}

/// Resolve the UDS path for a capability-domain symlink.
///
/// Returns e.g. `/run/user/1000/biomeos/discovery.sock`.
#[must_use]
pub fn capability_socket(capability: &str) -> String {
    format!("{}/{capability}.sock", socket_dir())
}

/// High-level JSON-RPC call with UDS-first, TCP-fallback transport.
///
/// Tries UDS (if path provided and platform supports it), then TCP.
/// Returns the `result` field from the JSON-RPC response, or an error string.
///
/// # Errors
///
/// Returns `Err` if no endpoint is available or all transports fail.
pub async fn call(
    uds_path: Option<&str>,
    tcp_endpoint: Option<&str>,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    #[cfg(unix)]
    if let Some(path) = uds_path {
        match call_uds(path, method, params.clone(), timeout).await {
            Ok(val) => return Ok(val),
            Err(e) => tracing::debug!("UDS {path}: {e}"),
        }
    }

    #[cfg(not(unix))]
    let _ = uds_path;

    if let Some(endpoint) = tcp_endpoint {
        let addr = endpoint.strip_prefix("http://").unwrap_or(endpoint);
        return call_tcp(addr, method, params, timeout).await;
    }

    Err("no endpoint available".to_string())
}

/// Send a JSON-RPC request over a Unix domain socket.
///
/// # Errors
///
/// Returns `Err` if the socket is unreachable or the RPC fails.
#[cfg(unix)]
pub async fn call_uds(
    socket_path: &str,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    use tokio::net::UnixStream;

    let stream = tokio::time::timeout(timeout, UnixStream::connect(socket_path))
        .await
        .map_err(|_| format!("timeout connecting to {socket_path}"))?
        .map_err(|e| format!("connect {socket_path}: {e}"))?;

    call_stream(stream, method, params, timeout).await
}

/// Send a JSON-RPC request over TCP.
///
/// # Errors
///
/// Returns `Err` if the address is unreachable or the RPC fails.
pub async fn call_tcp(
    addr: &str,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, String> {
    use tokio::net::TcpStream;

    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("timeout connecting to {addr}"))?
        .map_err(|e| format!("connect {addr}: {e}"))?;

    call_stream(stream, method, params, timeout).await
}

async fn call_stream<S>(
    stream: S,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let req = RpcRequest {
        jsonrpc: "2.0",
        method,
        params,
        id,
    };

    let mut buf = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    buf.push(b'\n');

    let (reader, mut writer) = tokio::io::split(stream);

    writer
        .write_all(&buf)
        .await
        .map_err(|e| format!("write: {e}"))?;
    writer.flush().await.map_err(|e| format!("flush: {e}"))?;

    let mut lines = BufReader::new(reader);
    let mut line = String::new();

    tokio::time::timeout(timeout, lines.read_line(&mut line))
        .await
        .map_err(|_| "timeout reading response".to_string())?
        .map_err(|e| format!("read: {e}"))?;

    let resp: RpcResponse =
        serde_json::from_str(line.trim()).map_err(|e| format!("parse response: {e}"))?;

    if let Some(err) = resp.error {
        return Err(format!("rpc error {}: {}", err.code, err.message));
    }

    resp.result.ok_or_else(|| "null result".to_string())
}

fn proc_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_dir_fallback() {
        let dir = socket_dir();
        assert!(dir.contains("biomeos"));
    }

    #[test]
    fn test_capability_socket_path() {
        let path = capability_socket("discovery");
        assert!(path.ends_with("discovery.sock"));
    }

    #[tokio::test]
    async fn test_call_unreachable_tcp() {
        let result = call_tcp(
            "127.0.0.1:1",
            "health.liveness",
            None,
            Duration::from_millis(500),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_call_no_endpoint() {
        let result = call(
            None,
            None,
            "health.liveness",
            None,
            Duration::from_millis(100),
        )
        .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no endpoint"));
    }
}

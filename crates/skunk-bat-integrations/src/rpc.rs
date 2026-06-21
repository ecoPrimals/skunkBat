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

/// Structured transport endpoint — wire-compatible with sourDough `TransportEndpoint`.
///
/// The launcher or Tower Atomic provides this via `TRANSPORT_ENDPOINT` env var.
/// Primals use it to discover how to reach other services without hardcoding transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport")]
pub enum TransportEndpoint {
    /// Unix Domain Socket — local primal on same host (fastest path).
    #[serde(rename = "uds")]
    Uds {
        /// Filesystem path to the socket.
        path: String,
    },
    /// TCP — direct network connection (cross-host or container).
    #[serde(rename = "tcp")]
    Tcp {
        /// Host address (IPv4, IPv6, or hostname).
        host: String,
        /// TCP port number.
        port: u16,
    },
    /// Mesh relay — primal reachable via Songbird's mesh network.
    #[serde(rename = "mesh_relay")]
    MeshRelay {
        /// Songbird peer identifier.
        peer_id: String,
        /// Capability domain being requested.
        capability: String,
    },
}

impl TransportEndpoint {
    /// Parse from the `TRANSPORT_ENDPOINT` env var (JSON).
    ///
    /// Returns `None` if the env var is unset or unparseable.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        std::env::var(skunk_bat_core::env_keys::TRANSPORT_ENDPOINT)
            .ok()
            .and_then(|v| serde_json::from_str(&v).ok())
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// IPC RPC call failure.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// Network or I/O failure (connection refused, write error).
    #[error("io: {0}")]
    Io(String),

    /// Server returned a JSON-RPC error response.
    #[error("rpc {code}: {message}")]
    Server {
        /// JSON-RPC error code.
        code: i32,
        /// Human-readable error message.
        message: String,
    },

    /// Response could not be parsed.
    #[error("parse: {0}")]
    Parse(String),

    /// Call timed out.
    #[error("timeout: {0}")]
    Timeout(String),
}

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
    std::env::var(skunk_bat_core::env_keys::BIOMEOS_SOCKET_DIR).unwrap_or_else(|_| {
        let runtime_dir =
            std::env::var(skunk_bat_core::env_keys::XDG_RUNTIME_DIR).unwrap_or_else(|_| {
                let uid = skunk_bat_core::platform::proc_uid();
                format!("/run/user/{uid}")
            });
        format!("{runtime_dir}/biomeos")
    })
}

/// Resolve the UDS path for a capability-domain symlink.
///
/// Returns e.g. `/run/user/1000/biomeos/discovery.sock`.
#[must_use]
pub fn capability_socket(capability: &str) -> String {
    let dir = socket_dir();
    format!("{dir}/{capability}.sock")
}

/// High-level JSON-RPC call with UDS-first, TCP-fallback transport.
///
/// Tries UDS (if path provided and platform supports it), then TCP.
/// Returns the `result` field from the JSON-RPC response.
///
/// # Errors
///
/// Returns [`RpcError`] if no endpoint is available or all transports fail.
pub async fn call(
    uds_path: Option<&str>,
    tcp_endpoint: Option<&str>,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, RpcError> {
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
        let addr = endpoint
            .strip_prefix("http://")
            .or_else(|| endpoint.strip_prefix("https://"))
            .unwrap_or(endpoint);
        return call_tcp(addr, method, params, timeout).await;
    }

    Err(RpcError::Io("no endpoint available".to_owned()))
}

/// JSON-RPC call via a resolved [`TransportEndpoint`].
///
/// Dispatches to UDS or TCP based on the endpoint variant.
/// `MeshRelay` is not yet supported (returns an error).
///
/// # Errors
///
/// Returns [`RpcError`] if the endpoint is unreachable or the RPC fails.
pub async fn call_endpoint(
    endpoint: &TransportEndpoint,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, RpcError> {
    match endpoint {
        #[cfg(unix)]
        TransportEndpoint::Uds { path } => call_uds(path, method, params, timeout).await,
        #[cfg(not(unix))]
        TransportEndpoint::Uds { path } => Err(RpcError::Io(format!(
            "UDS not available on this platform: {path}"
        ))),
        TransportEndpoint::Tcp { host, port } => {
            let addr = format!("{host}:{port}");
            call_tcp(&addr, method, params, timeout).await
        }
        TransportEndpoint::MeshRelay {
            peer_id,
            capability,
        } => Err(RpcError::Io(format!(
            "mesh_relay transport not yet implemented (peer={peer_id}, cap={capability})"
        ))),
    }
}

/// Send a JSON-RPC request over a Unix domain socket.
///
/// # Errors
///
/// Returns [`RpcError`] if the socket is unreachable or the RPC fails.
#[cfg(unix)]
pub async fn call_uds(
    socket_path: &str,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, RpcError> {
    use tokio::net::UnixStream;

    let stream = tokio::time::timeout(timeout, UnixStream::connect(socket_path))
        .await
        .map_err(|_| RpcError::Timeout(format!("connecting to {socket_path}")))?
        .map_err(|e| RpcError::Io(format!("connect {socket_path}: {e}")))?;

    call_stream(stream, method, params, timeout).await
}

/// Send a JSON-RPC request over TCP.
///
/// # Errors
///
/// Returns [`RpcError`] if the address is unreachable or the RPC fails.
pub async fn call_tcp(
    addr: &str,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, RpcError> {
    use tokio::net::TcpStream;

    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| RpcError::Timeout(format!("connecting to {addr}")))?
        .map_err(|e| RpcError::Io(format!("connect {addr}: {e}")))?;

    call_stream(stream, method, params, timeout).await
}

async fn call_stream<S>(
    stream: S,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, RpcError>
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

    let mut buf =
        serde_json::to_vec(&req).map_err(|e| RpcError::Parse(format!("serialize: {e}")))?;
    buf.push(b'\n');

    let (reader, mut writer) = tokio::io::split(stream);

    writer
        .write_all(&buf)
        .await
        .map_err(|e| RpcError::Io(format!("write: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| RpcError::Io(format!("flush: {e}")))?;

    let mut lines = BufReader::new(reader);
    let mut line = String::new();

    tokio::time::timeout(timeout, lines.read_line(&mut line))
        .await
        .map_err(|_| RpcError::Timeout("reading response".to_owned()))?
        .map_err(|e| RpcError::Io(format!("read: {e}")))?;

    let resp: RpcResponse =
        serde_json::from_str(line.trim()).map_err(|e| RpcError::Parse(format!("response: {e}")))?;

    if let Some(err) = resp.error {
        return Err(RpcError::Server {
            code: err.code,
            message: err.message,
        });
    }

    resp.result
        .ok_or_else(|| RpcError::Parse("null result".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

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
        assert!(result.unwrap_err().to_string().contains("no endpoint"));
    }

    #[tokio::test]
    async fn test_call_stream_success() {
        let (client, mut server) = tokio::io::duplex(1024);

        let handle = tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut reader = tokio::io::BufReader::new(&mut server);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(req["method"], "test.ping");
            assert_eq!(req["jsonrpc"], "2.0");

            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "result": {"pong": true},
                "id": req["id"]
            });
            let mut resp_line = serde_json::to_string(&resp).unwrap();
            resp_line.push('\n');
            server.write_all(resp_line.as_bytes()).await.unwrap();
            server.flush().await.unwrap();
        });

        let result = call_stream(
            client,
            "test.ping",
            Some(serde_json::json!({})),
            Duration::from_secs(5),
        )
        .await;

        handle.await.unwrap();
        let val = result.expect("should succeed");
        assert_eq!(val["pong"], true);
    }

    #[tokio::test]
    async fn test_call_stream_rpc_error() {
        let (client, mut server) = tokio::io::duplex(1024);

        let handle = tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut reader = tokio::io::BufReader::new(&mut server);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap();

            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": "Method not found"},
                "id": req["id"]
            });
            let mut resp_line = serde_json::to_string(&resp).unwrap();
            resp_line.push('\n');
            server.write_all(resp_line.as_bytes()).await.unwrap();
            server.flush().await.unwrap();
        });

        let result = call_stream(client, "bogus.method", None, Duration::from_secs(5)).await;

        handle.await.unwrap();
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(err_str.contains("-32601"));
        assert!(err_str.contains("Method not found"));
    }

    #[tokio::test]
    async fn test_call_stream_null_result() {
        let (client, mut server) = tokio::io::duplex(1024);

        let handle = tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut reader = tokio::io::BufReader::new(&mut server);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let resp = "{\"jsonrpc\":\"2.0\",\"result\":null,\"id\":1}\n";
            server.write_all(resp.as_bytes()).await.unwrap();
            server.flush().await.unwrap();
        });

        let result = call_stream(client, "test.null", None, Duration::from_secs(5)).await;

        handle.await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("null result"));
    }

    #[tokio::test]
    async fn test_call_stream_timeout() {
        let (client, _server) = tokio::io::duplex(1024);

        let result = call_stream(client, "test.slow", None, Duration::from_millis(50)).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timeout"));
    }

    #[tokio::test]
    async fn test_call_uds_unreachable() {
        let result = call_uds(
            "/nonexistent/socket.sock",
            "test.method",
            None,
            Duration::from_millis(100),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_call_tcp_fallback() {
        let result = call(
            Some("/nonexistent/socket.sock"),
            Some("127.0.0.1:1"),
            "test.method",
            None,
            Duration::from_millis(200),
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_request_id_increments() {
        let a = NEXT_ID.load(Ordering::Relaxed);
        let _ = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let b = NEXT_ID.load(Ordering::Relaxed);
        assert_eq!(b, a + 1);
    }

    #[test]
    fn test_proc_uid_returns_real_value() {
        assert!(skunk_bat_core::platform::proc_uid() > 0);
    }

    #[tokio::test]
    async fn test_call_tcp_with_http_prefix() {
        let result = call(
            None,
            Some("http://127.0.0.1:1"),
            "test.method",
            None,
            Duration::from_millis(200),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_call_tcp_with_https_prefix() {
        let result = call(
            None,
            Some("https://127.0.0.1:1"),
            "test.method",
            None,
            Duration::from_millis(200),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_call_stream_malformed_json() {
        let (client, mut server) = tokio::io::duplex(1024);

        let handle = tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut reader = tokio::io::BufReader::new(&mut server);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            server.write_all(b"not json\n").await.unwrap();
            server.flush().await.unwrap();
        });

        let result = call_stream(client, "test.bad", None, Duration::from_secs(5)).await;
        handle.await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parse"));
    }

    #[test]
    fn transport_endpoint_uds_serde_roundtrip() {
        let json = r#"{"transport":"uds","path":"/run/user/1000/biomeos/beardog.sock"}"#;
        let ep: TransportEndpoint = serde_json::from_str(json).unwrap();
        assert_eq!(
            ep,
            TransportEndpoint::Uds {
                path: "/run/user/1000/biomeos/beardog.sock".into()
            }
        );
        let back = serde_json::to_string(&ep).unwrap();
        assert!(back.contains(r#""transport":"uds""#));
        assert!(back.contains("beardog.sock"));
    }

    #[test]
    fn transport_endpoint_tcp_serde_roundtrip() {
        let json = r#"{"transport":"tcp","host":"127.0.0.1","port":9100}"#;
        let ep: TransportEndpoint = serde_json::from_str(json).unwrap();
        assert_eq!(
            ep,
            TransportEndpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 9100
            }
        );
    }

    #[test]
    fn transport_endpoint_mesh_relay_serde() {
        let json = r#"{"transport":"mesh_relay","peer_id":"strandgate","capability":"security"}"#;
        let ep: TransportEndpoint = serde_json::from_str(json).unwrap();
        assert_eq!(
            ep,
            TransportEndpoint::MeshRelay {
                peer_id: "strandgate".into(),
                capability: "security".into()
            }
        );
    }

    #[test]
    fn transport_endpoint_from_env_unset() {
        assert!(TransportEndpoint::from_env().is_none());
    }

    #[tokio::test]
    async fn call_endpoint_tcp_unreachable() {
        let ep = TransportEndpoint::Tcp {
            host: "127.0.0.1".into(),
            port: 1,
        };
        let result = call_endpoint(&ep, "health.liveness", None, Duration::from_millis(200)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn call_endpoint_mesh_relay_unsupported() {
        let ep = TransportEndpoint::MeshRelay {
            peer_id: "test".into(),
            capability: "security".into(),
        };
        let result = call_endpoint(&ep, "test.method", None, Duration::from_millis(100)).await;
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mesh_relay"));
        assert!(err.contains("not yet implemented"));
    }
}

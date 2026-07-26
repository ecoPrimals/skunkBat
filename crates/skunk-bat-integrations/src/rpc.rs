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

/// Default integration RPC timeout in milliseconds.
///
/// All integration clients (bearDog, songBird, toadStool) share this default
/// when `SKUNKBAT_INTEGRATION_TIMEOUT_MS` is not set.
const DEFAULT_INTEGRATION_TIMEOUT_MS: u64 = 5000;

/// Read integration RPC timeout from `SKUNKBAT_INTEGRATION_TIMEOUT_MS` env var,
/// falling back to [`DEFAULT_INTEGRATION_TIMEOUT_MS`].
#[must_use]
pub fn integration_timeout_ms() -> u64 {
    std::env::var(skunk_bat_core::env_keys::SKUNKBAT_INTEGRATION_TIMEOUT_MS)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_INTEGRATION_TIMEOUT_MS)
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

/// Parse a [`TransportEndpoint`] from an environment variable's JSON value.
///
/// Returns `None` if the variable is unset or its value is not valid
/// `TransportEndpoint` JSON.
#[must_use]
pub fn parse_transport_env(var: &str) -> Option<TransportEndpoint> {
    std::env::var(var)
        .ok()
        .and_then(|v| serde_json::from_str(&v).ok())
}

/// Parse a `host:port` string into a TCP [`TransportEndpoint`].
///
/// Accepts `host:port`, `http://host:port`, `https://host:port`.
/// Returns `None` if the string is empty or doesn't contain a valid port.
#[must_use]
pub fn parse_tcp_host_port(addr: &str) -> Option<TransportEndpoint> {
    let stripped = addr
        .strip_prefix("http://")
        .or_else(|| addr.strip_prefix("https://"))
        .unwrap_or(addr);
    if stripped.is_empty() {
        return None;
    }
    let (host, port_str) = stripped.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some(TransportEndpoint::Tcp {
        host: host.to_owned(),
        port,
    })
}

/// Shared transport configuration for capability-based integration clients.
///
/// Encapsulates transport resolution: resolves a [`TransportEndpoint`] from
/// environment (TCP, UDS) and dispatches calls through `call_endpoint`.
///
/// When BTSP strict mode is active (`BEARDOG_UDS_REQUIRE_BTSP=1`), the client
/// performs a BTSP `ClientHello` handshake before sending JSON-RPC.
#[derive(Clone, Debug)]
pub struct CapabilityClient {
    resolved: Option<TransportEndpoint>,
    timeout_ms: u64,
    btsp_enabled: bool,
}

impl CapabilityClient {
    /// Create with an explicit TCP endpoint.
    #[must_use]
    pub fn new(endpoint: &str, timeout_ms: u64) -> Self {
        let resolved = parse_tcp_host_port(endpoint);
        let btsp_enabled = crate::btsp_client::btsp_strict_mode_expected()
            && crate::btsp_client::btsp_handshake_available();
        Self {
            resolved,
            timeout_ms,
            btsp_enabled,
        }
    }

    /// Create from environment: reads transport env (JSON), then
    /// `endpoint_env` for TCP, probes `$BIOMEOS_SOCKET_DIR/{capability}.sock` for UDS.
    #[must_use]
    pub fn from_env(endpoint_env: &str, capability: &str, default_timeout_ms: u64) -> Self {
        let transport_env = format!("{}_TRANSPORT", endpoint_env.trim_end_matches("_ENDPOINT"));
        let resolved = parse_transport_env(&transport_env).or_else(|| {
            let tcp = std::env::var(endpoint_env).ok().filter(|v| !v.is_empty());
            if let Some(ref addr) = tcp {
                return parse_tcp_host_port(addr);
            }
            let path = capability_socket(capability);
            std::path::Path::new(&path)
                .exists()
                .then_some(TransportEndpoint::Uds { path })
        });

        let timeout_ms = std::env::var(skunk_bat_core::env_keys::SKUNKBAT_INTEGRATION_TIMEOUT_MS)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_timeout_ms);

        let btsp_enabled = crate::btsp_client::btsp_strict_mode_expected()
            && crate::btsp_client::btsp_handshake_available();

        Self {
            resolved,
            timeout_ms,
            btsp_enabled,
        }
    }

    /// Override the request timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Explicitly enable BTSP handshake (for testing or forced-strict scenarios).
    #[must_use]
    pub const fn with_btsp(mut self, enabled: bool) -> Self {
        self.btsp_enabled = enabled;
        self
    }

    /// Whether BTSP handshake is enabled on this client.
    #[must_use]
    pub const fn btsp_enabled(&self) -> bool {
        self.btsp_enabled
    }

    /// The resolved transport endpoint (if any).
    #[must_use]
    pub const fn resolved(&self) -> Option<&TransportEndpoint> {
        self.resolved.as_ref()
    }

    /// A string summary of the endpoint for logging (empty if unresolved).
    #[must_use]
    pub fn endpoint(&self) -> String {
        match &self.resolved {
            Some(TransportEndpoint::Tcp { host, port }) => format!("{host}:{port}"),
            Some(TransportEndpoint::Uds { path }) => path.clone(),
            Some(TransportEndpoint::MeshRelay { peer_id, .. }) => format!("mesh:{peer_id}"),
            None => String::new(),
        }
    }

    /// The TCP endpoint as a `host:port` string (if resolved to TCP).
    #[must_use]
    pub fn tcp_endpoint(&self) -> Option<String> {
        match &self.resolved {
            Some(TransportEndpoint::Tcp { host, port }) => Some(format!("{host}:{port}")),
            _ => None,
        }
    }

    /// The UDS path (if resolved to UDS).
    #[must_use]
    pub const fn uds_path(&self) -> Option<&str> {
        match &self.resolved {
            Some(TransportEndpoint::Uds { path }) => Some(path.as_str()),
            _ => None,
        }
    }

    /// The configured timeout as a `Duration`.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    /// Make a JSON-RPC call using the resolved `TransportEndpoint`.
    ///
    /// When BTSP strict mode is active, performs a `ClientHello` handshake
    /// before sending the JSON-RPC request.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError`] if no endpoint is resolved or the call fails.
    pub async fn call(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, RpcError> {
        let endpoint = self
            .resolved
            .as_ref()
            .ok_or_else(|| RpcError::Io("no transport endpoint resolved".to_owned()))?;
        let timeout = Duration::from_millis(self.timeout_ms);
        call_endpoint_with_btsp(endpoint, method, params, timeout, self.btsp_enabled).await
    }
}

/// JSON-RPC call via a resolved [`TransportEndpoint`].
///
/// Dispatches to UDS or TCP based on the endpoint variant.
/// `MeshRelay` is not yet supported (returns an error).
///
/// Does NOT perform BTSP handshake. Use [`call_endpoint_with_btsp`] for
/// BTSP-aware calls.
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
    call_endpoint_with_btsp(endpoint, method, params, timeout, false).await
}

/// JSON-RPC call via a resolved [`TransportEndpoint`], with optional BTSP handshake.
///
/// When `btsp` is `true`, performs a BTSP `ClientHello` 4-step handshake
/// before sending the JSON-RPC request. Required when bearDog is in strict
/// mode (`BEARDOG_UDS_REQUIRE_BTSP=1`).
///
/// # Errors
///
/// Returns [`RpcError`] if the endpoint is unreachable, the BTSP handshake
/// fails, or the RPC fails.
pub async fn call_endpoint_with_btsp(
    endpoint: &TransportEndpoint,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
    btsp: bool,
) -> Result<serde_json::Value, RpcError> {
    match endpoint {
        #[cfg(unix)]
        TransportEndpoint::Uds { path } => call_uds_btsp(path, method, params, timeout, btsp).await,
        #[cfg(not(unix))]
        TransportEndpoint::Uds { path } => Err(RpcError::Io(format!(
            "UDS not available on this platform: {path}"
        ))),
        TransportEndpoint::Tcp { host, port } => {
            let addr = format!("{host}:{port}");
            call_tcp_btsp(&addr, method, params, timeout, btsp).await
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
    call_uds_btsp(socket_path, method, params, timeout, false).await
}

/// Send a JSON-RPC request over a Unix domain socket, with optional BTSP.
#[cfg(unix)]
async fn call_uds_btsp(
    socket_path: &str,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
    btsp: bool,
) -> Result<serde_json::Value, RpcError> {
    use tokio::net::UnixStream;

    let mut stream = tokio::time::timeout(timeout, UnixStream::connect(socket_path))
        .await
        .map_err(|_| RpcError::Timeout(format!("connecting to {socket_path}")))?
        .map_err(|e| RpcError::Io(format!("connect {socket_path}: {e}")))?;

    if btsp {
        perform_btsp_handshake(&mut stream).await?;
    }

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
    call_tcp_btsp(addr, method, params, timeout, false).await
}

/// Send a JSON-RPC request over TCP, with optional BTSP.
async fn call_tcp_btsp(
    addr: &str,
    method: &str,
    params: Option<serde_json::Value>,
    timeout: Duration,
    btsp: bool,
) -> Result<serde_json::Value, RpcError> {
    use tokio::net::TcpStream;

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| RpcError::Timeout(format!("connecting to {addr}")))?
        .map_err(|e| RpcError::Io(format!("connect {addr}: {e}")))?;

    if btsp {
        perform_btsp_handshake(&mut stream).await?;
    }

    call_stream(stream, method, params, timeout).await
}

/// Run the BTSP `ClientHello` handshake, mapping errors to [`RpcError`].
async fn perform_btsp_handshake<S>(stream: &mut S) -> Result<(), RpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    crate::btsp_client::perform_client_handshake(stream)
        .await
        .map_err(|e| RpcError::Io(format!("BTSP handshake failed: {e}")))?;
    Ok(())
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
        let client = CapabilityClient::new("", 100);
        let result = client.call("health.liveness", None).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no transport endpoint resolved")
        );
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
        let ep = TransportEndpoint::Uds {
            path: "/nonexistent/socket.sock".into(),
        };
        let result = call_endpoint(&ep, "test.method", None, Duration::from_millis(200)).await;
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
        let ep = parse_tcp_host_port("http://127.0.0.1:1").unwrap();
        let result = call_endpoint(&ep, "test.method", None, Duration::from_millis(200)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_call_tcp_with_https_prefix() {
        let ep = parse_tcp_host_port("https://127.0.0.1:1").unwrap();
        let result = call_endpoint(&ep, "test.method", None, Duration::from_millis(200)).await;
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

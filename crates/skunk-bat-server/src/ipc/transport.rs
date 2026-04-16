// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Transport layer — TCP and Unix domain socket listeners.
//!
//! Implements BTSP Phase 1 (socket naming with `FAMILY_ID` awareness),
//! Phase 2 (BearDog-delegated handshake on both TCP and UDS), and
//! Primal IPC Protocol v3.1 (filesystem sockets in `$BIOMEOS_SOCKET_DIR`).
//!
//! Both TCP and UDS use first-byte peek to auto-detect protocol:
//! `{` → plain JSON-RPC (biomeOS composition bypass), otherwise BTSP
//! framed handshake. TCP uses native `TcpStream::peek`; UDS uses
//! `PeekedStream` (read-one-byte + replay) since `UnixStream` lacks peek.

use skunk_bat_core::SkunkBat;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use super::server::handle_connection;

// ── First-byte peek wrapper ──────────────────────────────────────────────
//
// `tokio::net::UnixStream` lacks `peek()`. This wrapper reads one byte
// destructively, then replays it on the first `poll_read`. Both
// `AsyncRead` and `AsyncWrite` are delegated so the wrapper is a
// transparent drop-in for any stream type.

struct PeekedStream<S> {
    peeked: Option<u8>,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(byte) = this.peeked.take() {
            buf.put_slice(&[byte]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeekedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// BTSP Phase 1 environment configuration.
pub struct BtspConfig {
    /// Socket directory (`BIOMEOS_SOCKET_DIR` or `XDG_RUNTIME_DIR/biomeos`).
    pub socket_dir: String,
    /// Family ID if set — triggers production socket naming.
    pub family_id: Option<String>,
    /// True when `BIOMEOS_INSECURE=1` is set (development mode).
    pub insecure: bool,
}

impl BtspConfig {
    /// Read BTSP Phase 1 config from environment.
    ///
    /// # Errors
    ///
    /// Returns `Err` when both `FAMILY_ID` and `BIOMEOS_INSECURE=1` are set.
    pub fn from_env() -> Result<Self, String> {
        let family_id = std::env::var("FAMILY_ID")
            .ok()
            .filter(|v| !v.is_empty() && v != "default");

        let insecure = std::env::var("BIOMEOS_INSECURE")
            .map(|v| v == "1")
            .unwrap_or(false);

        if family_id.is_some() && insecure {
            return Err(
                "BTSP guard: FAMILY_ID and BIOMEOS_INSECURE=1 cannot both be set".to_string(),
            );
        }

        let socket_dir = std::env::var("BIOMEOS_SOCKET_DIR").unwrap_or_else(|_| {
            let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
                .unwrap_or_else(|_| format!("/run/user/{}", proc_uid()));
            format!("{runtime_dir}/biomeos")
        });

        Ok(Self {
            socket_dir,
            family_id,
            insecure,
        })
    }

    /// Compute the UDS socket path per BTSP Phase 1 naming convention.
    ///
    /// - Development: `{socket_dir}/skunkbat.sock`
    /// - Production:  `{socket_dir}/skunkbat-{family_id}.sock`
    pub fn socket_path(&self) -> String {
        self.family_id.as_ref().map_or_else(
            || format!("{}/skunkbat.sock", self.socket_dir),
            |fid| format!("{}/skunkbat-{fid}.sock", self.socket_dir),
        )
    }

    /// Compute the capability-domain symlink path.
    ///
    /// `{socket_dir}/security.sock` → `skunkbat[-{fid}].sock`
    pub fn capability_symlink_path(&self) -> String {
        format!("{}/security.sock", self.socket_dir)
    }

    /// Log the current BTSP mode.
    pub fn log_mode(&self) {
        match &self.family_id {
            Some(fid) => {
                tracing::info!(
                    "BTSP Phase 1: production mode (FAMILY_ID={fid}), socket={}",
                    self.socket_path()
                );
            }
            None if self.insecure => {
                tracing::info!(
                    "BTSP: development mode (BIOMEOS_INSECURE=1), socket={}",
                    self.socket_path()
                );
            }
            None => {
                tracing::info!(
                    "BTSP: standalone mode (no FAMILY_ID), socket={}",
                    self.socket_path()
                );
            }
        }
    }
}

// ── BTSP Phase 2: Handshake Config ──────────────────────────────────────

/// Configuration for BTSP server-side handshake (Phase 2).
///
/// When present, every accepted connection must complete a BTSP handshake
/// via the `BearDog` security provider before JSON-RPC is served.
#[derive(Debug, Clone)]
pub struct BtspHandshakeConfig {
    /// Path to `BearDog`'s UDS socket for `btsp.session.*` RPCs.
    pub provider_socket: std::path::PathBuf,
    /// Family identifier (used for logging and future cipher scoping).
    #[expect(dead_code, reason = "reserved for BTSP Phase 2 cipher scoping")]
    pub family_id: String,
}

impl BtspHandshakeConfig {
    /// Resolve handshake config from the environment.
    ///
    /// Returns `Some` when `FAMILY_ID` is set to a production value.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let fid = std::env::var("FAMILY_ID")
            .ok()
            .filter(|v| !v.is_empty() && v != "default")?;

        let provider_socket = std::env::var("BTSP_PROVIDER_SOCKET")
            .or_else(|_| std::env::var("BEARDOG_SOCKET"))
            .ok()
            .map_or_else(
                || {
                    let provider =
                        std::env::var("BTSP_PROVIDER").unwrap_or_else(|_| "beardog".to_owned());
                    let socket_dir = std::env::var("BIOMEOS_SOCKET_DIR").unwrap_or_else(|_| {
                        let xdg =
                            std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_owned());
                        format!("{xdg}/biomeos")
                    });
                    std::path::PathBuf::from(format!("{socket_dir}/{provider}-{fid}.sock"))
                },
                std::path::PathBuf::from,
            );

        Some(Self {
            provider_socket,
            family_id: fid,
        })
    }
}

// ── BTSP Phase 2: Wire Framing ──────────────────────────────────────────

const MAX_FRAME_SIZE: u32 = 0x0100_0000;

async fn read_frame<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<bytes::Bytes, std::io::Error> {
    let len = reader.read_u32().await?;
    if len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("BTSP frame too large: {len}"),
        ));
    }
    let mut buf = bytes::BytesMut::zeroed(len as usize);
    reader.read_exact(&mut buf).await?;
    Ok(buf.freeze())
}

async fn write_frame<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<(), std::io::Error> {
    let len = u32::try_from(data.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large for u32")
    })?;
    writer.write_u32(len).await?;
    writer.write_all(data).await?;
    writer.flush().await
}

// ── BTSP Phase 2: Provider Client ───────────────────────────────────────

async fn provider_call(
    socket: &std::path::Path,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut stream = tokio::net::UnixStream::connect(socket)
        .await
        .map_err(|e| format!("BTSP provider {}: {e}", socket.display()))?;

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    let mut line = serde_json::to_string(&request).map_err(|e| e.to_string())?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .await
        .map_err(|e| e.to_string())?;

    let resp: serde_json::Value =
        serde_json::from_str(&response_line).map_err(|e| e.to_string())?;
    if let Some(err) = resp.get("error") {
        return Err(format!("BTSP provider error: {err}"));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| "no result in provider response".to_owned())
}

// ── BTSP Phase 2: Server Handshake ──────────────────────────────────────

/// Accumulated state during the BTSP handshake exchange.
struct HandshakeState {
    client_ephemeral_pub: String,
    challenge: String,
    session_id: String,
    server_ephemeral_pub: String,
    client_response: String,
    preferred_cipher: String,
}

async fn perform_server_handshake<S>(
    stream: &mut S,
    config: &BtspHandshakeConfig,
) -> Result<String, String>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let mut hs = btsp_exchange_hello(stream, config).await?;
    let (client_response, preferred_cipher) = btsp_read_challenge_response(stream).await?;
    hs.client_response = client_response;
    hs.preferred_cipher = preferred_cipher;

    btsp_verify_and_complete(stream, config, &hs).await?;

    tracing::info!(session_id = %hs.session_id, "BTSP handshake complete (null cipher)");
    Ok(hs.session_id)
}

async fn btsp_exchange_hello<S>(
    stream: &mut S,
    config: &BtspHandshakeConfig,
) -> Result<HandshakeState, String>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let client_hello_bytes = read_frame(stream)
        .await
        .map_err(|e| format!("read ClientHello: {e}"))?;
    let client_hello: serde_json::Value = serde_json::from_slice(&client_hello_bytes)
        .map_err(|e| format!("parse ClientHello: {e}"))?;

    let client_ephemeral_pub = json_str(&client_hello, "client_ephemeral_pub");
    let challenge = format!("{:032x}", rand_u128());

    let create_result = provider_call(
        &config.provider_socket,
        "btsp.session.create",
        serde_json::json!({
            "family_seed_ref": "env:FAMILY_SEED",
            "client_ephemeral_pub": client_ephemeral_pub,
            "challenge": challenge,
        }),
    )
    .await?;

    let session_id = json_str(&create_result, "session_id");
    let server_ephemeral_pub = json_str(&create_result, "server_ephemeral_pub");

    let server_hello = serde_json::json!({
        "session_id": session_id,
        "server_ephemeral_pub": server_ephemeral_pub,
        "challenge": challenge,
    });
    write_frame(
        stream,
        &serde_json::to_vec(&server_hello).map_err(|e| e.to_string())?,
    )
    .await
    .map_err(|e| format!("write ServerHello: {e}"))?;

    Ok(HandshakeState {
        client_ephemeral_pub,
        challenge,
        session_id,
        server_ephemeral_pub,
        client_response: String::new(),
        preferred_cipher: String::new(),
    })
}

async fn btsp_read_challenge_response<S>(stream: &mut S) -> Result<(String, String), String>
where
    S: tokio::io::AsyncReadExt + Unpin,
{
    let cr_bytes = read_frame(stream)
        .await
        .map_err(|e| format!("read ChallengeResponse: {e}"))?;
    let cr: serde_json::Value =
        serde_json::from_slice(&cr_bytes).map_err(|e| format!("parse ChallengeResponse: {e}"))?;

    Ok((
        json_str(&cr, "response"),
        json_str_or(&cr, "preferred_cipher", "null"),
    ))
}

async fn btsp_verify_and_complete<S>(
    stream: &mut S,
    config: &BtspHandshakeConfig,
    hs: &HandshakeState,
) -> Result<(), String>
where
    S: tokio::io::AsyncWriteExt + Unpin,
{
    let verify_result = provider_call(
        &config.provider_socket,
        "btsp.session.verify",
        serde_json::json!({
            "session_id": hs.session_id,
            "client_response": hs.client_response,
            "client_ephemeral_pub": hs.client_ephemeral_pub,
            "server_ephemeral_pub": hs.server_ephemeral_pub,
            "challenge": hs.challenge,
        }),
    )
    .await?;

    let verified = verify_result
        .get("verified")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if !verified {
        let reason = verify_result
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let err_frame = serde_json::json!({"error": "handshake_failed", "reason": reason});
        let _ = write_frame(stream, &serde_json::to_vec(&err_frame).unwrap_or_default()).await;
        return Err(format!("BTSP verify failed: {reason}"));
    }

    let _negotiate = provider_call(
        &config.provider_socket,
        "btsp.negotiate",
        serde_json::json!({
            "session_id": hs.session_id,
            "preferred_cipher": hs.preferred_cipher,
            "bond_type": "Covalent",
        }),
    )
    .await;

    let complete = serde_json::json!({
        "status": "complete",
        "session_id": hs.session_id,
        "cipher": "null",
    });
    write_frame(
        stream,
        &serde_json::to_vec(&complete).map_err(|e| e.to_string())?,
    )
    .await
    .map_err(|e| format!("write Complete: {e}"))?;

    Ok(())
}

fn json_str(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn json_str_or(value: &serde_json::Value, key: &str, default: &str) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or(default)
        .to_owned()
}

fn rand_u128() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    t ^ u128::from(std::process::id()) ^ 0x5555_5555_5555_5555_5555_5555_5555_5555
}

// ── Listeners ────────────────────────────────────────────────────────────

/// Bind TCP and accept connections with optional BTSP handshake.
///
/// TCP uses the same first-byte peek as `BearDog`: `{` → plain JSON-RPC
/// (biomeOS composition), otherwise BTSP framed handshake.
pub async fn serve_tcp(
    state: Arc<RwLock<SkunkBat>>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("TCP JSON-RPC listening on 0.0.0.0:{port}");

    let btsp_config = BtspHandshakeConfig::from_env().map(Arc::new);
    if let Some(ref cfg) = btsp_config {
        tracing::info!(
            "BTSP Phase 2 active on TCP: provider={}",
            cfg.provider_socket.display()
        );
    }

    loop {
        let (mut stream, addr) = listener.accept().await?;
        tracing::debug!("TCP connection from {addr}");
        let state = Arc::clone(&state);
        let btsp = btsp_config.clone();
        tokio::spawn(async move {
            if let Some(ref cfg) = btsp {
                let mut peek_buf = [0u8; 1];
                let n = stream.peek(&mut peek_buf).await.unwrap_or(0);
                if n > 0 && peek_buf[0] != b'{' {
                    match perform_server_handshake(&mut stream, cfg).await {
                        Ok(sid) => tracing::debug!("BTSP authenticated TCP {addr}: session={sid}"),
                        Err(e) => {
                            tracing::warn!("BTSP handshake failed TCP {addr}: {e}");
                            return;
                        }
                    }
                }
            }
            handle_connection(state, stream).await;
        });
    }
}

/// Bind UDS and accept connections per BTSP Phase 1 naming + Phase 2 handshake.
///
/// Uses first-byte peek (via `PeekedStream`) to auto-detect protocol:
/// `{` → plain JSON-RPC (biomeOS composition), otherwise BTSP framed
/// handshake. Matches the TCP behavior exactly.
#[cfg(unix)]
pub async fn serve_uds(
    state: Arc<RwLock<SkunkBat>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixListener;

    let btsp = BtspConfig::from_env()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    btsp.log_mode();

    let socket_path = btsp.socket_path();

    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    tokio::fs::remove_file(&socket_path).await.ok();
    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!("UDS JSON-RPC listening on {socket_path}");

    create_capability_symlink(&btsp);

    let btsp_config = BtspHandshakeConfig::from_env().map(Arc::new);
    if let Some(ref cfg) = btsp_config {
        tracing::info!(
            "BTSP Phase 2 active on UDS (first-byte peek): provider={}",
            cfg.provider_socket.display()
        );
    }

    loop {
        let (mut stream, _addr) = listener.accept().await?;
        tracing::debug!("UDS connection accepted");
        let state = Arc::clone(&state);
        let btsp = btsp_config.clone();
        tokio::spawn(async move {
            if let Some(ref cfg) = btsp {
                let mut first = [0u8; 1];
                let n = stream.read(&mut first).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                let mut peeked = PeekedStream {
                    peeked: Some(first[0]),
                    inner: stream,
                };
                if first[0] != b'{' {
                    match perform_server_handshake(&mut peeked, cfg).await {
                        Ok(sid) => tracing::debug!("BTSP authenticated UDS: session={sid}"),
                        Err(e) => {
                            tracing::warn!("BTSP handshake failed UDS: {e}");
                            return;
                        }
                    }
                }
                handle_connection(state, peeked).await;
            } else {
                handle_connection(state, stream).await;
            }
        });
    }
}

#[cfg(not(unix))]
pub async fn serve_uds(
    _state: Arc<RwLock<SkunkBat>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    tracing::warn!("Unix domain sockets not available on this platform");
    std::future::pending().await
}

/// Create capability-domain symlink: `security.sock` → `skunkbat[-{fid}].sock`
#[cfg(unix)]
fn create_capability_symlink(btsp: &BtspConfig) {
    let symlink_path = btsp.capability_symlink_path();
    let socket_name = std::path::Path::new(&btsp.socket_path())
        .file_name()
        .map_or_else(
            || "skunkbat.sock".to_string(),
            |n| n.to_string_lossy().to_string(),
        );

    std::fs::remove_file(&symlink_path).ok();
    match std::os::unix::fs::symlink(&socket_name, &symlink_path) {
        Ok(()) => tracing::info!("Capability symlink: security.sock -> {socket_name}"),
        Err(e) => tracing::warn!("Failed to create capability symlink: {e}"),
    }
}

/// Get UID without libc — `/proc/self/status` on Linux, `id -u` elsewhere.
fn proc_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or_else(uid_fallback)
    }
    #[cfg(not(target_os = "linux"))]
    {
        uid_fallback()
    }
}

fn uid_fallback() -> u32 {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_btsp_socket_path_standalone() {
        let config = BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: None,
            insecure: false,
        };
        assert_eq!(config.socket_path(), "/tmp/biomeos/skunkbat.sock");
    }

    #[test]
    fn test_btsp_socket_path_family() {
        let config = BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: Some("mygate".into()),
            insecure: false,
        };
        assert_eq!(config.socket_path(), "/tmp/biomeos/skunkbat-mygate.sock");
    }

    #[test]
    fn test_capability_symlink_path() {
        let config = BtspConfig {
            socket_dir: "/run/user/1000/biomeos".into(),
            family_id: None,
            insecure: false,
        };
        assert_eq!(
            config.capability_symlink_path(),
            "/run/user/1000/biomeos/security.sock"
        );
    }

    #[test]
    fn test_btsp_config_log_mode_standalone() {
        let config = BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: None,
            insecure: false,
        };
        config.log_mode();
    }

    #[test]
    fn test_btsp_config_log_mode_insecure() {
        let config = BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: None,
            insecure: true,
        };
        config.log_mode();
    }

    #[test]
    fn test_btsp_config_log_mode_family() {
        let config = BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: Some("prod".into()),
            insecure: false,
        };
        config.log_mode();
    }

    #[test]
    fn test_proc_uid_returns_real_value() {
        let uid = proc_uid();
        assert!(uid > 0, "UID should be a positive number");
    }

    #[test]
    fn test_uid_fallback_returns_value() {
        let uid = uid_fallback();
        assert!(uid > 0);
    }

    #[test]
    fn test_rand_u128_varies() {
        let a = rand_u128();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b = rand_u128();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn test_frame_roundtrip() {
        let data = b"hello world";
        let mut buf = Vec::new();
        write_frame(&mut buf, data).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await.unwrap();
        assert_eq!(&result[..], data);
    }

    #[tokio::test]
    async fn test_frame_too_large() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_SIZE + 1).to_be_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_frame_empty() {
        let data = b"";
        let mut buf = Vec::new();
        write_frame(&mut buf, data).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_provider_call_unreachable() {
        let result = provider_call(
            std::path::Path::new("/nonexistent/socket.sock"),
            "test.method",
            serde_json::json!({}),
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_json_str_helper() {
        let val = serde_json::json!({"key": "value"});
        assert_eq!(json_str(&val, "key"), "value");
        assert_eq!(json_str(&val, "missing"), "");
    }

    #[test]
    fn test_json_str_or_helper() {
        let val = serde_json::json!({"key": "value"});
        assert_eq!(json_str_or(&val, "key", "default"), "value");
        assert_eq!(json_str_or(&val, "missing", "fallback"), "fallback");
    }

    #[test]
    fn test_handshake_state_construction() {
        let hs = HandshakeState {
            client_ephemeral_pub: "pub_key".into(),
            challenge: "challenge_hex".into(),
            session_id: "session_1".into(),
            server_ephemeral_pub: "srv_key".into(),
            client_response: String::new(),
            preferred_cipher: "null".into(),
        };
        assert_eq!(hs.session_id, "session_1");
        assert!(hs.client_response.is_empty());
    }

    #[tokio::test]
    async fn test_peeked_stream_replays_byte() {
        use tokio::io::AsyncReadExt;

        let inner = std::io::Cursor::new(b"ello world");
        let mut ps = PeekedStream {
            peeked: Some(b'h'),
            inner,
        };

        let mut buf = vec![0u8; 11];
        let n = ps.read(&mut buf).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf[0], b'h');

        let n2 = ps.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"ello world");
    }

    #[tokio::test]
    async fn test_peeked_stream_json_detection() {
        use tokio::io::AsyncReadExt;

        let inner = std::io::Cursor::new(b"\"jsonrpc\":\"2.0\"}");
        let mut ps = PeekedStream {
            peeked: Some(b'{'),
            inner,
        };

        let mut buf = vec![0u8; 32];
        let mut total = 0;
        loop {
            let n = ps.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(&buf[..total], b"{\"jsonrpc\":\"2.0\"}");
    }

    #[tokio::test]
    async fn test_peeked_stream_write_passthrough() {
        use tokio::io::AsyncWriteExt;

        let inner = Vec::<u8>::new();
        let mut ps = PeekedStream {
            peeked: Some(b'x'),
            inner,
        };

        ps.write_all(b"hello").await.unwrap();
        ps.flush().await.unwrap();
        assert_eq!(&ps.inner, b"hello");
    }

    #[tokio::test]
    async fn test_peeked_stream_btsp_first_byte() {
        let btsp_frame = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&10u32.to_be_bytes());
            buf.extend_from_slice(b"0123456789");
            buf
        };
        let first = btsp_frame[0];
        let inner = std::io::Cursor::new(btsp_frame[1..].to_vec());
        let mut ps = PeekedStream {
            peeked: Some(first),
            inner,
        };

        let frame = read_frame(&mut ps).await.unwrap();
        assert_eq!(&frame[..], b"0123456789");
    }
}

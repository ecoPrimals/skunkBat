// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BTSP (Biotic Transport Security Protocol) — configuration, framing,
//! provider client, and server-side handshake.
//!
//! Phase 1: socket naming with `FAMILY_ID` awareness.
//! Phase 2: `BearDog`-delegated handshake via provider RPC.

use serde_json::Value;

/// Maximum BTSP frame size: 16 MiB.
const MAX_FRAME_SIZE: u32 = 0x0100_0000;

// ── Phase 1: Environment Configuration ──────────────────────────────────

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

// ── Phase 2: Handshake Config ───────────────────────────────────────────

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

// ── Phase 2: Wire Framing ───────────────────────────────────────────────

pub async fn read_frame<R: tokio::io::AsyncReadExt + Unpin>(
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

pub async fn write_frame<W: tokio::io::AsyncWriteExt + Unpin>(
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

// ── Phase 2: Provider Client ────────────────────────────────────────────

pub async fn provider_call(
    socket: &std::path::Path,
    method: &str,
    params: Value,
) -> Result<Value, String> {
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

    let resp: Value = serde_json::from_str(&response_line).map_err(|e| e.to_string())?;
    if let Some(err) = resp.get("error") {
        return Err(format!("BTSP provider error: {err}"));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| "no result in provider response".to_owned())
}

// ── Phase 2: Server Handshake ───────────────────────────────────────────

/// Accumulated state during the BTSP handshake exchange.
pub struct HandshakeState {
    client_ephemeral_pub: String,
    challenge: String,
    session_id: String,
    server_ephemeral_pub: String,
    client_response: String,
    preferred_cipher: String,
}

pub async fn perform_server_handshake<S>(
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
    let client_hello: Value = serde_json::from_slice(&client_hello_bytes)
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
    let cr: Value =
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
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !verified {
        let reason = verify_result
            .get("reason")
            .and_then(Value::as_str)
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

pub fn json_str(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn json_str_or(value: &Value, key: &str, default: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_owned()
}

pub fn rand_u128() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    t ^ u128::from(std::process::id()) ^ 0x5555_5555_5555_5555_5555_5555_5555_5555
}

/// Get UID without libc — `/proc/self/status` on Linux, `id -u` elsewhere.
pub fn proc_uid() -> u32 {
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

pub fn uid_fallback() -> u32 {
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
    fn socket_path_standalone() {
        let config = BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: None,
            insecure: false,
        };
        assert_eq!(config.socket_path(), "/tmp/biomeos/skunkbat.sock");
    }

    #[test]
    fn socket_path_family() {
        let config = BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: Some("mygate".into()),
            insecure: false,
        };
        assert_eq!(config.socket_path(), "/tmp/biomeos/skunkbat-mygate.sock");
    }

    #[test]
    fn capability_symlink_path() {
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
    fn log_mode_standalone() {
        BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: None,
            insecure: false,
        }
        .log_mode();
    }

    #[test]
    fn log_mode_insecure() {
        BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: None,
            insecure: true,
        }
        .log_mode();
    }

    #[test]
    fn log_mode_family() {
        BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: Some("prod".into()),
            insecure: false,
        }
        .log_mode();
    }

    #[test]
    fn proc_uid_returns_real_value() {
        assert!(proc_uid() > 0);
    }

    #[test]
    fn uid_fallback_returns_value() {
        assert!(uid_fallback() > 0);
    }

    #[test]
    fn rand_u128_varies() {
        let a = rand_u128();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b = rand_u128();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn frame_roundtrip() {
        let data = b"hello world";
        let mut buf = Vec::new();
        write_frame(&mut buf, data).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await.unwrap();
        assert_eq!(&result[..], data);
    }

    #[tokio::test]
    async fn frame_too_large() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_SIZE + 1).to_be_bytes());
        let mut cursor = std::io::Cursor::new(buf);
        assert!(read_frame(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn frame_empty() {
        let data = b"";
        let mut buf = Vec::new();
        write_frame(&mut buf, data).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn provider_call_unreachable() {
        let result = provider_call(
            std::path::Path::new("/nonexistent/socket.sock"),
            "test.method",
            serde_json::json!({}),
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn json_str_helper() {
        let val = serde_json::json!({"key": "value"});
        assert_eq!(json_str(&val, "key"), "value");
        assert_eq!(json_str(&val, "missing"), "");
    }

    #[test]
    fn json_str_or_helper() {
        let val = serde_json::json!({"key": "value"});
        assert_eq!(json_str_or(&val, "key", "default"), "value");
        assert_eq!(json_str_or(&val, "missing", "fallback"), "fallback");
    }

    #[test]
    fn handshake_state_construction() {
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
    async fn peeked_stream_btsp_first_byte() {
        use crate::ipc::transport::peek::PeekedStream;

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

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BTSP (Biotic Transport Security Protocol) — wire framing, provider
//! client, and server-side handshake (Phase 2).
//!
//! Configuration lives in [`super::config`]; UID helpers in [`super::sys`].

use serde_json::Value;

/// Maximum BTSP frame size: 16 MiB.
const MAX_FRAME_SIZE: u32 = 0x0100_0000;

// ── Wire Framing ───────────────────────────────────────────────────────

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

// ── Provider Client ────────────────────────────────────────────────────

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

// ── Handshake Key Derivation ──────────────────────────────────────────

/// Derive the handshake key from the family seed.
///
/// Matches `BearDog`'s `derive_handshake_key`:
/// `HKDF-SHA256(ikm=family_seed, salt="btsp-v1", info="handshake")` → 32 bytes
///
/// Returns `None` if `FAMILY_SEED` is not set or too short.
pub fn derive_handshake_key_from_env() -> Option<Vec<u8>> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let seed_str = std::env::var("FAMILY_SEED").ok()?;
    if seed_str.len() < 16 {
        tracing::warn!("FAMILY_SEED too short for BTSP key derivation (minimum 16 bytes)");
        return None;
    }

    let hk = Hkdf::<Sha256>::new(Some(b"btsp-v1"), seed_str.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"handshake", &mut key).ok()?;

    Some(key.to_vec())
}

// ── Server Handshake ───────────────────────────────────────────────────

/// Accumulated state during the BTSP handshake exchange.
///
/// Field names align with `BearDog`'s `btsp.server.*` RPC types:
/// - `session_token` from `SessionCreateResponse` (opaque server-side ref)
/// - `session_id` from `SessionVerifyResponse` (hex, set after verify)
pub struct HandshakeState {
    client_ephemeral_pub: String,
    session_token: String,
    session_id: Option<String>,
    client_response: String,
    preferred_cipher: String,
}

/// Result of a successful BTSP handshake: session ID + optional handshake key.
#[derive(Debug)]
pub struct HandshakeResult {
    pub session_id: String,
    pub handshake_key: Option<Vec<u8>>,
}

pub async fn perform_server_handshake<S>(
    stream: &mut S,
    config: &super::config::BtspHandshakeConfig,
) -> Result<HandshakeResult, String>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let mut hs = btsp_exchange_hello(stream, config).await?;
    let (client_response, preferred_cipher) = btsp_read_challenge_response(stream).await?;
    hs.client_response = client_response;
    hs.preferred_cipher = preferred_cipher;

    btsp_verify_and_complete(stream, config, &mut hs).await?;

    let sid = hs.session_id.as_deref().unwrap_or(&hs.session_token);
    tracing::info!(session_id = %sid, "BTSP handshake complete");

    let handshake_key = derive_handshake_key_from_env();
    if handshake_key.is_some() {
        tracing::debug!(session_id = %sid, "Handshake key derived — Phase 3 encryption available");
    }

    Ok(HandshakeResult {
        session_id: sid.to_owned(),
        handshake_key,
    })
}

async fn btsp_exchange_hello<S>(
    stream: &mut S,
    config: &super::config::BtspHandshakeConfig,
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

    let family_seed = std::env::var("FAMILY_SEED").unwrap_or_default();

    let create_result = provider_call(
        &config.provider_socket,
        "btsp.server.create_session",
        serde_json::json!({
            "family_seed": family_seed,
        }),
    )
    .await?;

    let session_token = json_str(&create_result, "session_token");
    let server_ephemeral_pub = json_str(&create_result, "server_ephemeral_pub");
    let challenge = json_str(&create_result, "challenge");

    let server_hello = serde_json::json!({
        "session_token": session_token,
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
        session_token,
        session_id: None,
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
    config: &super::config::BtspHandshakeConfig,
    hs: &mut HandshakeState,
) -> Result<(), String>
where
    S: tokio::io::AsyncWriteExt + Unpin,
{
    let verify_result = provider_call(
        &config.provider_socket,
        "btsp.server.verify",
        serde_json::json!({
            "session_token": hs.session_token,
            "client_ephemeral_pub": hs.client_ephemeral_pub,
            "response": hs.client_response,
            "preferred_cipher": hs.preferred_cipher,
        }),
    )
    .await?;

    let verified = verify_result
        .get("verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !verified {
        let reason = verify_result
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let err_frame = serde_json::json!({"error": "handshake_failed", "reason": reason});
        let _ = write_frame(stream, &serde_json::to_vec(&err_frame).unwrap_or_default()).await;
        return Err(format!("BTSP verify failed: {reason}"));
    }

    hs.session_id = verify_result
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let cipher = json_str_or(&verify_result, "cipher", "null");

    let _negotiate = provider_call(
        &config.provider_socket,
        "btsp.server.negotiate",
        serde_json::json!({
            "session_token": hs.session_token,
            "cipher": cipher,
        }),
    )
    .await;

    let sid = hs.session_id.as_deref().unwrap_or(&hs.session_token);
    let complete = serde_json::json!({
        "status": "complete",
        "session_id": sid,
        "cipher": cipher,
    });
    write_frame(
        stream,
        &serde_json::to_vec(&complete).map_err(|e| e.to_string())?,
    )
    .await
    .map_err(|e| format!("write Complete: {e}"))?;

    Ok(())
}

// ── JSON helpers ───────────────────────────────────────────────────────

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

#[cfg(test)]
mod tests {
    use super::*;

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
            session_token: "tok_abc".into(),
            session_id: Some("session_1".into()),
            client_response: String::new(),
            preferred_cipher: "chacha20_poly1305".into(),
        };
        assert_eq!(hs.session_token, "tok_abc");
        assert_eq!(hs.session_id.as_deref(), Some("session_1"));
        assert!(hs.client_response.is_empty());
    }

    #[tokio::test]
    async fn provider_call_success() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = std::env::temp_dir().join(format!("skunkbat-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("mock-provider.sock");
        let _ = std::fs::remove_file(&sock);

        let listener = tokio::net::UnixListener::bind(&sock).unwrap();

        let provider_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            if let Some(line) = lines.next_line().await.unwrap() {
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                let id = req["id"].clone();
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": {"greeting": "hello"},
                    "id": id,
                });
                let mut out = serde_json::to_string(&response).unwrap();
                out.push('\n');
                writer.write_all(out.as_bytes()).await.unwrap();
                writer.flush().await.unwrap();
            }
        });

        let result = provider_call(&sock, "test.hello", serde_json::json!({"name": "skunkbat"}))
            .await
            .unwrap();
        assert_eq!(result["greeting"], "hello");

        provider_handle.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn provider_call_rpc_error() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = std::env::temp_dir().join(format!("skunkbat-test-err-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("mock-err.sock");
        let _ = std::fs::remove_file(&sock);

        let listener = tokio::net::UnixListener::bind(&sock).unwrap();

        let provider_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            if let Some(line) = lines.next_line().await.unwrap() {
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                let id = req["id"].clone();
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "invalid request"},
                    "id": id,
                });
                let mut out = serde_json::to_string(&response).unwrap();
                out.push('\n');
                writer.write_all(out.as_bytes()).await.unwrap();
                writer.flush().await.unwrap();
            }
        });

        let result = provider_call(&sock, "test.bad", serde_json::json!({})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid request"));

        provider_handle.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handshake_exchange_with_mock_provider() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = std::env::temp_dir().join(format!("skunkbat-hs-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("mock-beardog.sock");
        let _ = std::fs::remove_file(&sock);

        let listener = tokio::net::UnixListener::bind(&sock).unwrap();

        let provider_handle = tokio::spawn(async move {
            for _ in 0..3 {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();

                if let Some(line) = lines.next_line().await.unwrap() {
                    let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                    let id = req["id"].clone();
                    let method = req["method"].as_str().unwrap_or("");

                    let result = match method {
                        "btsp.server.create_session" => serde_json::json!({
                            "server_ephemeral_pub": "c2VydmVyX2tleQ==",
                            "challenge": "Y2hhbGxlbmdlXzEyMw==",
                            "session_token": "tok_test_123",
                        }),
                        "btsp.server.verify" => serde_json::json!({
                            "verified": true,
                            "session_id": "sid_abc",
                            "cipher": "null",
                        }),
                        "btsp.server.negotiate" => serde_json::json!({
                            "accepted": true,
                            "cipher": "null",
                        }),
                        _ => serde_json::json!({"ok": true}),
                    };

                    let response = serde_json::json!({
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": id,
                    });
                    let mut out = serde_json::to_string(&response).unwrap();
                    out.push('\n');
                    writer.write_all(out.as_bytes()).await.unwrap();
                    writer.flush().await.unwrap();
                }
            }
        });

        let config = crate::ipc::transport::config::BtspHandshakeConfig {
            provider_socket: sock.clone(),
            family_id: "test-fam".into(),
        };

        let (client, server) = tokio::io::duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let mut server_stream = server;

        let client_handle = tokio::spawn(async move {
            let client_hello = serde_json::json!({"client_ephemeral_pub": "Y2xpZW50X2tleQ=="});
            let hello_bytes = serde_json::to_vec(&client_hello).unwrap();
            write_frame(&mut client_write, &hello_bytes).await.unwrap();

            let server_hello_bytes = read_frame(&mut client_read).await.unwrap();
            let server_hello: serde_json::Value =
                serde_json::from_slice(&server_hello_bytes).unwrap();
            assert!(server_hello.get("session_token").is_some());

            let cr =
                serde_json::json!({"response": "bXlfcmVzcG9uc2U=", "preferred_cipher": "null"});
            let cr_bytes = serde_json::to_vec(&cr).unwrap();
            write_frame(&mut client_write, &cr_bytes).await.unwrap();

            let complete_bytes = read_frame(&mut client_read).await.unwrap();
            let complete: serde_json::Value = serde_json::from_slice(&complete_bytes).unwrap();
            assert_eq!(complete["status"], "complete");
            assert_eq!(complete["session_id"], "sid_abc");
        });

        let result = perform_server_handshake(&mut server_stream, &config)
            .await
            .unwrap();
        assert_eq!(result.session_id, "sid_abc");

        client_handle.await.unwrap();
        provider_handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handshake_verify_failure() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let dir = std::env::temp_dir().join(format!("skunkbat-hs-fail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("mock-beardog-fail.sock");
        let _ = std::fs::remove_file(&sock);

        let listener = tokio::net::UnixListener::bind(&sock).unwrap();

        let provider_handle = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();

                if let Some(line) = lines.next_line().await.unwrap() {
                    let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                    let id = req["id"].clone();
                    let method = req["method"].as_str().unwrap_or("");

                    let result = match method {
                        "btsp.server.create_session" => serde_json::json!({
                            "server_ephemeral_pub": "c2VydmVyX2tleQ==",
                            "challenge": "Y2hhbGxlbmdlXzEyMw==",
                            "session_token": "tok_fail_123",
                        }),
                        "btsp.server.verify" => serde_json::json!({
                            "verified": false,
                            "error": "bad_response",
                        }),
                        _ => serde_json::json!({"ok": true}),
                    };

                    let response = serde_json::json!({
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": id,
                    });
                    let mut out = serde_json::to_string(&response).unwrap();
                    out.push('\n');
                    writer.write_all(out.as_bytes()).await.unwrap();
                    writer.flush().await.unwrap();
                }
            }
        });

        let config = crate::ipc::transport::config::BtspHandshakeConfig {
            provider_socket: sock.clone(),
            family_id: "test-fam".into(),
        };

        let (client, server) = tokio::io::duplex(4096);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let mut server_stream = server;

        let client_handle = tokio::spawn(async move {
            let client_hello = serde_json::json!({"client_ephemeral_pub": "Y2xpZW50X2tleQ=="});
            write_frame(
                &mut client_write,
                &serde_json::to_vec(&client_hello).unwrap(),
            )
            .await
            .unwrap();

            let _server_hello = read_frame(&mut client_read).await.unwrap();

            let cr = serde_json::json!({"response": "YmFk", "preferred_cipher": "null"});
            write_frame(&mut client_write, &serde_json::to_vec(&cr).unwrap())
                .await
                .unwrap();

            let err_bytes = read_frame(&mut client_read).await.unwrap();
            let err: serde_json::Value = serde_json::from_slice(&err_bytes).unwrap();
            assert_eq!(err["error"], "handshake_failed");
        });

        let result = perform_server_handshake(&mut server_stream, &config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bad_response"));

        client_handle.await.unwrap();
        provider_handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
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

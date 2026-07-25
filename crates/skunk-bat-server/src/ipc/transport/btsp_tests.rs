// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

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
    let ep = skunk_bat_integrations::rpc::TransportEndpoint::Uds {
        path: "/nonexistent/socket.sock".into(),
    };
    let result = provider_call(&ep, "test.method", serde_json::json!({})).await;
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

#[cfg(unix)]
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

    let ep = skunk_bat_integrations::rpc::TransportEndpoint::Uds {
        path: sock.to_string_lossy().into_owned(),
    };
    let result = provider_call(&ep, "test.hello", serde_json::json!({"name": "skunkbat"}))
        .await
        .unwrap();
    assert_eq!(result["greeting"], "hello");

    provider_handle.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
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

    let ep = skunk_bat_integrations::rpc::TransportEndpoint::Uds {
        path: sock.to_string_lossy().into_owned(),
    };
    let result = provider_call(&ep, "test.bad", serde_json::json!({})).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid request"));

    provider_handle.await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
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
        provider_endpoint: skunk_bat_integrations::rpc::TransportEndpoint::Uds {
            path: sock.to_string_lossy().into_owned(),
        },
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
        let server_hello: serde_json::Value = serde_json::from_slice(&server_hello_bytes).unwrap();
        assert!(server_hello.get("session_token").is_some());

        let cr = serde_json::json!({"response": "bXlfcmVzcG9uc2U=", "preferred_cipher": "null"});
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

#[cfg(unix)]
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
        provider_endpoint: skunk_bat_integrations::rpc::TransportEndpoint::Uds {
            path: sock.to_string_lossy().into_owned(),
        },
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
    assert!(result.unwrap_err().to_string().contains("bad_response"));

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

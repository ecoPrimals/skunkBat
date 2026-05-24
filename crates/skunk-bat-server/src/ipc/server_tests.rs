// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

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

    let handle = tokio::spawn(handle_connection(
        state,
        sessions,
        server,
        CallerContext::loopback(),
    ));

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

/// Helper: negotiate an encrypted session and return (writer, reader, keys).
async fn setup_encrypted_session(
    session_id: &str,
    handshake_key: Vec<u8>,
    nonce_byte: u8,
) -> (
    tokio::io::WriteHalf<tokio::io::DuplexStream>,
    tokio::io::ReadHalf<tokio::io::DuplexStream>,
    negotiate::SessionKeys,
    tokio::task::JoinHandle<()>,
) {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let state = make_state();
    let sessions = make_sessions();
    sessions
        .insert(session_id.to_owned(), Some(handshake_key.clone()))
        .await;

    let (client, server) = tokio::io::duplex(16384);
    let handle = tokio::spawn(handle_connection(
        state,
        sessions,
        server,
        CallerContext::loopback(),
    ));

    let (client_reader, mut client_writer) = tokio::io::split(client);

    let client_nonce = [nonce_byte; 16];
    let client_nonce_b64 = BASE64.encode(client_nonce);
    let negotiate_req = format!(
        r#"{{"jsonrpc":"2.0","method":"btsp.negotiate","params":{{"session_id":"{session_id}","ciphers":["chacha20-poly1305"],"client_nonce":"{client_nonce_b64}"}},"id":1}}"#
    );
    client_writer
        .write_all(format!("{negotiate_req}\n").as_bytes())
        .await
        .unwrap();

    let mut reader = BufReader::new(client_reader);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("timeout")
        .unwrap();

    let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(resp["result"]["cipher"], "chacha20-poly1305");

    let server_nonce = BASE64
        .decode(resp["result"]["server_nonce"].as_str().unwrap())
        .unwrap();
    let keys =
        negotiate::derive_session_keys(&handshake_key, &client_nonce, &server_nonce).unwrap();

    let inner_reader = reader.into_inner();
    (client_writer, inner_reader, keys, handle)
}

/// Helper: send an encrypted RPC request and read the decrypted response.
async fn encrypted_roundtrip(
    writer: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
    reader: &mut tokio::io::ReadHalf<tokio::io::DuplexStream>,
    keys: &negotiate::SessionKeys,
    request: &str,
) -> serde_json::Value {
    use tokio::io::AsyncReadExt;

    let encrypted = negotiate::encrypt_frame(&keys.decrypt_key, request.as_bytes()).unwrap();
    let len = u32::try_from(encrypted.len()).unwrap();
    writer.write_u32(len).await.unwrap();
    writer.write_all(&encrypted).await.unwrap();
    writer.flush().await.unwrap();

    let resp_len = tokio::time::timeout(Duration::from_secs(5), reader.read_u32())
        .await
        .expect("timeout reading frame len")
        .unwrap();
    let mut resp_buf = vec![0u8; resp_len as usize];
    reader.read_exact(&mut resp_buf).await.unwrap();

    let decrypted = negotiate::decrypt_frame(&keys.encrypt_key, &resp_buf).unwrap();
    serde_json::from_slice(&decrypted).unwrap()
}

// --- Basic NDJSON tests ---

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

    let handle = tokio::spawn(handle_connection(
        state,
        sessions,
        server,
        CallerContext::loopback(),
    ));

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

// --- BTSP negotiate tests ---

#[tokio::test]
async fn test_btsp_negotiate_no_session() {
    let line = roundtrip(
        r#"{"jsonrpc":"2.0","method":"btsp.negotiate","params":{"session_id":"fake","preferred_cipher":"chacha20-poly1305","bond_type":"Covalent"},"id":10}"#,
    ).await;
    let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert!(resp["error"].is_object());
}

#[tokio::test]
async fn test_btsp_negotiate_null_cipher_session() {
    let state = make_state();
    let sessions = make_sessions();
    sessions.insert("test-session-1".into(), None).await;

    let (client, server) = tokio::io::duplex(4096);
    let handle = tokio::spawn(handle_connection(
        state,
        sessions,
        server,
        CallerContext::loopback(),
    ));

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

// --- Encrypted frame loop tests ---

#[tokio::test]
async fn test_btsp_negotiate_upgrade_to_encrypted() {
    let (mut writer, mut reader, keys, handle) =
        setup_encrypted_session("enc-session", vec![0x42u8; 32], 0x01).await;

    let response = encrypted_roundtrip(
        &mut writer,
        &mut reader,
        &keys,
        r#"{"jsonrpc":"2.0","method":"health.liveness","id":2}"#,
    )
    .await;
    assert!(
        response["result"]["status"]
            .as_str()
            .unwrap()
            .contains("alive")
    );

    drop(writer);
    drop(reader);
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn test_encrypted_loop_multiple_messages() {
    let (mut writer, mut reader, keys, handle) =
        setup_encrypted_session("multi-session", vec![0xAA; 32], 0x02).await;

    let methods = ["health.liveness", "identity.get", "capabilities.list"];
    for (i, method) in methods.iter().enumerate() {
        let req = format!(r#"{{"jsonrpc":"2.0","method":"{method}","id":{}}}"#, i + 10);
        let response = encrypted_roundtrip(&mut writer, &mut reader, &keys, &req).await;
        assert!(
            response.get("result").is_some(),
            "message {i} ({method}) should have result, got: {response}"
        );
    }

    drop(writer);
    drop(reader);
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn test_plaintext_rejected_after_upgrade() {
    use tokio::io::AsyncReadExt;

    let (mut writer, mut inner_reader, _keys, handle) =
        setup_encrypted_session("reject-session", vec![0xBB; 32], 0x03).await;

    let plaintext_ndjson = b"{\"jsonrpc\":\"2.0\",\"method\":\"health.liveness\",\"id\":99}\n";
    writer.write_all(plaintext_ndjson).await.unwrap();
    writer.flush().await.unwrap();

    let read_result = tokio::time::timeout(Duration::from_secs(2), inner_reader.read_u32()).await;

    match read_result {
        Ok(Ok(_)) => panic!("server should not send a valid frame for plaintext input"),
        Ok(Err(e)) => {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "server should close connection on decrypt failure"
            );
        }
        Err(e) => {
            panic!("expected EOF, got error: {e} — server may be hanging");
        }
    }

    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn test_null_cipher_stays_ndjson() {
    let state = make_state();
    let sessions = make_sessions();
    sessions.insert("null-session".into(), None).await;

    let (client, server) = tokio::io::duplex(8192);
    let handle = tokio::spawn(handle_connection(
        state,
        sessions,
        server,
        CallerContext::loopback(),
    ));

    let (client_reader, mut client_writer) = tokio::io::split(client);

    let negotiate_req = r#"{"jsonrpc":"2.0","method":"btsp.negotiate","params":{"session_id":"null-session","preferred_cipher":"chacha20-poly1305"},"id":1}"#;
    client_writer
        .write_all(format!("{negotiate_req}\n").as_bytes())
        .await
        .unwrap();

    let mut reader = BufReader::new(client_reader);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("timeout")
        .unwrap();
    let resp: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(resp["result"]["cipher"], "null");

    let followup = r#"{"jsonrpc":"2.0","method":"health.liveness","id":2}"#;
    client_writer
        .write_all(format!("{followup}\n").as_bytes())
        .await
        .unwrap();

    let mut line2 = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line2))
        .await
        .expect("timeout reading followup response")
        .unwrap();
    let resp2: serde_json::Value = serde_json::from_str(line2.trim()).unwrap();
    assert!(
        resp2["result"]["status"]
            .as_str()
            .unwrap()
            .contains("alive")
    );

    client_writer.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn test_encrypted_batch_request() {
    use tokio::io::AsyncReadExt;

    let (mut writer, mut reader, keys, handle) =
        setup_encrypted_session("batch-session", vec![0xCC; 32], 0x04).await;

    let batch = r#"[{"jsonrpc":"2.0","method":"health.liveness","id":10},{"jsonrpc":"2.0","method":"identity.get","id":11}]"#;
    let response: Vec<serde_json::Value> = {
        let encrypted = negotiate::encrypt_frame(&keys.decrypt_key, batch.as_bytes()).unwrap();
        let len = u32::try_from(encrypted.len()).unwrap();
        writer.write_u32(len).await.unwrap();
        writer.write_all(&encrypted).await.unwrap();
        writer.flush().await.unwrap();

        let resp_len = tokio::time::timeout(Duration::from_secs(5), reader.read_u32())
            .await
            .expect("timeout")
            .unwrap();
        let mut resp_buf = vec![0u8; resp_len as usize];
        reader.read_exact(&mut resp_buf).await.unwrap();
        let decrypted = negotiate::decrypt_frame(&keys.encrypt_key, &resp_buf).unwrap();
        serde_json::from_slice(&decrypted).unwrap()
    };

    assert_eq!(response.len(), 2);
    assert!(
        response[0]["result"]["status"]
            .as_str()
            .unwrap()
            .contains("alive")
    );
    assert_eq!(response[1]["result"]["primal"], "skunkbat");

    drop(writer);
    drop(reader);
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn test_encrypted_notification_no_response() {
    use tokio::io::AsyncReadExt;

    let (mut writer, mut reader, keys, handle) =
        setup_encrypted_session("notif-session", vec![0xDD; 32], 0x05).await;

    let notification = r#"{"jsonrpc":"2.0","method":"health.liveness"}"#;
    let encrypted = negotiate::encrypt_frame(&keys.decrypt_key, notification.as_bytes()).unwrap();
    let len = u32::try_from(encrypted.len()).unwrap();
    writer.write_u32(len).await.unwrap();
    writer.write_all(&encrypted).await.unwrap();
    writer.flush().await.unwrap();

    let followup = r#"{"jsonrpc":"2.0","method":"identity.get","id":99}"#;
    let encrypted2 = negotiate::encrypt_frame(&keys.decrypt_key, followup.as_bytes()).unwrap();
    let len2 = u32::try_from(encrypted2.len()).unwrap();
    writer.write_u32(len2).await.unwrap();
    writer.write_all(&encrypted2).await.unwrap();
    writer.flush().await.unwrap();

    let resp_len = tokio::time::timeout(Duration::from_secs(5), reader.read_u32())
        .await
        .expect("timeout — notification may have caused a spurious response")
        .unwrap();
    let mut resp_buf = vec![0u8; resp_len as usize];
    reader.read_exact(&mut resp_buf).await.unwrap();

    let decrypted = negotiate::decrypt_frame(&keys.encrypt_key, &resp_buf).unwrap();
    let response: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(
        response["result"]["primal"], "skunkbat",
        "first response should be from identity.get (notification produces nothing)"
    );

    drop(writer);
    drop(reader);
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn test_negotiate_in_batch_rejected() {
    let state = make_state();
    let sessions = make_sessions();
    sessions
        .insert("batch-neg".into(), Some(vec![0xEE; 32]))
        .await;

    let (client, server) = tokio::io::duplex(8192);
    let handle = tokio::spawn(handle_connection(
        state,
        sessions,
        server,
        CallerContext::loopback(),
    ));

    let (client_reader, mut client_writer) = tokio::io::split(client);

    let batch = r#"[{"jsonrpc":"2.0","method":"btsp.negotiate","params":{"session_id":"batch-neg","ciphers":["chacha20-poly1305"],"client_nonce":"AAAAAAAAAAAAAAAAAAAAAA=="},"id":1},{"jsonrpc":"2.0","method":"health.liveness","id":2}]"#;
    client_writer
        .write_all(format!("{batch}\n").as_bytes())
        .await
        .unwrap();

    let mut reader = BufReader::new(client_reader);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .expect("timeout")
        .unwrap();

    let responses: Vec<serde_json::Value> = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(responses.len(), 2);

    assert!(
        responses[0]["error"].is_object(),
        "btsp.negotiate in batch should return error"
    );
    assert!(
        responses[0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("standalone"),
        "error should mention standalone requirement"
    );

    assert!(
        responses[1]["result"]["status"]
            .as_str()
            .unwrap()
            .contains("alive"),
        "other batch members should still succeed"
    );

    client_writer.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

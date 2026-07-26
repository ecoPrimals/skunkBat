// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BTSP client-side handshake for connecting to bearDog in strict mode.
//!
//! When `BEARDOG_UDS_REQUIRE_BTSP=1` is set, bearDog rejects plain JSON-RPC
//! with `-32600`. This module implements the consumer-side of the 4-step BTSP
//! handshake so skunkBat can authenticate before sending requests.
//!
//! The challenge response uses LOCAL `HMAC-SHA256` with the family seed — this
//! avoids the chicken-and-egg of needing bearDog to compute HMAC for the
//! handshake that authenticates us TO bearDog.
//!
//! ## Wire Format (NDJSON — newline-delimited)
//!
//! ```text
//! 1. Send  ClientHello       { protocol: "btsp", version: 1, client_ephemeral_pub }
//! 2. Read  ServerHello       { version, server_ephemeral_pub, challenge, session_id }
//! 3. Send  ChallengeResponse { response, preferred_cipher }
//! 4. Read  HandshakeComplete { cipher, session_id }
//! ```
//!
//! Reference: `songBird/crates/songbird-crypto-provider/src/btsp_client.rs`

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

type HmacSha256 = Hmac<Sha256>;

const BTSP_VERSION: u8 = 1;
const PREFERRED_CIPHER: &str = "chacha20_poly1305";

#[derive(Debug, Serialize)]
struct ClientHello {
    protocol: &'static str,
    version: u8,
    client_ephemeral_pub: String,
}

#[derive(Debug, Deserialize)]
struct ServerHello {
    #[expect(dead_code, reason = "validated implicitly by successful parse")]
    version: u8,
    #[expect(dead_code, reason = "used by session key derivation in Phase 3")]
    server_ephemeral_pub: String,
    challenge: String,
    session_id: String,
}

#[derive(Debug, Serialize)]
struct ChallengeResponse {
    response: String,
    preferred_cipher: &'static str,
}

#[derive(Debug, Deserialize)]
struct HandshakeComplete {
    pub cipher: String,
    pub session_id: String,
}

#[derive(Debug, Deserialize)]
struct HandshakeError {
    #[expect(dead_code, reason = "logged but not matched on")]
    pub error: String,
    pub reason: String,
}

/// Result of a successful client-side BTSP handshake.
#[derive(Debug, Clone)]
pub struct BtspClientSession {
    /// Unique session identifier from the server.
    pub session_id: String,
    /// Negotiated cipher suite (e.g. `chacha20_poly1305` or `null`).
    pub cipher: String,
}

/// Errors from the BTSP client handshake.
#[derive(Debug, thiserror::Error)]
pub enum BtspClientError {
    /// Family seed not available in environment.
    #[error("FAMILY_SEED not available — cannot perform BTSP handshake")]
    NoFamilySeed,
    /// I/O error on the stream during handshake.
    #[error("I/O error during BTSP handshake: {0}")]
    Io(#[from] std::io::Error),
    /// Server explicitly rejected the handshake (bad family seed, etc.).
    #[error("Server rejected handshake: {0}")]
    Rejected(String),
    /// Malformed or unexpected response from server.
    #[error("Malformed server response: {0}")]
    Protocol(String),
    /// HMAC computation failed (invalid key length).
    #[error("HMAC computation failed")]
    Hmac,
}

/// Resolve the raw family seed from environment.
///
/// Checks (in priority order): `BTSP_FAMILY_SEED`, `FAMILY_SEED`,
/// `BIOMEOS_FAMILY_SEED`.
fn resolve_family_seed_raw() -> Option<String> {
    std::env::var("BTSP_FAMILY_SEED")
        .or_else(|_| std::env::var(skunk_bat_core::env_keys::FAMILY_SEED))
        .or_else(|_| std::env::var("BIOMEOS_FAMILY_SEED"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
}

/// Check whether BTSP strict mode is expected (bearDog requires handshake).
///
/// Returns `true` if `BEARDOG_UDS_REQUIRE_BTSP=1` or `BTSP_STRICT_MODE=1`.
#[must_use]
pub fn btsp_strict_mode_expected() -> bool {
    std::env::var("BEARDOG_UDS_REQUIRE_BTSP")
        .or_else(|_| std::env::var("BTSP_STRICT_MODE"))
        .is_ok_and(|v| v.trim() == "1")
}

/// Check whether BTSP handshake is available (family seed present).
#[must_use]
pub fn btsp_handshake_available() -> bool {
    resolve_family_seed_raw().is_some()
}

/// Perform the client-side BTSP handshake over an NDJSON stream.
///
/// Authenticates to bearDog using the family seed from environment.
/// After success, the stream is ready for JSON-RPC traffic.
///
/// # Errors
///
/// Returns [`BtspClientError`] if the family seed is unavailable, the server
/// rejects the handshake, or I/O fails.
pub async fn perform_client_handshake<S>(
    stream: &mut S,
) -> Result<BtspClientSession, BtspClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let family_seed = resolve_family_seed_raw().ok_or(BtspClientError::NoFamilySeed)?;
    perform_client_handshake_with_seed(stream, &family_seed).await
}

/// Inner handshake with an explicit seed (testable without env mutation).
pub(crate) async fn perform_client_handshake_with_seed<S>(
    stream: &mut S,
    family_seed: &str,
) -> Result<BtspClientSession, BtspClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Generate ephemeral key material (32 random bytes)
    let mut ephemeral_key = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_key).map_err(|_| BtspClientError::Hmac)?;

    // Step 1: Send ClientHello
    let hello = ClientHello {
        protocol: "btsp",
        version: BTSP_VERSION,
        client_ephemeral_pub: BASE64_STANDARD.encode(ephemeral_key),
    };
    let hello_json = serde_json::to_string(&hello)
        .map_err(|e| BtspClientError::Protocol(format!("serialize ClientHello: {e}")))?;
    stream
        .write_all(hello_json.as_bytes())
        .await
        .map_err(BtspClientError::Io)?;
    stream.write_all(b"\n").await.map_err(BtspClientError::Io)?;
    stream.flush().await.map_err(BtspClientError::Io)?;

    debug!("BTSP client: sent ClientHello");

    // Step 2: Read ServerHello (or HandshakeError)
    let mut buf_reader = BufReader::new(&mut *stream);
    let mut line = String::new();
    buf_reader
        .read_line(&mut line)
        .await
        .map_err(BtspClientError::Io)?;

    if line.trim().is_empty() {
        return Err(BtspClientError::Protocol(String::from(
            "empty response from server",
        )));
    }

    if line.contains("\"error\"") && line.contains("\"reason\"") {
        let err: HandshakeError = serde_json::from_str(line.trim())
            .map_err(|e| BtspClientError::Protocol(format!("parse error response: {e}")))?;
        return Err(BtspClientError::Rejected(err.reason));
    }

    let server_hello: ServerHello = serde_json::from_str(line.trim())
        .map_err(|e| BtspClientError::Protocol(format!("parse ServerHello: {e}")))?;

    debug!(
        session_id = %server_hello.session_id,
        "BTSP client: received ServerHello"
    );

    // Step 3: Compute challenge response — HMAC-SHA256(family_seed, challenge)
    let challenge_bytes = BASE64_STANDARD
        .decode(&server_hello.challenge)
        .map_err(|e| BtspClientError::Protocol(format!("decode challenge: {e}")))?;

    let mut mac = HmacSha256::new_from_slice(family_seed.trim().as_bytes())
        .map_err(|_| BtspClientError::Hmac)?;
    mac.update(&challenge_bytes);
    let hmac_result = mac.finalize().into_bytes();

    let response = ChallengeResponse {
        response: BASE64_STANDARD.encode(hmac_result),
        preferred_cipher: PREFERRED_CIPHER,
    };
    let resp_json = serde_json::to_string(&response)
        .map_err(|e| BtspClientError::Protocol(format!("serialize ChallengeResponse: {e}")))?;

    let stream = buf_reader.into_inner();
    stream
        .write_all(resp_json.as_bytes())
        .await
        .map_err(BtspClientError::Io)?;
    stream.write_all(b"\n").await.map_err(BtspClientError::Io)?;
    stream.flush().await.map_err(BtspClientError::Io)?;

    debug!("BTSP client: sent ChallengeResponse");

    // Step 4: Read HandshakeComplete (or HandshakeError)
    let mut buf_reader = BufReader::new(&mut *stream);
    let mut line = String::new();
    buf_reader
        .read_line(&mut line)
        .await
        .map_err(BtspClientError::Io)?;

    if line.contains("\"error\"") && line.contains("\"reason\"") {
        let err: HandshakeError = serde_json::from_str(line.trim())
            .map_err(|e| BtspClientError::Protocol(format!("parse error response: {e}")))?;
        return Err(BtspClientError::Rejected(err.reason));
    }

    let complete: HandshakeComplete = serde_json::from_str(line.trim())
        .map_err(|e| BtspClientError::Protocol(format!("parse HandshakeComplete: {e}")))?;

    debug!(
        session_id = %complete.session_id,
        cipher = %complete.cipher,
        "BTSP client: handshake COMPLETE"
    );

    Ok(BtspClientSession {
        session_id: complete.session_id,
        cipher: complete.cipher,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btsp_strict_mode_default_off() {
        assert!(!btsp_strict_mode_expected());
    }

    #[test]
    fn hmac_computation_produces_32_bytes() {
        let key = b"test-family-seed";
        let challenge = b"random-challenge-data";
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(challenge);
        let result = mac.finalize().into_bytes();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn client_hello_serializes_correctly() {
        let hello = ClientHello {
            protocol: "btsp",
            version: 1,
            client_ephemeral_pub: String::from("AAAA"),
        };
        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("\"protocol\":\"btsp\""));
        assert!(json.contains("\"version\":1"));
    }

    #[test]
    fn challenge_response_serializes_correctly() {
        let resp = ChallengeResponse {
            response: String::from("dGVzdA=="),
            preferred_cipher: PREFERRED_CIPHER,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"preferred_cipher\":\"chacha20_poly1305\""));
        assert!(json.contains("\"response\":\"dGVzdA==\""));
    }

    #[test]
    fn handshake_complete_deserializes() {
        let json = r#"{"cipher":"chacha20_poly1305","session_id":"sess-123"}"#;
        let hc: HandshakeComplete = serde_json::from_str(json).unwrap();
        assert_eq!(hc.cipher, "chacha20_poly1305");
        assert_eq!(hc.session_id, "sess-123");
    }

    #[test]
    fn handshake_error_deserializes() {
        let json = r#"{"error":"auth_failed","reason":"bad HMAC"}"#;
        let he: HandshakeError = serde_json::from_str(json).unwrap();
        assert_eq!(he.reason, "bad HMAC");
    }

    #[test]
    fn server_hello_deserializes() {
        let json = r#"{"version":1,"server_ephemeral_pub":"BBBB","challenge":"Y2hhbA==","session_id":"sess-456"}"#;
        let sh: ServerHello = serde_json::from_str(json).unwrap();
        assert_eq!(sh.session_id, "sess-456");
        assert_eq!(sh.challenge, "Y2hhbA==");
    }

    /// Full 4-step handshake against a mock bearDog server.
    #[tokio::test]
    async fn full_handshake_against_mock_server() {
        use tokio::io::AsyncWriteExt;

        let seed = "test-family-seed-for-btsp";
        let (mut client_side, mut server_side) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let mut reader = BufReader::new(&mut server_side);

            // Step 1: Read `ClientHello`
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let hello: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(hello["protocol"], "btsp");
            assert_eq!(hello["version"], 1);
            assert!(!hello["client_ephemeral_pub"].as_str().unwrap().is_empty());

            // Step 2: Send `ServerHello`
            let challenge_bytes = b"mock-challenge-32-bytes-padding!";
            let challenge_b64 = BASE64_STANDARD.encode(challenge_bytes);
            let server_hello = serde_json::json!({
                "version": 1,
                "server_ephemeral_pub": "mock-server-pub",
                "challenge": challenge_b64,
                "session_id": "mock-session-001"
            });
            let stream = reader.into_inner();
            let mut sh_json = serde_json::to_string(&server_hello).unwrap();
            sh_json.push('\n');
            stream.write_all(sh_json.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();

            // Step 3: Read `ChallengeResponse` and verify HMAC
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let cr: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(cr["preferred_cipher"], "chacha20_poly1305");

            let client_hmac_b64 = cr["response"].as_str().unwrap();
            let client_hmac = BASE64_STANDARD.decode(client_hmac_b64).unwrap();

            let mut mac = HmacSha256::new_from_slice(seed.as_bytes()).unwrap();
            mac.update(challenge_bytes);
            let expected = mac.finalize().into_bytes();
            assert_eq!(client_hmac.as_slice(), expected.as_slice());

            // Step 4: Send `HandshakeComplete`
            let complete = serde_json::json!({
                "cipher": "chacha20_poly1305",
                "session_id": "mock-session-001"
            });
            let stream = reader.into_inner();
            let mut hc_json = serde_json::to_string(&complete).unwrap();
            hc_json.push('\n');
            stream.write_all(hc_json.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
        });

        let result = perform_client_handshake_with_seed(&mut client_side, seed).await;

        server.await.unwrap();

        let session = result.expect("handshake should succeed");
        assert_eq!(session.session_id, "mock-session-001");
        assert_eq!(session.cipher, "chacha20_poly1305");
    }

    /// Server sends `HandshakeError` at Step 2.
    #[tokio::test]
    async fn handshake_rejected_at_server_hello() {
        use tokio::io::AsyncWriteExt;

        let (mut client_side, mut server_side) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let mut reader = BufReader::new(&mut server_side);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let err = serde_json::json!({
                "error": "auth_failed",
                "reason": "unknown client identity"
            });
            let stream = reader.into_inner();
            let mut err_json = serde_json::to_string(&err).unwrap();
            err_json.push('\n');
            stream.write_all(err_json.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
        });

        let result = perform_client_handshake_with_seed(&mut client_side, "test-seed").await;

        server.await.unwrap();

        let err = result.unwrap_err();
        assert!(err.to_string().contains("unknown client identity"));
    }

    /// Server sends `HandshakeError` at Step 4 (bad HMAC).
    #[tokio::test]
    async fn handshake_rejected_at_challenge_response() {
        use tokio::io::AsyncWriteExt;

        let (mut client_side, mut server_side) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let mut reader = BufReader::new(&mut server_side);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let server_hello = serde_json::json!({
                "version": 1,
                "server_ephemeral_pub": "pub",
                "challenge": BASE64_STANDARD.encode(b"challenge"),
                "session_id": "sess"
            });
            let stream = reader.into_inner();
            let mut sh = serde_json::to_string(&server_hello).unwrap();
            sh.push('\n');
            stream.write_all(sh.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();

            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();

            let err = serde_json::json!({
                "error": "auth_failed",
                "reason": "HMAC mismatch"
            });
            let stream = reader.into_inner();
            let mut ej = serde_json::to_string(&err).unwrap();
            ej.push('\n');
            stream.write_all(ej.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
        });

        let result = perform_client_handshake_with_seed(&mut client_side, "wrong-seed").await;

        server.await.unwrap();

        let err = result.unwrap_err();
        assert!(err.to_string().contains("HMAC mismatch"));
    }

    /// Empty server response → protocol error.
    #[tokio::test]
    async fn handshake_empty_server_response() {
        let (mut client_side, mut server_side) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let mut reader = BufReader::new(&mut server_side);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let stream = reader.into_inner();
            stream.write_all(b"\n").await.unwrap();
            stream.flush().await.unwrap();
        });

        let result = perform_client_handshake_with_seed(&mut client_side, "seed").await;
        server.await.unwrap();

        assert!(matches!(result, Err(BtspClientError::Protocol(_))));
    }
}

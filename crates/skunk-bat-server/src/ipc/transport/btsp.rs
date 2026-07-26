// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BTSP (Biotic Transport Security Protocol) — wire framing, provider
//! client, and server-side handshake (Phase 2).
//!
//! Configuration lives in [`super::config`]; UID helpers in [`super::sys`].

use super::error::TransportError;
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

/// Timeout for provider (`BearDog`) RPC calls.
///
/// 10s is generous for local calls on the same gate; accommodates slow
/// crypto on resource-constrained hardware without hanging indefinitely.
const PROVIDER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Call the BTSP security provider via its resolved `TransportEndpoint`.
///
/// Dispatches through `rpc::call_endpoint` — works on any platform where
/// the provider is reachable (UDS on Unix, TCP everywhere).
pub async fn provider_call(
    endpoint: &skunk_bat_integrations::rpc::TransportEndpoint,
    method: &str,
    params: Value,
) -> Result<Value, TransportError> {
    let btsp = skunk_bat_integrations::btsp_client::btsp_strict_mode_expected()
        && skunk_bat_integrations::btsp_client::btsp_handshake_available();
    skunk_bat_integrations::rpc::call_endpoint_with_btsp(
        endpoint,
        method,
        Some(params),
        PROVIDER_TIMEOUT,
        btsp,
    )
    .await
    .map_err(|e| TransportError::Provider(format!("{endpoint:?}: {e}")))
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

    const MIN_FAMILY_SEED_BYTES: usize = 16;

    let seed_str = std::env::var(skunk_bat_core::env_keys::FAMILY_SEED).ok()?;
    if seed_str.len() < MIN_FAMILY_SEED_BYTES {
        tracing::warn!(
            "FAMILY_SEED too short for BTSP key derivation (minimum {MIN_FAMILY_SEED_BYTES} bytes)"
        );
        return None;
    }

    let hk = Hkdf::<Sha256>::new(Some(b"btsp-v1"), seed_str.as_bytes());
    let mut key = [0u8; 32];
    if let Err(e) = hk.expand(b"handshake", &mut key) {
        tracing::warn!("HKDF expand for BTSP handshake key failed: {e}");
        return None;
    }

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

/// Maximum time allowed for the full BTSP handshake sequence.
///
/// 30s default accommodates WAN latency (65ms+ RTT) plus `BearDog`
/// provider calls while preventing indefinite connection hangs.
/// Overridable via `SKUNKBAT_HANDSHAKE_DEADLINE`.
fn handshake_deadline() -> std::time::Duration {
    std::env::var(skunk_bat_core::env_keys::SKUNKBAT_HANDSHAKE_DEADLINE)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs,
        )
}

pub async fn perform_server_handshake<S>(
    stream: &mut S,
    config: &super::config::BtspHandshakeConfig,
) -> Result<HandshakeResult, TransportError>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let deadline = handshake_deadline();
    tokio::time::timeout(deadline, perform_server_handshake_inner(stream, config))
        .await
        .map_err(|_| {
            TransportError::Handshake(format!("timed out after {}s", deadline.as_secs()))
        })?
}

async fn perform_server_handshake_inner<S>(
    stream: &mut S,
    config: &super::config::BtspHandshakeConfig,
) -> Result<HandshakeResult, TransportError>
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
) -> Result<HandshakeState, TransportError>
where
    S: tokio::io::AsyncReadExt + tokio::io::AsyncWriteExt + Unpin,
{
    let client_hello_bytes = read_frame(stream)
        .await
        .map_err(|e| TransportError::Handshake(format!("read ClientHello: {e}")))?;
    let client_hello: Value = serde_json::from_slice(&client_hello_bytes)
        .map_err(|e| TransportError::Handshake(format!("parse ClientHello: {e}")))?;

    let client_ephemeral_pub = json_str(&client_hello, "client_ephemeral_pub");

    let family_seed = std::env::var(skunk_bat_core::env_keys::FAMILY_SEED).unwrap_or_default();

    let create_result = provider_call(
        &config.provider_endpoint,
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
    let hello_bytes = serde_json::to_vec(&server_hello)
        .map_err(|e| TransportError::Handshake(format!("serialize ServerHello: {e}")))?;
    write_frame(stream, &hello_bytes)
        .await
        .map_err(|e| TransportError::Handshake(format!("write ServerHello: {e}")))?;

    Ok(HandshakeState {
        client_ephemeral_pub,
        session_token,
        session_id: None,
        client_response: String::new(),
        preferred_cipher: String::new(),
    })
}

async fn btsp_read_challenge_response<S>(stream: &mut S) -> Result<(String, String), TransportError>
where
    S: tokio::io::AsyncReadExt + Unpin,
{
    let cr_bytes = read_frame(stream)
        .await
        .map_err(|e| TransportError::Handshake(format!("read ChallengeResponse: {e}")))?;
    let cr: Value = serde_json::from_slice(&cr_bytes)
        .map_err(|e| TransportError::Handshake(format!("parse ChallengeResponse: {e}")))?;

    Ok((
        json_str(&cr, "response"),
        json_str_or(&cr, "preferred_cipher", "null"),
    ))
}

async fn btsp_verify_and_complete<S>(
    stream: &mut S,
    config: &super::config::BtspHandshakeConfig,
    hs: &mut HandshakeState,
) -> Result<(), TransportError>
where
    S: tokio::io::AsyncWriteExt + Unpin,
{
    let verify_result = provider_call(
        &config.provider_endpoint,
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
        if let Err(e) =
            write_frame(stream, &serde_json::to_vec(&err_frame).unwrap_or_default()).await
        {
            tracing::warn!("failed to send handshake error frame to peer: {e}");
        }
        return Err(TransportError::Handshake(format!(
            "verify failed: {reason}"
        )));
    }

    hs.session_id = verify_result
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let cipher = json_str_or(&verify_result, "cipher", "null");

    if let Err(e) = provider_call(
        &config.provider_endpoint,
        "btsp.server.negotiate",
        serde_json::json!({
            "session_token": hs.session_token,
            "cipher": cipher,
        }),
    )
    .await
    {
        tracing::warn!("btsp.server.negotiate call to provider failed: {e}");
    }

    let sid = hs.session_id.as_deref().unwrap_or(&hs.session_token);
    let complete = serde_json::json!({
        "status": "complete",
        "session_id": sid,
        "cipher": cipher,
    });
    let complete_bytes = serde_json::to_vec(&complete)
        .map_err(|e| TransportError::Handshake(format!("serialize Complete: {e}")))?;
    write_frame(stream, &complete_bytes)
        .await
        .map_err(|e| TransportError::Handshake(format!("write Complete: {e}")))?;

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
#[path = "btsp_tests.rs"]
mod tests;

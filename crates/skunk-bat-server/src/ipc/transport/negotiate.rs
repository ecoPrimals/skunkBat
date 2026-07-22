// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BTSP Phase 3 — cipher negotiation and session key management.
//!
//! After a successful Phase 1/2 handshake, clients may send a
//! `btsp.negotiate` JSON-RPC method to request encrypted framing.
//! This module manages the session registry and cipher negotiation.
//!
//! When a handshake key is available (derived from `FAMILY_SEED` during
//! Phase 2), negotiation produces directional `ChaCha20-Poly1305` session
//! keys and the connection upgrades to encrypted framing. Falls back to
//! authenticated NULL cipher when no key material is present.

use chacha20poly1305::aead::rand_core::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Supported cipher suites per BTSP Protocol Standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// No encryption — authenticated via handshake only.
    Null,
    /// HMAC-SHA256 integrity tag per frame (no confidentiality).
    HmacPlain,
    /// ChaCha20-Poly1305 AEAD (full confidentiality + integrity).
    ChaCha20Poly1305,
}

impl CipherSuite {
    /// Wire representation for JSON-RPC responses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::HmacPlain => "hmac-plain",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

impl std::str::FromStr for CipherSuite {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "chacha20-poly1305" | "chacha20_poly1305" | "BTSP_CHACHA20_POLY1305" => {
                Self::ChaCha20Poly1305
            }
            "hmac-plain" | "hmac_plain" | "BTSP_HMAC_PLAIN" => Self::HmacPlain,
            _ => Self::Null,
        })
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// BTSP protocol version advertised in `btsp.negotiate` and `btsp.capabilities`.
pub const BTSP_PROTOCOL_VERSION: &str = "1.0";

/// Bond types that determine minimum cipher requirements.
///
/// Covalent bonds (genetic lineage) allow any cipher including null.
/// Metallic bonds (organizational) require at least HMAC integrity.
/// Ionic bonds (contractual) require full AEAD encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondType {
    /// Covalent (genetic lineage) — any cipher allowed including null.
    Covalent,
    /// Metallic (organizational) — minimum HMAC.
    Metallic,
    /// Ionic (contractual) — encrypted only.
    Ionic,
}

impl BondType {
    /// Minimum cipher required by this bond type.
    #[must_use]
    pub const fn minimum_cipher(self) -> CipherSuite {
        match self {
            Self::Covalent => CipherSuite::Null,
            Self::Metallic => CipherSuite::HmacPlain,
            Self::Ionic => CipherSuite::ChaCha20Poly1305,
        }
    }
}

impl std::str::FromStr for BondType {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Metallic" | "metallic" => Self::Metallic,
            "Ionic" | "ionic" => Self::Ionic,
            _ => Self::Covalent,
        })
    }
}

impl std::fmt::Display for BondType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Covalent => f.write_str("Covalent"),
            Self::Metallic => f.write_str("Metallic"),
            Self::Ionic => f.write_str("Ionic"),
        }
    }
}

/// State for an authenticated BTSP session.
#[derive(Debug, Clone)]
pub struct SessionState {
    /// When this session was created — used for TTL sweep.
    pub created_at: Instant,
    /// The negotiated cipher (initially Null after Phase 2).
    pub cipher: CipherSuite,
    /// Handshake key from `BearDog`'s `btsp.session.verify` (if provided).
    /// Required for Phase 3 key derivation.
    pub session_key: Option<Vec<u8>>,
    /// Derived directional keys after Phase 3 negotiate (server perspective).
    pub phase3_keys: Option<SessionKeys>,
}

/// Registry of active BTSP sessions.
///
/// Shared across all connections on a server instance. Sessions are
/// inserted after Phase 2 verify succeeds and looked up when
/// `btsp.negotiate` arrives.
#[derive(Debug, Clone, Default)]
pub struct SessionRegistry {
    sessions: Arc<RwLock<HashMap<String, SessionState>>>,
}

impl SessionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a session after successful Phase 2 handshake.
    pub async fn insert(&self, session_id: String, session_key: Option<Vec<u8>>) {
        let state = SessionState {
            created_at: Instant::now(),
            cipher: CipherSuite::Null,
            session_key,
            phase3_keys: None,
        };
        self.sessions.write().await.insert(session_id, state);
    }

    /// Look up a session by ID.
    pub async fn get(&self, session_id: &str) -> Option<SessionState> {
        self.sessions.read().await.get(session_id).cloned()
    }

    /// Update a session after Phase 3 negotiate completes.
    pub async fn update_phase3(&self, session_id: &str, cipher: CipherSuite, keys: SessionKeys) {
        if let Some(session) = self.sessions.write().await.get_mut(session_id) {
            session.cipher = cipher;
            session.phase3_keys = Some(keys);
        }
    }

    /// Remove a session (on disconnect or timeout).
    pub async fn remove(&self, session_id: &str) {
        self.sessions.write().await.remove(session_id);
    }

    /// Number of active sessions.
    pub async fn len(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Evict sessions older than `ttl`. Returns the number of evicted sessions.
    pub async fn sweep_expired(&self, ttl: std::time::Duration) -> usize {
        let now = Instant::now();
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, state| now.duration_since(state.created_at) < ttl);
        let evicted = before - sessions.len();
        drop(sessions);
        if evicted > 0 {
            tracing::info!("Session TTL sweep: evicted {evicted} expired sessions");
        }
        evicted
    }
}

/// Result of a `btsp.negotiate` call — includes both the JSON response
/// and the derived session keys (when encryption was negotiated).
pub struct NegotiateOutcome {
    /// The JSON-RPC result value to return to the client.
    pub response: serde_json::Value,
    /// Derived session keys when a non-null cipher was negotiated.
    pub session_keys: Option<SessionKeys>,
}

fn negotiate_error(error: &str, message: impl Into<String>) -> NegotiateOutcome {
    NegotiateOutcome {
        response: serde_json::json!({ "error": error, "message": message.into() }),
        session_keys: None,
    }
}

/// Handle a `btsp.negotiate` request.
///
/// Per BTSP Protocol Standard and `BearDog` reference implementation:
/// 1. Validate `session_id` exists in registry
/// 2. Decode `client_nonce` (base64)
/// 3. Select best cipher from `ciphers` array or `preferred_cipher`
/// 4. Generate 32-byte `server_nonce`
/// 5. Derive directional session keys via HKDF-SHA256
/// 6. Return negotiated cipher + `server_nonce` (base64)
///
/// Returns `{"cipher":"null","server_nonce":""}` when no supported cipher
/// is offered or no handshake key is available.
pub async fn handle_negotiate(
    registry: &SessionRegistry,
    params: Option<serde_json::Value>,
) -> NegotiateOutcome {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let Some(params) = params else {
        return negotiate_error(
            "params_required",
            "btsp.negotiate requires session_id, client_nonce, ciphers/preferred_cipher",
        );
    };

    let session_id = params
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    if session_id.is_empty() {
        return negotiate_error("invalid_session", "session_id is required");
    }

    let client_nonce_b64 = params
        .get("client_nonce")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    let client_nonce = if client_nonce_b64.is_empty() {
        Vec::new()
    } else {
        match BASE64.decode(client_nonce_b64) {
            Ok(n) => n,
            Err(e) => {
                return negotiate_error(
                    "invalid_client_nonce",
                    format!("base64 decode failed: {e}"),
                );
            }
        }
    };

    let offered_ciphers = extract_offered_ciphers(&params);

    let bond_type = params
        .get("bond_type")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| s.parse::<BondType>().ok());

    let Some(session) = registry.get(session_id).await else {
        return negotiate_error("unknown_session", "session_id not found in registry");
    };

    let selected = select_best_cipher(&offered_ciphers, session.session_key.is_some(), bond_type);

    if selected == CipherSuite::Null {
        tracing::info!(
            session_id = %session_id,
            "BTSP Phase 3: returning null cipher (no key material or unsupported ciphers)"
        );
        return NegotiateOutcome {
            response: serde_json::json!({
                "version": BTSP_PROTOCOL_VERSION,
                "cipher": "null",
                "server_nonce": "",
                "fallback": true
            }),
            session_keys: None,
        };
    }

    let mut server_nonce = [0u8; 32];
    chacha20poly1305::aead::OsRng.fill_bytes(&mut server_nonce);
    let server_nonce_b64 = BASE64.encode(server_nonce);

    let derived_keys = if let Some(ref handshake_key) = session.session_key {
        match derive_session_keys(handshake_key, &client_nonce, &server_nonce) {
            Ok(keys) => {
                registry
                    .update_phase3(session_id, selected, keys.clone())
                    .await;
                Some(keys)
            }
            Err(e) => {
                tracing::error!("BTSP Phase 3 key derivation failed: {e}");
                return negotiate_error("key_derivation_failed", "key derivation failed");
            }
        }
    } else {
        None
    };

    tracing::info!(
        session_id = %session_id,
        cipher = %selected.as_str(),
        "BTSP Phase 3 negotiate complete"
    );

    NegotiateOutcome {
        response: serde_json::json!({
            "version": BTSP_PROTOCOL_VERSION,
            "cipher": selected.as_str(),
            "server_nonce": server_nonce_b64,
            "fallback": false
        }),
        session_keys: derived_keys,
    }
}

/// Extract offered ciphers from params — accepts both `ciphers` array and
/// `preferred_cipher` string (`BearDog`-compatible).
#[expect(
    clippy::option_if_let_else,
    reason = "three-branch logic is clearest with if-let"
)]
fn extract_offered_ciphers(params: &serde_json::Value) -> Vec<CipherSuite> {
    if let Some(arr) = params.get("ciphers").and_then(|v| v.as_array()) {
        arr.iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.parse().unwrap_or(CipherSuite::Null))
            .collect()
    } else if let Some(cipher) = params.get("preferred_cipher").and_then(|v| v.as_str()) {
        vec![cipher.parse().unwrap_or(CipherSuite::Null)]
    } else {
        vec![CipherSuite::Null]
    }
}

/// Select the best cipher from client offers, respecting key availability
/// and optional bond-type minimum requirements.
///
/// `HmacPlain` is recognized in the protocol but not yet implemented on
/// the wire — treated as `Null` until a frame-level HMAC path exists.
fn select_best_cipher(
    offered: &[CipherSuite],
    has_key: bool,
    bond_type: Option<BondType>,
) -> CipherSuite {
    if !has_key {
        return CipherSuite::Null;
    }

    let selected = if offered.contains(&CipherSuite::ChaCha20Poly1305) {
        CipherSuite::ChaCha20Poly1305
    } else {
        CipherSuite::Null
    };

    if let Some(bond) = bond_type {
        let minimum = bond.minimum_cipher();
        if cipher_strength(selected) < cipher_strength(minimum) {
            tracing::warn!(
                bond_type = %bond,
                selected = %selected,
                minimum = %minimum,
                "bond type requires stronger cipher than negotiated — rejecting"
            );
            return CipherSuite::Null;
        }
    }

    selected
}

/// Numeric strength ordering for cipher comparison.
const fn cipher_strength(c: CipherSuite) -> u8 {
    match c {
        CipherSuite::Null => 0,
        CipherSuite::HmacPlain => 1,
        CipherSuite::ChaCha20Poly1305 => 2,
    }
}

// ── BTSP Phase 3 Key Derivation ───────────────────────────────────────

/// Derived session keys for bidirectional encrypted communication.
#[derive(Clone)]
pub struct SessionKeys {
    /// Key for encrypting outbound frames (server → client).
    pub encrypt_key: [u8; 32],
    /// Key for decrypting inbound frames (client → server).
    pub decrypt_key: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("encrypt_key", &"[REDACTED]")
            .field("decrypt_key", &"[REDACTED]")
            .finish()
    }
}

/// Derive bidirectional session keys from the handshake key and nonces.
///
/// Per BTSP Protocol Standard (`BearDog` reference implementation):
/// ```text
/// HKDF-SHA256(
///   ikm = handshake_key,
///   salt = client_nonce || server_nonce
/// )
/// expand(info = "btsp-session-v1-c2s") → client_to_server key (32 bytes)
/// expand(info = "btsp-session-v1-s2c") → server_to_client key (32 bytes)
/// ```
///
/// Server encrypts with `s2c` key, decrypts with `c2s` key.
/// # Errors
///
/// Returns `TransportError::Crypto` if HKDF expansion fails (should not
/// occur for 32-byte output, but handled without panics).
#[must_use = "session keys must be stored for encrypted transport"]
pub fn derive_session_keys(
    handshake_key: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> Result<SessionKeys, super::TransportError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut salt = Vec::with_capacity(client_nonce.len() + server_nonce.len());
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);

    let hk = Hkdf::<Sha256>::new(Some(&salt), handshake_key);

    let mut client_to_server = [0u8; 32];
    hk.expand(b"btsp-session-v1-c2s", &mut client_to_server)
        .map_err(|_| super::TransportError::Crypto("HKDF expand c2s failed".to_owned()))?;

    let mut server_to_client = [0u8; 32];
    hk.expand(b"btsp-session-v1-s2c", &mut server_to_client)
        .map_err(|_| super::TransportError::Crypto("HKDF expand s2c failed".to_owned()))?;

    Ok(SessionKeys {
        encrypt_key: server_to_client,
        decrypt_key: client_to_server,
    })
}

/// Nonce size for `ChaCha20-Poly1305` (12 bytes).
const NONCE_SIZE: usize = 12;

/// Minimum encrypted frame size: 12-byte nonce + 16-byte Poly1305 tag.
const MIN_ENCRYPTED_FRAME: usize = NONCE_SIZE + 16;

/// Encrypt a plaintext payload for BTSP wire transmission.
///
/// Returns `nonce(12) || ciphertext || tag(16)`.
/// Uses a random nonce per frame (matching `sweetGrass` / `BearDog` wire format).
///
/// # Errors
///
/// Returns `TransportError::Crypto` if AEAD encryption fails.
#[must_use = "encrypted frame must be transmitted"]
pub fn encrypt_frame(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, super::TransportError> {
    use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
    use chacha20poly1305::{AeadCore, ChaCha20Poly1305};

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| super::TransportError::Crypto(format!("encrypt: {e}")))?;

    let mut frame = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

/// Decrypt an incoming BTSP encrypted frame.
///
/// Expects `nonce(12) || ciphertext || tag(16)`.
///
/// # Errors
///
/// Returns `TransportError::Crypto` if the frame is too short or AEAD
/// authentication fails.
#[must_use = "decrypted frame must be processed"]
pub fn decrypt_frame(key: &[u8; 32], frame: &[u8]) -> Result<Vec<u8>, super::TransportError> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    if frame.len() < MIN_ENCRYPTED_FRAME {
        return Err(super::TransportError::Crypto(format!(
            "frame too short: {} bytes (min {MIN_ENCRYPTED_FRAME})",
            frame.len()
        )));
    }

    let (nonce_bytes, ciphertext) = frame.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| super::TransportError::Crypto(format!("decrypt: {e}")))
}

#[cfg(test)]
#[path = "negotiate_tests.rs"]
mod tests;

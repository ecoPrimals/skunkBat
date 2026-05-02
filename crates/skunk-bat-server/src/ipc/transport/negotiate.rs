// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BTSP Phase 3 — cipher negotiation and session key management.
//!
//! After a successful Phase 1/2 handshake, clients may send a
//! `btsp.negotiate` JSON-RPC method to request encrypted framing.
//! This module manages the session registry and cipher negotiation.
//!
//! Current state: returns `{"cipher":"null"}` (authenticated plaintext).
//! Infrastructure for `ChaCha20-Poly1305` AEAD is wired and ready for
//! activation once `BearDog` exposes session key material via IPC.

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
    /// Parse from the wire representation.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s {
            "chacha20-poly1305" | "chacha20_poly1305" | "BTSP_CHACHA20_POLY1305" => {
                Self::ChaCha20Poly1305
            }
            "hmac-plain" | "hmac_plain" | "BTSP_HMAC_PLAIN" => Self::HmacPlain,
            _ => Self::Null,
        }
    }

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

/// Bond types that determine minimum cipher requirements.
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
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s {
            "Metallic" | "metallic" => Self::Metallic,
            "Ionic" | "ionic" => Self::Ionic,
            _ => Self::Covalent,
        }
    }

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

/// State for an authenticated BTSP session.
#[derive(Debug, Clone)]
pub struct SessionState {
    /// When this session was created (for TTL expiry in Phase 3+).
    #[expect(
        dead_code,
        reason = "used for session expiry once cleanup task is added"
    )]
    pub created_at: Instant,
    /// The negotiated cipher (initially Null after Phase 2).
    pub cipher: CipherSuite,
    /// Session key from `BearDog`'s `btsp.session.verify` (if provided).
    /// Required for Phase 3 encrypted framing.
    pub session_key: Option<Vec<u8>>,
    /// Server nonce generated during negotiate (12 bytes, hex-encoded on wire).
    pub server_nonce: Option<[u8; 12]>,
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
            server_nonce: None,
        };
        self.sessions.write().await.insert(session_id, state);
    }

    /// Look up a session by ID.
    pub async fn get(&self, session_id: &str) -> Option<SessionState> {
        self.sessions.read().await.get(session_id).cloned()
    }

    /// Update a session after negotiate.
    pub async fn update_cipher(
        &self,
        session_id: &str,
        cipher: CipherSuite,
        server_nonce: [u8; 12],
    ) {
        if let Some(session) = self.sessions.write().await.get_mut(session_id) {
            session.cipher = cipher;
            session.server_nonce = Some(server_nonce);
        }
    }

    /// Remove a session (on disconnect or timeout).
    #[allow(dead_code, reason = "used in tests + future session TTL cleanup")]
    pub async fn remove(&self, session_id: &str) {
        self.sessions.write().await.remove(session_id);
    }

    /// Number of active sessions.
    #[allow(dead_code, reason = "used in tests + future metrics")]
    pub async fn len(&self) -> usize {
        self.sessions.read().await.len()
    }
}

/// Handle a `btsp.negotiate` request.
///
/// Per BTSP Protocol Standard:
/// 1. Validate `session_id` exists in registry
/// 2. Check `bond_type` minimum cipher requirements
/// 3. Generate 12-byte `server_nonce`
/// 4. Return negotiated cipher + `server_nonce`
///
/// Currently returns `{"cipher":"null"}` because session key material
/// from `BearDog` is not yet propagated through the handshake pipeline.
/// When `BearDog`'s `btsp.session.verify` response includes a `session_key`,
/// this will upgrade to `chacha20-poly1305` automatically.
pub async fn handle_negotiate(
    registry: &SessionRegistry,
    params: Option<serde_json::Value>,
) -> serde_json::Value {
    let Some(params) = params else {
        return serde_json::json!({
            "error": "params_required",
            "message": "btsp.negotiate requires session_id, preferred_cipher, bond_type"
        });
    };

    let session_id = params
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    if session_id.is_empty() {
        return serde_json::json!({
            "error": "invalid_session",
            "message": "session_id is required"
        });
    }

    let preferred = params
        .get("preferred_cipher")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("null");
    let bond_type = params
        .get("bond_type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("Covalent");

    let Some(session) = registry.get(session_id).await else {
        return serde_json::json!({
            "error": "unknown_session",
            "message": "session_id not found in registry"
        });
    };

    let requested = CipherSuite::from_str(preferred);
    let bond = BondType::from_str(bond_type);
    let minimum = bond.minimum_cipher();

    let selected = select_cipher(requested, minimum, session.session_key.is_some());

    let server_nonce: [u8; 12] = rand::random();
    let nonce_hex = hex::encode(server_nonce);

    registry
        .update_cipher(session_id, selected, server_nonce)
        .await;

    tracing::info!(
        session_id = %session_id,
        cipher = %selected.as_str(),
        "BTSP Phase 3 negotiate complete"
    );

    serde_json::json!({
        "cipher": selected.as_str(),
        "server_nonce": nonce_hex
    })
}

/// Select the best cipher given request, bond minimum, and key availability.
///
/// Enforces: if requested cipher is weaker than minimum, upgrades to minimum.
/// Without key material, always falls back to Null (authenticated plaintext).
const fn select_cipher(requested: CipherSuite, minimum: CipherSuite, has_key: bool) -> CipherSuite {
    if !has_key {
        return CipherSuite::Null;
    }

    if cipher_strength(requested) >= cipher_strength(minimum) {
        requested
    } else {
        minimum
    }
}

/// Cipher strength ordering for comparison.
const fn cipher_strength(cipher: CipherSuite) -> u8 {
    match cipher {
        CipherSuite::Null => 0,
        CipherSuite::HmacPlain => 1,
        CipherSuite::ChaCha20Poly1305 => 2,
    }
}

// ── BTSP Phase 3 Key Derivation ───────────────────────────────────────

/// Derived session keys for bidirectional encrypted communication.
#[allow(dead_code, reason = "activated once BearDog propagates session keys")]
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
/// Uses HKDF-SHA256 per BTSP Protocol Standard:
/// ```text
/// HKDF-SHA256(
///   ikm = handshake_key,
///   salt = "btsp-session-v1",
///   info = client_nonce || server_nonce
/// ) → 64 bytes → split into encrypt_key(32) + decrypt_key(32)
/// ```
#[allow(dead_code, reason = "activated once BearDog propagates session keys")]
pub fn derive_session_keys(
    handshake_key: &[u8],
    client_nonce: &[u8; 12],
    server_nonce: &[u8; 12],
) -> SessionKeys {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let salt = b"btsp-session-v1";
    let mut info = [0u8; 24];
    info[..12].copy_from_slice(client_nonce);
    info[12..].copy_from_slice(server_nonce);

    let hk = Hkdf::<Sha256>::new(Some(salt), handshake_key);
    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm)
        .expect("64 bytes is within HKDF-SHA256 output limit");

    let mut encrypt_key = [0u8; 32];
    let mut decrypt_key = [0u8; 32];
    encrypt_key.copy_from_slice(&okm[..32]);
    decrypt_key.copy_from_slice(&okm[32..]);

    SessionKeys {
        encrypt_key,
        decrypt_key,
    }
}

/// Encrypt a single BTSP frame using `ChaCha20-Poly1305`.
///
/// Returns the ciphertext with appended Poly1305 tag (16 bytes).
/// The `frame_counter` is used to construct the 12-byte nonce.
#[allow(
    dead_code,
    reason = "activated once encrypted framing is wired into handle_connection"
)]
pub fn encrypt_frame(
    key: &[u8; 32],
    frame_counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    let cipher = ChaCha20Poly1305::new(key.into());

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&frame_counter.to_be_bytes());
    let nonce = Nonce::from(nonce_bytes);

    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("encrypt failed: {e}"))
}

/// Decrypt a single BTSP frame using `ChaCha20-Poly1305`.
///
/// Expects ciphertext with appended Poly1305 tag.
#[allow(
    dead_code,
    reason = "activated once encrypted framing is wired into handle_connection"
)]
pub fn decrypt_frame(
    key: &[u8; 32],
    frame_counter: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    let cipher = ChaCha20Poly1305::new(key.into());

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&frame_counter.to_be_bytes());
    let nonce = Nonce::from(nonce_bytes);

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| format!("decrypt failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_suite_roundtrip() {
        assert_eq!(
            CipherSuite::from_str("chacha20-poly1305"),
            CipherSuite::ChaCha20Poly1305
        );
        assert_eq!(
            CipherSuite::from_str("chacha20_poly1305"),
            CipherSuite::ChaCha20Poly1305
        );
        assert_eq!(CipherSuite::from_str("hmac-plain"), CipherSuite::HmacPlain);
        assert_eq!(CipherSuite::from_str("null"), CipherSuite::Null);
        assert_eq!(CipherSuite::from_str("unknown"), CipherSuite::Null);
        assert_eq!(CipherSuite::ChaCha20Poly1305.as_str(), "chacha20-poly1305");
        assert_eq!(CipherSuite::HmacPlain.as_str(), "hmac-plain");
        assert_eq!(CipherSuite::Null.as_str(), "null");
    }

    #[test]
    fn bond_type_minimum_cipher() {
        assert_eq!(BondType::Covalent.minimum_cipher(), CipherSuite::Null);
        assert_eq!(BondType::Metallic.minimum_cipher(), CipherSuite::HmacPlain);
        assert_eq!(
            BondType::Ionic.minimum_cipher(),
            CipherSuite::ChaCha20Poly1305
        );
    }

    #[test]
    fn bond_type_parsing() {
        assert_eq!(BondType::from_str("Covalent"), BondType::Covalent);
        assert_eq!(BondType::from_str("Metallic"), BondType::Metallic);
        assert_eq!(BondType::from_str("Ionic"), BondType::Ionic);
        assert_eq!(BondType::from_str("ionic"), BondType::Ionic);
        assert_eq!(BondType::from_str("garbage"), BondType::Covalent);
    }

    #[tokio::test]
    async fn session_registry_lifecycle() {
        let reg = SessionRegistry::new();
        assert_eq!(reg.len().await, 0);

        reg.insert("ses-1".into(), None).await;
        assert_eq!(reg.len().await, 1);

        let session = reg.get("ses-1").await.unwrap();
        assert_eq!(session.cipher, CipherSuite::Null);
        assert!(session.session_key.is_none());

        reg.update_cipher("ses-1", CipherSuite::ChaCha20Poly1305, [0xAA; 12])
            .await;
        let updated = reg.get("ses-1").await.unwrap();
        assert_eq!(updated.cipher, CipherSuite::ChaCha20Poly1305);
        assert_eq!(updated.server_nonce, Some([0xAA; 12]));

        reg.remove("ses-1").await;
        assert!(reg.get("ses-1").await.is_none());
        assert_eq!(reg.len().await, 0);
    }

    #[tokio::test]
    async fn session_registry_with_key() {
        let reg = SessionRegistry::new();
        let key = vec![0x42; 32];
        reg.insert("ses-key".into(), Some(key.clone())).await;

        let session = reg.get("ses-key").await.unwrap();
        assert_eq!(session.session_key.as_deref(), Some(key.as_slice()));
    }

    #[tokio::test]
    async fn negotiate_missing_params() {
        let reg = SessionRegistry::new();
        let result = handle_negotiate(&reg, None).await;
        assert!(result.get("error").is_some());
    }

    #[tokio::test]
    async fn negotiate_empty_session_id() {
        let reg = SessionRegistry::new();
        let params = serde_json::json!({
            "session_id": "",
            "preferred_cipher": "chacha20-poly1305",
            "bond_type": "Covalent"
        });
        let result = handle_negotiate(&reg, Some(params)).await;
        assert_eq!(result["error"], "invalid_session");
    }

    #[tokio::test]
    async fn negotiate_unknown_session() {
        let reg = SessionRegistry::new();
        let params = serde_json::json!({
            "session_id": "nonexistent",
            "preferred_cipher": "chacha20-poly1305",
            "bond_type": "Covalent"
        });
        let result = handle_negotiate(&reg, Some(params)).await;
        assert_eq!(result["error"], "unknown_session");
    }

    #[tokio::test]
    async fn negotiate_null_fallback_no_key() {
        let reg = SessionRegistry::new();
        reg.insert("ses-nokey".into(), None).await;

        let params = serde_json::json!({
            "session_id": "ses-nokey",
            "preferred_cipher": "chacha20-poly1305",
            "bond_type": "Covalent"
        });
        let result = handle_negotiate(&reg, Some(params)).await;
        assert_eq!(result["cipher"], "null");
        assert!(result["server_nonce"].is_string());
    }

    #[tokio::test]
    async fn negotiate_chacha_with_key() {
        let reg = SessionRegistry::new();
        reg.insert("ses-withkey".into(), Some(vec![0x42; 32])).await;

        let params = serde_json::json!({
            "session_id": "ses-withkey",
            "preferred_cipher": "chacha20-poly1305",
            "bond_type": "Covalent"
        });
        let result = handle_negotiate(&reg, Some(params)).await;
        assert_eq!(result["cipher"], "chacha20-poly1305");
        assert!(result["server_nonce"].is_string());

        let nonce_hex = result["server_nonce"].as_str().unwrap();
        assert_eq!(nonce_hex.len(), 24); // 12 bytes = 24 hex chars
    }

    #[test]
    fn select_cipher_no_key_always_null() {
        assert_eq!(
            select_cipher(CipherSuite::ChaCha20Poly1305, CipherSuite::Null, false),
            CipherSuite::Null
        );
        assert_eq!(
            select_cipher(
                CipherSuite::ChaCha20Poly1305,
                CipherSuite::ChaCha20Poly1305,
                false
            ),
            CipherSuite::Null
        );
    }

    #[test]
    fn select_cipher_with_key_honors_request() {
        assert_eq!(
            select_cipher(CipherSuite::ChaCha20Poly1305, CipherSuite::Null, true),
            CipherSuite::ChaCha20Poly1305
        );
        assert_eq!(
            select_cipher(CipherSuite::HmacPlain, CipherSuite::Null, true),
            CipherSuite::HmacPlain
        );
    }

    #[test]
    fn select_cipher_enforces_minimum() {
        assert_eq!(
            select_cipher(CipherSuite::Null, CipherSuite::HmacPlain, true),
            CipherSuite::HmacPlain,
            "Metallic bond requires at minimum HMAC"
        );
        assert_eq!(
            select_cipher(CipherSuite::HmacPlain, CipherSuite::ChaCha20Poly1305, true),
            CipherSuite::ChaCha20Poly1305,
            "Ionic bond requires full encryption"
        );
        assert_eq!(
            select_cipher(
                CipherSuite::ChaCha20Poly1305,
                CipherSuite::ChaCha20Poly1305,
                true
            ),
            CipherSuite::ChaCha20Poly1305,
            "Request matches minimum"
        );
    }

    #[test]
    fn cipher_strength_ordering() {
        assert!(cipher_strength(CipherSuite::Null) < cipher_strength(CipherSuite::HmacPlain));
        assert!(
            cipher_strength(CipherSuite::HmacPlain)
                < cipher_strength(CipherSuite::ChaCha20Poly1305)
        );
    }

    // ── Key Derivation Tests ──────────────────────────────────────────

    #[test]
    fn derive_session_keys_deterministic() {
        let handshake_key = [0x42u8; 32];
        let client_nonce = [0x01u8; 12];
        let server_nonce = [0x02u8; 12];

        let keys1 = derive_session_keys(&handshake_key, &client_nonce, &server_nonce);
        let keys2 = derive_session_keys(&handshake_key, &client_nonce, &server_nonce);

        assert_eq!(keys1.encrypt_key, keys2.encrypt_key);
        assert_eq!(keys1.decrypt_key, keys2.decrypt_key);
    }

    #[test]
    fn derive_session_keys_different_nonces_different_keys() {
        let handshake_key = [0x42u8; 32];
        let client_nonce = [0x01u8; 12];
        let server_nonce_a = [0x02u8; 12];
        let server_nonce_b = [0x03u8; 12];

        let keys_a = derive_session_keys(&handshake_key, &client_nonce, &server_nonce_a);
        let keys_b = derive_session_keys(&handshake_key, &client_nonce, &server_nonce_b);

        assert_ne!(keys_a.encrypt_key, keys_b.encrypt_key);
    }

    #[test]
    fn derive_session_keys_encrypt_decrypt_differ() {
        let handshake_key = [0x42u8; 32];
        let client_nonce = [0x01u8; 12];
        let server_nonce = [0x02u8; 12];

        let keys = derive_session_keys(&handshake_key, &client_nonce, &server_nonce);
        assert_ne!(keys.encrypt_key, keys.decrypt_key);
    }

    #[test]
    fn session_keys_debug_redacts() {
        let keys = derive_session_keys(&[0x42; 32], &[0x01; 12], &[0x02; 12]);
        let debug = format!("{keys:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("42"));
    }

    // ── Encrypt/Decrypt Tests ─────────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_session_keys(&[0xAA; 32], &[0x01; 12], &[0x02; 12]);
        let plaintext = b"hello btsp phase 3";

        let ciphertext = encrypt_frame(&key.encrypt_key, 0, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
        assert!(ciphertext.len() > plaintext.len()); // tag adds 16 bytes

        let decrypted = decrypt_frame(&key.encrypt_key, 0, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_different_counters_different_ciphertext() {
        let key = [0xBB; 32];
        let plaintext = b"same plaintext";

        let ct0 = encrypt_frame(&key, 0, plaintext).unwrap();
        let ct1 = encrypt_frame(&key, 1, plaintext).unwrap();
        assert_ne!(ct0, ct1);
    }

    #[test]
    fn decrypt_wrong_counter_fails() {
        let key = [0xCC; 32];
        let plaintext = b"sensitive data";

        let ciphertext = encrypt_frame(&key, 42, plaintext).unwrap();
        let result = decrypt_frame(&key, 43, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key_a = [0xDD; 32];
        let key_b = [0xEE; 32];
        let plaintext = b"classified";

        let ciphertext = encrypt_frame(&key_a, 0, plaintext).unwrap();
        let result = decrypt_frame(&key_b, 0, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = [0xFF; 32];
        let plaintext = b"integrity check";

        let mut ciphertext = encrypt_frame(&key, 0, plaintext).unwrap();
        if let Some(byte) = ciphertext.get_mut(5) {
            *byte ^= 0x01;
        }
        let result = decrypt_frame(&key, 0, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_empty_payload() {
        let key = [0x11; 32];
        let ciphertext = encrypt_frame(&key, 0, b"").unwrap();
        assert_eq!(ciphertext.len(), 16); // just the tag
        let decrypted = decrypt_frame(&key, 0, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BTSP Phase 3 — encrypted frame operations and session key derivation.
//!
//! Pure cryptographic operations for BTSP wire-level encrypted transport.
//! Separated from negotiation logic so that frame encrypt/decrypt can be
//! used independently by the connection handler without pulling in session
//! registry or cipher selection.

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

/// Nonce size for `ChaCha20-Poly1305` (12 bytes).
pub const NONCE_SIZE: usize = 12;

/// Minimum encrypted frame size: 12-byte nonce + 16-byte Poly1305 tag.
const MIN_ENCRYPTED_FRAME: usize = NONCE_SIZE + 16;

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

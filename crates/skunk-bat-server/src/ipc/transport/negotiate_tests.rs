use super::*;

#[test]
fn cipher_suite_roundtrip() {
    assert_eq!(
        "chacha20-poly1305".parse::<CipherSuite>().unwrap(),
        CipherSuite::ChaCha20Poly1305
    );
    assert_eq!(
        "chacha20_poly1305".parse::<CipherSuite>().unwrap(),
        CipherSuite::ChaCha20Poly1305
    );
    assert_eq!(
        "hmac-plain".parse::<CipherSuite>().unwrap(),
        CipherSuite::HmacPlain
    );
    assert_eq!("null".parse::<CipherSuite>().unwrap(), CipherSuite::Null);
    assert_eq!("unknown".parse::<CipherSuite>().unwrap(), CipherSuite::Null);
    assert_eq!(CipherSuite::ChaCha20Poly1305.as_str(), "chacha20-poly1305");
    assert_eq!(CipherSuite::HmacPlain.as_str(), "hmac-plain");
    assert_eq!(CipherSuite::Null.as_str(), "null");
    assert_eq!(
        CipherSuite::ChaCha20Poly1305.to_string(),
        "chacha20-poly1305"
    );
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
    assert_eq!("Covalent".parse::<BondType>().unwrap(), BondType::Covalent);
    assert_eq!("Metallic".parse::<BondType>().unwrap(), BondType::Metallic);
    assert_eq!("Ionic".parse::<BondType>().unwrap(), BondType::Ionic);
    assert_eq!("ionic".parse::<BondType>().unwrap(), BondType::Ionic);
    assert_eq!("garbage".parse::<BondType>().unwrap(), BondType::Covalent);
    assert_eq!(BondType::Ionic.to_string(), "Ionic");
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
    assert!(session.phase3_keys.is_none());

    let keys = derive_session_keys(&[0x42; 32], &[0x01; 12], &[0x02; 32]).unwrap();
    reg.update_phase3("ses-1", CipherSuite::ChaCha20Poly1305, keys)
        .await;
    let updated = reg.get("ses-1").await.unwrap();
    assert_eq!(updated.cipher, CipherSuite::ChaCha20Poly1305);
    assert!(updated.phase3_keys.is_some());

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
    let outcome = handle_negotiate(&reg, None).await;
    assert!(outcome.response.get("error").is_some());
    assert!(outcome.session_keys.is_none());
}

#[tokio::test]
async fn negotiate_empty_session_id() {
    let reg = SessionRegistry::new();
    let params = serde_json::json!({
        "session_id": "",
        "preferred_cipher": "chacha20-poly1305",
        "bond_type": "Covalent"
    });
    let outcome = handle_negotiate(&reg, Some(params)).await;
    assert_eq!(outcome.response["error"], "invalid_session");
    assert!(outcome.session_keys.is_none());
}

#[tokio::test]
async fn negotiate_unknown_session() {
    let reg = SessionRegistry::new();
    let params = serde_json::json!({
        "session_id": "nonexistent",
        "preferred_cipher": "chacha20-poly1305",
        "bond_type": "Covalent"
    });
    let outcome = handle_negotiate(&reg, Some(params)).await;
    assert_eq!(outcome.response["error"], "unknown_session");
    assert!(outcome.session_keys.is_none());
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
    let outcome = handle_negotiate(&reg, Some(params)).await;
    assert_eq!(outcome.response["cipher"], "null");
    assert!(outcome.response["server_nonce"].is_string());
    assert!(outcome.session_keys.is_none());
}

#[tokio::test]
async fn negotiate_chacha_with_key() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let reg = SessionRegistry::new();
    reg.insert("ses-withkey".into(), Some(vec![0x42; 32])).await;

    let client_nonce = BASE64.encode([0x01u8; 16]);
    let params = serde_json::json!({
        "session_id": "ses-withkey",
        "ciphers": ["chacha20-poly1305"],
        "client_nonce": client_nonce,
        "bond_type": "Covalent"
    });
    let outcome = handle_negotiate(&reg, Some(params)).await;
    assert_eq!(outcome.response["cipher"], "chacha20-poly1305");
    assert!(outcome.response["server_nonce"].is_string());
    assert!(outcome.session_keys.is_some());

    let nonce_b64 = outcome.response["server_nonce"].as_str().unwrap();
    let decoded = BASE64.decode(nonce_b64).unwrap();
    assert_eq!(decoded.len(), 32);

    let session = reg.get("ses-withkey").await.unwrap();
    assert_eq!(session.cipher, CipherSuite::ChaCha20Poly1305);
    assert!(session.phase3_keys.is_some());
}

#[test]
fn select_best_cipher_no_key_always_null() {
    let offered = vec![CipherSuite::ChaCha20Poly1305];
    assert_eq!(select_best_cipher(&offered, false), CipherSuite::Null);
}

#[test]
fn select_best_cipher_prefers_chacha20() {
    let offered = vec![
        CipherSuite::Null,
        CipherSuite::ChaCha20Poly1305,
        CipherSuite::HmacPlain,
    ];
    assert_eq!(
        select_best_cipher(&offered, true),
        CipherSuite::ChaCha20Poly1305
    );
}

#[test]
fn select_best_cipher_hmac_not_implemented_falls_to_null() {
    let offered = vec![CipherSuite::Null, CipherSuite::HmacPlain];
    assert_eq!(
        select_best_cipher(&offered, true),
        CipherSuite::Null,
        "hmac-plain recognized but not implemented on wire — falls to null"
    );
}

#[test]
fn select_best_cipher_null_only() {
    let offered = vec![CipherSuite::Null];
    assert_eq!(select_best_cipher(&offered, true), CipherSuite::Null);
}

#[test]
fn extract_offered_ciphers_from_array() {
    let params = serde_json::json!({
        "ciphers": ["chacha20-poly1305", "hmac-plain"]
    });
    let ciphers = extract_offered_ciphers(&params);
    assert_eq!(ciphers.len(), 2);
    assert!(ciphers.contains(&CipherSuite::ChaCha20Poly1305));
    assert!(ciphers.contains(&CipherSuite::HmacPlain));
}

#[test]
fn extract_offered_ciphers_from_preferred() {
    let params = serde_json::json!({
        "preferred_cipher": "chacha20-poly1305"
    });
    let ciphers = extract_offered_ciphers(&params);
    assert_eq!(ciphers, vec![CipherSuite::ChaCha20Poly1305]);
}

#[test]
fn extract_offered_ciphers_fallback_null() {
    let params = serde_json::json!({});
    let ciphers = extract_offered_ciphers(&params);
    assert_eq!(ciphers, vec![CipherSuite::Null]);
}

// ── Key Derivation Tests ──────────────────────────────────────────

#[test]
fn derive_session_keys_deterministic() {
    let handshake_key = [0x42u8; 32];
    let client_nonce = [0x01u8; 12];
    let server_nonce = [0x02u8; 12];

    let keys1 = derive_session_keys(&handshake_key, &client_nonce, &server_nonce).unwrap();
    let keys2 = derive_session_keys(&handshake_key, &client_nonce, &server_nonce).unwrap();

    assert_eq!(keys1.encrypt_key, keys2.encrypt_key);
    assert_eq!(keys1.decrypt_key, keys2.decrypt_key);
}

#[test]
fn derive_session_keys_different_nonces_different_keys() {
    let handshake_key = [0x42u8; 32];
    let client_nonce = [0x01u8; 12];
    let server_nonce_a = [0x02u8; 12];
    let server_nonce_b = [0x03u8; 12];

    let keys_a = derive_session_keys(&handshake_key, &client_nonce, &server_nonce_a).unwrap();
    let keys_b = derive_session_keys(&handshake_key, &client_nonce, &server_nonce_b).unwrap();

    assert_ne!(keys_a.encrypt_key, keys_b.encrypt_key);
}

#[test]
fn derive_session_keys_encrypt_decrypt_differ() {
    let handshake_key = [0x42u8; 32];
    let client_nonce = [0x01u8; 12];
    let server_nonce = [0x02u8; 12];

    let keys = derive_session_keys(&handshake_key, &client_nonce, &server_nonce).unwrap();
    assert_ne!(keys.encrypt_key, keys.decrypt_key);
}

#[test]
fn session_keys_debug_redacts() {
    let keys = derive_session_keys(&[0x42; 32], &[0x01; 12], &[0x02; 12]).unwrap();
    let debug = format!("{keys:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("42"));
}

// ── Encrypt/Decrypt Tests ─────────────────────────────────────────

#[test]
fn encrypt_decrypt_roundtrip() {
    let keys = derive_session_keys(&[0xAA; 32], &[0x01; 12], &[0x02; 12]).unwrap();
    let plaintext = b"hello btsp phase 3";

    let frame = encrypt_frame(&keys.encrypt_key, plaintext).unwrap();
    assert!(frame.len() >= NONCE_SIZE + 16);
    assert!(frame.len() > plaintext.len());

    let decrypted = decrypt_frame(&keys.encrypt_key, &frame).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_produces_different_frames() {
    let key = [0xBB; 32];
    let plaintext = b"same plaintext";

    let ct0 = encrypt_frame(&key, plaintext).unwrap();
    let ct1 = encrypt_frame(&key, plaintext).unwrap();
    assert_ne!(ct0, ct1, "random nonces should make frames differ");
}

#[test]
fn decrypt_wrong_key_fails() {
    let key_a = [0xDD; 32];
    let key_b = [0xEE; 32];
    let plaintext = b"classified";

    let frame = encrypt_frame(&key_a, plaintext).unwrap();
    let result = decrypt_frame(&key_b, &frame);
    assert!(result.is_err());
}

#[test]
fn decrypt_tampered_ciphertext_fails() {
    let key = [0xFF; 32];
    let plaintext = b"integrity check";

    let mut frame = encrypt_frame(&key, plaintext).unwrap();
    if let Some(byte) = frame.get_mut(NONCE_SIZE + 5) {
        *byte ^= 0x01;
    }
    let result = decrypt_frame(&key, &frame);
    assert!(result.is_err());
}

#[test]
fn decrypt_too_short_fails() {
    let key = [0x11; 32];
    let result = decrypt_frame(&key, &[0u8; 10]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("too short"));
}

#[test]
fn encrypt_empty_payload() {
    let key = [0x11; 32];
    let frame = encrypt_frame(&key, b"").unwrap();
    assert_eq!(frame.len(), NONCE_SIZE + 16); // nonce + tag only
    let decrypted = decrypt_frame(&key, &frame).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn directional_keys_encrypt_decrypt() {
    let keys = derive_session_keys(&[0xAA; 32], &[0x01; 16], &[0x02; 32]).unwrap();
    let plaintext = b"server to client message";

    let frame = encrypt_frame(&keys.encrypt_key, plaintext).unwrap();
    let decrypted = decrypt_frame(&keys.encrypt_key, &frame).unwrap();
    assert_eq!(decrypted, plaintext);

    let result = decrypt_frame(&keys.decrypt_key, &frame);
    assert!(result.is_err(), "wrong directional key should fail");
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Typed errors for the BTSP transport layer.
//!
//! Replaces unstructured `String` errors with categorized variants,
//! enabling callers to match on failure mode.

/// Transport-layer error covering BTSP configuration, handshake, and crypto.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Invalid environment configuration (conflicting or missing values).
    #[error("config: {0}")]
    Config(String),

    /// BTSP provider (`BearDog`) communication failure.
    #[error("provider: {0}")]
    Provider(String),

    /// BTSP Phase 2 handshake protocol failure.
    #[error("handshake: {0}")]
    Handshake(String),

    /// Cryptographic operation failure (encrypt/decrypt).
    #[error("crypto: {0}")]
    Crypto(String),

    /// Underlying I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Spawned task panicked or was cancelled.
    #[error("task: {0}")]
    Task(#[from] tokio::task::JoinError),
}

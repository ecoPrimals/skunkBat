// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Common error types for primals.

use thiserror::Error;

/// Result type for primal operations.
pub type PrimalResult<T> = Result<T, PrimalError>;

/// Common errors that any primal might encounter.
#[derive(Debug, Error)]
pub enum PrimalError {
    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Identity/signing error.
    #[error("identity error: {0}")]
    Identity(String),

    /// Discovery/registration error.
    #[error("discovery error: {0}")]
    Discovery(String),

    /// Lifecycle error (start/stop/reload).
    #[error("lifecycle error: {0}")]
    Lifecycle(String),

    /// Health check error.
    #[error("health error: {0}")]
    Health(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Network error.
    #[error("network error: {0}")]
    Network(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Timeout.
    #[error("operation timed out: {0}")]
    Timeout(String),

    /// Operation cancelled.
    #[error("operation cancelled: {0}")]
    Cancelled(String),

    /// Resource not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Already exists.
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// Permission denied.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Invalid input.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Dependency error (upstream service failed).
    #[error("dependency error: {service}: {message}")]
    Dependency {
        /// Name of the dependency that failed.
        service: String,
        /// Error message.
        message: String,
    },

    /// Custom domain-specific error.
    #[error("{domain} error: {message}")]
    Domain {
        /// Domain/primal name.
        domain: String,
        /// Error message.
        message: String,
    },
}

impl PrimalError {
    /// Create a configuration error.
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Create an identity error.
    pub fn identity(msg: impl Into<String>) -> Self {
        Self::Identity(msg.into())
    }

    /// Create a discovery error.
    pub fn discovery(msg: impl Into<String>) -> Self {
        Self::Discovery(msg.into())
    }

    /// Create a lifecycle error.
    pub fn lifecycle(msg: impl Into<String>) -> Self {
        Self::Lifecycle(msg.into())
    }

    /// Create a dependency error.
    pub fn dependency(service: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::Dependency {
            service: service.into(),
            message: msg.into(),
        }
    }

    /// Create a domain-specific error.
    pub fn domain(domain: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::Domain {
            domain: domain.into(),
            message: msg.into(),
        }
    }

    /// Check if this is a retryable error.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Network(_) | Self::Timeout(_) | Self::Dependency { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_constructors() {
        assert!(matches!(PrimalError::config("x"), PrimalError::Config(_)));
        assert!(matches!(
            PrimalError::identity("x"),
            PrimalError::Identity(_)
        ));
        assert!(matches!(
            PrimalError::discovery("x"),
            PrimalError::Discovery(_)
        ));
        assert!(matches!(
            PrimalError::lifecycle("x"),
            PrimalError::Lifecycle(_)
        ));
        assert!(matches!(
            PrimalError::dependency("svc", "msg"),
            PrimalError::Dependency { .. }
        ));
        assert!(matches!(
            PrimalError::domain("d", "m"),
            PrimalError::Domain { .. }
        ));
    }

    #[test]
    fn error_display() {
        let err = PrimalError::config("invalid setting");
        assert_eq!(err.to_string(), "configuration error: invalid setting");

        let err = PrimalError::dependency("database", "connection failed");
        assert_eq!(
            err.to_string(),
            "dependency error: database: connection failed"
        );
    }

    #[test]
    fn error_retryable() {
        assert!(PrimalError::Network("timeout".to_owned()).is_retryable());
        assert!(PrimalError::Timeout("slow".to_owned()).is_retryable());
        assert!(PrimalError::dependency("db", "down").is_retryable());

        assert!(!PrimalError::Config("bad".to_owned()).is_retryable());
        assert!(!PrimalError::InvalidInput("wrong".to_owned()).is_retryable());
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err: PrimalError = io_err.into();
        assert!(matches!(err, PrimalError::Io(_)));
    }
}

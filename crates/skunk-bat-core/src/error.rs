//! skunkBat error types.

use thiserror::Error;

/// Errors specific to skunkBat.
#[derive(Debug, Error)]
pub enum SkunkBatError {
    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Reconnaissance error.
    #[error("reconnaissance error: {0}")]
    Reconnaissance(String),

    /// Threat detection error.
    #[error("threat detection error: {0}")]
    ThreatDetection(String),

    /// Defense error.
    #[error("defense error: {0}")]
    Defense(String),

    /// Observability error.
    #[error("observability error: {0}")]
    Observability(String),

    /// Lineage verification error.
    #[error("lineage verification error: {0}")]
    LineageVerification(String),

    /// Integration error with external primal.
    #[error("integration error: {0}")]
    Integration(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

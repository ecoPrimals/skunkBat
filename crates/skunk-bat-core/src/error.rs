// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        let e = SkunkBatError::Config("bad value".to_owned());
        assert_eq!(e.to_string(), "configuration error: bad value");

        let e = SkunkBatError::Reconnaissance("scan failed".to_owned());
        assert!(e.to_string().contains("scan failed"));

        let e = SkunkBatError::ThreatDetection("anomaly".to_owned());
        assert!(e.to_string().contains("anomaly"));

        let e = SkunkBatError::Defense("blocked".to_owned());
        assert!(e.to_string().contains("blocked"));

        let e = SkunkBatError::Observability("metrics lost".to_owned());
        assert!(e.to_string().contains("metrics lost"));

        let e = SkunkBatError::LineageVerification("unknown peer".to_owned());
        assert!(e.to_string().contains("unknown peer"));

        let e = SkunkBatError::Integration("timeout".to_owned());
        assert!(e.to_string().contains("timeout"));

        let e = SkunkBatError::Internal("panic".to_owned());
        assert!(e.to_string().contains("panic"));
    }

    #[test]
    fn error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(SkunkBatError::Config("test".to_owned()));
        assert!(e.to_string().contains("test"));
    }
}

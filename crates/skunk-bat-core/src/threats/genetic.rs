// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Genetic lineage and topology verification implementations.
//!
//! Contains the conservative local defaults. In production these are
//! replaced at runtime by capability-discovered verifiers (e.g. a primal
//! that announces `lineage-verification`).

use super::traits::{LineageVerifier, TopologyValidator};
use super::types::PathValidation;
use crate::error::SkunkBatError;

/// Local-only lineage verifier (no external authority).
///
/// Returns `Err` for all queries — the conservative default when no
/// capability provider is discovered at runtime. Callers should treat
/// errors as "inconclusive" (degraded mode) rather than "denied."
///
/// A real authority (e.g. a primal announcing `lineage-verification`)
/// replaces this at runtime via [`RuntimeVerifier`](crate) enum dispatch.
pub struct LocalLineageVerifier;

impl LineageVerifier for LocalLineageVerifier {
    async fn is_family(&self, _peer_id: &str) -> Result<bool, SkunkBatError> {
        Err(SkunkBatError::LineageVerification(
            "no lineage authority available (local-only mode)".to_owned(),
        ))
    }

    async fn get_lineage(&self, _peer_id: &str) -> Result<Option<String>, SkunkBatError> {
        Err(SkunkBatError::LineageVerification(
            "no lineage authority available (local-only mode)".to_owned(),
        ))
    }
}

/// Layer-based topology validator.
///
/// Validates that connections traverse layers in the correct sequence,
/// detecting layer-hopping and security boundary bypasses.
pub struct LayerTopologyValidator {
    expected_path: Vec<u8>,
}

impl LayerTopologyValidator {
    /// Create a new topology validator with expected layer traversal path.
    #[must_use]
    pub const fn new(expected_path: Vec<u8>) -> Self {
        Self { expected_path }
    }
}

impl TopologyValidator for LayerTopologyValidator {
    async fn validate_path(&self, actual_path: &[u8]) -> Result<PathValidation, SkunkBatError> {
        let is_valid = actual_path == self.expected_path.as_slice();

        let bypassed_layers: Vec<u8> = self
            .expected_path
            .iter()
            .filter(|layer| !actual_path.contains(layer))
            .copied()
            .collect();

        Ok(PathValidation {
            is_valid,
            expected_path: self.expected_path.clone(),
            actual_path: actual_path.to_vec(),
            bypassed_layers,
        })
    }

    fn expected_path(&self) -> Vec<u8> {
        self.expected_path.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_lineage_returns_err_no_authority() {
        let verifier = LocalLineageVerifier;
        let result = verifier.is_family("any-peer").await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no lineage authority")
        );
    }

    #[tokio::test]
    async fn local_lineage_get_lineage_returns_err() {
        let verifier = LocalLineageVerifier;
        let result = verifier.get_lineage("any-peer").await;
        assert!(result.is_err());
    }

    #[test]
    fn topology_validator_construction() {
        let validator = LayerTopologyValidator::new(vec![1, 2, 3, 4]);
        assert_eq!(validator.expected_path(), vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn topology_valid_path() {
        let validator = LayerTopologyValidator::new(vec![1, 2, 3]);
        let result = validator.validate_path(&[1, 2, 3]).await.unwrap();
        assert!(result.is_valid);
        assert!(result.bypassed_layers.is_empty());
        assert_eq!(result.expected_path, vec![1, 2, 3]);
        assert_eq!(result.actual_path, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn topology_invalid_path_detects_bypass() {
        let validator = LayerTopologyValidator::new(vec![1, 2, 3, 4]);
        let result = validator.validate_path(&[1, 4]).await.unwrap();
        assert!(!result.is_valid);
        assert_eq!(result.bypassed_layers, vec![2, 3]);
    }

    #[tokio::test]
    async fn topology_empty_actual_path() {
        let validator = LayerTopologyValidator::new(vec![1, 2, 3]);
        let result = validator.validate_path(&[]).await.unwrap();
        assert!(!result.is_valid);
        assert_eq!(result.bypassed_layers, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn topology_empty_expected_path() {
        let validator = LayerTopologyValidator::new(vec![]);
        let result = validator.validate_path(&[1, 2]).await.unwrap();
        assert!(!result.is_valid);
        assert!(result.bypassed_layers.is_empty());
    }
}

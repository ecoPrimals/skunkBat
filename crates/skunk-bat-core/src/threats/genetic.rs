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

/// Local-only lineage verifier (no external dependencies).
///
/// Always returns "not family" for unknown peers — the conservative
/// default.  Trust must be explicitly verified via a runtime-discovered
/// capability provider.
pub struct LocalLineageVerifier;

impl LineageVerifier for LocalLineageVerifier {
    async fn is_family(&self, _peer_id: &str) -> Result<bool, SkunkBatError> {
        Ok(false)
    }

    async fn get_lineage(&self, _peer_id: &str) -> Result<Option<String>, SkunkBatError> {
        Ok(None)
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

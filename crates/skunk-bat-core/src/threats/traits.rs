// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Threat detection trait abstractions.
//!
//! These traits define extension points for lineage verification,
//! behavioral analysis, and topology validation — all discoverable
//! at runtime via capability-based patterns.

use async_trait::async_trait;

use super::types::{Anomaly, Observation, PathValidation};
use crate::error::SkunkBatError;

/// Trait for lineage verification.
///
/// Abstracts lineage verification mechanisms, allowing skunkBat to verify
/// genetic lineage via any provider that announces the
/// `lineage-verification` capability at runtime.
#[async_trait]
pub trait LineageVerifier: Send + Sync {
    /// Verify if a peer is part of the genetic family.
    async fn is_family(&self, peer_id: &str) -> Result<bool, SkunkBatError>;

    /// Get the lineage chain for a peer.
    async fn get_lineage(&self, peer_id: &str) -> Result<Option<String>, SkunkBatError>;
}

/// Trait for behavioral baseline management.
///
/// Abstracts baseline profiling for anomaly detection,
/// allowing different statistical and machine learning approaches.
#[async_trait]
pub trait BaselineProfiler: Send + Sync {
    /// Check if baseline is established.
    fn is_established(&self) -> bool;

    /// Return the most recent observation (if any).
    fn latest_observation(&self) -> Option<&Observation>;

    /// Update baseline with new observations.
    async fn update(&mut self, observation: &Observation) -> Result<(), SkunkBatError>;

    /// Detect anomalies against baseline.
    async fn detect_anomalies(
        &self,
        observation: &Observation,
    ) -> Result<Vec<Anomaly>, SkunkBatError>;
}

/// Trait for topology path validation.
///
/// Abstracts layer path validation for `BiomeOS` architectural enforcement,
/// detecting layer-hopping and security boundary bypasses.
#[async_trait]
pub trait TopologyValidator: Send + Sync {
    /// Validate a connection path through network layers.
    async fn validate_path(&self, actual_path: &[u8]) -> Result<PathValidation, SkunkBatError>;

    /// Get the expected path for a connection.
    fn expected_path(&self) -> Vec<u8>;
}

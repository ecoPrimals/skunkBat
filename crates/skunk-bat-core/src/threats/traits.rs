// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Threat detection trait abstractions.
//!
//! These traits define extension points for lineage verification,
//! behavioral analysis, and topology validation — all discoverable
//! at runtime via capability-based patterns.
//!
//! All traits use native `async fn` (RPITIT, Edition 2024) — no
//! `#[async_trait]` or `dyn` dispatch. Implementations are selected
//! via enum dispatch at construction time.

use std::future::Future;

use super::types::{Anomaly, Observation, PathValidation};
use crate::error::SkunkBatError;

/// Trait for lineage verification.
///
/// Abstracts lineage verification mechanisms, allowing skunkBat to verify
/// genetic lineage via any provider that announces the
/// `lineage-verification` capability at runtime.
pub trait LineageVerifier: Send + Sync {
    /// Verify if a peer is part of the genetic family.
    fn is_family(&self, peer_id: &str) -> impl Future<Output = Result<bool, SkunkBatError>> + Send;

    /// Get the lineage chain for a peer.
    fn get_lineage(
        &self,
        peer_id: &str,
    ) -> impl Future<Output = Result<Option<String>, SkunkBatError>> + Send;
}

/// Trait for behavioral baseline management.
///
/// Abstracts baseline profiling for anomaly detection,
/// allowing different statistical and machine learning approaches.
pub trait BaselineProfiler: Send + Sync {
    /// Check if baseline is established.
    fn is_established(&self) -> bool;

    /// Return the most recent observation (if any).
    fn latest_observation(&self) -> Option<&Observation>;

    /// Update baseline with new observations.
    fn update(
        &mut self,
        observation: &Observation,
    ) -> impl Future<Output = Result<(), SkunkBatError>> + Send;

    /// Detect anomalies against baseline.
    fn detect_anomalies(
        &self,
        observation: &Observation,
    ) -> impl Future<Output = Result<Vec<Anomaly>, SkunkBatError>> + Send;
}

/// Trait for topology path validation.
///
/// Abstracts layer path validation for `BiomeOS` architectural enforcement,
/// detecting layer-hopping and security boundary bypasses.
pub trait TopologyValidator: Send + Sync {
    /// Validate a connection path through network layers.
    fn validate_path(
        &self,
        actual_path: &[u8],
    ) -> impl Future<Output = Result<PathValidation, SkunkBatError>> + Send;

    /// Get the expected path for a connection.
    fn expected_path(&self) -> Vec<u8>;
}

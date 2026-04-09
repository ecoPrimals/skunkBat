// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Statistical behavioral analysis for anomaly detection.

use async_trait::async_trait;
use std::collections::VecDeque;

use super::traits::BaselineProfiler;
use super::types::{Anomaly, Observation};
use crate::error::SkunkBatError;

/// Statistical baseline profiler using moving averages and standard deviations.
///
/// Learns the owner's network "normal" over a rolling window, then flags
/// observations that deviate beyond a configurable sigma threshold.
pub struct StatisticalProfiler {
    observations: VecDeque<Observation>,
    threshold: f64,
}

impl StatisticalProfiler {
    /// Create a new statistical profiler.
    ///
    /// * `threshold` - Standard-deviation multiplier for anomaly detection (e.g. 2.5σ)
    #[must_use]
    pub const fn new(threshold: f64) -> Self {
        Self {
            observations: VecDeque::new(),
            threshold,
        }
    }

    fn calculate_stats(values: &[f64]) -> Option<(f64, f64)> {
        if values.is_empty() {
            return None;
        }

        #[allow(clippy::cast_precision_loss)]
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        #[allow(clippy::cast_precision_loss)]
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
        let std_dev = variance.sqrt();

        Some((mean, std_dev))
    }
}

#[async_trait]
impl BaselineProfiler for StatisticalProfiler {
    fn is_established(&self) -> bool {
        self.observations.len() >= 10
    }

    fn latest_observation(&self) -> Option<&Observation> {
        self.observations.back()
    }

    async fn update(&mut self, observation: &Observation) -> Result<(), SkunkBatError> {
        const ROLLING_WINDOW: usize = 100;

        self.observations.push_back(observation.clone());
        if self.observations.len() > ROLLING_WINDOW {
            self.observations.pop_front();
        }

        Ok(())
    }

    async fn detect_anomalies(
        &self,
        observation: &Observation,
    ) -> Result<Vec<Anomaly>, SkunkBatError> {
        if !self.is_established() {
            return Ok(Vec::new());
        }

        let mut anomalies = Vec::new();

        let rates: Vec<f64> = self
            .observations
            .iter()
            .map(|o| o.connection_rate)
            .collect();

        if let Some((mean, std_dev)) = Self::calculate_stats(&rates) {
            let deviation = (observation.connection_rate - mean).abs() / std_dev;

            if deviation > self.threshold {
                anomalies.push(Anomaly {
                    deviation,
                    behavior: format!(
                        "Unusual connection rate: {:.2}/s (baseline: {mean:.2}±{std_dev:.2})",
                        observation.connection_rate,
                    ),
                    confidence: (deviation / (self.threshold * 2.0)).min(1.0),
                });
            }
        }

        Ok(anomalies)
    }
}

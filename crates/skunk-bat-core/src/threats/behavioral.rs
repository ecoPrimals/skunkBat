// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Statistical behavioral analysis for anomaly detection.

use std::collections::VecDeque;

use super::traits::BaselineProfiler;
use super::types::{Anomaly, BaselineStats, DimensionStats, Observation};
use crate::error::SkunkBatError;

/// Statistical baseline profiler using moving averages and standard deviations.
///
/// Learns the owner's network "normal" over a rolling window, then flags
/// observations that deviate beyond a configurable sigma threshold.
pub struct StatisticalProfiler {
    observations: VecDeque<Observation>,
    threshold: f64,
    rolling_window: usize,
    min_observations: usize,
    seed_port: u16,
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
            rolling_window: 100,
            min_observations: 10,
            seed_port: crate::DEFAULT_PORT,
        }
    }

    /// Create a profiler with configurable window and minimum observation count.
    #[must_use]
    pub const fn with_config(
        threshold: f64,
        rolling_window: usize,
        min_observations: usize,
    ) -> Self {
        Self {
            observations: VecDeque::new(),
            threshold,
            rolling_window,
            min_observations,
            seed_port: crate::DEFAULT_PORT,
        }
    }

    /// Set the port used for synthetic baseline seeding on `reset(true)`.
    pub const fn set_seed_port(&mut self, port: u16) {
        self.seed_port = port;
    }

    /// Seed the profiler with baseline observations to establish normal behavior.
    ///
    /// Must be called before detection will fire. Requires at least 10 observations
    /// for the baseline to be considered established. Pen-test pattern: call this
    /// with representative "normal" traffic to teach skunkBat what benign looks like,
    /// then anomalous traffic (fuzz, enumeration) will trigger detection.
    pub fn seed_baseline(&mut self, observations: &[Observation]) {
        for obs in observations {
            self.observations.push_back(obs.clone());
        }
        while self.observations.len() > self.rolling_window {
            self.observations.pop_front();
        }
        if self.is_established() {
            tracing::info!(
                "Baseline established with {} observations",
                self.observations.len()
            );
        }
    }

    /// Reset the profiler, discarding all learned observations.
    ///
    /// Optionally re-seeds with baseline data so anomaly detection remains active.
    pub fn reset(&mut self, reseed: bool) {
        self.observations.clear();
        if reseed {
            self.seed_baseline(&super::baseline::normal_baseline_with_port(self.seed_port));
        }
    }

    /// Query current profiler statistics for each observed dimension.
    ///
    /// Returns `None` if the baseline is not established (< 10 observations).
    #[must_use]
    pub fn query_stats(&self) -> Option<BaselineStats> {
        if !self.is_established() {
            return None;
        }
        let connection_rate = Self::stats_over(self.observations.iter().map(|o| o.connection_rate));
        #[expect(clippy::cast_precision_loss, reason = "traffic volumes fit in f64")]
        let traffic_volume =
            Self::stats_over(self.observations.iter().map(|o| o.traffic_volume as f64));
        #[expect(clippy::cast_precision_loss, reason = "port counts fit in f64")]
        let port_diversity = Self::stats_over(
            self.observations
                .iter()
                .map(|o| o.ports_accessed.len() as f64),
        );
        Some(BaselineStats {
            observation_count: self.observations.len(),
            threshold: self.threshold,
            connection_rate: connection_rate.map(|(m, s)| DimensionStats {
                mean: m,
                std_dev: s,
            }),
            traffic_volume: traffic_volume.map(|(m, s)| DimensionStats {
                mean: m,
                std_dev: s,
            }),
            port_diversity: port_diversity.map(|(m, s)| DimensionStats {
                mean: m,
                std_dev: s,
            }),
            http_request_rate: Self::stats_over(
                self.observations
                    .iter()
                    .filter_map(|o| o.http.as_ref().map(|h| h.request_rate)),
            )
            .map(|(m, s)| DimensionStats {
                mean: m,
                std_dev: s,
            }),
            http_path_diversity: Self::stats_over(
                self.observations
                    .iter()
                    .filter_map(|o| o.http.as_ref().map(|h| f64::from(h.path_diversity))),
            )
            .map(|(m, s)| DimensionStats {
                mean: m,
                std_dev: s,
            }),
            http_error_rate_4xx: Self::stats_over(
                self.observations
                    .iter()
                    .filter_map(|o| o.http.as_ref().map(|h| h.error_rate_4xx)),
            )
            .map(|(m, s)| DimensionStats {
                mean: m,
                std_dev: s,
            }),
        })
    }

    /// Single-pass mean and standard deviation over an iterator (Welford-like two-pass
    /// avoidance via sum + sum-of-squares). No intermediate `Vec` allocation.
    fn stats_over(iter: impl Iterator<Item = f64>) -> Option<(f64, f64)> {
        let mut count: u64 = 0;
        let mut sum = 0.0_f64;
        let mut sum_sq = 0.0_f64;
        for v in iter {
            count += 1;
            sum += v;
            sum_sq = v.mul_add(v, sum_sq);
        }
        if count == 0 {
            return None;
        }
        #[expect(clippy::cast_precision_loss, reason = "observation counts fit in f64")]
        let n = count as f64;
        let mean = sum / n;
        let variance = mean.mul_add(-mean, sum_sq / n);
        let std_dev = variance.max(0.0).sqrt();
        Some((mean, std_dev))
    }

    /// Detect anomalies in HTTP outer membrane dimensions.
    fn detect_http_anomalies(
        &self,
        http: &super::types::HttpObservation,
        anomalies: &mut Vec<Anomaly>,
    ) {
        if let Some((mean, std_dev)) = Self::stats_over(
            self.observations
                .iter()
                .filter_map(|o| o.http.as_ref().map(|h| h.request_rate)),
        ) {
            let deviation = (http.request_rate - mean).abs() / std_dev;
            if deviation > self.threshold {
                anomalies.push(Anomaly {
                    deviation,
                    behavior: format!(
                        "Unusual HTTP request rate: {:.1}/s (baseline: {mean:.1}±{std_dev:.1})",
                        http.request_rate,
                    ),
                    confidence: (deviation / (self.threshold * 2.0)).min(1.0),
                });
            }
        }

        if let Some((mean, std_dev)) = Self::stats_over(
            self.observations
                .iter()
                .filter_map(|o| o.http.as_ref().map(|h| f64::from(h.path_diversity))),
        ) {
            let current = f64::from(http.path_diversity);
            let deviation = (current - mean).abs() / std_dev;
            if deviation > self.threshold {
                anomalies.push(Anomaly {
                    deviation,
                    behavior: format!(
                        "Unusual HTTP path diversity: {} paths (baseline: {mean:.1}±{std_dev:.1})",
                        http.path_diversity,
                    ),
                    confidence: (deviation / (self.threshold * 2.0)).min(1.0),
                });
            }
        }

        if let Some((mean, std_dev)) = Self::stats_over(
            self.observations
                .iter()
                .filter_map(|o| o.http.as_ref().map(|h| h.error_rate_4xx)),
        ) {
            let deviation = (http.error_rate_4xx - mean).abs() / std_dev;
            if deviation > self.threshold {
                anomalies.push(Anomaly {
                    deviation,
                    behavior: format!(
                        "Unusual HTTP 4xx error rate: {:.1}% (baseline: {:.1}%±{:.1}%)",
                        http.error_rate_4xx * 100.0,
                        mean * 100.0,
                        std_dev * 100.0,
                    ),
                    confidence: (deviation / (self.threshold * 2.0)).min(1.0),
                });
            }
        }
    }
}

impl BaselineProfiler for StatisticalProfiler {
    fn is_established(&self) -> bool {
        self.observations.len() >= self.min_observations
    }

    fn latest_observation(&self) -> Option<&Observation> {
        self.observations.back()
    }

    async fn update(&mut self, observation: &Observation) -> Result<(), SkunkBatError> {
        self.observations.push_back(observation.clone());
        if self.observations.len() > self.rolling_window {
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

        // Dimension 1: Connection rate
        if let Some((mean, std_dev)) =
            Self::stats_over(self.observations.iter().map(|o| o.connection_rate))
        {
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

        // Dimension 2: Traffic volume
        #[expect(clippy::cast_precision_loss, reason = "traffic volumes fit in f64")]
        if let Some((mean, std_dev)) =
            Self::stats_over(self.observations.iter().map(|o| o.traffic_volume as f64))
        {
            let deviation = (observation.traffic_volume as f64 - mean).abs() / std_dev;
            if deviation > self.threshold {
                anomalies.push(Anomaly {
                    deviation,
                    behavior: format!(
                        "Unusual traffic volume: {} B/s (baseline: {mean:.0}±{std_dev:.0})",
                        observation.traffic_volume,
                    ),
                    confidence: (deviation / (self.threshold * 2.0)).min(1.0),
                });
            }
        }

        // Dimension 3: Port diversity (number of distinct ports accessed)
        #[expect(clippy::cast_precision_loss, reason = "port counts fit in f64")]
        if let Some((mean, std_dev)) = Self::stats_over(
            self.observations
                .iter()
                .map(|o| o.ports_accessed.len() as f64),
        ) {
            let current_ports = observation.ports_accessed.len() as f64;
            let deviation = (current_ports - mean).abs() / std_dev;
            if deviation > self.threshold {
                anomalies.push(Anomaly {
                    deviation,
                    behavior: format!(
                        "Unusual port diversity: {} ports (baseline: {mean:.1}±{std_dev:.1})",
                        observation.ports_accessed.len(),
                    ),
                    confidence: (deviation / (self.threshold * 2.0)).min(1.0),
                });
            }
        }

        if let Some(http) = &observation.http {
            self.detect_http_anomalies(http, &mut anomalies);
        }

        Ok(anomalies)
    }

    fn query_stats(&self) -> Option<BaselineStats> {
        self.query_stats()
    }

    fn reset(&mut self, reseed: bool) {
        self.reset(reseed);
    }
}

#[cfg(test)]
#[path = "behavioral_tests.rs"]
mod tests;

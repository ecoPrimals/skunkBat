// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Statistical behavioral analysis for anomaly detection.

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

    /// Seed the profiler with baseline observations to establish normal behavior.
    ///
    /// Must be called before detection will fire. Requires at least 10 observations
    /// for the baseline to be considered established. Pen-test pattern: call this
    /// with representative "normal" traffic to teach skunkBat what benign looks like,
    /// then anomalous traffic (fuzz, enumeration) will trigger detection.
    pub fn seed_baseline(&mut self, observations: &[Observation]) {
        const ROLLING_WINDOW: usize = 100;
        for obs in observations {
            self.observations.push_back(obs.clone());
        }
        while self.observations.len() > ROLLING_WINDOW {
            self.observations.pop_front();
        }
        if self.is_established() {
            tracing::info!(
                "Baseline established with {} observations",
                self.observations.len()
            );
        }
    }

    fn calculate_stats(values: &[f64]) -> Option<(f64, f64)> {
        if values.is_empty() {
            return None;
        }

        #[expect(clippy::cast_precision_loss, reason = "observation counts fit in f64")]
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        #[expect(clippy::cast_precision_loss, reason = "observation counts fit in f64")]
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
        let std_dev = variance.sqrt();

        Some((mean, std_dev))
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn observation(rate: f64) -> Observation {
        Observation {
            connection_rate: rate,
            traffic_volume: 1000,
            ports_accessed: vec![80, 443],
            timestamp: SystemTime::now(),
        }
    }

    #[test]
    fn profiler_not_established_initially() {
        let profiler = StatisticalProfiler::new(2.5);
        assert!(!profiler.is_established());
        assert!(profiler.latest_observation().is_none());
    }

    #[tokio::test]
    async fn profiler_establishes_after_10_observations() {
        let mut profiler = StatisticalProfiler::new(2.5);
        for i in 0..9 {
            profiler
                .update(&observation(10.0 + f64::from(i)))
                .await
                .unwrap();
        }
        assert!(!profiler.is_established());

        profiler.update(&observation(10.0)).await.unwrap();
        assert!(profiler.is_established());
    }

    #[tokio::test]
    async fn no_anomalies_when_not_established() {
        let profiler = StatisticalProfiler::new(2.5);
        let obs = observation(100.0);
        let anomalies = profiler.detect_anomalies(&obs).await.unwrap();
        assert!(anomalies.is_empty());
    }

    #[tokio::test]
    async fn no_anomaly_for_normal_traffic() {
        let mut profiler = StatisticalProfiler::new(2.5);
        for i in 0..20 {
            let rate = f64::from(i).mul_add(0.1, 10.0);
            profiler.update(&observation(rate)).await.unwrap();
        }

        let anomalies = profiler.detect_anomalies(&observation(10.5)).await.unwrap();
        assert!(anomalies.is_empty());
    }

    #[tokio::test]
    async fn detects_anomaly_for_spike() {
        let mut profiler = StatisticalProfiler::new(2.5);
        for _ in 0..20 {
            profiler.update(&observation(10.0)).await.unwrap();
        }

        let anomalies = profiler
            .detect_anomalies(&observation(500.0))
            .await
            .unwrap();
        assert!(!anomalies.is_empty());
        assert!(anomalies[0].deviation > 2.5);
        assert!(anomalies[0].confidence > 0.0);
        assert!(anomalies[0].behavior.contains("Unusual connection rate"));
    }

    #[tokio::test]
    async fn rolling_window_caps_at_100() {
        let mut profiler = StatisticalProfiler::new(2.5);
        for i in 0..150_i32 {
            profiler.update(&observation(f64::from(i))).await.unwrap();
        }
        assert_eq!(profiler.observations.len(), 100);
    }

    #[tokio::test]
    async fn latest_observation_returns_most_recent() {
        let mut profiler = StatisticalProfiler::new(2.5);
        profiler.update(&observation(5.0)).await.unwrap();
        profiler.update(&observation(7.0)).await.unwrap();

        let latest = profiler.latest_observation().unwrap();
        assert!((latest.connection_rate - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn calculate_stats_empty() {
        assert!(StatisticalProfiler::calculate_stats(&[]).is_none());
    }

    #[test]
    fn calculate_stats_single_value() {
        let (mean, std_dev) = StatisticalProfiler::calculate_stats(&[5.0]).unwrap();
        assert!((mean - 5.0).abs() < f64::EPSILON);
        assert!((std_dev - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn calculate_stats_uniform() {
        let values = [10.0, 10.0, 10.0, 10.0];
        let (mean, std_dev) = StatisticalProfiler::calculate_stats(&values).unwrap();
        assert!((mean - 10.0).abs() < f64::EPSILON);
        assert!((std_dev - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn confidence_capped_at_1() {
        let mut profiler = StatisticalProfiler::new(1.0);
        for _ in 0..20 {
            profiler.update(&observation(10.0)).await.unwrap();
        }

        let anomalies = profiler
            .detect_anomalies(&observation(10_000.0))
            .await
            .unwrap();
        assert!(!anomalies.is_empty());
        assert!(anomalies[0].confidence <= 1.0);
    }

    #[test]
    fn seed_baseline_establishes_profiler() {
        use super::super::baseline;

        let mut profiler = StatisticalProfiler::new(2.5);
        assert!(!profiler.is_established());

        profiler.seed_baseline(&baseline::normal_baseline());
        assert!(profiler.is_established());
        assert_eq!(profiler.observations.len(), 12);
    }

    #[tokio::test]
    async fn seeded_profiler_detects_pentest_patterns() {
        use super::super::baseline;

        let mut profiler = StatisticalProfiler::new(2.5);
        profiler.seed_baseline(&baseline::normal_baseline());

        let attacks = baseline::pentest_attack_patterns();
        let mut detected = 0;
        for attack in &attacks {
            let anomalies = profiler.detect_anomalies(attack).await.unwrap();
            if !anomalies.is_empty() {
                detected += 1;
            }
        }

        assert!(
            detected >= 5,
            "expected at least 5/7 pen-test patterns to trigger detection, got {detected}"
        );
    }

    #[tokio::test]
    async fn seeded_profiler_no_false_positives_on_normal() {
        use super::super::baseline;

        let mut profiler = StatisticalProfiler::new(2.5);
        profiler.seed_baseline(&baseline::normal_baseline());

        let normal = baseline::normal_baseline();
        for obs in &normal {
            let anomalies = profiler.detect_anomalies(obs).await.unwrap();
            assert!(
                anomalies.is_empty(),
                "false positive on normal traffic: {anomalies:?}"
            );
        }
    }
}

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

    /// Single-pass mean and standard deviation over an iterator (Welford-like two-pass
    /// avoidance via sum + sum-of-squares). No intermediate `Vec` allocation.
    fn stats_over(iter: impl Iterator<Item = f64>) -> Option<(f64, f64)> {
        let mut count: u64 = 0;
        let mut sum = 0.0_f64;
        let mut sum_sq = 0.0_f64;
        for v in iter {
            count += 1;
            sum += v;
            sum_sq += v * v;
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
    fn stats_over_empty() {
        assert!(StatisticalProfiler::stats_over(std::iter::empty()).is_none());
    }

    #[test]
    fn stats_over_single_value() {
        let (mean, std_dev) = StatisticalProfiler::stats_over([5.0].into_iter()).unwrap();
        assert!((mean - 5.0).abs() < f64::EPSILON);
        assert!((std_dev - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn stats_over_uniform() {
        let values = [10.0, 10.0, 10.0, 10.0];
        let (mean, std_dev) = StatisticalProfiler::stats_over(values.into_iter()).unwrap();
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

    #[test]
    fn new_profiler_not_established() {
        let profiler = StatisticalProfiler::new(3.0);
        assert!(!profiler.is_established());
    }

    #[test]
    fn new_profiler_no_latest_observation() {
        let profiler = StatisticalProfiler::new(3.0);
        assert!(profiler.latest_observation().is_none());
    }

    #[tokio::test]
    async fn profiler_different_thresholds() {
        let mut strict = StatisticalProfiler::new(1.0);
        let mut lenient = StatisticalProfiler::new(5.0);

        for _ in 0..20 {
            strict.update(&observation(10.0)).await.unwrap();
            lenient.update(&observation(10.0)).await.unwrap();
        }

        let spike = observation(30.0);
        let strict_anomalies = strict.detect_anomalies(&spike).await.unwrap();
        let lenient_anomalies = lenient.detect_anomalies(&spike).await.unwrap();

        assert!(
            strict_anomalies.len() >= lenient_anomalies.len(),
            "stricter threshold should detect more anomalies"
        );
    }

    #[tokio::test]
    async fn update_returns_ok() {
        let mut profiler = StatisticalProfiler::new(2.5);
        let result = profiler.update(&observation(10.0)).await;
        assert!(result.is_ok());
    }

    #[test]
    fn stats_over_known_values() {
        let values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let (mean, _std_dev) = StatisticalProfiler::stats_over(values.into_iter()).unwrap();
        assert!((mean - 5.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn detect_anomalies_on_traffic_volume() {
        let mut profiler = StatisticalProfiler::new(2.5);
        for _ in 0..20 {
            profiler
                .update(&Observation {
                    connection_rate: 10.0,
                    traffic_volume: 1000,
                    ports_accessed: vec![80],
                    timestamp: SystemTime::now(),
                })
                .await
                .unwrap();
        }

        let anomalies = profiler
            .detect_anomalies(&Observation {
                connection_rate: 10.0,
                traffic_volume: 100_000_000,
                ports_accessed: vec![80],
                timestamp: SystemTime::now(),
            })
            .await
            .unwrap();
        assert!(!anomalies.is_empty(), "traffic volume spike should trigger");
    }

    #[tokio::test]
    async fn seed_then_detect_normal() {
        use super::super::baseline;

        let mut profiler = StatisticalProfiler::new(2.5);
        profiler.seed_baseline(&baseline::normal_baseline());
        assert!(profiler.is_established());

        let anomalies = profiler.detect_anomalies(&observation(3.0)).await.unwrap();
        assert!(anomalies.is_empty());
    }

    #[tokio::test]
    async fn negative_deviation_no_anomaly() {
        let mut profiler = StatisticalProfiler::new(2.5);
        for _ in 0..20 {
            profiler.update(&observation(100.0)).await.unwrap();
        }

        let anomalies = profiler.detect_anomalies(&observation(1.0)).await.unwrap();
        assert!(
            !anomalies.is_empty(),
            "drop to near-zero should flag anomaly"
        );
    }

    #[test]
    fn stats_over_two_values() {
        let (mean, std_dev) = StatisticalProfiler::stats_over([10.0, 20.0].into_iter()).unwrap();
        assert!((mean - 15.0).abs() < f64::EPSILON);
        assert!(std_dev > 0.0);
    }
}

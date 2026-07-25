// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

use super::*;
use std::time::SystemTime;

fn observation(rate: f64) -> Observation {
    Observation {
        connection_rate: rate,
        traffic_volume: 1000,
        ports_accessed: vec![80, 443],
        timestamp: SystemTime::now(),
        http: None,
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
                http: None,
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
            http: None,
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

fn http_observation(request_rate: f64, path_diversity: u32, error_rate: f64) -> Observation {
    Observation {
        connection_rate: 0.0,
        traffic_volume: 0,
        ports_accessed: Vec::new(),
        timestamp: SystemTime::now(),
        http: Some(super::super::types::HttpObservation {
            request_rate,
            error_rate_4xx: error_rate,
            error_rate_5xx: 0.0,
            path_diversity,
            avg_payload_bytes: 256,
            method_diversity: 2,
        }),
    }
}

#[tokio::test]
async fn http_baseline_no_anomaly_within_normal_range() {
    let mut profiler = StatisticalProfiler::new(2.5);
    for i in 0..15 {
        let rate = f64::from(i).mul_add(0.3, 10.0);
        let paths = 5 + (i % 3);
        let err = f64::from(i).mul_add(0.002, 0.02);
        profiler
            .update(&http_observation(rate, paths, err))
            .await
            .unwrap();
    }
    let anomalies = profiler
        .detect_anomalies(&http_observation(12.0, 6, 0.03))
        .await
        .unwrap();
    assert!(anomalies.is_empty(), "slight variation should not trigger");
}

#[tokio::test]
async fn http_detects_request_rate_spike() {
    let mut profiler = StatisticalProfiler::new(2.5);
    for i in 0..15 {
        let rate = f64::from(i).mul_add(0.3, 10.0);
        profiler
            .update(&http_observation(
                rate,
                5 + (i % 3),
                f64::from(i).mul_add(0.002, 0.02),
            ))
            .await
            .unwrap();
    }
    let anomalies = profiler
        .detect_anomalies(&http_observation(500.0, 5, 0.02))
        .await
        .unwrap();
    assert!(
        anomalies
            .iter()
            .any(|a| a.behavior.contains("HTTP request rate")),
        "should detect HTTP request rate anomaly"
    );
}

#[tokio::test]
async fn http_detects_path_diversity_spike() {
    let mut profiler = StatisticalProfiler::new(2.5);
    for i in 0..15 {
        profiler
            .update(&http_observation(
                f64::from(i).mul_add(0.3, 10.0),
                5 + (i % 3),
                0.02,
            ))
            .await
            .unwrap();
    }
    let anomalies = profiler
        .detect_anomalies(&http_observation(10.0, 200, 0.02))
        .await
        .unwrap();
    assert!(
        anomalies
            .iter()
            .any(|a| a.behavior.contains("HTTP path diversity")),
        "should detect HTTP path diversity anomaly"
    );
}

#[tokio::test]
async fn http_detects_error_rate_spike() {
    let mut profiler = StatisticalProfiler::new(2.5);
    for i in 0..15 {
        profiler
            .update(&http_observation(
                10.0,
                5 + (i % 3),
                f64::from(i).mul_add(0.002, 0.02),
            ))
            .await
            .unwrap();
    }
    let anomalies = profiler
        .detect_anomalies(&http_observation(10.0, 5, 0.90))
        .await
        .unwrap();
    assert!(
        anomalies
            .iter()
            .any(|a| a.behavior.contains("HTTP 4xx error rate")),
        "should detect HTTP 4xx error rate anomaly"
    );
}

#[tokio::test]
async fn http_stats_populated_in_baseline() {
    let mut profiler = StatisticalProfiler::new(2.5);
    for i in 0..15 {
        profiler
            .update(&http_observation(
                f64::from(i).mul_add(0.3, 10.0),
                5 + (i % 3),
                0.02,
            ))
            .await
            .unwrap();
    }
    let stats = profiler
        .query_stats()
        .expect("baseline should be established");
    assert!(stats.http_request_rate.is_some());
    assert!(stats.http_path_diversity.is_some());
    assert!(stats.http_error_rate_4xx.is_some());
}

#[tokio::test]
async fn mixed_observations_http_stats_only_from_http() {
    let mut profiler = StatisticalProfiler::new(2.5);
    for _ in 0..10 {
        profiler.update(&observation(10.0)).await.unwrap();
    }
    for _ in 0..5 {
        profiler
            .update(&http_observation(20.0, 8, 0.05))
            .await
            .unwrap();
    }
    let stats = profiler
        .query_stats()
        .expect("baseline should be established");
    assert!(stats.connection_rate.is_some());
    assert!(stats.http_request_rate.is_some());
}

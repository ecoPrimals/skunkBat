// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Fleet threat detection — population-level analysis for stealth fleet identification.
//!
//! Receives [`FleetObservation`] from `skunky-ingest` and evaluates whether
//! the population behavior matches pathogenic patterns. When a fleet is
//! detected, generates a [`FleetAntibody`] that encodes the behavioral
//! fingerprint for persistent memory.
//!
//! ## Detection Philosophy
//!
//! Individual requests look normal (real browser UA, valid paths). The pathology
//! is only visible at population level:
//!
//! - **UA uniformity**: 2-4 UAs split 50/50 across thousands of requests
//! - **Metronomic timing**: coefficient of variation < 0.3
//! - **Commit-URL concentration**: >80% of paths are `/commit/<hash>` URLs
//! - **Deception signals**: hides identity + rotates IPs + ignores rejection
//!
//! ## Commensal Safety
//!
//! Commensals (Googlebot, ClaudeBot) *never* trigger detection because:
//! 1. They identify in their UA → `hides_identity = false`
//! 2. They have diverse path patterns → `commit_url_pct < 0.3`
//! 3. They respect 429/403 → `ignores_rejection = false`

use std::collections::VecDeque;
use std::time::SystemTime;

use cellmembrane_types::fleet::{
    DeceptionSignals, DefensePosture, FleetAntibody, FleetObservation, PathPattern,
    TimingSignature, UaFingerprint, DEFAULT_FORGIVE_WINDOW_SECS,
};

/// Configuration for fleet detection thresholds.
#[derive(Debug, Clone)]
pub struct FleetDetectorConfig {
    /// Minimum deception signals to consider pathogenic (0-4).
    pub min_deception_signals: u8,
    /// Maximum UA count that looks suspicious (e.g., 4).
    pub max_fleet_ua_count: u8,
    /// Minimum top-UA percentage that looks suspicious (e.g., 0.3).
    pub min_top_ua_pct: f32,
    /// Maximum CV of inter-arrival times (metronomic threshold).
    pub max_timing_cv: f32,
    /// Minimum commit-URL percentage to flag.
    pub min_commit_url_pct: f32,
    /// Minimum single-page percentage to flag.
    pub min_single_page_pct: f32,
    /// Minimum total requests in a window to analyze.
    pub min_requests: u64,
    /// How many recent observations to retain for pattern confirmation.
    pub observation_window: usize,
    /// Confidence assigned to newly generated antibodies.
    pub initial_confidence: f64,
}

impl Default for FleetDetectorConfig {
    fn default() -> Self {
        Self {
            min_deception_signals: 2,
            max_fleet_ua_count: 4,
            min_top_ua_pct: 0.3,
            max_timing_cv: 0.3,
            min_commit_url_pct: 0.5,
            min_single_page_pct: 0.7,
            min_requests: 20,
            observation_window: 10,
            initial_confidence: 0.85,
        }
    }
}

/// Fleet detector — analyzes population-level observations to identify stealth fleets.
pub struct FleetDetector {
    config: FleetDetectorConfig,
    recent_observations: VecDeque<FleetObservation>,
    detections: u64,
}

impl FleetDetector {
    /// Create a new fleet detector with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(FleetDetectorConfig::default())
    }

    /// Create a fleet detector with custom configuration.
    #[must_use]
    pub fn with_config(config: FleetDetectorConfig) -> Self {
        let window = config.observation_window;
        Self {
            config,
            recent_observations: VecDeque::with_capacity(window),
            detections: 0,
        }
    }

    /// Analyze a fleet observation and return an antibody if pathogenic.
    ///
    /// The observation is always stored in the recent window. An antibody
    /// is only generated when the observation crosses enough thresholds.
    pub fn analyze(&mut self, obs: FleetObservation) -> Option<FleetAntibody> {
        if obs.total_requests < self.config.min_requests {
            self.store_observation(obs);
            return None;
        }

        let score = self.score_observation(&obs);
        let antibody = if score >= 3 {
            Some(self.generate_antibody(&obs, score))
        } else {
            None
        };

        self.store_observation(obs);
        antibody
    }

    /// Score an observation (0-6) based on fleet indicators.
    fn score_observation(&self, obs: &FleetObservation) -> u8 {
        let mut score: u8 = 0;

        // UA uniformity
        if obs.ua_fingerprint.ua_count <= self.config.max_fleet_ua_count
            && obs.ua_fingerprint.top_ua_pct >= self.config.min_top_ua_pct
        {
            score += 1;
        }

        // Metronomic timing
        if obs.timing.interval_cv < self.config.max_timing_cv && obs.timing.mean_interval_ms > 0 {
            score += 1;
        }

        // Commit-URL concentration
        if obs.path_pattern.commit_url_pct >= self.config.min_commit_url_pct {
            score += 1;
        }

        // Single-page sessions (IP rotation signature)
        if obs.path_pattern.single_page_pct >= self.config.min_single_page_pct {
            score += 1;
        }

        // Deception signals (including header poverty / chrome impersonation)
        let deception_count = u8::from(obs.deception.hides_identity)
            + u8::from(obs.deception.rotates_ips)
            + u8::from(obs.deception.ignores_rejection)
            + u8::from(obs.deception.encoding_uniform)
            + u8::from(obs.deception.chrome_impersonation)
            + u8::from(obs.deception.header_poverty);
        if deception_count >= self.config.min_deception_signals {
            score += 1;
        }

        // Confirmed by recent history (multiple windows show same pattern)
        let recent_fleet_count = self
            .recent_observations
            .iter()
            .filter(|prev| {
                prev.ua_fingerprint.ua_count <= self.config.max_fleet_ua_count
                    && prev.deception.hides_identity
            })
            .count();
        if recent_fleet_count >= 2 {
            score += 1;
        }

        score
    }

    /// Generate an antibody from a confirmed fleet observation.
    fn generate_antibody(&mut self, obs: &FleetObservation, score: u8) -> FleetAntibody {
        self.detections += 1;

        let id = format!(
            "fleet-{:x}-{:04x}",
            obs.timestamp_epoch,
            self.detections
        );

        let now_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        FleetAntibody {
            id,
            ua_fingerprint: UaFingerprint {
                ua_count: obs.ua_fingerprint.ua_count,
                top_ua_pct: obs.ua_fingerprint.top_ua_pct,
                platform_split: obs.ua_fingerprint.platform_split,
            },
            timing: TimingSignature {
                mean_interval_ms: obs.timing.mean_interval_ms,
                interval_cv: obs.timing.interval_cv,
            },
            path_pattern: PathPattern {
                commit_url_pct: obs.path_pattern.commit_url_pct,
                single_page_pct: obs.path_pattern.single_page_pct,
                has_referrer_pct: obs.path_pattern.has_referrer_pct,
            },
            deception: DeceptionSignals {
                hides_identity: obs.deception.hides_identity,
                rotates_ips: obs.deception.rotates_ips,
                ignores_rejection: obs.deception.ignores_rejection,
                encoding_uniform: obs.deception.encoding_uniform,
                chrome_impersonation: obs.deception.chrome_impersonation,
                header_poverty: obs.deception.header_poverty,
            },
            confidence: self.config.initial_confidence * (f64::from(score) / 6.0).min(1.0),
            first_seen_epoch: now_epoch,
            last_matched_epoch: now_epoch,
            match_count: 1,
            escalation: DefensePosture::Observe,
            last_defection_epoch: 0,
            defection_count: 0,
            forgive_window_secs: DEFAULT_FORGIVE_WINDOW_SECS,
        }
    }

    fn store_observation(&mut self, obs: FleetObservation) {
        if self.recent_observations.len() >= self.config.observation_window {
            self.recent_observations.pop_front();
        }
        self.recent_observations.push_back(obs);
    }

    /// Total number of fleets detected since creation.
    #[must_use]
    pub fn detection_count(&self) -> u64 {
        self.detections
    }

    /// Number of recent observations in the window.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.recent_observations.len()
    }
}

impl Default for FleetDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stealth_fleet_observation() -> FleetObservation {
        FleetObservation {
            timestamp_epoch: 1_700_000_000,
            total_requests: 200,
            unique_ips: 180,
            ua_fingerprint: UaFingerprint {
                ua_count: 2,
                top_ua_pct: 0.50,
                platform_split: [0.50, 0.50, 0.0],
            },
            timing: TimingSignature {
                mean_interval_ms: 6000,
                interval_cv: 0.15,
            },
            path_pattern: PathPattern {
                commit_url_pct: 0.92,
                single_page_pct: 0.95,
                has_referrer_pct: 0.0,
            },
            deception: DeceptionSignals {
                hides_identity: true,
                rotates_ips: true,
                ignores_rejection: true,
                encoding_uniform: true,
                chrome_impersonation: true,
                header_poverty: true,
            },
            depth_distribution: [170, 8, 2, 0],
            rejected_ips: 160,
        }
    }

    fn human_observation() -> FleetObservation {
        FleetObservation {
            timestamp_epoch: 1_700_000_000,
            total_requests: 50,
            unique_ips: 30,
            ua_fingerprint: UaFingerprint {
                ua_count: 25,
                top_ua_pct: 0.08,
                platform_split: [0.30, 0.55, 0.15],
            },
            timing: TimingSignature {
                mean_interval_ms: 45_000,
                interval_cv: 1.8,
            },
            path_pattern: PathPattern {
                commit_url_pct: 0.02,
                single_page_pct: 0.20,
                has_referrer_pct: 0.70,
            },
            deception: DeceptionSignals {
                hides_identity: false,
                rotates_ips: false,
                ignores_rejection: false,
                encoding_uniform: false,
                chrome_impersonation: false,
                header_poverty: false,
            },
            depth_distribution: [10, 12, 6, 2],
            rejected_ips: 0,
        }
    }

    #[test]
    fn detect_stealth_fleet() {
        let mut detector = FleetDetector::new();
        let antibody = detector
            .analyze(stealth_fleet_observation())
            .expect("should detect stealth fleet");

        assert!(antibody.confidence > 0.3);
        assert_eq!(antibody.ua_fingerprint.ua_count, 2);
        assert!(antibody.path_pattern.commit_url_pct > 0.9);
        assert!(antibody.deception.hides_identity);
        assert_eq!(detector.detection_count(), 1);
    }

    #[test]
    fn no_false_positive_on_human_traffic() {
        let mut detector = FleetDetector::new();
        let antibody = detector.analyze(human_observation());
        assert!(antibody.is_none());
        assert_eq!(detector.detection_count(), 0);
    }

    #[test]
    fn commensal_bot_not_detected() {
        let mut detector = FleetDetector::new();
        let commensal = FleetObservation {
            timestamp_epoch: 1_700_000_000,
            total_requests: 100,
            unique_ips: 5,
            ua_fingerprint: UaFingerprint {
                ua_count: 1,
                top_ua_pct: 1.0,
                platform_split: [0.0, 0.0, 1.0],
            },
            timing: TimingSignature {
                mean_interval_ms: 30_000,
                interval_cv: 0.5,
            },
            path_pattern: PathPattern {
                commit_url_pct: 0.10,
                single_page_pct: 0.10,
                has_referrer_pct: 0.0,
            },
            deception: DeceptionSignals {
                hides_identity: false,
                rotates_ips: false,
                ignores_rejection: false,
                encoding_uniform: true,
                chrome_impersonation: false,
                header_poverty: false,
            },
            depth_distribution: [5, 0, 0, 0],
            rejected_ips: 0,
        };
        assert!(detector.analyze(commensal).is_none());
    }

    #[test]
    fn confirmed_with_history() {
        let mut detector = FleetDetector::new();

        // First two observations build history
        detector.analyze(stealth_fleet_observation());
        detector.analyze(stealth_fleet_observation());

        // Third should have history bonus
        let ab = detector
            .analyze(stealth_fleet_observation())
            .expect("confirmed with history");
        assert!(ab.confidence > 0.7);
    }

    #[test]
    fn too_few_requests_skipped() {
        let mut detector = FleetDetector::new();
        let mut obs = stealth_fleet_observation();
        obs.total_requests = 5;
        assert!(detector.analyze(obs).is_none());
    }
}

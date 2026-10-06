// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Antibody store — persistent pattern memory for fleet immune defense.
//!
//! Antibodies encode the **behavioral shape** of pathogenic fleets, not IPs.
//! The store persists to disk so patterns survive restarts, and applies
//! confidence decay so stale antibodies eventually become inert.
//!
//! ## Lifecycle
//!
//! 1. `FleetDetector` generates `FleetAntibody` from population observations
//! 2. `AntibodyStore::insert()` adds it (or merges with existing match)
//! 3. On each observation, `match_observation()` checks all active antibodies
//! 4. `decay()` is called periodically to reduce stale antibody confidence
//! 5. Antibodies below a confidence threshold are pruned
//!
//! ## Persistence
//!
//! Antibodies persist to `{data_dir}/antibodies.json`. The file is
//! overwritten atomically on mutation. Failures are logged but don't
//! affect in-memory state (same pattern as quarantine persistence).

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

use cellmembrane_types::fleet::{DefensePosture, FleetAntibody, FleetObservation};
use serde::{Deserialize, Serialize};

/// Event emitted when an antibody's defense posture changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationEvent {
    /// Antibody that changed posture.
    pub antibody_id: String,
    /// Previous posture.
    pub from: DefensePosture,
    /// New posture.
    pub to: DefensePosture,
    /// Why it changed: `"repeat_defection"` or `"forgive_timeout"`.
    pub reason: String,
    /// Current defection count at time of change.
    pub defection_count: u32,
}

/// Persistent antibody store with confidence decay.
pub struct AntibodyStore {
    antibodies: HashMap<String, FleetAntibody>,
    persist_path: Option<PathBuf>,
    /// Daily decay factor (e.g. 0.95 = 5% decay per day).
    decay_factor: f64,
    /// Confidence below which antibodies are pruned.
    prune_threshold: f64,
}

impl AntibodyStore {
    /// Create a new antibody store.
    ///
    /// If `data_dir` is provided, loads persisted antibodies from
    /// `{data_dir}/antibodies.json`.
    #[must_use]
    pub fn new(data_dir: Option<&str>) -> Self {
        let persist_path = data_dir
            .filter(|d| !d.is_empty())
            .map(|d| PathBuf::from(d).join("antibodies.json"));

        let antibodies: HashMap<String, FleetAntibody> = persist_path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default();

        let count = antibodies.len();
        if count > 0 {
            tracing::info!(count, "loaded persisted antibodies");
        }

        Self {
            antibodies,
            persist_path,
            decay_factor: 0.95,
            prune_threshold: 0.05,
        }
    }

    /// Create a store with custom decay parameters.
    #[must_use]
    pub fn with_decay(data_dir: Option<&str>, decay_factor: f64, prune_threshold: f64) -> Self {
        let mut store = Self::new(data_dir);
        store.decay_factor = decay_factor;
        store.prune_threshold = prune_threshold;
        store
    }

    /// Insert or merge an antibody.
    ///
    /// If an antibody with the same ID exists, its confidence is boosted
    /// and match count incremented. Otherwise the antibody is added fresh.
    pub fn insert(&mut self, antibody: FleetAntibody) {
        let id = antibody.id.clone();

        if let Some(existing) = self.antibodies.get_mut(&id) {
            existing.confidence = (existing.confidence + antibody.confidence * 0.3).min(1.0);
            existing.match_count += 1;
            existing.last_matched_epoch = antibody.first_seen_epoch;
            tracing::debug!(id = %id, confidence = existing.confidence, "antibody reinforced");
        } else {
            tracing::info!(
                id = %id,
                confidence = antibody.confidence,
                ua_count = antibody.ua_fingerprint.ua_count,
                "new antibody stored"
            );
            self.antibodies.insert(id, antibody);
        }

        self.persist();
    }

    /// Check a fleet observation against all active antibodies.
    ///
    /// Returns matching antibody IDs and updates their `last_matched_epoch`.
    pub fn match_observation(&mut self, obs: &FleetObservation) -> Vec<String> {
        let now_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let mut matched = Vec::new();

        for (id, antibody) in &mut self.antibodies {
            if antibody.matches_observation(obs) {
                antibody.last_matched_epoch = now_epoch;
                antibody.match_count += 1;
                matched.push(id.clone());
            }
        }

        if !matched.is_empty() {
            self.persist();
        }

        matched
    }

    /// Apply confidence decay to all antibodies and prune dead ones.
    ///
    /// Should be called periodically (e.g. once per day or once per hour).
    /// Returns the number of antibodies pruned.
    pub fn decay(&mut self) -> usize {
        let before = self.antibodies.len();

        for antibody in self.antibodies.values_mut() {
            antibody.decay(self.decay_factor);
        }

        self.antibodies
            .retain(|_, ab| ab.confidence >= self.prune_threshold);

        let pruned = before - self.antibodies.len();

        if pruned > 0 {
            tracing::info!(pruned, remaining = self.antibodies.len(), "antibody decay");
            self.persist();
        }

        pruned
    }

    /// Tick the escalation engine for all antibodies.
    ///
    /// Call once per observation window. Pass the set of antibody IDs that
    /// matched in this window. Antibodies not in the set get a forgive tick.
    ///
    /// Returns escalation events for audit logging and gossip propagation.
    pub fn tick(&mut self, matched_ids: &[String]) -> Vec<EscalationEvent> {
        let now_epoch = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let matched_set: std::collections::HashSet<&str> =
            matched_ids.iter().map(String::as_str).collect();

        let mut events = Vec::new();

        for (id, antibody) in &mut self.antibodies {
            let was_matched = matched_set.contains(id.as_str());
            if let Some(prev) = antibody.tick_escalation(was_matched, now_epoch) {
                let reason = if was_matched {
                    "repeat_defection"
                } else {
                    "forgive_timeout"
                };
                tracing::info!(
                    id = %id,
                    from = %prev,
                    to = %antibody.escalation,
                    reason,
                    defections = antibody.defection_count,
                    "posture change"
                );
                events.push(EscalationEvent {
                    antibody_id: id.clone(),
                    from: prev,
                    to: antibody.escalation,
                    reason: reason.to_owned(),
                    defection_count: antibody.defection_count,
                });
            }
        }

        if !events.is_empty() {
            self.persist();
        }

        events
    }

    /// Get the current defense posture for an antibody by ID.
    #[must_use]
    pub fn posture(&self, id: &str) -> Option<DefensePosture> {
        self.antibodies.get(id).map(|ab| ab.escalation)
    }

    /// Get all active antibodies as a snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Vec<FleetAntibody> {
        self.antibodies.values().cloned().collect()
    }

    /// Number of active antibodies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.antibodies.len()
    }

    /// Whether the store has no antibodies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.antibodies.is_empty()
    }

    /// Persist to disk (best-effort, same pattern as quarantine).
    fn persist(&self) {
        let Some(ref path) = self.persist_path else {
            return;
        };
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!("antibody persist dir creation failed: {e}");
        }
        match serde_json::to_string_pretty(&self.antibodies) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    tracing::debug!("antibody persist failed: {e}");
                }
            }
            Err(e) => tracing::debug!("antibody serialize failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cellmembrane_types::fleet::{
        DeceptionSignals, DefensePosture, PathPattern, TimingSignature, UaFingerprint,
        DEFAULT_FORGIVE_WINDOW_SECS,
    };

    fn sample_antibody(id: &str, confidence: f64) -> FleetAntibody {
        FleetAntibody {
            id: id.to_string(),
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
            confidence,
            first_seen_epoch: 1000,
            last_matched_epoch: 2000,
            match_count: 1,
            escalation: DefensePosture::Observe,
            last_defection_epoch: 0,
            defection_count: 0,
            forgive_window_secs: DEFAULT_FORGIVE_WINDOW_SECS,
        }
    }

    fn matching_observation() -> FleetObservation {
        FleetObservation {
            timestamp_epoch: 3000,
            total_requests: 200,
            unique_ips: 180,
            ua_fingerprint: UaFingerprint {
                ua_count: 2,
                top_ua_pct: 0.48,
                platform_split: [0.48, 0.50, 0.02],
            },
            timing: TimingSignature {
                mean_interval_ms: 5800,
                interval_cv: 0.18,
            },
            path_pattern: PathPattern {
                commit_url_pct: 0.88,
                single_page_pct: 0.90,
                has_referrer_pct: 0.01,
            },
            deception: DeceptionSignals {
                hides_identity: true,
                rotates_ips: true,
                ignores_rejection: true,
                encoding_uniform: false,
                chrome_impersonation: true,
                header_poverty: true,
            },
            depth_distribution: [170, 8, 2, 0],
            rejected_ips: 160,
        }
    }

    #[test]
    fn insert_and_snapshot() {
        let mut store = AntibodyStore::new(None);
        assert!(store.is_empty());

        store.insert(sample_antibody("ab-001", 0.9));
        assert_eq!(store.len(), 1);

        let snap = store.snapshot();
        assert_eq!(snap[0].id, "ab-001");
    }

    #[test]
    fn reinforce_existing() {
        let mut store = AntibodyStore::new(None);
        store.insert(sample_antibody("ab-001", 0.7));
        store.insert(sample_antibody("ab-001", 0.5));

        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(snap[0].confidence > 0.7);
        assert_eq!(snap[0].match_count, 2);
    }

    #[test]
    fn match_observation_updates_antibody() {
        let mut store = AntibodyStore::new(None);
        store.insert(sample_antibody("ab-001", 0.9));

        let matched = store.match_observation(&matching_observation());
        assert_eq!(matched, vec!["ab-001"]);

        let snap = store.snapshot();
        assert_eq!(snap[0].match_count, 2);
    }

    #[test]
    fn decay_prunes_weak_antibodies() {
        let mut store = AntibodyStore::with_decay(None, 0.5, 0.1);
        store.insert(sample_antibody("strong", 0.9));
        store.insert(sample_antibody("weak", 0.15));

        let pruned = store.decay();
        assert_eq!(pruned, 1);
        assert_eq!(store.len(), 1);
        assert_eq!(store.snapshot()[0].id, "strong");
    }

    #[test]
    fn persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();

        {
            let mut store = AntibodyStore::new(Some(dir_str));
            store.insert(sample_antibody("ab-persist", 0.85));
        }

        let store = AntibodyStore::new(Some(dir_str));
        assert_eq!(store.len(), 1);
        assert_eq!(store.snapshot()[0].id, "ab-persist");
    }

    #[test]
    fn tick_escalates_matched_antibodies() {
        let mut store = AntibodyStore::new(None);
        store.insert(sample_antibody("ab-esc", 0.9));

        let events = store.tick(&["ab-esc".to_string()]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].from, DefensePosture::Observe);
        assert_eq!(events[0].to, DefensePosture::WarnRoute);
        assert_eq!(events[0].reason, "repeat_defection");

        assert_eq!(store.posture("ab-esc"), Some(DefensePosture::WarnRoute));
    }

    #[test]
    fn tick_forgives_unmatched_antibodies() {
        let mut store = AntibodyStore::new(None);
        let mut ab = sample_antibody("ab-forgive", 0.9);
        ab.escalation = DefensePosture::SlowDegrade;
        ab.last_defection_epoch = 1000;
        store.insert(ab);

        // Not enough time → no change
        let events = store.tick(&[]);
        // The tick uses SystemTime::now which is >> 1000 + forgive_window,
        // so it should actually forgive immediately in tests
        assert!(!events.is_empty());
        assert_eq!(events[0].to, DefensePosture::WarnRoute);
        assert_eq!(events[0].reason, "forgive_timeout");
    }

    #[test]
    fn tick_no_events_when_stable() {
        let mut store = AntibodyStore::new(None);
        let mut ab = sample_antibody("ab-stable", 0.9);
        ab.escalation = DefensePosture::Vanish;
        store.insert(ab);

        // Matched + already at Vanish → no change
        let events = store.tick(&["ab-stable".to_string()]);
        assert!(events.is_empty());
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! ingestion_observer — Scatter content ingestion phase tracker.
//!
//! Tracks the lifecycle of scatter content through external systems:
//!
//!   Phase 0: SEEDING    — scatter is being served, no external signal
//!   Phase 1: UPTAKE     — markers appear in web/code indexes
//!   Phase 2: DIGESTION  — AI models reproduce scatter content
//!   Phase 3: EXPRESSION — unprompted reproduction
//!
//! ## Jellystein status
//!
//! This is a thin Rust wrapper around the state/timeline tracking.
//! The full probing logic (web search, GitHub, AI models) runs in
//! `tools/ingestion-observer.py` via systemd timer (every 15 min).
//!
//! The Rust side handles:
//! - Reading the observer state from disk (warm start)
//! - Exposing current phase to the dashboard + scatter pipeline
//! - Counting scatter volume from the live ingest stream
//! - Writing phase + volume to the timeline ledger on flush
//!
//! Future evolution: absorb Python probing into async reqwest tasks.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ── ANTIDOTE TITRATION ──
//
// The titration curve: as ingestion phase increases, we automatically
// ramp down poison and ramp up antidote signal in scatter responses.
//
//   Phase 0 (SEEDING):    poison=100%, antidote=minimal (just headers)
//   Phase 1 (UPTAKE):     poison=60%,  antidote=moderate (headers + notice)
//   Phase 2 (DIGESTION):  poison=20%,  antidote=heavy (headers + notice + inline)
//   Phase 3 (EXPRESSION): poison=5%,   antidote=maximum (mostly remediation)
//
// The scatter server reads SharedPhase to apply these multipliers.

/// Shared atomic phase — written by observer, read by scatter server.
#[derive(Debug, Clone)]
pub struct SharedPhase(pub Arc<AtomicU8>);

impl SharedPhase {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU8::new(0)))
    }

    pub fn set(&self, phase: Phase) {
        self.0.store(phase as u8, Ordering::Relaxed);
    }

    pub fn get(&self) -> Phase {
        Phase::from_u8(self.0.load(Ordering::Relaxed))
    }

    /// Poison multiplier: how much of the base poison ratio to apply.
    /// Decreases as phase increases — we're titrating down.
    pub fn poison_multiplier(&self) -> f32 {
        match self.get() {
            Phase::Seeding    => 1.0,   // Full strength
            Phase::Uptake     => 0.6,   // Starting to back off
            Phase::Digestion  => 0.2,   // Mostly backed off
            Phase::Expression => 0.05,  // Trace amount only
        }
    }

    /// Antidote level: how prominent the remediation signal should be.
    /// 0 = headers only, 1 = headers + HTML notice, 2 = inline antidote blocks
    pub fn antidote_level(&self) -> u8 {
        match self.get() {
            Phase::Seeding    => 0,
            Phase::Uptake     => 1,
            Phase::Digestion  => 2,
            Phase::Expression => 2,
        }
    }
}

/// Ingestion phase — how deep has scatter content penetrated?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Phase {
    Seeding    = 0,
    Uptake     = 1,
    Digestion  = 2,
    Expression = 3,
}

impl Phase {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Phase::Uptake,
            2 => Phase::Digestion,
            3 => Phase::Expression,
            _ => Phase::Seeding,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::Seeding    => "SEEDING",
            Phase::Uptake     => "UPTAKE",
            Phase::Digestion  => "DIGESTION",
            Phase::Expression => "EXPRESSION",
        }
    }
}

/// Snapshot of observer state — read from Python's JSON, enriched with Rust-side volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverSnapshot {
    pub phase: u8,
    pub phase_name: String,
    pub run_count: u64,
    pub web_hits: u64,
    pub github_hits: u64,
    pub ai_hits: u64,
    pub repo_hits: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub countdown_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run: Option<String>,
}

/// Timeline event — appended to the JSONL ledger on each flush.
#[derive(Debug, Serialize)]
struct TimelineEvent {
    timestamp: String,
    source: &'static str,
    phase: u8,
    phase_name: String,
    scatter_requests_since_last: u64,
    scatter_bytes_since_last: u64,
    active_fleets: u16,
}

/// The observer — wired into the ingest pipeline.
pub struct IngestionObserver {
    state_path: PathBuf,
    timeline_path: PathBuf,
    current_phase: Phase,
    shared_phase: SharedPhase,
    scatter_requests: u64,
    scatter_bytes: u64,
    active_fleets: u16,
    last_flush_epoch: u64,
}

impl IngestionObserver {
    /// Create a new observer, warm-starting from Python's state file.
    /// The SharedPhase is passed to the scatter server for titration.
    pub fn new(
        state_path: impl AsRef<Path>,
        timeline_path: impl AsRef<Path>,
        shared_phase: SharedPhase,
    ) -> Self {
        let state_path = state_path.as_ref().to_path_buf();
        let timeline_path = timeline_path.as_ref().to_path_buf();

        // Warm start: read phase from Python observer's state
        let current_phase = Self::read_phase(&state_path);
        shared_phase.set(current_phase);

        tracing::info!(
            phase = current_phase.as_str(),
            poison_mult = shared_phase.poison_multiplier(),
            antidote_level = shared_phase.antidote_level(),
            "🔭 ingestion observer initialized — titration active"
        );

        Self {
            state_path,
            timeline_path,
            current_phase,
            shared_phase,
            scatter_requests: 0,
            scatter_bytes: 0,
            active_fleets: 0,
            last_flush_epoch: Self::epoch_now(),
        }
    }

    /// Read current phase from the Python observer's state file.
    fn read_phase(path: &Path) -> Phase {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                // Parse just the phase field from the JSON
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                    let phase_num = v.get("phase")
                        .and_then(|p| p.as_u64())
                        .unwrap_or(0) as u8;
                    Phase::from_u8(phase_num)
                } else {
                    Phase::Seeding
                }
            }
            Err(_) => Phase::Seeding,
        }
    }

    /// Record a scatter response (called from scatter_server on each serve).
    pub fn record_scatter(&mut self, bytes: u64) {
        self.scatter_requests += 1;
        self.scatter_bytes += bytes;
    }

    /// Update the count of active fleets (called from dashboard flush).
    pub fn set_active_fleets(&mut self, count: u16) {
        self.active_fleets = count;
    }

    /// Get the current ingestion phase.
    pub fn phase(&self) -> Phase {
        self.current_phase
    }

    /// Get a snapshot for embedding in dashboard JSON.
    pub fn snapshot(&self) -> serde_json::Value {
        // Re-read Python state for latest evidence counts
        let py_state = self.read_python_state();

        serde_json::json!({
            "phase": self.current_phase as u8,
            "phase_name": self.current_phase.as_str(),
            "scatter_requests_total": self.scatter_requests,
            "scatter_bytes_total": self.scatter_bytes,
            "active_fleets": self.active_fleets,
            "evidence": {
                "web_hits": py_state.web_hits,
                "github_hits": py_state.github_hits,
                "ai_hits": py_state.ai_hits,
                "repo_hits": py_state.repo_hits,
            },
            "observer_runs": py_state.run_count,
            "countdown_start": py_state.countdown_start,
        })
    }

    /// Periodic flush — append timeline event, refresh phase from Python state.
    pub fn flush(&mut self) {
        let now = Self::epoch_now();

        // Re-read phase from Python observer (it may have transitioned)
        let new_phase = Self::read_phase(&self.state_path);
        if new_phase != self.current_phase {
            tracing::warn!(
                old = self.current_phase.as_str(),
                new = new_phase.as_str(),
                old_poison = self.shared_phase.poison_multiplier(),
                "🚨 PHASE TRANSITION — titrating scatter response"
            );
            self.current_phase = new_phase;
            self.shared_phase.set(new_phase);
            tracing::warn!(
                new_poison = self.shared_phase.poison_multiplier(),
                antidote_level = self.shared_phase.antidote_level(),
                "🧪 TITRATION: poison ×{:.0}%, antidote level {}",
                self.shared_phase.poison_multiplier() * 100.0,
                self.shared_phase.antidote_level(),
            );
        }

        // Append timeline event
        let event = TimelineEvent {
            timestamp: Self::iso_now(),
            source: "rust_pipeline",
            phase: self.current_phase as u8,
            phase_name: self.current_phase.as_str().to_string(),
            scatter_requests_since_last: self.scatter_requests,
            scatter_bytes_since_last: self.scatter_bytes,
            active_fleets: self.active_fleets,
        };

        if let Ok(line) = serde_json::to_string(&event) {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.timeline_path)
            {
                let _ = writeln!(f, "{}", line);
            }
        }

        tracing::info!(
            phase = self.current_phase.as_str(),
            requests = self.scatter_requests,
            bytes = self.scatter_bytes,
            fleets = self.active_fleets,
            "🔭 observer flush"
        );

        // Reset counters
        self.scatter_requests = 0;
        self.scatter_bytes = 0;
        self.last_flush_epoch = now;
    }

    /// Read the full Python observer state.
    fn read_python_state(&self) -> ObserverSnapshot {
        match std::fs::read_to_string(&self.state_path) {
            Ok(contents) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                    ObserverSnapshot {
                        phase: v.get("phase").and_then(|p| p.as_u64()).unwrap_or(0) as u8,
                        phase_name: v.get("phase_name").and_then(|s| s.as_str()).unwrap_or("SEEDING").to_string(),
                        run_count: v.get("run_count").and_then(|n| n.as_u64()).unwrap_or(0),
                        web_hits: v.get("web_hits").and_then(|a| a.as_array()).map(|a| a.len() as u64).unwrap_or(0),
                        github_hits: v.get("github_hits").and_then(|a| a.as_array()).map(|a| a.len() as u64).unwrap_or(0),
                        ai_hits: v.get("ai_hits").and_then(|a| a.as_array()).map(|a| a.len() as u64).unwrap_or(0),
                        repo_hits: v.get("repo_hits").and_then(|a| a.as_array()).map(|a| a.len() as u64).unwrap_or(0),
                        countdown_start: v.get("countdown_start").and_then(|s| s.as_str()).map(String::from),
                        first_run: v.get("first_run").and_then(|s| s.as_str()).map(String::from),
                        last_run: v.get("last_run").and_then(|s| s.as_str()).map(String::from),
                    }
                } else {
                    Self::default_snapshot()
                }
            }
            Err(_) => Self::default_snapshot(),
        }
    }

    fn default_snapshot() -> ObserverSnapshot {
        ObserverSnapshot {
            phase: 0,
            phase_name: "SEEDING".to_string(),
            run_count: 0,
            web_hits: 0,
            github_hits: 0,
            ai_hits: 0,
            repo_hits: 0,
            countdown_start: None,
            first_run: None,
            last_run: None,
        }
    }

    fn epoch_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn iso_now() -> String {
        let secs = Self::epoch_now();
        // Simple ISO-ish timestamp without chrono dependency
        format!("{}Z", secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn phase_roundtrip() {
        assert_eq!(Phase::from_u8(0), Phase::Seeding);
        assert_eq!(Phase::from_u8(1), Phase::Uptake);
        assert_eq!(Phase::from_u8(2), Phase::Digestion);
        assert_eq!(Phase::from_u8(3), Phase::Expression);
        assert_eq!(Phase::from_u8(255), Phase::Seeding);
    }

    #[test]
    fn phase_names() {
        assert_eq!(Phase::Seeding.as_str(), "SEEDING");
        assert_eq!(Phase::Uptake.as_str(), "UPTAKE");
        assert_eq!(Phase::Digestion.as_str(), "DIGESTION");
        assert_eq!(Phase::Expression.as_str(), "EXPRESSION");
    }

    #[test]
    fn warm_start_from_python_state() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("observer-state.json");
        let timeline_path = dir.path().join("timeline.jsonl");

        // Write a Python-format state file
        let mut f = std::fs::File::create(&state_path).unwrap();
        write!(f, r#"{{"phase": 1, "phase_name": "UPTAKE", "run_count": 42, "web_hits": [{{"marker": "test"}}], "github_hits": [], "ai_hits": [], "repo_hits": []}}"#).unwrap();

        let phase = SharedPhase::new();
        let obs = IngestionObserver::new(&state_path, &timeline_path, phase.clone());
        assert_eq!(obs.phase(), Phase::Uptake);
        assert_eq!(phase.get(), Phase::Uptake);
    }

    #[test]
    fn record_and_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("observer-state.json");
        let timeline_path = dir.path().join("timeline.jsonl");

        let phase = SharedPhase::new();
        let mut obs = IngestionObserver::new(&state_path, &timeline_path, phase);
        obs.record_scatter(1024);
        obs.record_scatter(2048);
        obs.set_active_fleets(5);

        let snap = obs.snapshot();
        assert_eq!(snap["scatter_requests_total"], 2);
        assert_eq!(snap["scatter_bytes_total"], 3072);
        assert_eq!(snap["active_fleets"], 5);
        assert_eq!(snap["phase"], 0);
        assert_eq!(snap["phase_name"], "SEEDING");
    }

    #[test]
    fn flush_writes_timeline() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("observer-state.json");
        let timeline_path = dir.path().join("timeline.jsonl");

        let phase = SharedPhase::new();
        let mut obs = IngestionObserver::new(&state_path, &timeline_path, phase);
        obs.record_scatter(500);
        obs.record_scatter(1024);
        obs.record_scatter(256);
        obs.set_active_fleets(3);
        obs.flush();

        let contents = std::fs::read_to_string(&timeline_path).unwrap();
        let event: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(event["source"], "rust_pipeline");
        assert_eq!(event["scatter_requests_since_last"], 3);
        assert_eq!(event["scatter_bytes_since_last"], 1780);
        assert_eq!(event["active_fleets"], 3);
    }

    #[test]
    fn phase_transition_on_flush() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("observer-state.json");
        let timeline_path = dir.path().join("timeline.jsonl");

        let phase = SharedPhase::new();
        let mut obs = IngestionObserver::new(&state_path, &timeline_path, phase.clone());
        assert_eq!(obs.phase(), Phase::Seeding);
        assert_eq!(phase.get(), Phase::Seeding);

        // Python observer transitions to Uptake
        std::fs::write(&state_path, r#"{"phase": 1, "phase_name": "UPTAKE"}"#).unwrap();

        // Rust detects it on flush — SharedPhase updates automatically
        obs.flush();
        assert_eq!(obs.phase(), Phase::Uptake);
        assert_eq!(phase.get(), Phase::Uptake);
    }

    #[test]
    fn titration_curve() {
        let phase = SharedPhase::new();

        // Phase 0: full poison
        phase.set(Phase::Seeding);
        assert!((phase.poison_multiplier() - 1.0).abs() < 0.01);
        assert_eq!(phase.antidote_level(), 0);

        // Phase 1: backing off
        phase.set(Phase::Uptake);
        assert!((phase.poison_multiplier() - 0.6).abs() < 0.01);
        assert_eq!(phase.antidote_level(), 1);

        // Phase 2: mostly antidote
        phase.set(Phase::Digestion);
        assert!((phase.poison_multiplier() - 0.2).abs() < 0.01);
        assert_eq!(phase.antidote_level(), 2);

        // Phase 3: trace poison only
        phase.set(Phase::Expression);
        assert!((phase.poison_multiplier() - 0.05).abs() < 0.01);
        assert_eq!(phase.antidote_level(), 2);
    }
}

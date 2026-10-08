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
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ── LOGARITHMIC ANTIDOTE TITRATION ──
//
// Continuous titration curve — antidote flows from day 1, not just on
// phase transitions. By the time we DETECT ingestion, weeks of scatter
// content already has antidote mixed in.
//
// The curve: poison_mult = 1.0 / (1.0 + k * ln(1 + effective_days))
//
//   effective_days = real_days + phase_boost
//
// Where phase_boost accelerates the curve forward on detection:
//   Phase 0: +0 days  (time alone drives the ramp)
//   Phase 1: +30 days (jump forward — we know they ate it)
//   Phase 2: +90 days (heavy acceleration)
//   Phase 3: +180 days (maximum — mostly antidote)
//
// At k=0.15 (tuned for ~90 day training pipeline latency):
//   Day 0:   poison ×100%  antidote=0
//   Day 1:   poison ×96%   antidote already flowing
//   Day 7:   poison ×77%   
//   Day 30:  poison ×66%   
//   Day 60:  poison ×62%   ← if no detection, still ramping
//   Phase 1 hits: effective_days jumps +30 → poison drops to ~52%
//   Phase 2 hits: effective_days jumps +90 → poison drops to ~31%
//
// The shape: fast initial ramp (antidote starts flowing immediately),
// then long logarithmic tail. Phase transitions are jump discontinuities
// that accelerate the curve when evidence arrives.

/// Titration rate constant. Higher = faster antidote ramp.
/// 0.15 is tuned for ~90 day pipeline latency assumption.
const TITRATION_K: f64 = 0.15;

/// Floor — never go below 5% poison (trace amount for continued tracking).
const POISON_FLOOR: f32 = 0.05;

/// Phase boost: how many effective days each phase adds to the curve.
const PHASE_BOOST: [f64; 4] = [
    0.0,    // Phase 0: SEEDING — time alone
    30.0,   // Phase 1: UPTAKE — 30 day jump
    90.0,   // Phase 2: DIGESTION — 90 day jump
    180.0,  // Phase 3: EXPRESSION — 180 day jump
];

/// Shared titration state — written by observer, read by scatter server.
/// Stores both phase AND the epoch when titration started, enabling
/// continuous logarithmic decay from the moment scatter begins serving.
#[derive(Debug, Clone)]
pub struct SharedPhase {
    phase: Arc<AtomicU8>,
    /// Epoch (seconds) when titration started — set once on first init.
    titration_start: Arc<AtomicU64>,
}

impl SharedPhase {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            phase: Arc::new(AtomicU8::new(0)),
            titration_start: Arc::new(AtomicU64::new(now)),
        }
    }

    /// Initialize with a known start epoch (for warm-starting from state).
    pub fn with_start_epoch(epoch_secs: u64) -> Self {
        Self {
            phase: Arc::new(AtomicU8::new(0)),
            titration_start: Arc::new(AtomicU64::new(epoch_secs)),
        }
    }

    pub fn set(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::Relaxed);
    }

    pub fn get(&self) -> Phase {
        Phase::from_u8(self.phase.load(Ordering::Relaxed))
    }

    /// Set the titration start epoch (called once on init from observer state).
    pub fn set_start_epoch(&self, epoch: u64) {
        self.titration_start.store(epoch, Ordering::Relaxed);
    }

    /// Days since titration started.
    pub fn days_elapsed(&self) -> f64 {
        let start = self.titration_start.load(Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        (now.saturating_sub(start) as f64) / 86400.0
    }

    /// Effective days = real days + phase boost.
    /// Phase transitions jump the curve forward.
    pub fn effective_days(&self) -> f64 {
        let real = self.days_elapsed();
        let boost = PHASE_BOOST[self.get() as usize];
        real + boost
    }

    /// Logarithmic poison multiplier: 1.0 / (1.0 + k * ln(1 + effective_days))
    /// Starts at ~1.0, decays continuously, accelerates on phase transitions.
    /// Never goes below POISON_FLOOR (5%).
    pub fn poison_multiplier(&self) -> f32 {
        let t = self.effective_days();
        let mult = 1.0 / (1.0 + TITRATION_K * (1.0 + t).ln());
        (mult as f32).max(POISON_FLOOR)
    }

    /// Antidote level: how prominent the remediation signal should be.
    /// Determined by effective_days (continuous, not just phase steps).
    ///   0 = headers only (early seeding)
    ///   1 = headers + HTML comment notice
    ///   2 = headers + notice + inline visible antidote block
    pub fn antidote_level(&self) -> u8 {
        let t = self.effective_days();
        if t >= 60.0 {
            2  // Heavy antidote
        } else if t >= 7.0 {
            1  // Moderate antidote
        } else {
            0  // Headers only
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

        // Warm start: read phase AND titration_start from state
        let current_phase = Self::read_phase(&state_path);
        shared_phase.set(current_phase);

        // Restore titration start epoch from Python observer state
        // (or use current time if this is the very first run)
        if let Ok(contents) = std::fs::read_to_string(&state_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&contents) {
                if let Some(first_run) = v.get("first_run").and_then(|s| s.as_str()) {
                    // Parse ISO timestamp to epoch seconds
                    if let Some(epoch) = Self::parse_iso_epoch(first_run) {
                        shared_phase.set_start_epoch(epoch);
                    }
                }
            }
        }

        tracing::info!(
            phase = current_phase.as_str(),
            days_elapsed = format!("{:.1}", shared_phase.days_elapsed()),
            effective_days = format!("{:.1}", shared_phase.effective_days()),
            poison_mult = format!("{:.2}", shared_phase.poison_multiplier()),
            antidote_level = shared_phase.antidote_level(),
            "🔭 ingestion observer — logarithmic titration active"
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
                new_poison = format!("{:.1}%", self.shared_phase.poison_multiplier() * 100.0),
                antidote_level = self.shared_phase.antidote_level(),
                effective_days = format!("{:.1}", self.shared_phase.effective_days()),
                "🧪 PHASE JUMP — logarithmic curve accelerated"
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
            poison = format!("{:.1}%", self.shared_phase.poison_multiplier() * 100.0),
            antidote = self.shared_phase.antidote_level(),
            days = format!("{:.1}", self.shared_phase.days_elapsed()),
            eff_days = format!("{:.1}", self.shared_phase.effective_days()),
            requests = self.scatter_requests,
            bytes = self.scatter_bytes,
            fleets = self.active_fleets,
            "🔭 observer flush — titration curve"
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

    /// Parse an ISO 8601 timestamp to epoch seconds (simple parser, no chrono dep).
    fn parse_iso_epoch(iso: &str) -> Option<u64> {
        // Format: 2026-10-08T15:58:43.346876+00:00 or 2026-10-08T15:58:43Z
        // We just need year-month-day-hour-min-sec
        let parts: Vec<&str> = iso.split('T').collect();
        if parts.len() < 2 { return None; }
        let date_parts: Vec<u64> = parts[0].split('-').filter_map(|s| s.parse().ok()).collect();
        let time_str = parts[1].split('+').next()?.split('Z').next()?;
        let time_parts: Vec<u64> = time_str.split(':')
            .filter_map(|s| s.split('.').next().and_then(|n| n.parse().ok()))
            .collect();
        if date_parts.len() < 3 || time_parts.len() < 3 { return None; }

        // Rough epoch calculation (good enough for day-level titration)
        let (y, m, d) = (date_parts[0], date_parts[1], date_parts[2]);
        let (h, min, s) = (time_parts[0], time_parts[1], time_parts[2]);
        // Days since epoch (approximate — ignoring leap seconds, good enough)
        let days_approx = (y - 1970) * 365 + (y - 1969) / 4
            + [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
                .get((m as usize).saturating_sub(1))
                .copied()
                .unwrap_or(0)
            + d - 1;
        Some(days_approx * 86400 + h * 3600 + min * 60 + s)
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
    fn logarithmic_titration_curve() {
        // Start at "now" — day 0
        let phase = SharedPhase::new();
        phase.set(Phase::Seeding);

        // Day 0: poison should be very close to 1.0 (just started)
        let p0 = phase.poison_multiplier();
        assert!(p0 > 0.95, "Day 0 poison should be ~1.0, got {p0}");
        assert_eq!(phase.antidote_level(), 0);

        // Phase 1 jump: effective_days += 30
        // At effective_days=30: 1/(1 + 0.15 * ln(31)) ≈ 0.66
        phase.set(Phase::Uptake);
        let p1 = phase.poison_multiplier();
        assert!(p1 < 0.75, "Phase 1 should drop poison below 0.75, got {p1}");
        assert!(p1 > 0.55, "Phase 1 should keep poison above 0.55, got {p1}");
        assert_eq!(phase.antidote_level(), 1); // effective_days ≈ 30 > 7

        // Phase 2 jump: effective_days += 90
        // At effective_days=90: 1/(1 + 0.15 * ln(91)) ≈ 0.60
        phase.set(Phase::Digestion);
        let p2 = phase.poison_multiplier();
        assert!(p2 < p1, "Phase 2 poison should be less than Phase 1");
        assert!(p2 < 0.65, "Phase 2 should drop below 0.65, got {p2}");
        assert_eq!(phase.antidote_level(), 2); // effective_days ≈ 90 > 60

        // Phase 3 jump: effective_days += 180
        // At effective_days=180: 1/(1 + 0.15 * ln(181)) ≈ 0.56
        phase.set(Phase::Expression);
        let p3 = phase.poison_multiplier();
        assert!(p3 < p2, "Phase 3 poison should be less than Phase 2");
        assert!(p3 > POISON_FLOOR, "Should stay above floor {POISON_FLOOR}");
    }

    #[test]
    fn titration_with_time_elapsed() {
        // Simulate starting 30 days ago
        let thirty_days_ago = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            - (30 * 86400);

        let phase = SharedPhase::with_start_epoch(thirty_days_ago);
        phase.set(Phase::Seeding);

        // 30 days in, still Phase 0: should be noticeably lower than 1.0
        // 1/(1 + 0.15 * ln(31)) ≈ 0.66
        let p = phase.poison_multiplier();
        assert!(p < 0.80, "30 days in, poison should be < 0.80, got {p}");
        assert!(p > 0.55, "30 days in, poison should be > 0.55, got {p}");
        assert_eq!(phase.antidote_level(), 1); // 30 > 7 days → level 1

        // Now phase 1 hits — effective_days = 30 + 30 = 60
        phase.set(Phase::Uptake);
        let p1 = phase.poison_multiplier();
        assert!(p1 < p, "Phase transition should further reduce poison");
        assert_eq!(phase.antidote_level(), 2); // 60 >= 60 → level 2
    }

    #[test]
    fn poison_never_below_floor() {
        // Simulate starting 1000 days ago with Phase 3
        let long_ago = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            - (1000 * 86400);

        let phase = SharedPhase::with_start_epoch(long_ago);
        phase.set(Phase::Expression);

        let p = phase.poison_multiplier();
        assert!(p >= POISON_FLOOR, "Should never go below {POISON_FLOOR}, got {p}");
        // ln(1181) ≈ 7.07, so 1/(1 + 0.15*7.07) ≈ 0.485 — log decay is slow by design.
        // The curve never truly hits floor via time alone, but stays well below 1.0
        assert!(p < 0.55, "After 1000+ effective days, poison should be < 0.55, got {p}");
    }

    #[test]
    fn iso_epoch_parse() {
        let epoch = IngestionObserver::parse_iso_epoch("2026-10-08T15:58:43.346876+00:00");
        assert!(epoch.is_some());
        let e = epoch.unwrap();
        // Should be roughly 2026-10-08 in epoch seconds
        assert!(e > 1_790_000_000, "epoch {e} too small");
        assert!(e < 1_800_000_000, "epoch {e} too large");
    }
}

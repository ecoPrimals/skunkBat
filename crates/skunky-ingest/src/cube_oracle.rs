// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BingoCube Decision Grid and Oracle — unified randomization + evolutionary learning.
//!
//! Replaces hand-rolled `% N` probability gates with a BingoCube color grid
//! that provides multi-axis deterministic decisions from (fleet_hash, path, epoch).
//!
//! The CubeOracle trait defines an IPC-ready boundary: any primal consuming
//! bingoCube gets the same interface, whether in-process or via IPC.

#![allow(missing_docs)]

use bingocube_core::{BingoCube, Color, Config};
use bingocube_nautilus::{
    InstanceId, NautilusShell, ReservoirInput, ShellConfig,
};

use crate::scatter_rng::CubePrng;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ══════════════════════════════════════════════════════════════════════
// CubeDecisionGrid — multi-axis decision matrix from BingoCube colors
// ══════════════════════════════════════════════════════════════════════

/// Cell assignments for the 5x5 decision grid.
///
/// Each cell's color (0-15) drives a different scatter decision axis.
/// The grid is seeded from (fleet_hash, path, epoch), so it is deterministic
/// for repeat requests but varies per fleet + epoch.
///
/// ```text
///         col0          col1          col2          col3          col4
/// row0  jitter_type   content_var   poison_gate   mirror_gate   crawl_density
/// row1  antibody_idx  header_var    inject_pos    federation    personality
/// row2  temporal_ph   lure_type     fluoro_layer  prism_mode    amplify_scale
/// row3  reserved(nautilus-override) ...
/// row4  reserved(nautilus-override) ...
/// ```
pub struct CubeDecisionGrid {
    colors: [[Color; 5]; 5],
    scalars: [[u64; 5]; 5],
}

/// Jitter type derived from cell (0,0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterType {
    /// Normal path-based content (colors 0-12, ~81%)
    Normal,
    /// Cross-type: wrong content for the path (colors 13-14, ~12.5%)
    CrossType,
    /// Personality shift: different forge identity (color 15, ~6.25%)
    PersonalityShift,
}

/// Content variant for cross-type jitter, derived from cell (0,1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ContentVariant {
    Blame,
    Commit,
    File,
    Repo,
    Issue,
    Wiki,
    Release,
    Release2,
}

impl CubeDecisionGrid {
    /// Create a decision grid from context.
    ///
    /// Same (fleet_hash, path, epoch) -> same grid -> same decisions.
    pub fn from_context(fleet_hash: &str, path: &str, epoch: u64) -> Self {
        let seed = format!("scatter:decision:{fleet_hash}:{path}:{epoch}");
        Self::from_seed_string(&seed)
    }

    /// Cross-frame mixing: create a grid seeded by TWO entities.
    ///
    /// Entity A's request gets a grid partially determined by entity B's
    /// behavioral fingerprint. Rows 0-2 come from A's seed (response-level
    /// decisions stay entity-specific). Rows 3-4 come from the mixed seed
    /// (nautilus-override rows absorb the donor's influence).
    ///
    /// This creates "mirrors" — A sees content shaped by B's maze frame.
    /// We observe A's reaction: does A mimic B's pattern? Does A abort
    /// (apoptosis)? Does A change behavior? Each reaction is a new signal.
    ///
    /// Biological parallel: MHC cross-presentation. Dendritic cells present
    /// fragments of OTHER cells' antigens to T cells. The T cell's response
    /// (activate, ignore, suppress) classifies the presented antigen.
    pub fn from_cross_frame(
        fleet_hash: &str,
        donor_hash: &str,
        path: &str,
        epoch: u64,
    ) -> Self {
        let own_seed = format!("scatter:decision:{fleet_hash}:{path}:{epoch}");
        let mix_seed = format!("scatter:crossframe:{fleet_hash}:{donor_hash}:{path}:{epoch}");

        let own = Self::from_seed_string(&own_seed);
        let mixed = Self::from_seed_string(&mix_seed);

        // Rows 0-2: entity's own decisions (jitter, content, temporal)
        // Rows 3-4: mixed with donor (nautilus-override rows)
        let mut colors = own.colors;
        let mut scalars = own.scalars;
        colors[3] = mixed.colors[3];
        colors[4] = mixed.colors[4];
        scalars[3] = mixed.scalars[3];
        scalars[4] = mixed.scalars[4];

        Self { colors, scalars }
    }

    fn from_seed_string(seed: &str) -> Self {
        let config = Config {
            grid_size: 5,
            universe_size: 100,
            palette_size: 16,
            free_cell: None,
        };
        let cube = BingoCube::from_seed(seed.as_bytes(), config)
            .expect("decision grid config is always valid");

        let mut colors = [[0u8; 5]; 5];
        let mut scalars = [[0u64; 5]; 5];
        for row in 0..5 {
            for col in 0..5 {
                colors[row][col] = cube.get_color(row, col).unwrap_or(0);
                scalars[row][col] = cube.get_scalar(row, col).unwrap_or(0);
            }
        }

        Self { colors, scalars }
    }

    /// Cell color at (row, col). Range 0-15.
    pub fn color(&self, row: usize, col: usize) -> u8 {
        self.colors[row][col]
    }

    /// Cell scalar at (row, col). Full u64 range.
    pub fn scalar(&self, row: usize, col: usize) -> u64 {
        self.scalars[row][col]
    }

    // ── Row 0: Response-level decisions ──

    /// Jitter type: Normal (81%), CrossType (12.5%), PersonalityShift (6.25%).
    ///
    /// Replaces `jitter_roll % 100 < 5/20` in scatter_generator.
    pub fn jitter_type(&self) -> JitterType {
        match self.colors[0][0] {
            15 => JitterType::PersonalityShift,
            13 | 14 => JitterType::CrossType,
            _ => JitterType::Normal,
        }
    }

    /// Content variant for cross-type jitter (8 types from 16 colors).
    ///
    /// Replaces `rng.next_u64() % 6` in gen_cross_type.
    pub fn content_variant(&self) -> ContentVariant {
        match self.colors[0][1] % 8 {
            0 => ContentVariant::Blame,
            1 => ContentVariant::Commit,
            2 => ContentVariant::File,
            3 => ContentVariant::Repo,
            4 => ContentVariant::Issue,
            5 => ContentVariant::Wiki,
            6 => ContentVariant::Release,
            _ => ContentVariant::Release2,
        }
    }

    /// Poison gate: whether to serve poison vs 404 decoy.
    ///
    /// Replaces `(path_hash % 100) < (poison_ratio * 100)` in scatter_server.
    /// Returns a value 0-15; caller compares against scaled poison_ratio.
    pub fn poison_gate(&self) -> u8 {
        self.colors[0][2]
    }

    /// Mirror probability gate.
    ///
    /// Replaces `(mirror_hash % 100) < mirror_prob` in scatter_server.
    pub fn mirror_gate(&self) -> u8 {
        self.colors[0][3]
    }

    /// Crawl link density tier (0-15).
    pub fn crawl_density(&self) -> u8 {
        self.colors[0][4]
    }

    // ── Row 1: Injection-level decisions ──

    /// Antibody chain index (0-15 variants, up from 10).
    ///
    /// Replaces `fleet_seed % 10` in inject_opsonize_antibody.
    pub fn antibody_index(&self) -> u8 {
        self.colors[1][0]
    }

    /// Header jitter variant (0-15, up from 10 server versions).
    ///
    /// Replaces `jitter_seed % 10` in generate_header_jitter.
    pub fn header_variant(&self) -> u8 {
        self.colors[1][1]
    }

    /// Antibody inject position in HTML (0=head, 1=div, 2=body, plus 3-15 new positions).
    ///
    /// Replaces `variant % 3` in inject_opsonize_antibody.
    pub fn inject_position(&self) -> u8 {
        self.colors[1][2]
    }

    /// Federation header inclusion flags (0-15).
    pub fn federation_flags(&self) -> u8 {
        self.colors[1][3]
    }

    /// Personality index (0-15, up from 10 forge identities).
    ///
    /// Replaces `(epoch_minutes + rng.next_u64()) % 10` in gen_personality_shift.
    pub fn personality_index(&self) -> u8 {
        self.colors[1][4]
    }

    // ── Row 2: Content-level decisions ──

    /// Temporal phase (0-4 from 16 colors via modular mapping).
    ///
    /// Replaces `h % 5` and the pressure_temporal_phase distribution in scatter_defense.
    pub fn temporal_phase(&self, pressure: f64) -> u8 {
        let color = self.colors[2][0];
        if pressure < 0.3 {
            color % 5
        } else if pressure < 0.6 {
            // Medium: bias toward Migrate(2) and Phase-out(3)
            match color {
                0 | 1 => 0,           // 12.5% Materialize
                2 | 3 | 4 => 1,       // 18.75% Stable
                5 | 6 | 7 | 8 => 2,   // 25% Migrate
                9 | 10 | 11 => 3,     // 18.75% Phase-out
                _ => 4,               // 25% Ghost
            }
        } else {
            // High pressure: dissolving
            match color {
                0 => 0,               // 6.25% Materialize
                1 => 1,               // 6.25% Stable
                2..=6 => 2,           // 31.25% Migrate
                7..=11 => 3,          // 31.25% Phase-out
                _ => 4,               // 25% Ghost
            }
        }
    }

    /// Lure type selection (0-15).
    pub fn lure_type(&self) -> u8 {
        self.colors[2][1]
    }

    /// Fluoro encoding layer emphasis (0-15).
    pub fn fluoro_layer(&self) -> u8 {
        self.colors[2][2]
    }

    /// Prism mix mode (0-15).
    pub fn prism_mode(&self) -> u8 {
        self.colors[2][3]
    }

    /// Amplify scale factor (0-15).
    pub fn amplify_scale(&self) -> u8 {
        self.colors[2][4]
    }

    // ── Row 3-4: Reserved for nautilus overrides ──
    // Integration point: when predict() is wired to the scatter serve path,
    // the oracle populates rows 3-4 with strategy overrides. The scatter path
    // reads nautilus_cell(3, col) for jitter type and nautilus_cell(4, col)
    // for content variant. Until then, rows 3-4 carry the deterministic hash
    // values and are not consulted by the decision logic.

    /// Nautilus override value at (row, col) in the reserved region.
    /// Row 3-4 are reserved for trained model predictions.
    #[allow(dead_code)] // Nautilus integration point — wired when predict() feeds scatter serve
    pub fn nautilus_cell(&self, row: usize, col: usize) -> u8 {
        assert!(row >= 3 && row < 5 && col < 5);
        self.colors[row][col]
    }

    /// Full scalar for hash-based decisions (when 16 colors aren't enough).
    pub fn scalar_decision(&self, row: usize, col: usize, modulus: u64) -> u64 {
        self.scalars[row][col] % modulus
    }
}

// ══════════════════════════════════════════════════════════════════════
// ScatterObservation — what we learn from each fleet interaction
// ══════════════════════════════════════════════════════════════════════

/// An observation from a scatter interaction, fed to nautilus for training.
#[derive(Debug, Clone)]
pub struct ScatterObservation {
    /// Fleet identity hash.
    #[allow(dead_code)]
    pub fleet_hash: String,
    /// Epitope flags (8-bit): which behavioral markers were detected.
    pub epitope_flags: u8,
    /// Target classification (3-bit): what the fleet is trying to extract.
    pub target_class: u8,
    /// Detector bitmap (8-bit): which detectors fired.
    pub detector_bitmap: u8,
    /// Confidence score from the classifier (0.0-1.0).
    pub confidence: f64,
    /// How deep in the chain this fleet has gone.
    pub chain_depth: u8,
    /// Whether the entity declared itself via HTTP headers (Accept-Language, Sec-Fetch).
    /// F=103,308 — the single strongest signal in the system.
    pub declared: bool,
    /// What response type we served (for correlating with effectiveness).
    pub response_type: ResponseType,
}

/// What kind of scatter response was served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ResponseType {
    Normal,
    CrossType,
    PersonalityShift,
    ViolationMirror,
    Disperse,
    Honeytoken,
    TemporalPhaseout,
    TemporalGhost,
    /// Honeycomb prism — fleet team sees chimera'd data from other teams.
    Prism,
}

// ══════════════════════════════════════════════════════════════════════
// ScatterStrategy — what nautilus recommends
// ══════════════════════════════════════════════════════════════════════

/// Nautilus-predicted scatter strategy for a given fleet cluster.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ScatterStrategy {
    /// Recommended jitter type weight adjustments.
    /// [0] = normal weight, [1] = cross-type weight, [2] = personality weight
    pub jitter_weights: [f64; 3],
    /// Preferred content variant indices (sorted by predicted effectiveness).
    pub content_preference: Vec<u8>,
    /// Recommended antibody chain variants (top-K).
    pub antibody_preference: Vec<u8>,
    /// Predicted amplify scale (0.0-1.0).
    pub amplify_factor: f64,
    /// Confidence in this prediction (0.0-1.0).
    /// Below threshold, caller falls back to CubeDecisionGrid.
    pub confidence: f64,
}

impl Default for ScatterStrategy {
    fn default() -> Self {
        Self {
            jitter_weights: [0.8, 0.125, 0.0625],
            content_preference: vec![0, 1, 2, 3, 4, 5],
            antibody_preference: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            amplify_factor: 0.5,
            confidence: 0.0,
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
// CubeOracle trait — IPC-ready boundary for any primal
// ══════════════════════════════════════════════════════════════════════

/// Trait defining how any primal consumes bingoCube for scatter decisions.
///
/// Two implementations:
/// - `InProcessOracle`: library crate, in-process (ships now)
/// - Future `IpcOracle`: JSON-RPC / tarpc client to bingoCube service
pub trait CubeOracle: Send + Sync {
    /// Create a PRNG from seed bytes (replaces XorShift64::new).
    fn roll(&self, seed: &[u8]) -> CubePrng;

    /// Create a decision grid from fleet context.
    fn decide(&self, fleet_hash: &str, path: &str, epoch: u64) -> CubeDecisionGrid;

    /// Record an observation for training.
    fn observe(&self, observation: ScatterObservation);

    /// Predict optimal strategy for fleet features.
    fn predict(&self, fleet_features: &[f64]) -> ScatterStrategy;

    /// Current generation of the nautilus shell (0 if untrained).
    fn generation(&self) -> u64;

    /// Whether the model has enough training data to make predictions.
    fn is_trained(&self) -> bool;

    /// Inject concept edges from entity_classifier topology changes.
    ///
    /// Concept edges are regions of input space where predictions fail.
    /// The nautilus shell biases new boards toward these regions during evolution.
    fn set_concept_edges(&self, edges: Vec<Vec<f64>>);

    /// Record a bloom sensor signal for training feedback.
    ///
    /// Signal rates from bloom_sensor indicate how effective scatter is
    /// at disrupting fleet behavior — high signal rates mean the fleet
    /// is persisting despite scatter, low rates mean disruption is working.
    fn record_bloom_signal(&self, fleet_hash: &str, signal_rate: f64);
}

// ══════════════════════════════════════════════════════════════════════
// InProcessOracle — library-linked implementation
// ══════════════════════════════════════════════════════════════════════

/// Observation batch size before triggering evolution.
const EVOLVE_BATCH_SIZE: usize = 100;

/// Confidence threshold below which predictions are ignored.
#[allow(dead_code)] // Nautilus integration point — used when predict() is wired to scatter serve path
const PREDICTION_CONFIDENCE_THRESHOLD: f64 = 0.3;

/// Number of targets the nautilus shell predicts:
/// [jitter_normal, jitter_cross, jitter_personality, amplify, antibody_pref]
const N_TARGETS: usize = 5;

/// Number of input features per observation:
/// [epitope_flags/255, target_class/7, detector_bitmap/255, confidence, chain_depth/255, declared]
#[allow(dead_code)] // Nautilus integration point — used when predict() is wired to scatter serve path
const N_FEATURES: usize = 6;

/// In-process bingoCube oracle backed by bingocube-core + bingocube-nautilus.
pub(crate) struct InProcessOracle {
    /// Nautilus shell for evolutionary learning.
    shell: Mutex<NautilusShell>,
    /// Buffered observations awaiting batch evolution.
    observation_buffer: Mutex<Vec<(Vec<f64>, Vec<f64>)>>,
    /// Total observations processed.
    observation_count: AtomicU64,
    /// Path for sourdough persistence.
    persist_path: Option<PathBuf>,
}

impl InProcessOracle {
    /// Create a new oracle with a fresh nautilus shell.
    pub(crate) fn new(seed: u64) -> Self {
        let config = ShellConfig {
            population_size: 12,
            n_targets: N_TARGETS,
            ..Default::default()
        };
        let id = InstanceId::new("skunkbat-scatter");
        let shell = NautilusShell::from_seed(config, id, seed)
            .expect("nautilus shell config is valid");

        Self {
            shell: Mutex::new(shell),
            observation_buffer: Mutex::new(Vec::with_capacity(EVOLVE_BATCH_SIZE)),
            observation_count: AtomicU64::new(0),
            persist_path: None,
        }
    }

    /// Create an oracle that persists its shell to disk (sourdough pattern).
    pub(crate) fn with_persistence(seed: u64, path: PathBuf) -> Self {
        let oracle = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(json) => match serde_json::from_str::<NautilusShell>(&json) {
                    Ok(shell) => {
                        tracing::info!(
                            generation = shell.generation(),
                            "🧬 nautilus shell restored from sourdough"
                        );
                        Self {
                            shell: Mutex::new(shell),
                            observation_buffer: Mutex::new(Vec::with_capacity(EVOLVE_BATCH_SIZE)),
                            observation_count: AtomicU64::new(0),
                            persist_path: Some(path),
                        }
                    }
                    Err(e) => {
                        tracing::warn!("⚠️ nautilus sourdough parse failed: {e}, starting fresh");
                        let mut o = Self::new(seed);
                        o.persist_path = Some(path);
                        o
                    }
                },
                Err(e) => {
                    tracing::warn!("⚠️ nautilus sourdough read failed: {e}, starting fresh");
                    let mut o = Self::new(seed);
                    o.persist_path = Some(path);
                    o
                }
            }
        } else {
            let mut o = Self::new(seed);
            o.persist_path = Some(path);
            o
        };
        oracle
    }

    /// Save shell to disk (sourdough).
    fn persist(&self) {
        if let Some(ref path) = self.persist_path {
            if let Ok(shell) = self.shell.lock() {
                match serde_json::to_string(&*shell) {
                    Ok(json) => {
                        if let Err(e) = std::fs::write(path, json) {
                            tracing::warn!("⚠️ nautilus persist failed: {e}");
                        }
                    }
                    Err(e) => tracing::warn!("⚠️ nautilus serialize failed: {e}"),
                }
            }
        }
    }

    /// Convert observation to feature vector for nautilus input.
    fn observation_to_features(obs: &ScatterObservation) -> Vec<f64> {
        vec![
            f64::from(obs.epitope_flags) / 255.0,
            f64::from(obs.target_class) / 7.0,
            f64::from(obs.detector_bitmap) / 255.0,
            obs.confidence,
            f64::from(obs.chain_depth) / 255.0,
            if obs.declared { 1.0 } else { 0.0 },
        ]
    }

    /// Convert observation to target vector (what we want to optimize).
    ///
    /// Targets encode: how effective was the response type at disrupting this fleet?
    /// Higher values = more effective. This is a proxy; real effectiveness comes
    /// from subsequent observations of the same fleet_hash.
    fn observation_to_targets(obs: &ScatterObservation) -> Vec<f64> {
        let base_effectiveness = match obs.response_type {
            ResponseType::ViolationMirror => 0.9,
            ResponseType::PersonalityShift => 0.7,
            ResponseType::CrossType => 0.6,
            ResponseType::TemporalGhost => 0.5,
            ResponseType::TemporalPhaseout => 0.4,
            ResponseType::Honeytoken => 0.8,
            ResponseType::Prism => 0.85,
            ResponseType::Disperse => 0.3,
            ResponseType::Normal => 0.2,
        };

        // Scale by confidence — high-confidence detections mean we know what works
        let scaled = base_effectiveness * obs.confidence.max(0.1);

        vec![
            if obs.response_type == ResponseType::Normal { scaled } else { 0.0 },
            if obs.response_type == ResponseType::CrossType { scaled } else { 0.0 },
            if obs.response_type == ResponseType::PersonalityShift { scaled } else { 0.0 },
            scaled, // amplify factor proxy
            f64::from(obs.chain_depth) / 255.0 * scaled, // antibody depth effectiveness
        ]
    }
}

impl CubeOracle for InProcessOracle {
    fn roll(&self, seed: &[u8]) -> CubePrng {
        CubePrng::from_bytes(seed)
    }

    fn decide(&self, fleet_hash: &str, path: &str, epoch: u64) -> CubeDecisionGrid {
        CubeDecisionGrid::from_context(fleet_hash, path, epoch)
    }

    fn observe(&self, observation: ScatterObservation) {
        let features = Self::observation_to_features(&observation);
        let targets = Self::observation_to_targets(&observation);

        let count = self.observation_count.fetch_add(1, Ordering::Relaxed) + 1;

        if let Ok(mut buf) = self.observation_buffer.lock() {
            buf.push((features, targets));

            if buf.len() >= EVOLVE_BATCH_SIZE {
                let batch: Vec<_> = buf.drain(..).collect();
                drop(buf);

                let inputs: Vec<ReservoirInput> = batch.iter()
                    .map(|(f, _)| ReservoirInput::Continuous(f.clone()))
                    .collect();
                let targets: Vec<Vec<f64>> = batch.into_iter()
                    .map(|(_, t)| t)
                    .collect();

                if let Ok(mut shell) = self.shell.lock() {
                    match shell.evolve_generation(&inputs, &targets) {
                        Ok(mse) => {
                            tracing::info!(
                                generation = shell.generation(),
                                mse = %format!("{mse:.6}"),
                                observations = count,
                                "🧬 nautilus evolved — scatter strategy adapting"
                            );
                        }
                        Err(e) => {
                            tracing::warn!("⚠️ nautilus evolution failed: {e}");
                        }
                    }
                }

                // Persist after evolution
                self.persist();
            }
        }
    }

    fn predict(&self, fleet_features: &[f64]) -> ScatterStrategy {
        if let Ok(shell) = self.shell.lock() {
            if shell.generation() == 0 {
                return ScatterStrategy::default();
            }

            let input = ReservoirInput::Continuous(fleet_features.to_vec());
            let raw = shell.predict(&input);

            if raw.len() < N_TARGETS {
                return ScatterStrategy::default();
            }

            // Normalize jitter weights to sum to 1
            let jitter_sum = raw[0].abs() + raw[1].abs() + raw[2].abs();
            let jitter_weights = if jitter_sum > 0.0 {
                [
                    raw[0].abs() / jitter_sum,
                    raw[1].abs() / jitter_sum,
                    raw[2].abs() / jitter_sum,
                ]
            } else {
                [0.8, 0.125, 0.0625]
            };

            // Estimate confidence from generation depth + drift
            let gen_confidence = (shell.generation() as f64 / 50.0).min(1.0);
            let drift_penalty = if shell.is_drifting() { 0.5 } else { 1.0 };
            let confidence = gen_confidence * drift_penalty;

            ScatterStrategy {
                jitter_weights,
                content_preference: vec![0, 1, 2, 3, 4, 5],
                antibody_preference: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                amplify_factor: raw[3].clamp(0.0, 1.0),
                confidence,
            }
        } else {
            ScatterStrategy::default()
        }
    }

    fn generation(&self) -> u64 {
        self.shell
            .lock()
            .map(|s| s.generation() as u64)
            .unwrap_or(0)
    }

    fn is_trained(&self) -> bool {
        self.generation() > 0
    }

    fn set_concept_edges(&self, edges: Vec<Vec<f64>>) {
        if let Ok(mut shell) = self.shell.lock() {
            let edge_count = edges.len();
            shell.set_concept_edges(edges);
            tracing::info!(
                edges = edge_count,
                generation = shell.generation(),
                "🧬 concept edges injected — nautilus will bias toward failure regions"
            );
        }
    }

    fn record_bloom_signal(&self, fleet_hash: &str, signal_rate: f64) {
        // High signal rate → fleet is persisting → current strategy is failing
        // Low signal rate → fleet is disrupted → current strategy is effective
        // We encode this as a negative observation — inverse effectiveness
        let effectiveness = (1.0 - signal_rate).clamp(0.0, 1.0);
        let features = vec![
            0.0, // epitope_flags unknown from bloom alone
            0.0, // target_class unknown
            0.0, // detector_bitmap unknown
            effectiveness,
            0.0, // chain_depth unknown
            0.0, // declared unknown from bloom alone
        ];

        if let Ok(mut buf) = self.observation_buffer.lock() {
            let targets = vec![effectiveness; N_TARGETS];
            buf.push((features, targets));
        }

        tracing::debug!(
            fleet_hash = %fleet_hash,
            signal_rate = signal_rate,
            effectiveness = effectiveness,
            "🔬 bloom signal fed to nautilus"
        );
    }
}

// ══════════════════════════════════════════════════════════════════════
// Shared oracle instance for the scatter server
// ══════════════════════════════════════════════════════════════════════

/// Thread-safe shared oracle.
pub type SharedOracle = Arc<dyn CubeOracle>;

/// Create the default in-process oracle.
pub fn create_oracle(seed: u64, persist_path: Option<&Path>) -> SharedOracle {
    match persist_path {
        Some(path) => Arc::new(InProcessOracle::with_persistence(seed, path.to_path_buf())),
        None => Arc::new(InProcessOracle::new(seed)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_grid_deterministic() {
        let a = CubeDecisionGrid::from_context("fleet_abc", "/repo/blame/main.rs", 100);
        let b = CubeDecisionGrid::from_context("fleet_abc", "/repo/blame/main.rs", 100);
        for row in 0..5 {
            for col in 0..5 {
                assert_eq!(a.color(row, col), b.color(row, col));
            }
        }
    }

    #[test]
    fn decision_grid_varies_by_fleet() {
        let a = CubeDecisionGrid::from_context("fleet_abc", "/repo/blame/main.rs", 100);
        let b = CubeDecisionGrid::from_context("fleet_xyz", "/repo/blame/main.rs", 100);
        let mut diffs = 0;
        for row in 0..5 {
            for col in 0..5 {
                if a.color(row, col) != b.color(row, col) {
                    diffs += 1;
                }
            }
        }
        assert!(diffs > 5, "different fleets should get mostly different grids");
    }

    #[test]
    fn decision_grid_varies_by_epoch() {
        let a = CubeDecisionGrid::from_context("fleet_abc", "/repo/blame/main.rs", 100);
        let b = CubeDecisionGrid::from_context("fleet_abc", "/repo/blame/main.rs", 101);
        let mut diffs = 0;
        for row in 0..5 {
            for col in 0..5 {
                if a.color(row, col) != b.color(row, col) {
                    diffs += 1;
                }
            }
        }
        assert!(diffs > 5, "different epochs should shift the grid");
    }

    #[test]
    fn jitter_type_distribution_reasonable() {
        let mut normal = 0;
        let mut cross = 0;
        let mut personality = 0;
        for i in 0..1000 {
            let grid = CubeDecisionGrid::from_context(
                &format!("fleet_{i}"), "/test", 42,
            );
            match grid.jitter_type() {
                JitterType::Normal => normal += 1,
                JitterType::CrossType => cross += 1,
                JitterType::PersonalityShift => personality += 1,
            }
        }
        // Normal should dominate, CrossType should be moderate, PersonalityShift should be rare
        assert!(normal > 700, "normal should be >70%, got {normal}/1000");
        assert!(cross > 50, "cross-type should be >5%, got {cross}/1000");
        assert!(personality > 20, "personality should be >2%, got {personality}/1000");
    }

    #[test]
    fn temporal_phase_all_values_reachable() {
        let mut seen = [false; 5];
        for i in 0..200 {
            let grid = CubeDecisionGrid::from_context(&format!("f{i}"), "/t", 1);
            let phase = grid.temporal_phase(0.1) as usize;
            assert!(phase < 5);
            seen[phase] = true;
        }
        assert!(seen.iter().all(|&s| s), "all 5 phases should be reachable");
    }

    #[test]
    fn oracle_roll_deterministic() {
        let oracle = InProcessOracle::new(42);
        let mut a = oracle.roll(b"test_seed");
        let mut b = oracle.roll(b"test_seed");
        for _ in 0..50 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn oracle_default_strategy() {
        let oracle = InProcessOracle::new(42);
        let strategy = oracle.predict(&[0.5, 0.3, 0.7, 0.8, 0.1]);
        assert_eq!(strategy.confidence, 0.0);
        assert!(!oracle.is_trained());
    }

    #[test]
    fn oracle_observe_buffers() {
        let oracle = InProcessOracle::new(42);
        for i in 0..50 {
            oracle.observe(ScatterObservation {
                fleet_hash: format!("fleet_{i}"),
                epitope_flags: (i % 256) as u8,
                target_class: (i % 7) as u8,
                detector_bitmap: (i % 256) as u8,
                confidence: (i as f64) / 50.0,
                chain_depth: (i % 10) as u8,
                declared: i % 3 == 0,
                response_type: ResponseType::Normal,
            });
        }
        // Not enough observations to trigger evolution
        assert_eq!(oracle.generation(), 0);
    }

    #[test]
    fn oracle_evolves_after_batch() {
        let oracle = InProcessOracle::new(42);
        for i in 0..EVOLVE_BATCH_SIZE {
            oracle.observe(ScatterObservation {
                fleet_hash: format!("fleet_{i}"),
                epitope_flags: (i % 256) as u8,
                target_class: (i % 7) as u8,
                detector_bitmap: (i % 256) as u8,
                confidence: (i as f64) / EVOLVE_BATCH_SIZE as f64,
                chain_depth: (i % 10) as u8,
                declared: i % 5 == 0,
                response_type: if i % 3 == 0 {
                    ResponseType::CrossType
                } else if i % 5 == 0 {
                    ResponseType::ViolationMirror
                } else {
                    ResponseType::Normal
                },
            });
        }
        assert_eq!(oracle.generation(), 1);
        assert!(oracle.is_trained());

        // Predictions should now be non-default
        let strategy = oracle.predict(&[0.5, 0.3, 0.7, 0.8, 0.1]);
        assert!(strategy.confidence > 0.0);
    }

    #[test]
    fn scalar_decision_modulus() {
        let grid = CubeDecisionGrid::from_context("test", "/path", 1);
        let val = grid.scalar_decision(3, 0, 100);
        assert!(val < 100);
    }
}

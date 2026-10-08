// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! # MazeCube — N-dimensional scatter function via BingoCube scalar field
//!
//! ## The Problem
//!
//! The scatter server currently uses enums to define content behavior:
//! - `PrismMode::Dominant | Layered | Chimera | ...` (7 variants)
//! - `temporal_phase()` returning 0-4
//! - `BackPressure` with hand-coded threshold bands
//! - Explicit match arms for every combination
//!
//! This means we're **enumerating the defense from our side** — deciding
//! "this is Chimera mode" or "this is Phase-out" — and the fleet could
//! potentially map those categories.
//!
//! ## The Solution
//!
//! Treat all dimensions as orthogonal axes in a single input space,
//! hash them through a BingoCube-style scalar field, and let the output
//! be continuous. No enums. No modes. The maze IS the function.
//!
//! ```text
//! Input vector (all normalized to [0,1]):
//!   dim 0: path         (hash of request path)
//!   dim 1: fleet_hash   (behavioral fingerprint)
//!   dim 2: time         (fractional epoch position)
//!   dim 3: pressure     (request velocity sigmoid)
//!   dim 4: surface      (honeycomb subdomain index)
//!   dim 5: confidence   (opsonize pipeline)
//!   dim 6: chain_depth  (violation ledger depth)
//!   ... extensible with no code changes
//!
//! Output (continuous, from scalar field):
//!   coherence      0.0 = Frankenstein    1.0 = clean
//!   volatility     0.0 = stable          1.0 = dissolving
//!   link_density   0.0 = no links        1.0 = trap door forest
//!   content_seed   deterministic seed for content generation
//!   redirect_prob  0.0 = serve content   1.0 = 301/404/410
//!   mirror_blend   0.0 = own data        1.0 = other team's data
//!   urgency        0.0 = calm            1.0 = "deadline 5 min"
//! ```
//!
//! ## Why This Works
//!
//! "We know time and pressure are different in physics, but we are just
//! orthogonalizing and feeding it."
//!
//! The hash function doesn't care what physical quantity each axis
//! represents. Time, pressure, identity, path — they're all just
//! dimensions in the input space. The scalar field treats them equally.
//! The behavior that emerges is a continuous function over this space,
//! not a finite set of enumerated modes.
//!
//! The fleet cannot map this function because:
//! - They control 2 of 7+ dimensions (path, surface)
//! - The other dimensions are invisible to them
//! - The output space is continuous, not categorical
//! - They have no quality signal to reverse-engineer the mapping
//!
//! ## Classification: Observational, Not Prescriptive
//!
//! Instead of us defining "Chimera" and "Dominant" modes, we observe
//! what the fleet and humans actually see and interact with. The
//! taxonomy emerges from the output, not the input. We classify by
//! observing the output distribution, not by enumerating generators.

use std::hash::{Hash, Hasher};

/// A single dimension of the maze input space.
///
/// Each dimension is an orthogonal axis. The cube doesn't care
/// what physical quantity it represents — time, pressure, identity
/// are all just numbers in [0, 1].
#[derive(Debug, Clone, Copy)]
pub struct Dimension {
    /// Normalized value in [0.0, 1.0]
    pub value: f64,
    /// Which axis this occupies (index into the input vector)
    pub axis: u8,
}

/// Well-known dimension axes.
///
/// These are semantic labels for documentation — the cube treats
/// them all identically as orthogonal axes.
pub mod axes {
    /// Request path (hashed, normalized)
    pub const PATH: u8 = 0;
    /// Behavioral fingerprint of the requesting entity
    pub const FLEET_HASH: u8 = 1;
    /// Temporal position (fractional epoch)
    pub const TIME: u8 = 2;
    /// Request velocity (sigmoid-normalized back pressure)
    pub const PRESSURE: u8 = 3;
    /// Honeycomb subdomain index (0-11 → 0.0-1.0)
    pub const SURFACE: u8 = 4;
    /// Opsonize pipeline confidence
    pub const CONFIDENCE: u8 = 5;
    /// Violation ledger chain depth
    pub const CHAIN_DEPTH: u8 = 6;
}

/// N-dimensional input to the maze.
///
/// Each request produces one of these. All values are normalized
/// to [0, 1] regardless of their original physical domain.
#[derive(Debug, Clone)]
pub struct MazeInput {
    /// Ordered dimension values. Index = axis.
    dims: Vec<f64>,
    /// Base seed for the maze (configured at startup).
    seed: u64,
}

impl MazeInput {
    /// Create a new input with the given number of dimensions, all zero.
    pub fn new(n_dims: usize, seed: u64) -> Self {
        Self {
            dims: vec![0.0; n_dims],
            seed,
        }
    }

    /// Set a dimension value. Clamps to [0, 1].
    pub fn set(&mut self, axis: u8, value: f64) {
        let idx = axis as usize;
        if idx >= self.dims.len() {
            self.dims.resize(idx + 1, 0.0);
        }
        self.dims[idx] = value.clamp(0.0, 1.0);
    }

    /// Get a dimension value.
    pub fn get(&self, axis: u8) -> f64 {
        self.dims.get(axis as usize).copied().unwrap_or(0.0)
    }

    /// Number of active dimensions.
    pub fn n_dims(&self) -> usize {
        self.dims.len()
    }
}

/// Continuous output from the maze — no enums.
///
/// Every field is a continuous value derived from the scalar field.
/// The "mode" is the entire vector, not a single category.
/// Classification of these outputs is observational (what did the
/// fleet receive?) not prescriptive (what did we send?).
#[derive(Debug, Clone)]
pub struct MazeOutput {
    /// Content coherence: how internally consistent the response is.
    /// 0.0 = Frankenstein blending (imports don't match, signatures wrong)
    /// 1.0 = clean, coherent scatter (could pass for real code)
    pub coherence: f64,

    /// Content volatility: how stable/transient the content appears.
    /// 0.0 = stable, always returns same content
    /// 1.0 = dissolving, content is "migrating" / "phasing out"
    pub volatility: f64,

    /// Cross-link density: how many trap doors per response.
    /// 0.0 = no honeycomb links
    /// 1.0 = every element is a link to another surface
    pub link_density: f64,

    /// Deterministic content seed derived from the full input vector.
    /// Same input → same seed → same content.
    pub content_seed: u64,

    /// Redirect probability: likelihood of 301/404/410 vs 200.
    /// 0.0 = always serve content
    /// 1.0 = always redirect/ghost
    pub redirect_prob: f64,

    /// Mirror blend: how much of the content comes from other teams.
    /// 0.0 = content is from this fleet hash's own profile
    /// 1.0 = content is entirely another team's data
    pub mirror_blend: f64,

    /// Urgency: how much "deadline" / "migration" language appears.
    /// 0.0 = calm, neutral language
    /// 1.0 = "migration deadline 5 minutes, 7 orgs already migrated"
    pub urgency: f64,

    /// Competitive pressure: how many "rival" references.
    /// 0.0 = no mentions of other organizations
    /// 1.0 = heavy "N other orgs accessed this in the last hour"
    pub jealousy: f64,
}

/// The maze cube — an N-dimensional scatter function.
///
/// Feed it any number of orthogonalized dimensions, get continuous
/// output that determines content behavior. No enums. No modes.
/// The function IS the maze.
///
/// Uses BLAKE3 as the scalar field hash, same as BingoCube core.
pub struct MazeCube {
    /// Base seed (configured at startup, never changes).
    seed: u64,
}

impl MazeCube {
    /// Create a new maze cube with the given base seed.
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

    /// Hash an input vector through the scalar field.
    ///
    /// This is the core function. Everything else is derived from this.
    /// The hash mixes ALL dimensions equally — the cube doesn't know
    /// or care which axis is "time" vs "pressure" vs "identity."
    fn scalar(&self, input: &MazeInput, channel: u64) -> u64 {
        let mut hasher = std::hash::DefaultHasher::new();
        self.seed.hash(&mut hasher);
        channel.hash(&mut hasher);
        for (i, &dim) in input.dims.iter().enumerate() {
            i.hash(&mut hasher);
            dim.to_bits().hash(&mut hasher);
        }
        hasher.finish()
    }

    /// SHA-256-based scalar field for cryptographic quality mixing.
    ///
    /// When we need the output to be indistinguishable from random
    /// (for content generation), use this instead of DefaultHasher.
    /// SHA-256 is already in the workspace; structurally equivalent
    /// to BingoCube core's BLAKE3 usage — just a different hash.
    fn scalar_sha256(&self, input: &MazeInput, channel: &[u8]) -> u64 {
        use sha2::{Sha256, Digest};
        let mut h = Sha256::new();
        h.update(b"MAZE_CUBE_V1");
        h.update(self.seed.to_le_bytes());
        h.update(channel);
        for (i, &dim) in input.dims.iter().enumerate() {
            h.update((i as u32).to_le_bytes());
            h.update(dim.to_bits().to_le_bytes());
        }
        let hash = h.finalize();
        u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ])
    }

    /// Normalize a scalar to [0.0, 1.0].
    fn normalize(value: u64) -> f64 {
        value as f64 / u64::MAX as f64
    }

    /// Map an input through the maze. Returns continuous output.
    ///
    /// Each output field is derived from a different "channel" of
    /// the scalar field — same input, different salt → different
    /// output per field. All channels are independent.
    pub fn map(&self, input: &MazeInput) -> MazeOutput {
        MazeOutput {
            coherence: Self::normalize(self.scalar_sha256(input, b"coherence")),
            volatility: Self::normalize(self.scalar_sha256(input, b"volatility")),
            link_density: Self::normalize(self.scalar_sha256(input, b"link_density")),
            content_seed: self.scalar_sha256(input, b"content_seed"),
            redirect_prob: Self::normalize(self.scalar_sha256(input, b"redirect")),
            mirror_blend: Self::normalize(self.scalar_sha256(input, b"mirror")),
            urgency: Self::normalize(self.scalar_sha256(input, b"urgency")),
            jealousy: Self::normalize(self.scalar_sha256(input, b"jealousy")),
        }
    }

    /// Convenience: build a MazeInput from the scatter server's live state.
    ///
    /// Normalizes each physical quantity to [0, 1]:
    /// - path: hash of path string → [0, 1]
    /// - fleet_hash: hash of behavioral fingerprint → [0, 1]
    /// - time: current time mod epoch_seconds / epoch_seconds
    /// - pressure: sigmoid-normalized request velocity (already [0, 1])
    /// - surface: subdomain index / 12
    /// - confidence: opsonize confidence (already [0, 1])
    /// - chain_depth: min(depth / 100, 1.0)
    pub fn input_from_request(
        &self,
        path: &str,
        fleet_hash: &str,
        pressure: f64,
        surface_idx: u8,
        confidence: f64,
        chain_depth: u32,
    ) -> MazeInput {
        let mut input = MazeInput::new(7, self.seed);

        // Path → normalized hash
        let path_h = self.hash_to_unit(path.as_bytes());
        input.set(axes::PATH, path_h);

        // Fleet hash → normalized hash (empty = 0.5, neutral)
        let fleet_h = if fleet_hash.is_empty() {
            0.5
        } else {
            self.hash_to_unit(fleet_hash.as_bytes())
        };
        input.set(axes::FLEET_HASH, fleet_h);

        // Time → fractional position in current hour
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let time_frac = (now % 3600) as f64 / 3600.0;
        input.set(axes::TIME, time_frac);

        // Pressure → already [0, 1] from BackPressure sigmoid
        input.set(axes::PRESSURE, pressure);

        // Surface → normalize to [0, 1]
        input.set(axes::SURFACE, surface_idx as f64 / 12.0);

        // Confidence → already [0, 1]
        input.set(axes::CONFIDENCE, confidence);

        // Chain depth → normalized (100 interactions = max)
        input.set(axes::CHAIN_DEPTH, (chain_depth as f64 / 100.0).min(1.0));

        input
    }

    /// Hash arbitrary bytes to a value in [0.0, 1.0].
    fn hash_to_unit(&self, data: &[u8]) -> f64 {
        use sha2::{Sha256, Digest};
        let mut h = Sha256::new();
        h.update(&self.seed.to_le_bytes());
        h.update(data);
        let hash = h.finalize();
        let v = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ]);
        v as f64 / u64::MAX as f64
    }
}

impl MazeOutput {
    /// Interpret the continuous output as a coarse temporal behavior.
    ///
    /// This is the OBSERVATIONAL classification — we look at what the
    /// output IS, not what enum we wanted it to be. Useful for logging
    /// and metrics, but the actual content generation uses the raw
    /// continuous values.
    pub fn observed_behavior(&self) -> &'static str {
        if self.redirect_prob > 0.8 {
            if self.volatility > 0.7 { "ghost" } else { "redirect" }
        } else if self.volatility > 0.7 {
            "migrating"
        } else if self.coherence < 0.3 {
            "chimeric"
        } else if self.mirror_blend > 0.7 {
            "mirrored"
        } else {
            "stable"
        }
    }

    /// Is this output likely to produce a non-200 response?
    pub fn is_redirect(&self) -> bool {
        self.redirect_prob > 0.6
    }

    /// Effective HTTP status derived from continuous values.
    pub fn http_status(&self) -> &'static str {
        if self.redirect_prob > 0.85 && self.volatility > 0.7 {
            "404 Not Found"
        } else if self.redirect_prob > 0.7 {
            "301 Moved Permanently"
        } else if self.redirect_prob > 0.6 {
            "410 Gone"
        } else {
            "200 OK"
        }
    }

    /// How many cross-links to inject (from continuous density).
    pub fn cross_link_count(&self) -> usize {
        (self.link_density * 12.0) as usize
    }

    /// Number of "rival organizations" to mention.
    pub fn rival_count(&self) -> usize {
        (self.jealousy * 8.0) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let cube = MazeCube::new(0xDEAD_BEEF);
        let mut input = MazeInput::new(7, cube.seed);
        input.set(axes::PATH, 0.5);
        input.set(axes::PRESSURE, 0.3);

        let out1 = cube.map(&input);
        let out2 = cube.map(&input);

        assert_eq!(out1.content_seed, out2.content_seed);
        assert!((out1.coherence - out2.coherence).abs() < f64::EPSILON);
        assert!((out1.volatility - out2.volatility).abs() < f64::EPSILON);
    }

    #[test]
    fn different_inputs_different_outputs() {
        let cube = MazeCube::new(0xDEAD_BEEF);

        let mut a = MazeInput::new(7, cube.seed);
        a.set(axes::PATH, 0.1);

        let mut b = MazeInput::new(7, cube.seed);
        b.set(axes::PATH, 0.9);

        let out_a = cube.map(&a);
        let out_b = cube.map(&b);

        assert_ne!(out_a.content_seed, out_b.content_seed);
    }

    #[test]
    fn pressure_dimension_affects_output() {
        let cube = MazeCube::new(0xCAFE_BABE);

        let mut low = MazeInput::new(7, cube.seed);
        low.set(axes::PATH, 0.5);
        low.set(axes::PRESSURE, 0.05);

        let mut high = MazeInput::new(7, cube.seed);
        high.set(axes::PATH, 0.5);
        high.set(axes::PRESSURE, 0.95);

        let out_low = cube.map(&low);
        let out_high = cube.map(&high);

        // Different pressure → different output
        // (NOT necessarily higher/lower — just different)
        assert_ne!(out_low.content_seed, out_high.content_seed);
    }

    #[test]
    fn all_outputs_bounded() {
        let cube = MazeCube::new(42);

        for i in 0..100 {
            let mut input = MazeInput::new(7, cube.seed);
            input.set(axes::PATH, i as f64 / 100.0);
            input.set(axes::PRESSURE, (i * 7 % 100) as f64 / 100.0);
            input.set(axes::TIME, (i * 13 % 100) as f64 / 100.0);

            let out = cube.map(&input);

            assert!(out.coherence >= 0.0 && out.coherence <= 1.0);
            assert!(out.volatility >= 0.0 && out.volatility <= 1.0);
            assert!(out.link_density >= 0.0 && out.link_density <= 1.0);
            assert!(out.redirect_prob >= 0.0 && out.redirect_prob <= 1.0);
            assert!(out.mirror_blend >= 0.0 && out.mirror_blend <= 1.0);
            assert!(out.urgency >= 0.0 && out.urgency <= 1.0);
            assert!(out.jealousy >= 0.0 && out.jealousy <= 1.0);
        }
    }

    #[test]
    fn observed_behavior_labels() {
        let out = MazeOutput {
            coherence: 0.8, volatility: 0.2, link_density: 0.5,
            content_seed: 0, redirect_prob: 0.1, mirror_blend: 0.1,
            urgency: 0.3, jealousy: 0.2,
        };
        assert_eq!(out.observed_behavior(), "stable");

        let ghost = MazeOutput {
            redirect_prob: 0.9, volatility: 0.9, ..out.clone()
        };
        assert_eq!(ghost.observed_behavior(), "ghost");

        let chimeric = MazeOutput {
            coherence: 0.1, redirect_prob: 0.2, volatility: 0.3, ..out.clone()
        };
        assert_eq!(chimeric.observed_behavior(), "chimeric");

        let mirrored = MazeOutput {
            mirror_blend: 0.9, redirect_prob: 0.2, volatility: 0.3,
            coherence: 0.5, ..out
        };
        assert_eq!(mirrored.observed_behavior(), "mirrored");
    }

    #[test]
    fn input_from_request_normalizes() {
        let cube = MazeCube::new(0xBEEF);
        let input = cube.input_from_request(
            "/org/repo/commit/abc123",
            "c3459931a321af46",
            0.6,   // pressure
            3,     // surface idx
            0.75,  // confidence
            5,     // chain depth
        );

        assert_eq!(input.n_dims(), 7);

        // All dimensions should be in [0, 1]
        for i in 0..7 {
            let v = input.get(i as u8);
            assert!(v >= 0.0 && v <= 1.0, "dim {i} = {v} out of bounds");
        }

        // Surface should be 3/12 = 0.25
        assert!((input.get(axes::SURFACE) - 0.25).abs() < 0.01);

        // Pressure should be exactly 0.6
        assert!((input.get(axes::PRESSURE) - 0.6).abs() < f64::EPSILON);

        // Chain depth should be 5/100 = 0.05
        assert!((input.get(axes::CHAIN_DEPTH) - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn dimensions_are_truly_orthogonal() {
        let cube = MazeCube::new(0x1234);

        // Fix all dims except one, vary that one → output changes
        let dims_to_test = [
            axes::PATH, axes::FLEET_HASH, axes::TIME,
            axes::PRESSURE, axes::SURFACE, axes::CONFIDENCE,
            axes::CHAIN_DEPTH,
        ];

        for &vary_axis in &dims_to_test {
            let mut base = MazeInput::new(7, cube.seed);
            for &a in &dims_to_test {
                base.set(a, 0.5);
            }

            // Set the varying axis to two different values
            let mut low = base.clone();
            low.set(vary_axis, 0.1);
            let mut high = base;
            high.set(vary_axis, 0.9);

            let out_low = cube.map(&low);
            let out_high = cube.map(&high);

            assert_ne!(
                out_low.content_seed, out_high.content_seed,
                "varying axis {} should change output",
                vary_axis
            );
        }
    }

    #[test]
    fn extensible_dimensions() {
        let cube = MazeCube::new(42);

        // 7 dimensions
        let mut narrow = MazeInput::new(7, cube.seed);
        narrow.set(0, 0.5);

        // 10 dimensions — extra axes are valid
        let mut wide = MazeInput::new(10, cube.seed);
        wide.set(0, 0.5);
        wide.set(7, 0.3); // new axis 7
        wide.set(8, 0.7); // new axis 8
        wide.set(9, 0.1); // new axis 9

        let out_narrow = cube.map(&narrow);
        let out_wide = cube.map(&wide);

        // Different because wide has extra non-zero dimensions
        assert_ne!(out_narrow.content_seed, out_wide.content_seed);
    }
}

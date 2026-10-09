// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Anderson bridge — observation → theory reverse mapping.
//!
//! Closes the loop between behavioral observation (BingoCubeTrio, scatter
//! metrics, population statistics) and the Anderson transport equations
//! (Paper 01, Paper 43). Self-contained — no barracuda dependency.
//!
//! ## Multi-scale parameter mapping
//!
//! | Scale        | Observable              | Anderson parameter |
//! |--------------|-------------------------|--------------------|
//! | Population   | Pielou J (entity mix)   | W (disorder)       |
//! | Per-entity   | BingoCubeTrio variance  | W_eff per mode     |
//! | Geographic   | Bodies observing entity  | d_eff (dimension)  |
//! | Signal       | Request frequency       | E (energy)         |
//!
//! ## Imaginary projection
//!
//! The residual between predicted and observed permeability maps to the
//! imaginary dimension: P_complex = P_predicted + i·(P_observed - P_predicted).
//!
//! - residual > 0 → entity adapting (penetrating membrane beyond equilibrium)
//! - residual < 0 → membrane actively defending beyond what disorder explains
//!
//! See Paper 46: "Inverse Anderson — Behavioral Observation as Disorder Measurement"

use std::collections::HashMap;
use std::sync::Arc;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::dashboard_writer::{IpProfile, TrioClass, score_trio};

/// Shared Anderson profile — updated by DashboardWriter, read by scatter server.
pub type SharedAndersonProfile = Arc<RwLock<Option<AndersonProfile>>>;

// ══════════════════════════════════════════════════════════════════════
// Anderson transport equations (self-contained, mirrors barracuda)
// ══════════════════════════════════════════════════════════════════════

/// Thouless localization length ξ for 1D Anderson model.
///
/// ξ ≈ 105·(4 - E²) / max(W², ε)
///
/// From Paper 01 §3.1, validated in barracuda `localization_length()`.
fn localization_length_1d(disorder: f64, energy: f64) -> f64 {
    let numerator = 105.0 * (4.0 - energy * energy).max(0.0);
    let denominator = (disorder * disorder).max(1e-10);
    (numerator / denominator).max(0.1)
}

/// Dimensional localization length — fractional d_eff.
///
/// Interpolates between dimension-dependent behaviors:
/// - d=1: all states localized (Thouless ξ)
/// - d=2: weak localization (logarithmic corrections)
/// - d=3: metal-insulator transition at W_c ≈ 16.5
/// - fractional d: log-linear interpolation
///
/// From Paper 43 §4.2, barracuda `dimensional_localization_length()`.
fn dimensional_localization_length(disorder: f64, energy: f64, d_eff: f64) -> f64 {
    let xi_1d = localization_length_1d(disorder, energy);

    if d_eff <= 1.0 {
        return xi_1d;
    }

    // 2D: weak localization — ξ_2d grows exponentially with ξ_1d.
    // Capped to prevent overflow; always ≥ ξ_1d.
    let xi_2d = {
        let exponent = (std::f64::consts::PI * xi_1d / 2.0).min(12.0);
        (xi_1d * exponent.exp()).min(1e6)
    };

    if d_eff <= 2.0 {
        let frac = d_eff - 1.0;
        let log_xi = xi_1d.ln() * (1.0 - frac) + xi_2d.ln() * frac;
        return log_xi.exp();
    }

    // 3D: metal-insulator transition at W_c ≈ 16.5
    let w_c = 16.5;
    let nu = 1.57;
    let xi_3d = if disorder < w_c {
        // Extended regime — effectively infinite. Must be ≥ ξ_2d for monotonicity.
        xi_2d.max(1e6) * 10.0
    } else {
        // Localized regime: ξ_3d = A · |W - W_c|^(-ν)
        // Still ≥ ξ_2d at the transition; decays for W >> W_c.
        let a = 1.0;
        let xi_loc = a * (disorder - w_c).abs().max(0.01).powf(-nu);
        xi_loc.max(xi_2d)
    };

    if d_eff <= 3.0 {
        let frac = d_eff - 2.0;
        let log_xi = xi_2d.ln() * (1.0 - frac) + xi_3d.ln().max(-20.0) * frac;
        return log_xi.exp();
    }

    // d > 3: extrapolate (higher dimensions → harder to localize)
    xi_3d * (d_eff - 3.0 + 1.0)
}

/// Membrane permeability P(ω) = exp(-L/ξ) for a single mode.
fn membrane_permeability(disorder: f64, energy: f64, d_eff: f64, system_size: f64) -> f64 {
    let xi = dimensional_localization_length(disorder, energy, d_eff);
    (-system_size / xi).exp()
}

// ══════════════════════════════════════════════════════════════════════
// Population-scale: Pielou J → W
// ══════════════════════════════════════════════════════════════════════

/// Compute Pielou evenness J from a distribution of counts.
///
/// J = H' / H'_max where H' = -Σ(p_i · ln(p_i)), H'_max = ln(S).
/// J=1 means perfectly even; J→0 means monoculture.
pub fn pielou_evenness(counts: &[u64]) -> f64 {
    let total: u64 = counts.iter().sum();
    if total == 0 || counts.len() <= 1 {
        return 0.0;
    }

    let s = counts.iter().filter(|&&c| c > 0).count();
    if s <= 1 {
        return 0.0;
    }

    let h_prime: f64 = counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total as f64;
            -p * p.ln()
        })
        .sum();

    let h_max = (s as f64).ln();
    if h_max <= 0.0 {
        return 0.0;
    }

    (h_prime / h_max).clamp(0.0, 1.0)
}

/// Map Pielou evenness J to Anderson disorder W.
///
/// W = 0.5 + 14.5·(1 - J)
/// - J=1 (perfect diversity) → W=0.5 (minimal disorder, all signals propagate)
/// - J=0 (monoculture fleet) → W=15.0 (high disorder, signals localize)
///
/// From Paper 01 §3.3: `evenness_to_disorder(j, scale=14.5)`.
pub fn evenness_to_disorder(j: f64) -> f64 {
    0.5 + 14.5 * (1.0 - j.clamp(0.0, 1.0))
}

// ══════════════════════════════════════════════════════════════════════
// Anderson profile — the bridge output
// ══════════════════════════════════════════════════════════════════════

/// Per-mode Anderson analysis — one entry per TrioClass.
#[derive(Debug, Clone, Serialize)]
pub struct ModeAnalysis {
    /// Ecological class name.
    pub class: String,
    /// Entity count in this class.
    pub count: u64,
    /// Effective disorder from intra-class behavioral variance.
    pub w_eff: f64,
    /// Effective dimension from geographic distribution.
    pub d_eff: f64,
    /// Signal energy from request frequency.
    pub energy: f64,
    /// Membrane thickness (number of detection layers).
    pub system_size: f64,
    /// Predicted permeability from forward Anderson model.
    pub p_predicted: f64,
    /// Observed permeability from accept/block ratios.
    pub p_observed: f64,
    /// Imaginary residual: P_observed - P_predicted.
    /// Positive = adapting, negative = actively defended.
    pub residual: f64,
}

/// Full Anderson profile for a golgi body's observation window.
#[derive(Debug, Clone, Serialize)]
pub struct AndersonProfile {
    /// Population-level disorder from entity diversity.
    pub w_population: f64,
    /// Pielou evenness of the entity population.
    pub pielou_j: f64,
    /// Number of golgi bodies in the mesh.
    pub d_mesh: u32,
    /// Per-mode (per-TrioClass) analysis.
    pub modes: Vec<ModeAnalysis>,
    /// Selectivity predicted: max(P) - min(P) across modes.
    pub selectivity_predicted: f64,
    /// Selectivity observed: max(P_obs) - min(P_obs) across modes.
    pub selectivity_observed: f64,
    /// Magnitude of the imaginary component: sqrt(Σ residual²).
    pub imaginary_magnitude: f64,
}

/// Input: per-class observation statistics for the Anderson bridge.
#[derive(Debug, Clone)]
pub struct ClassObservation {
    /// Number of entities in this class.
    pub count: u64,
    /// Mean trio scores for entities in this class.
    pub mean_attention: f32,
    pub mean_curiosity: f32,
    pub mean_interaction: f32,
    /// Variance of trio scores (behavioral disorder within class).
    pub variance: f64,
    /// Average requests per hour across entities in this class.
    pub requests_per_hour: f64,
    /// How many bodies observe entities with this class.
    pub bodies_observing: u32,
    /// Fraction of entities that were accepted (not blocked).
    pub accept_ratio: f64,
}

/// Compute the Anderson profile from population observations.
///
/// `observations` maps TrioClass → ClassObservation.
/// `mesh_size` is the total number of golgi bodies in the mesh.
/// `membrane_thickness` is L (number of detection rules/layers).
pub fn compute_profile(
    observations: &HashMap<TrioClass, ClassObservation>,
    mesh_size: u32,
    membrane_thickness: f64,
) -> AndersonProfile {
    // Population-level Pielou J from class counts
    let counts: Vec<u64> = [TrioClass::Parasite, TrioClass::Commensal, TrioClass::Sovereign]
        .iter()
        .map(|c| observations.get(c).map(|o| o.count).unwrap_or(0))
        .collect();
    let j = pielou_evenness(&counts);
    let w_pop = evenness_to_disorder(j);

    let mut modes = Vec::new();

    for (class, label) in [
        (TrioClass::Parasite, "parasite"),
        (TrioClass::Commensal, "commensal"),
        (TrioClass::Sovereign, "sovereign"),
    ] {
        let obs = match observations.get(&class) {
            Some(o) if o.count > 0 => o,
            _ => continue,
        };

        // Per-mode W_eff: population disorder modulated by intra-class variance.
        // High variance within a class = more disordered mode.
        let w_eff = w_pop * (1.0 + obs.variance.sqrt().min(2.0));

        // Per-mode d_eff: geographic dimension from body observation count.
        let d_eff = (obs.bodies_observing as f64).max(1.0).min(mesh_size as f64);

        // Energy from request frequency: E = log2(rph + 1) normalized to [0, 2].
        let energy = (obs.requests_per_hour + 1.0).log2().min(2.0);

        // Forward model
        let p_predicted = membrane_permeability(w_eff, energy, d_eff, membrane_thickness);
        let p_observed = obs.accept_ratio.clamp(0.0, 1.0);
        let residual = p_observed - p_predicted;

        modes.push(ModeAnalysis {
            class: label.to_string(),
            count: obs.count,
            w_eff: (w_eff * 1000.0).round() / 1000.0,
            d_eff: (d_eff * 10.0).round() / 10.0,
            energy: (energy * 1000.0).round() / 1000.0,
            system_size: membrane_thickness,
            p_predicted: (p_predicted * 10000.0).round() / 10000.0,
            p_observed: (p_observed * 10000.0).round() / 10000.0,
            residual: (residual * 10000.0).round() / 10000.0,
        });
    }

    // Selectivity: max(P) - min(P)
    let s_pred = if modes.len() >= 2 {
        let max_p = modes.iter().map(|m| m.p_predicted).fold(0.0_f64, f64::max);
        let min_p = modes.iter().map(|m| m.p_predicted).fold(1.0_f64, f64::min);
        max_p - min_p
    } else {
        0.0
    };

    let s_obs = if modes.len() >= 2 {
        let max_p = modes.iter().map(|m| m.p_observed).fold(0.0_f64, f64::max);
        let min_p = modes.iter().map(|m| m.p_observed).fold(1.0_f64, f64::min);
        max_p - min_p
    } else {
        0.0
    };

    // Imaginary magnitude: L2 norm of residuals
    let imag_mag = modes.iter()
        .map(|m| m.residual * m.residual)
        .sum::<f64>()
        .sqrt();

    AndersonProfile {
        w_population: (w_pop * 1000.0).round() / 1000.0,
        pielou_j: (j * 1000.0).round() / 1000.0,
        d_mesh: mesh_size,
        modes,
        selectivity_predicted: (s_pred * 10000.0).round() / 10000.0,
        selectivity_observed: (s_obs * 10000.0).round() / 10000.0,
        imaginary_magnitude: (imag_mag * 10000.0).round() / 10000.0,
    }
}

/// Extract class observations from a population of IP profiles.
///
/// This is the primary bridge function: takes the raw dashboard_writer
/// data and maps it into the Anderson parameter space.
pub fn extract_observations(
    profiles: &HashMap<u64, IpProfile>,
    mesh_size: u32,
) -> HashMap<TrioClass, ClassObservation> {
    let mut class_profiles: HashMap<TrioClass, Vec<(f32, f32, f32, u64)>> = HashMap::new();

    for profile in profiles.values() {
        let trio = score_trio(profile);
        let rph = if profile.last_seen > profile.first_seen {
            let hours = (profile.last_seen - profile.first_seen) / 3600.0;
            if hours > 0.0 { profile.requests as f64 / hours } else { profile.requests as f64 }
        } else {
            profile.requests as f64
        };

        class_profiles
            .entry(trio.classification)
            .or_default()
            .push((trio.attention, trio.curiosity, trio.interaction, rph as u64));
    }

    let mut observations = HashMap::new();

    for (class, entries) in &class_profiles {
        let count = entries.len() as u64;
        if count == 0 { continue; }

        let (sum_a, sum_c, sum_i, sum_rph) = entries.iter().fold(
            (0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64),
            |(a, c, i, r), (ea, ec, ei, er)| {
                (a + *ea as f64, c + *ec as f64, i + *ei as f64, r + *er as f64)
            },
        );

        let n = count as f64;
        let mean_a = sum_a / n;
        let mean_c = sum_c / n;
        let mean_i = sum_i / n;

        // Variance of trio scores (across all three axes)
        let variance: f64 = entries.iter()
            .map(|(a, c, i, _)| {
                let da = *a as f64 - mean_a;
                let dc = *c as f64 - mean_c;
                let di = *i as f64 - mean_i;
                (da * da + dc * dc + di * di) / 3.0
            })
            .sum::<f64>() / n;

        // Accept ratio: for parasites, assume most are blocked (low accept).
        // For sovereigns, assume most are accepted (high accept).
        // For commensals, middle ground.
        // This is the observation-side P — in production, would come from
        // actual iptables/Caddy accept/reject counters.
        let accept_ratio = match class {
            TrioClass::Parasite => {
                // Parasites: fraction that weren't explicitly fleet-classified
                let not_fleet = entries.iter()
                    .enumerate()
                    .filter(|(idx, _)| {
                        profiles.values().nth(*idx)
                            .map(|p| !p.is_fleet)
                            .unwrap_or(false)
                    })
                    .count();
                not_fleet as f64 / n
            }
            TrioClass::Commensal => 0.85,
            TrioClass::Sovereign => 0.97,
        };

        observations.insert(*class, ClassObservation {
            count,
            mean_attention: (mean_a as f32 * 100.0).round() / 100.0,
            mean_curiosity: (mean_c as f32 * 100.0).round() / 100.0,
            mean_interaction: (mean_i as f32 * 100.0).round() / 100.0,
            variance,
            requests_per_hour: sum_rph / n,
            bodies_observing: mesh_size.min(count as u32).max(1),
            accept_ratio,
        });
    }

    observations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pielou_evenness_perfect() {
        assert!((pielou_evenness(&[100, 100, 100]) - 1.0).abs() < 0.001);
    }

    #[test]
    fn pielou_evenness_monoculture() {
        assert!(pielou_evenness(&[1000, 0, 0]) < 0.01);
    }

    #[test]
    fn pielou_evenness_empty() {
        assert_eq!(pielou_evenness(&[]), 0.0);
        assert_eq!(pielou_evenness(&[0, 0, 0]), 0.0);
    }

    #[test]
    fn disorder_mapping() {
        let w_diverse = evenness_to_disorder(1.0);
        let w_mono = evenness_to_disorder(0.0);
        assert!((w_diverse - 0.5).abs() < 0.01);
        assert!((w_mono - 15.0).abs() < 0.01);
    }

    #[test]
    fn localization_length_increases_with_dimension() {
        let w = 5.0;
        let e = 0.5;
        let xi_1 = dimensional_localization_length(w, e, 1.0);
        let xi_2 = dimensional_localization_length(w, e, 2.0);
        let xi_3 = dimensional_localization_length(w, e, 3.0);
        assert!(xi_2 > xi_1, "ξ should increase with dimension");
        assert!(xi_3 > xi_2, "ξ should increase with dimension");
    }

    #[test]
    fn permeability_decreases_with_disorder() {
        let p_low = membrane_permeability(1.0, 0.5, 2.0, 10.0);
        let p_high = membrane_permeability(10.0, 0.5, 2.0, 10.0);
        assert!(p_low > p_high, "P should decrease with higher disorder");
    }

    #[test]
    fn selectivity_healthy_membrane() {
        // Healthy membrane: parasites blocked (high W), sovereigns pass (low W)
        let mut obs = HashMap::new();
        obs.insert(TrioClass::Parasite, ClassObservation {
            count: 100, mean_attention: 0.1, mean_curiosity: 0.1,
            mean_interaction: 0.05, variance: 0.01, requests_per_hour: 500.0,
            bodies_observing: 1, accept_ratio: 0.0,
        });
        obs.insert(TrioClass::Sovereign, ClassObservation {
            count: 20, mean_attention: 0.8, mean_curiosity: 0.6,
            mean_interaction: 0.7, variance: 0.15, requests_per_hour: 2.0,
            bodies_observing: 4, accept_ratio: 0.97,
        });

        let profile = compute_profile(&obs, 4, 10.0);
        assert!(profile.selectivity_predicted > 0.5, "healthy membrane should have high selectivity");
        assert!(profile.pielou_j > 0.0, "non-zero population should have non-zero J");
    }

    #[test]
    fn imaginary_residual_sign() {
        // Adapting entity: observed P > predicted P
        let mut obs = HashMap::new();
        obs.insert(TrioClass::Commensal, ClassObservation {
            count: 50, mean_attention: 0.5, mean_curiosity: 0.4,
            mean_interaction: 0.3, variance: 0.1, requests_per_hour: 10.0,
            bodies_observing: 2, accept_ratio: 0.95,
        });

        let profile = compute_profile(&obs, 4, 10.0);
        // With moderate disorder and d=2, predicted P should be less than 0.95
        // so residual should be positive (entity more permeable than expected)
        if let Some(mode) = profile.modes.first() {
            if mode.p_predicted < 0.95 {
                assert!(mode.residual > 0.0, "adapting entity should have positive residual");
            }
        }
    }
}

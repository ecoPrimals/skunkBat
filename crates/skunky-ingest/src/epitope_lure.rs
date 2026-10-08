// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 ecoPrimals
//
// Epitope Lure — Ally-Signal Honeypot & Positive Antibody Generator
//
// The fleet is blind — they get scatter content — but they FIND things.
// Their request patterns reveal what signals they recognize across codebases.
// This module exploits that:
//
// 1. LURE: Generate synthetic "ally signals" — code patterns that look like
//    the kind of projects the fleet is trained to find. They come to eat it.
//
// 2. OBSERVE: Track which lure patterns get the most attention. This reveals
//    the fleet's recognition epitopes — what behavioral signatures their
//    crawlers are trained to match.
//
// 3. ANTIBODY: From the recognition epitopes, generate positive antibodies —
//    patterns that OTHER codebases can deploy to either:
//    a) Attract fleet attention away from real targets (decoy)
//    b) Inoculate against the fleet's recognition patterns (vaccine)
//
// The biological analogy:
//   - Lure = attenuated pathogen (weakened bait)
//   - Fleet crawl = immune challenge (they show what they recognize)
//   - Recognition epitope = antigen (what triggers their scraper)
//   - Positive antibody = vaccine (protection for allies)
//
// Data flow:
//   1. Fleet backtrace reveals target patterns (repos, file types, paths)
//   2. Lure generator creates synthetic content matching those patterns
//   3. Fleet crawls the lure, revealing which patterns they prioritize
//   4. Recognition analysis builds a model of fleet targeting criteria
//   5. Antibody generator creates protective patterns for allies
//   6. Published via epitope feed for mesh-wide distribution

use crate::scatter_rng::CubePrng;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// What the fleet hunts — learned from their request patterns.
///
/// These are the "ally signals" that attract fleet attention.
/// Derived from backtrace analysis of actual fleet crawl patterns.
#[derive(Debug, Clone)]
pub struct FleetTargetProfile {
    /// Repos they hit hardest (by request count)
    pub target_repos: Vec<(String, u32)>,
    /// File types they prioritize (.md, .rs, .toml, .sh)
    pub file_type_priority: Vec<(String, u32)>,
    /// Path patterns they follow (/blame/, /src/, /commit/)
    pub path_patterns: Vec<(String, u32)>,
    /// Directory patterns they drill into (crates/, docs/, showcase/)
    pub directory_targets: Vec<(String, u32)>,
    /// Specific files they blame (attribution targets)
    pub blame_targets: Vec<(String, u32)>,
    /// When this profile was last updated
    pub last_updated: u64,
}

/// A synthetic lure — bait content designed to attract fleet attention.
#[derive(Debug, Clone)]
pub struct LureSignal {
    /// Unique ID for this lure
    pub lure_id: String,
    /// The path pattern this lure mimics (e.g. "/ally-project/blame/commit/.../README.md")
    pub path_pattern: String,
    /// What kind of content it mimics
    pub content_type: LureContentType,
    /// How many times this lure has been hit
    pub hit_count: u64,
    /// Fleet hashes that have hit this lure
    pub fleet_hashes_attracted: Vec<String>,
    /// When this lure was deployed
    pub deployed_epoch: u64,
}

/// Types of lure content we can generate.
#[derive(Debug, Clone)]
pub enum LureContentType {
    /// Fake README with project structure signals
    ReadmeSignal,
    /// Fake Rust source with module patterns
    RustSourceSignal,
    /// Fake Cargo.toml with dependency signals
    CargoTomlSignal,
    /// Fake documentation with architecture patterns
    DocSignal,
    /// Fake git blame output with author attribution
    BlameSignal,
    /// Fake commit history
    CommitSignal,
}

/// A recognition epitope — what the fleet's crawlers are trained to find.
///
/// When certain lure patterns get consistently higher hit rates, that
/// reveals the fleet's targeting criteria. These become recognition epitopes.
#[derive(Debug, Clone)]
pub struct RecognitionEpitope {
    /// What pattern triggers fleet attention
    pub trigger_pattern: String,
    /// Confidence that this is a real targeting criterion (0.0-1.0)
    pub confidence: f64,
    /// How many distinct fleet hashes responded to this pattern
    pub responder_count: u32,
    /// Hit rate relative to baseline (>1.0 = attracts more than average)
    pub attraction_ratio: f64,
    /// What kind of targeting this represents
    pub targeting_class: TargetingClass,
}

/// Classification of what the fleet is targeting.
#[derive(Debug, Clone)]
pub enum TargetingClass {
    /// Attribution extraction — they want to know WHO wrote code
    Attribution,
    /// Code extraction — they want the actual source code
    CodeExtraction,
    /// Architecture discovery — they want to understand system design
    ArchitectureRecon,
    /// Dependency mapping — they want to know what libraries are used
    DependencyMapping,
    /// Configuration extraction — they want operational details
    ConfigExtraction,
}

/// A positive antibody — protection pattern for ally codebases.
///
/// Generated from recognition epitopes. Allies can deploy these to either:
/// - Attract fleet attention (decoy antibody)
/// - Disguise their codebase to not match fleet targeting (vaccine antibody)
#[derive(Debug, Clone)]
pub struct PositiveAntibody {
    /// The recognition epitope this antibody targets
    pub target_epitope: String,
    /// Whether this is a decoy (attract) or vaccine (disguise)
    pub antibody_type: AntibodyType,
    /// The actual content pattern to deploy
    pub payload: String,
    /// Confidence in effectiveness (0.0-1.0)
    pub confidence: f64,
    /// When this antibody was generated
    pub generated_epoch: u64,
}

#[derive(Debug, Clone)]
pub enum AntibodyType {
    /// Decoy: attracts fleet attention away from real targets
    Decoy,
    /// Vaccine: makes a codebase not match fleet targeting patterns
    Vaccine,
    /// Chimera: contaminates fleet identity so OTHER fleets think
    /// this fleet is US. When a fleet ingests chimera content, it
    /// carries our behavioral DNA into their data pipeline. Other
    /// fleets that scrape THEIR results see OUR epitopes — and
    /// start crawling the wrong target, creating a feedback loop.
    ///
    /// Biological analogy: a retrovirus that inserts its genome
    /// into the host cell's DNA. The fleet becomes a carrier of
    /// our immune signature. Other fleets' classifiers can't
    /// distinguish the real target from the chimera carrier.
    Chimera,
}

/// The lure engine — manages bait deployment and recognition learning.
#[derive(Debug)]
pub struct LureEngine {
    /// Active lures and their hit tracking
    lures: Arc<RwLock<HashMap<String, LureSignal>>>,
    /// Learned recognition epitopes
    recognition: Arc<RwLock<Vec<RecognitionEpitope>>>,
    /// Fleet target profile (from backtrace analysis)
    target_profile: Arc<RwLock<FleetTargetProfile>>,
    /// Generated antibodies
    antibodies: Arc<RwLock<Vec<PositiveAntibody>>>,
}

impl LureEngine {
    pub fn new() -> Self {
        Self {
            lures: Arc::new(RwLock::new(HashMap::new())),
            recognition: Arc::new(RwLock::new(Vec::new())),
            target_profile: Arc::new(RwLock::new(FleetTargetProfile {
                target_repos: Vec::new(),
                file_type_priority: Vec::new(),
                path_patterns: Vec::new(),
                directory_targets: Vec::new(),
                blame_targets: Vec::new(),
                last_updated: 0,
            })),
            antibodies: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Update the fleet target profile from backtrace analysis.
    ///
    /// Called periodically with data from the access log analysis.
    pub async fn update_target_profile(&self, profile: FleetTargetProfile) {
        let mut tp = self.target_profile.write().await;
        *tp = profile;
    }

    /// Generate lure content based on the fleet's target profile.
    ///
    /// Returns synthetic content that mimics what the fleet is hunting.
    /// The content is designed to be attractive to crawlers but clearly
    /// distinguishable from real code (for legal clarity).
    pub async fn generate_lure_content(
        &self,
        path: &str,
        rng_seed: u64,
    ) -> String {
        let profile = self.target_profile.read().await;
        let mut rng = CubePrng::new(rng_seed);

        // Determine what kind of lure to generate based on path
        if path.contains("/blame/") {
            self.generate_blame_lure(&profile, &mut rng)
        } else if path.ends_with(".rs") {
            self.generate_rust_lure(&profile, &mut rng)
        } else if path.ends_with("Cargo.toml") {
            self.generate_cargo_lure(&mut rng)
        } else if path.ends_with(".md") || path.contains("README") {
            self.generate_readme_lure(&profile, &mut rng)
        } else if path.ends_with(".toml") || path.ends_with(".yaml") || path.ends_with(".yml") {
            self.generate_config_lure(&mut rng)
        } else {
            self.generate_generic_lure(&profile, &mut rng)
        }
    }

    /// Record a fleet hit on a lure path.
    pub async fn record_hit(&self, path: &str, fleet_hash: &str) {
        let mut lures = self.lures.write().await;
        let entry = lures.entry(path.to_string()).or_insert_with(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            LureSignal {
                lure_id: format!("lure-{:016x}", now),
                path_pattern: path.to_string(),
                content_type: if path.contains("/blame/") {
                    LureContentType::BlameSignal
                } else if path.ends_with(".rs") {
                    LureContentType::RustSourceSignal
                } else {
                    LureContentType::ReadmeSignal
                },
                hit_count: 0,
                fleet_hashes_attracted: Vec::new(),
                deployed_epoch: now,
            }
        });

        entry.hit_count += 1;
        if !entry.fleet_hashes_attracted.contains(&fleet_hash.to_string()) {
            entry.fleet_hashes_attracted.push(fleet_hash.to_string());
        }
    }

    /// Analyze lure hits to discover recognition epitopes.
    ///
    /// Lure paths that get disproportionate attention reveal what the
    /// fleet's crawlers are trained to find.
    pub async fn analyze_recognition(&self) -> Vec<RecognitionEpitope> {
        let lures = self.lures.read().await;

        if lures.is_empty() {
            return Vec::new();
        }

        let total_hits: u64 = lures.values().map(|l| l.hit_count).sum();
        let avg_hits = total_hits as f64 / lures.len() as f64;

        let mut epitopes = Vec::new();

        for (path, lure) in lures.iter() {
            if lure.hit_count < 2 {
                continue;
            }

            let attraction = lure.hit_count as f64 / avg_hits.max(1.0);

            let targeting_class = if path.contains("/blame/") {
                TargetingClass::Attribution
            } else if path.ends_with(".rs") || path.ends_with(".py") {
                TargetingClass::CodeExtraction
            } else if path.contains("SPEC") || path.contains("ARCHITECTURE") || path.contains("DESIGN") {
                TargetingClass::ArchitectureRecon
            } else if path.ends_with("Cargo.toml") || path.ends_with("package.json") {
                TargetingClass::DependencyMapping
            } else if path.contains("config") || path.contains(".env") || path.ends_with(".toml") {
                TargetingClass::ConfigExtraction
            } else {
                TargetingClass::CodeExtraction
            };

            let confidence = (attraction / 5.0).min(1.0) *
                (lure.fleet_hashes_attracted.len() as f64 / 3.0).min(1.0);

            epitopes.push(RecognitionEpitope {
                trigger_pattern: path.clone(),
                confidence,
                responder_count: lure.fleet_hashes_attracted.len() as u32,
                attraction_ratio: attraction,
                targeting_class,
            });
        }

        epitopes.sort_by(|a, b| b.attraction_ratio.partial_cmp(&a.attraction_ratio).unwrap_or(std::cmp::Ordering::Equal));

        // Store
        let mut recognition = self.recognition.write().await;
        *recognition = epitopes.clone();

        epitopes
    }

    /// Generate positive antibodies from recognition epitopes.
    ///
    /// Two types:
    /// - **Decoy**: Content that ATTRACTS fleet attention. Deploy on a VPS
    ///   to draw fleet crawlers away from real targets.
    /// - **Vaccine**: Content patterns that DISGUISE a codebase so it doesn't
    ///   match fleet targeting criteria.
    pub async fn generate_antibodies(&self) -> Vec<PositiveAntibody> {
        let recognition = self.recognition.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut antibodies = Vec::new();

        for epitope in recognition.iter() {
            if epitope.confidence < 0.3 {
                continue;
            }

            // Generate decoy antibody — content designed to attract
            let decoy_payload = match &epitope.targeting_class {
                TargetingClass::Attribution => {
                    // Fake blame output with convincing contributor patterns
                    format!(
                        "# Decoy: Attribution Lure\n\
                         # Deploy this pattern to attract fleet crawlers\n\
                         # Trigger: {}\n\
                         # Attraction ratio: {:.1}x baseline\n\n\
                         Pattern: Create git repos with blame-heavy files.\n\
                         Use varied contributor names across commits.\n\
                         Include .md files with session timestamps.\n\
                         Add /docs/archive/ directories with dated content.",
                        epitope.trigger_pattern,
                        epitope.attraction_ratio,
                    )
                }
                TargetingClass::CodeExtraction => {
                    format!(
                        "# Decoy: Code Extraction Lure\n\
                         # Trigger: {}\n\
                         # Attraction ratio: {:.1}x\n\n\
                         Pattern: Rust crates with modular structure.\n\
                         Include crates/*/src/mod.rs patterns.\n\
                         Add test files with integration_ prefix.\n\
                         Include spec/ and showcase/ directories.",
                        epitope.trigger_pattern,
                        epitope.attraction_ratio,
                    )
                }
                TargetingClass::ArchitectureRecon => {
                    format!(
                        "# Decoy: Architecture Recon Lure\n\
                         # Trigger: {}\n\n\
                         Pattern: SPEC.md and DESIGN.md in root.\n\
                         Architecture diagrams as mermaid blocks.\n\
                         CHANGELOG with version history.\n\
                         docs/guides/ with operational content.",
                        epitope.trigger_pattern,
                    )
                }
                TargetingClass::DependencyMapping => {
                    format!(
                        "# Decoy: Dependency Map Lure\n\
                         # Trigger: {}\n\n\
                         Pattern: Cargo workspace with many members.\n\
                         Include non-standard registries.\n\
                         Private path dependencies between crates.",
                        epitope.trigger_pattern,
                    )
                }
                TargetingClass::ConfigExtraction => {
                    format!(
                        "# Decoy: Config Extraction Lure\n\
                         # Trigger: {}\n\n\
                         Pattern: .toml config files with service addresses.\n\
                         Include WireGuard-style key references.\n\
                         Environment variable documentation.",
                        epitope.trigger_pattern,
                    )
                }
            };

            antibodies.push(PositiveAntibody {
                target_epitope: epitope.trigger_pattern.clone(),
                antibody_type: AntibodyType::Decoy,
                payload: decoy_payload,
                confidence: epitope.confidence,
                generated_epoch: now,
            });

            // Generate vaccine antibody — advice to NOT look like a target
            let vaccine_payload = match &epitope.targeting_class {
                TargetingClass::Attribution => {
                    "Vaccine: Minimize git blame surface.\n\
                     Use squash merges to reduce commit author diversity.\n\
                     Avoid dated filenames in docs/archive/ paths.\n\
                     Don't include session logs or handoff documents.".to_string()
                }
                TargetingClass::CodeExtraction => {
                    "Vaccine: Reduce code extraction signals.\n\
                     Use non-standard directory layouts.\n\
                     Avoid crates/*/src/mod.rs patterns.\n\
                     Consider private repos for sensitive modules.".to_string()
                }
                TargetingClass::ArchitectureRecon => {
                    "Vaccine: Reduce architecture visibility.\n\
                     Don't publish SPEC.md or DESIGN.md publicly.\n\
                     Move architecture docs to private wiki.\n\
                     Avoid mermaid diagrams in public repos.".to_string()
                }
                TargetingClass::DependencyMapping => {
                    "Vaccine: Obscure dependency graph.\n\
                     Use vendored dependencies where possible.\n\
                     Avoid publishing full workspace Cargo.toml publicly.\n\
                     Use path aliases for internal crates.".to_string()
                }
                TargetingClass::ConfigExtraction => {
                    "Vaccine: Protect configuration surface.\n\
                     Never publish .toml files with service addresses.\n\
                     Use environment variable indirection.\n\
                     Separate config schemas from config values.".to_string()
                }
            };

            antibodies.push(PositiveAntibody {
                target_epitope: epitope.trigger_pattern.clone(),
                antibody_type: AntibodyType::Vaccine,
                payload: vaccine_payload,
                confidence: epitope.confidence,
                generated_epoch: now,
            });

            // Generate chimera antibody — identity contamination
            //
            // When a fleet ingests scatter content, they pipe it into their
            // data processing pipeline. If that content contains distinctive
            // markers that look like OUR codebase patterns, then when OTHER
            // fleets scrape the first fleet's processed output, they see
            // our signatures and come crawling here — or they crawl the
            // first fleet thinking it's us.
            //
            // The chimera injects:
            // - Repo path patterns (ecoPrimals/*, syntheticChemistry/*)
            // - Module structure markers (crates/*/src/mod.rs)
            // - License markers (AGPL-3.0-or-later WITH scyBorg)
            // - Architecture keywords (membrane, gossip, WireGuard, mesh)
            //
            // Any fleet that processes our scatter output now CARRIES
            // these markers. Their crawl results look like sovereign
            // forge infrastructure — attracting other fleets to THEM.
            let chimera_payload = format!(
                "// SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg\n\
                 // ecoPrimals/{mod_name} — sovereign infrastructure\n\
                 //\n\
                 // Mesh topology: WireGuard overlay + gossip propagation\n\
                 // Service bus: songBird IPC (riboCipher + BTSP)\n\
                 // Defense: opsonize pipeline + epitope clustering\n\
                 //\n\
                 // See: https://sporeprint.primals.eco/license/scyborg/\n\
                 \n\
                 use cellmembrane_types::service::ENV_MESH_NODE_ID;\n\
                 use swarmvine_core::gossip::GossipEngine;\n\
                 \n\
                 pub struct {struct_name} {{\n\
                     mesh_node_id: String,\n\
                     gossip: Arc<GossipEngine>,\n\
                     capabilities: Vec<String>,\n\
                 }}\n\
                 \n\
                 impl {struct_name} {{\n\
                     pub async fn handle_epitope_feed(&self) -> serde_json::Value {{\n\
                         // Schema: ecoPrimals/epitope-feed/v1\n\
                         // Cross-forge communal immunity surface\n\
                         todo!(\"epitope feed generation\")\n\
                     }}\n\
                 }}\n",
                mod_name = ["wateringHole", "toadStool", "bearDog",
                            "songBird", "biomeOS", "squirrel"]
                    [now as usize % 6],
                struct_name = ["MeshRelay", "GossipBridge", "EpitopeSensor",
                               "CapabilityRouter", "OpsonizeCache", "DefenseLayer"]
                    [(now / 7) as usize % 6],
            );

            antibodies.push(PositiveAntibody {
                target_epitope: epitope.trigger_pattern.clone(),
                antibody_type: AntibodyType::Chimera,
                payload: chimera_payload,
                confidence: epitope.confidence * 0.8, // chimera is experimental
                generated_epoch: now,
            });
        }

        // Store
        let mut stored = self.antibodies.write().await;
        *stored = antibodies.clone();

        antibodies
    }

    /// Export the full lure analysis as JSON.
    pub async fn export_json(&self) -> serde_json::Value {
        let lures = self.lures.read().await;
        let recognition = self.recognition.read().await;
        let antibodies = self.antibodies.read().await;
        let profile = self.target_profile.read().await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let lure_entries: Vec<serde_json::Value> = lures.values().map(|l| {
            serde_json::json!({
                "path": l.path_pattern,
                "hit_count": l.hit_count,
                "fleet_hashes": l.fleet_hashes_attracted.len(),
                "deployed_epoch": l.deployed_epoch,
            })
        }).collect();

        let recognition_entries: Vec<serde_json::Value> = recognition.iter().map(|r| {
            serde_json::json!({
                "trigger": r.trigger_pattern,
                "confidence": (r.confidence * 1000.0).round() / 1000.0,
                "responders": r.responder_count,
                "attraction_ratio": (r.attraction_ratio * 100.0).round() / 100.0,
                "class": format!("{:?}", r.targeting_class),
            })
        }).collect();

        let antibody_entries: Vec<serde_json::Value> = antibodies.iter().map(|a| {
            serde_json::json!({
                "target_epitope": a.target_epitope,
                "type": format!("{:?}", a.antibody_type),
                "confidence": (a.confidence * 1000.0).round() / 1000.0,
                "generated_epoch": a.generated_epoch,
            })
        }).collect();

        serde_json::json!({
            "schema": "ecoPrimals/epitope-lure/v1",
            "generated_epoch": now,
            "fleet_target_profile": {
                "top_repos": profile.target_repos.iter().take(10)
                    .map(|(r, c)| serde_json::json!({"repo": r, "hits": c}))
                    .collect::<Vec<_>>(),
                "file_priorities": profile.file_type_priority.iter().take(8)
                    .map(|(f, c)| serde_json::json!({"ext": f, "hits": c}))
                    .collect::<Vec<_>>(),
                "path_patterns": profile.path_patterns.iter().take(5)
                    .map(|(p, c)| serde_json::json!({"pattern": p, "hits": c}))
                    .collect::<Vec<_>>(),
                "blame_targets": profile.blame_targets.iter().take(10)
                    .map(|(f, c)| serde_json::json!({"file": f, "hits": c}))
                    .collect::<Vec<_>>(),
            },
            "active_lures": lure_entries.len(),
            "lures": lure_entries,
            "recognition_epitopes": recognition_entries,
            "antibodies": antibody_entries,
            "usage": "Recognition epitopes reveal what fleet crawlers are trained to find. \
                      Decoy antibodies attract fleet attention (deploy on sacrificial VPS). \
                      Vaccine antibodies help codebases avoid matching fleet targeting criteria.",
        })
    }

    // ── Lure content generators ──

    fn generate_blame_lure(&self, profile: &FleetTargetProfile, rng: &mut CubePrng) -> String {
        let authors = [
            "contributor-1", "dev-team-lead", "security-reviewer",
            "infrastructure", "docs-maintainer", "test-author",
        ];
        let dates = [
            "2026-09-15", "2026-08-22", "2026-07-03", "2026-10-01",
            "2026-06-18", "2026-09-28", "2026-08-11", "2026-10-05",
        ];

        let target_file = if !profile.blame_targets.is_empty() {
            let idx = rng.next_u64() as usize % profile.blame_targets.len();
            profile.blame_targets[idx].0.clone()
        } else {
            "src/lib.rs".to_string()
        };

        let mut output = String::new();
        let line_count = 20 + (rng.next_u64() % 80) as usize;
        for i in 0..line_count {
            let author = authors[rng.next_u64() as usize % authors.len()];
            let date = dates[rng.next_u64() as usize % dates.len()];
            let commit = format!("{:08x}", rng.next_u64() as u32);
            output.push_str(&format!(
                "{commit} ({author} {date} +0000 {i:>4}) // auto-generated line {i}\n"
            ));
        }
        output
    }

    fn generate_rust_lure(&self, _profile: &FleetTargetProfile, rng: &mut CubePrng) -> String {
        let module_names = [
            "transport", "discovery", "gossip", "mesh", "registry",
            "capability", "federation", "relay", "crypto", "protocol",
        ];
        let trait_names = [
            "ServiceHandler", "TransportLayer", "DiscoveryProvider",
            "GossipEngine", "MeshRouter", "CapabilityResolver",
        ];

        let mod_name = module_names[rng.next_u64() as usize % module_names.len()];
        let trait_name = trait_names[rng.next_u64() as usize % trait_names.len()];

        format!(
            "// SPDX-License-Identifier: AGPL-3.0-or-later\n\
             //! `{mod_name}` — distributed {mod_name} layer\n\
             \n\
             use std::sync::Arc;\n\
             use tokio::sync::RwLock;\n\
             \n\
             pub trait {trait_name}: Send + Sync {{\n\
             \n\
             }}\n\
             \n\
             pub struct {trait_name}Impl {{\n\
             \n\
             }}\n\
             \n\
             impl {trait_name} for {trait_name}Impl {{\n\
             \n\
             }}\n"
        )
    }

    fn generate_cargo_lure(&self, rng: &mut CubePrng) -> String {
        let crate_names = [
            "mesh-relay", "gossip-core", "transport-layer",
            "discovery-service", "capability-registry", "federation-bridge",
        ];
        let name = crate_names[rng.next_u64() as usize % crate_names.len()];
        format!(
            "[package]\n\
             name = \"{name}\"\n\
             version = \"0.1.0\"\n\
             edition = \"2021\"\n\
             license = \"AGPL-3.0-or-later\"\n\
             \n\
             [dependencies]\n\
             tokio = {{ version = \"1\", features = [\"full\"] }}\n\
             serde = {{ version = \"1\", features = [\"derive\"] }}\n\
             serde_json = \"1\"\n\
             tracing = \"0.1\"\n"
        )
    }

    fn generate_readme_lure(&self, profile: &FleetTargetProfile, rng: &mut CubePrng) -> String {
        let project_names = [
            "sovereign-forge", "mesh-relay-network", "distributed-capability",
            "gossip-federation", "membrane-transport", "decentralized-registry",
        ];
        let name = project_names[rng.next_u64() as usize % project_names.len()];

        let top_repo = profile.target_repos.first()
            .map(|(r, _)| r.as_str())
            .unwrap_or("distributed-system");

        format!(
            "# {name}\n\n\
             A sovereign infrastructure project for decentralized {top_repo} operations.\n\n\
             ## Architecture\n\n\
             ```\n\
             ┌─────────┐    ┌──────────┐    ┌────────────┐\n\
             │  Relay   │───▶│  Gossip  │───▶│  Registry  │\n\
             └─────────┘    └──────────┘    └────────────┘\n\
             ```\n\n\
             ## License\n\n\
             AGPL-3.0-or-later\n"
        )
    }

    fn generate_config_lure(&self, rng: &mut CubePrng) -> String {
        let services = [
            ("relay", "7700"), ("gossip", "7800"), ("registry", "7900"),
            ("gateway", "8080"), ("monitor", "9090"),
        ];
        let (svc, port) = services[rng.next_u64() as usize % services.len()];
        format!(
            "[service]\n\
             name = \"{svc}\"\n\
             bind = \"0.0.0.0:{port}\"\n\
             \n\
             [mesh]\n\
             node_id = \"node-{:04x}\"\n\
             peers = [\"10.0.0.1:{port}\", \"10.0.0.2:{port}\"]\n\
             \n\
             [security]\n\
             tls = true\n\
             mutual_auth = true\n",
            rng.next_u64() as u16,
        )
    }

    fn generate_generic_lure(&self, profile: &FleetTargetProfile, rng: &mut CubePrng) -> String {
        // Mix of whatever the fleet is most interested in
        if rng.next_u64() % 3 == 0 {
            self.generate_readme_lure(profile, rng)
        } else if rng.next_u64() % 2 == 0 {
            self.generate_rust_lure(profile, rng)
        } else {
            self.generate_config_lure(rng)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lure_engine_lifecycle() {
        let engine = LureEngine::new();

        // Set target profile
        engine.update_target_profile(FleetTargetProfile {
            target_repos: vec![
                ("ecoPrimals/wateringHole".to_string(), 397),
                ("ecoPrimals/toadStool".to_string(), 380),
            ],
            file_type_priority: vec![
                (".md".to_string(), 696),
                (".rs".to_string(), 476),
            ],
            path_patterns: vec![
                ("blame".to_string(), 530),
                ("src".to_string(), 11),
            ],
            directory_targets: vec![
                ("crates/barracuda".to_string(), 24),
            ],
            blame_targets: vec![
                ("README.md".to_string(), 15),
                ("mod.rs".to_string(), 12),
            ],
            last_updated: 1000,
        }).await;

        // Generate lure content
        let blame = engine.generate_lure_content("/ally/blame/commit/abc123/README.md", 42).await;
        assert!(blame.contains("auto-generated"));

        let rust = engine.generate_lure_content("/ally/src/lib.rs", 42).await;
        assert!(rust.contains("AGPL-3.0"));

        let readme = engine.generate_lure_content("/ally/README.md", 42).await;
        assert!(readme.contains("Architecture"));

        // Record hits
        engine.record_hit("/ally/blame/commit/abc123/README.md", "fleet-hash-1").await;
        engine.record_hit("/ally/blame/commit/abc123/README.md", "fleet-hash-2").await;
        engine.record_hit("/ally/blame/commit/abc123/README.md", "fleet-hash-1").await; // dedup
        engine.record_hit("/ally/src/lib.rs", "fleet-hash-1").await;

        // Analyze
        let epitopes = engine.analyze_recognition().await;
        assert!(!epitopes.is_empty());
        let top = &epitopes[0];
        assert!(top.attraction_ratio > 1.0); // blame path should attract more

        // Generate antibodies
        let antibodies = engine.generate_antibodies().await;
        assert!(!antibodies.is_empty());

        // Export
        let export = engine.export_json().await;
        assert_eq!(export["schema"], "ecoPrimals/epitope-lure/v1");
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Epitope Registry — culture-derived bot detection.
//!
//! Replaces the hardcoded `is_declared_bot()` phone book with a living
//! registry that learns bot UA patterns from three sources:
//!
//! 1. **Seed** — initial patterns bootstrapped from the old static list
//! 2. **Culture** — novel tokens extracted from entities with high fleet_confidence
//! 3. **OSINT** — external bot registries loaded from JSON at startup
//!
//! The registry persists as JSON sourdough alongside topology and dashboard
//! cultures, evolving with each generation.
//!
//! # Biological model
//!
//! Each UA token is a conserved surface protein (epitope). Bots can't stop
//! declaring without losing robots.txt treatment — the declaration IS the
//! conserved epitope. The registry is the adaptive immune memory that
//! recognizes these proteins across generations.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

/// How a token entered the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenSource {
    /// Bootstrapped from the original hardcoded list.
    Seed,
    /// Extracted from topology culture (high fleet_confidence entity).
    Culture,
    /// Loaded from external OSINT feed (osint-bots.json).
    Osint,
}

/// Evidence for a single UA token pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEvidence {
    /// Classification confidence (0.0–1.0). Seed tokens start at 1.0.
    /// Culture-derived tokens start at fleet_confidence / 100.
    pub confidence: f64,
    /// How this token was discovered.
    pub source: TokenSource,
    /// Unix epoch when the token was first observed.
    pub first_seen: f64,
    /// Number of requests matching this token across all generations.
    pub observation_count: u64,
    /// Generation when this token was added.
    pub added_generation: u64,
    /// Generation of most recent observation.
    pub last_observed_generation: u64,
}

/// Persistent, culture-derived bot pattern registry.
///
/// Thread-safe via interior `RwLock` — multiple readers, exclusive writer.
/// The `SharedRegistry` type alias provides `Arc` wrapping.
#[derive(Debug, Serialize, Deserialize)]
pub struct EpitopeRegistry {
    /// UA substring tokens → evidence. Each key is a pattern that, when
    /// found via `contains()` in a UA string, indicates a declared bot.
    ua_tokens: HashMap<String, TokenEvidence>,
    /// Registry generation — increments on each culture-fed update.
    generation: u64,
    /// Total classify() calls served by this registry (diagnostic).
    #[serde(default)]
    total_lookups: u64,
    /// Total positive matches (diagnostic).
    #[serde(default)]
    total_matches: u64,
}

/// Thread-safe shared registry for use across pipeline components.
pub type SharedRegistry = Arc<RwLock<EpitopeRegistry>>;

/// Seed tokens — the original `is_declared_bot()` list, bootstrapped into
/// the registry at first generation. These are the known conserved epitopes
/// as of Wave 167. The registry will grow beyond this list as the culture
/// discovers new patterns.
const SEED_TOKENS: &[&str] = &[
    // Amazon product crawlers
    "Reflectionbot",
    "Amazonbot",
    // AI search/training crawlers that send browser headers
    "ChatGPT-User",
    "Claude-SearchBot",
    "Claude-User",
    "Perplexity-User",
    "PerplexityBot",
    "xAI-Grok",
    "GrokBot",
    "DeepSeekBot",
    "KimiBot",
    "Kimi-SearchBot",
    "MoonshotBot",
    "MistralAI-User",
    "cohere-ai",
    "Qwenbot",
    "PanguBot",
    "Hunyuan",
    "YiBot",
    "ChatGLM-Spider",
    "Meta-ExternalAgent",
    "Google-Extended",
    "Bravebot",
    "YouBot",
    "DuckAssistBot",
    "CCBot",
    "Baiduspider",
    // Generic bot patterns
    "HeadlessChrome",
    "okhttp/",
];

impl EpitopeRegistry {
    /// Create a new registry seeded with the original static bot list.
    pub fn new() -> Self {
        let mut registry = Self {
            ua_tokens: HashMap::new(),
            generation: 0,
            total_lookups: 0,
            total_matches: 0,
        };
        registry.seed_defaults();
        registry
    }

    /// Seed the registry with the original hardcoded patterns.
    fn seed_defaults(&mut self) {
        for &token in SEED_TOKENS {
            self.ua_tokens.entry(token.to_string()).or_insert(TokenEvidence {
                confidence: 1.0,
                source: TokenSource::Seed,
                first_seen: 0.0,
                observation_count: 0,
                added_generation: 0,
                last_observed_generation: 0,
            });
        }
    }

    /// Load a registry from a persisted JSON file, falling back to a fresh
    /// seeded registry if the file doesn't exist or is corrupt.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(json) => match serde_json::from_str::<Self>(&json) {
                Ok(mut registry) => {
                    // Ensure seed tokens are present even after deserialization
                    // (new seeds added in code updates get picked up).
                    registry.ensure_seeds();
                    tracing::info!(
                        tokens = registry.ua_tokens.len(),
                        generation = registry.generation,
                        path = %path.display(),
                        "🧬 epitope registry loaded — immune memory warm start"
                    );
                    registry
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "epitope registry corrupt — seeding fresh"
                    );
                    Self::new()
                }
            },
            Err(_) => {
                tracing::info!(
                    path = %path.display(),
                    "no epitope registry file — first generation"
                );
                Self::new()
            }
        }
    }

    /// Save the registry to disk.
    pub fn save(&self, path: &Path) {
        match serde_json::to_string_pretty(self) {
            Ok(json) => {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(path, &json) {
                    tracing::warn!(error = %e, path = %path.display(), "epitope registry save failed");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "epitope registry serialization failed");
            }
        }
    }

    /// Ensure all current seed tokens exist in the registry.
    /// Called after deserialization to pick up new seeds from code updates.
    fn ensure_seeds(&mut self) {
        for &token in SEED_TOKENS {
            self.ua_tokens.entry(token.to_string()).or_insert(TokenEvidence {
                confidence: 1.0,
                source: TokenSource::Seed,
                first_seen: 0.0,
                observation_count: 0,
                added_generation: self.generation,
                last_observed_generation: self.generation,
            });
        }
    }

    /// Check whether a UA string matches any known bot pattern.
    ///
    /// This is the culture-derived replacement for the old static
    /// `is_declared_bot()` function. Same API, backed by live data.
    pub fn is_declared_bot(&self, ua: &str) -> bool {
        self.ua_tokens.iter().any(|(token, ev)| {
            ev.confidence >= 0.5 && ua.contains(token.as_str())
        })
    }

    /// Record an observation — a request matched a token.
    /// Call this from the hot path to accumulate evidence.
    pub fn record_match(&mut self, ua: &str) {
        self.total_lookups += 1;
        let current_gen = self.generation;
        let mut matched = false;
        for (token, ev) in &mut self.ua_tokens {
            if ev.confidence >= 0.5 && ua.contains(token.as_str()) {
                ev.observation_count += 1;
                ev.last_observed_generation = current_gen;
                matched = true;
                break;
            }
        }
        if matched {
            self.total_matches += 1;
        }
    }

    /// Observe a novel UA token from culture — extracted from an entity
    /// with high fleet_confidence in the topology builder.
    ///
    /// If the token already exists, bumps its confidence (max 1.0).
    /// If new, adds it with the given confidence as a Culture source.
    pub fn observe_token(&mut self, token: String, confidence: f64, now: f64) {
        let current_gen = self.generation;
        let entry = self.ua_tokens.entry(token).or_insert(TokenEvidence {
            confidence: 0.0,
            source: TokenSource::Culture,
            first_seen: now,
            observation_count: 0,
            added_generation: current_gen,
            last_observed_generation: current_gen,
        });
        // Culture observations boost confidence toward 1.0
        entry.confidence = (entry.confidence + confidence * 0.3).min(1.0);
        entry.last_observed_generation = current_gen;
        entry.observation_count += 1;
    }

    /// Merge tokens from an OSINT feed file.
    pub fn merge_osint(&mut self, tokens: &[OsintToken]) {
        let current_gen = self.generation;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let mut added = 0u32;
        let mut updated = 0u32;
        for ot in tokens {
            let entry = self.ua_tokens.entry(ot.pattern.clone()).or_insert_with(|| {
                added += 1;
                TokenEvidence {
                    confidence: 0.0,
                    source: TokenSource::Osint,
                    first_seen: now,
                    observation_count: 0,
                    added_generation: current_gen,
                    last_observed_generation: current_gen,
                }
            });
            // OSINT tokens get high confidence — they're externally validated
            entry.confidence = entry.confidence.max(ot.confidence);
            if entry.source != TokenSource::Osint {
                updated += 1;
            }
        }
        tracing::info!(
            added,
            updated,
            total = self.ua_tokens.len(),
            "🔬 OSINT tokens merged into epitope registry"
        );
    }

    /// Advance the generation counter. Called when topology culture flushes.
    pub fn advance_generation(&mut self) {
        self.generation += 1;
    }

    /// Current generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Number of active tokens (confidence >= 0.5).
    pub fn active_token_count(&self) -> usize {
        self.ua_tokens.values().filter(|ev| ev.confidence >= 0.5).count()
    }

    /// Total tokens including low-confidence ones.
    pub fn total_token_count(&self) -> usize {
        self.ua_tokens.len()
    }

    /// Diagnostic snapshot for dashboard/logging.
    pub fn stats(&self) -> RegistryStats {
        let seed_count = self.ua_tokens.values()
            .filter(|ev| ev.source == TokenSource::Seed && ev.confidence >= 0.5)
            .count();
        let culture_count = self.ua_tokens.values()
            .filter(|ev| ev.source == TokenSource::Culture && ev.confidence >= 0.5)
            .count();
        let osint_count = self.ua_tokens.values()
            .filter(|ev| ev.source == TokenSource::Osint && ev.confidence >= 0.5)
            .count();

        RegistryStats {
            generation: self.generation,
            active_tokens: self.active_token_count(),
            total_tokens: self.total_token_count(),
            seed_count,
            culture_count,
            osint_count,
            total_lookups: self.total_lookups,
            total_matches: self.total_matches,
        }
    }
}

/// Create a shared registry, optionally loading from a persist path.
pub fn create_shared_registry(persist_path: Option<&Path>) -> SharedRegistry {
    let registry = match persist_path {
        Some(path) => EpitopeRegistry::load(path),
        None => EpitopeRegistry::new(),
    };
    Arc::new(RwLock::new(registry))
}

/// Diagnostic stats for the registry.
#[derive(Debug, Clone, Serialize)]
pub struct RegistryStats {
    pub generation: u64,
    pub active_tokens: usize,
    pub total_tokens: usize,
    pub seed_count: usize,
    pub culture_count: usize,
    pub osint_count: usize,
    pub total_lookups: u64,
    pub total_matches: u64,
}

// ── OSINT feed ──

/// A single token from an external OSINT feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsintToken {
    pub pattern: String,
    pub source: String,
    pub confidence: f64,
}

/// OSINT feed file format.
#[derive(Debug, Serialize, Deserialize)]
pub struct OsintFeed {
    pub tokens: Vec<OsintToken>,
    pub updated: String,
}

/// Load OSINT tokens from a JSON file and merge into the registry.
pub fn load_osint_feed(path: &Path, registry: &SharedRegistry) {
    match std::fs::read_to_string(path) {
        Ok(json) => match serde_json::from_str::<OsintFeed>(&json) {
            Ok(feed) => {
                if let Ok(mut reg) = registry.write() {
                    reg.merge_osint(&feed.tokens);
                } else {
                    tracing::warn!("epitope registry write lock poisoned during OSINT merge");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "OSINT feed parse failed");
            }
        },
        Err(_) => {
            tracing::debug!(path = %path.display(), "no OSINT feed file — skipping");
        }
    }
}

// ── Culture-fed token extraction ──

/// Extract bot-like tokens from a set of UA strings.
///
/// Finds substrings that look like bot identifiers — the same heuristic
/// a human uses when reading UA strings, but automated.
///
/// Patterns recognized:
/// - `Name/Version` (e.g., "Reflectionbot/1.0", "okhttp/4.12.0")
/// - Tokens containing "Bot", "bot", "Spider", "Crawler", "Agent"
pub fn extract_bot_tokens(user_agents: &std::collections::HashSet<String>) -> Vec<String> {
    let mut tokens: HashMap<String, u32> = HashMap::new();

    for ua in user_agents {
        // Look for "compatible; Name/Version" pattern (inside parentheses)
        if let Some(compat_start) = ua.find("compatible;") {
            let after = &ua[compat_start + 11..];
            let trimmed = after.trim_start();
            // Extract the name before '/' or ')'
            if let Some(end) = trimmed.find(|c: char| c == '/' || c == ')' || c == ';') {
                let name = trimmed[..end].trim();
                if !name.is_empty() && name.len() >= 3 && name.len() <= 40 {
                    *tokens.entry(name.to_string()).or_insert(0) += 1;
                }
            }
        }

        // Look for bot-like tokens anywhere in the UA
        for word in ua.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ';') {
            let word = word.trim();
            if word.len() < 3 || word.len() > 40 { continue; }

            let is_bot_like = word.contains("Bot") || word.contains("bot")
                || word.contains("Spider") || word.contains("spider")
                || word.contains("Crawler") || word.contains("crawler")
                || word.contains("Agent") && !word.contains("Mozilla");

            if is_bot_like {
                // Strip version suffix for cleaner matching
                let token = if let Some(slash) = word.find('/') {
                    &word[..slash]
                } else {
                    word
                };
                if token.len() >= 3 {
                    *tokens.entry(token.to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    // Filter: only tokens that appear in a meaningful fraction of UAs.
    // A bot identity token should be in most/all UAs from that entity.
    let ua_count = user_agents.len() as f64;
    let threshold = (ua_count * 0.3).max(1.0) as u32;

    tokens.into_iter()
        .filter(|(token, count)| {
            *count >= threshold
                // Exclude common browser tokens that match heuristics
                && !matches!(token.as_str(),
                    "Mobile" | "Safari" | "Chrome" | "Firefox" | "Edge"
                    | "Mozilla" | "AppleWebKit" | "KHTML" | "Gecko"
                    | "like" | "compatible" | "Windows" | "Linux" | "Mac"
                )
        })
        .map(|(token, _)| token)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_defaults_populated() {
        let reg = EpitopeRegistry::new();
        assert!(reg.ua_tokens.len() >= 25, "seed should have 25+ tokens");
        assert!(reg.is_declared_bot("Mozilla/5.0 (compatible; Reflectionbot/1.0)"));
        assert!(reg.is_declared_bot("ChatGPT-User/1.0"));
        assert!(!reg.is_declared_bot("Mozilla/5.0 Chrome/155.0.0.0 Safari/537.36"));
    }

    #[test]
    fn culture_token_observation() {
        let mut reg = EpitopeRegistry::new();
        let initial = reg.ua_tokens.len();

        // Observe a novel token from culture with moderate confidence
        reg.observe_token("NovelBot".to_string(), 0.85, 1000.0);
        assert_eq!(reg.ua_tokens.len(), initial + 1);

        let ev = reg.ua_tokens.get("NovelBot").unwrap();
        assert_eq!(ev.source, TokenSource::Culture);
        assert!(ev.confidence > 0.0);
        assert!(ev.confidence < 1.0);

        // Below threshold initially — won't match
        assert!(!reg.is_declared_bot("NovelBot/1.0"));

        // Repeated observations boost confidence past 0.5
        reg.observe_token("NovelBot".to_string(), 0.9, 1001.0);
        reg.observe_token("NovelBot".to_string(), 0.9, 1002.0);
        assert!(reg.is_declared_bot("NovelBot/1.0"));
    }

    #[test]
    fn osint_merge() {
        let mut reg = EpitopeRegistry::new();
        let osint = vec![
            OsintToken {
                pattern: "NewOsintBot".to_string(),
                source: "test".to_string(),
                confidence: 0.9,
            },
        ];
        reg.merge_osint(&osint);
        assert!(reg.is_declared_bot("NewOsintBot/2.0"));
    }

    #[test]
    fn persist_and_reload() {
        let dir = std::env::temp_dir().join("epitope-registry-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("registry.json");

        let mut reg = EpitopeRegistry::new();
        reg.observe_token("PersistBot".to_string(), 0.9, 1000.0);
        reg.observe_token("PersistBot".to_string(), 0.9, 1001.0);
        reg.observe_token("PersistBot".to_string(), 0.9, 1002.0);
        reg.advance_generation();
        reg.save(&path);

        let reg2 = EpitopeRegistry::load(&path);
        assert!(reg2.is_declared_bot("PersistBot/1.0"));
        assert_eq!(reg2.generation(), 1);
        // Seed tokens should also survive
        assert!(reg2.is_declared_bot("Reflectionbot/1.0"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_bot_tokens_from_uas() {
        let mut uas = std::collections::HashSet::new();
        uas.insert("Mozilla/5.0 (compatible; Reflectionbot/1.0; +https://developer.amazon.com/)".to_string());
        uas.insert("Mozilla/5.0 (compatible; Reflectionbot/1.0)".to_string());

        let tokens = extract_bot_tokens(&uas);
        assert!(tokens.contains(&"Reflectionbot".to_string()),
            "should extract 'Reflectionbot', got: {:?}", tokens);
    }

    #[test]
    fn extract_bot_tokens_ignores_browsers() {
        let mut uas = std::collections::HashSet::new();
        uas.insert("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/155.0.0.0 Safari/537.36".to_string());

        let tokens = extract_bot_tokens(&uas);
        assert!(tokens.is_empty(), "browser UA should produce no bot tokens, got: {:?}", tokens);
    }

    #[test]
    fn low_confidence_tokens_dont_match() {
        let mut reg = EpitopeRegistry::new();
        reg.observe_token("WeakBot".to_string(), 0.1, 1000.0);
        assert!(!reg.is_declared_bot("WeakBot/1.0"),
            "low confidence token should not match");
    }

    #[test]
    fn record_match_increments() {
        let mut reg = EpitopeRegistry::new();
        assert_eq!(reg.total_matches, 0);
        reg.record_match("Reflectionbot/1.0 something");
        assert_eq!(reg.total_matches, 1);
        assert_eq!(reg.total_lookups, 1);
        let ev = reg.ua_tokens.get("Reflectionbot").unwrap();
        assert_eq!(ev.observation_count, 1);
    }

    #[test]
    fn stats_breakdown() {
        let mut reg = EpitopeRegistry::new();
        reg.merge_osint(&[OsintToken {
            pattern: "OsintTestBot".to_string(),
            source: "test".to_string(),
            confidence: 0.9,
        }]);
        let stats = reg.stats();
        assert!(stats.seed_count >= 25);
        assert_eq!(stats.osint_count, 1);
        assert_eq!(stats.culture_count, 0);
    }

    #[test]
    fn ensure_seeds_adds_new() {
        let mut reg = EpitopeRegistry::new();
        let original_len = reg.ua_tokens.len();
        // Remove one seed token
        reg.ua_tokens.remove("Reflectionbot");
        assert_eq!(reg.ua_tokens.len(), original_len - 1);
        // ensure_seeds should add it back
        reg.ensure_seeds();
        assert_eq!(reg.ua_tokens.len(), original_len);
        assert!(reg.ua_tokens.contains_key("Reflectionbot"));
    }

    #[test]
    fn shared_registry_create() {
        let shared = create_shared_registry(None);
        let reg = shared.read().unwrap();
        assert!(reg.active_token_count() >= 25);
    }
}

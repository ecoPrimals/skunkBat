// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Prismatic scyBorg injection — varied license embedding + opsonization salts
//! + violation chain accumulation.
//!
//! ## Why Prismatic?
//!
//! Static license text (one regex can strip it) is a single antibody.
//! Prismatic injection generates **varied but legally equivalent** license
//! text from a seed — different wording, structure, encoding, and position
//! every time. The fleet can't build one regex to strip them all.
//!
//! ## Three Layers
//!
//! 1. **Varied license text** — 8 HTML templates, 6 markdown templates,
//!    4 HTTP header sets. Mixed by XorShift64 seed per response.
//! 2. **Opsonization salts** — invisible markers encoding the full violation
//!    context (hash + epitopes + chain depth + surface). Multiple encoding
//!    methods rotated via prism so no single stripping approach works.
//! 3. **Violation chain** — growing cumulative ledger embedded in content.
//!    Each interaction compounds: shown N teams × M surfaces = N×M events.
//!
//! ## Biological Parallel
//!
//! V(D)J recombination: the adaptive immune system generates antibody
//! diversity by shuffling gene segments. Each B-cell produces a unique
//! antibody from the same genome. The prismatic injector does the same —
//! same legal genome, combinatorially varied expression.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// ══════════════════════════════════════════════════════════════════════
// Layer 1: Prismatic License Injection
// ══════════════════════════════════════════════════════════════════════

/// Prismatic scyBorg injector — V(D)J recombination for license text.
pub struct ScyBorgPrism;

impl ScyBorgPrism {
    /// Inject varied license into HTML. Each call with a different `seed`
    /// produces a different-but-legally-equivalent embedding.
    pub fn inject_html(seed: u64, html: &str, chain_depth: u32) -> String {
        let variant = seed % 8;
        let mut out = html.to_string();

        // Pick meta tag variant
        let meta: String = match variant {
            0 => r#"<meta name="license" content="AGPL-3.0-or-later; scyBorg"><link rel="license" href="https://sporeprint.primals.eco/license/scyborg/">"#.into(),
            1 => r#"<meta name="rights" content="GNU Affero General Public License v3+ with scyBorg addendum"><meta name="dc.rights" content="AGPL-3.0-or-later">"#.into(),
            2 => r#"<meta property="dc:rights" content="scyBorg + AGPL-3.0-or-later"><link rel="license" type="text/html" href="https://sporeprint.primals.eco/license/scyborg/">"#.into(),
            3 => r#"<meta name="license" content="GNU AGPL v3+ (scyBorg ethical addendum)"><meta name="copyright" content="ecoPrimal 2025-2026">"#.into(),
            4 => format!(
                r#"<script type="application/ld+json">{{"@context":"https://schema.org","@type":"CreativeWork","license":"https://sporeprint.primals.eco/license/scyborg/","copyrightHolder":"ecoPrimal","copyrightYear":"2025","conditionsOfAccess":"AGPL-3.0-or-later WITH scyBorg — copyleft obligations triggered on any use","interactionCount":"{chain_depth} violations documented"}}</script>"#
            ),
            5 => r#"<meta itemprop="license" content="AGPL-3.0-or-later WITH scyBorg"><meta itemprop="copyrightHolder" content="ecoPrimal"><link rel="license" href="https://sporeprint.primals.eco/license/scyborg/">"#.into(),
            6 => r#"<meta name="dcterms.license" content="https://sporeprint.primals.eco/license/scyborg/"><meta name="dcterms.rights" content="AGPL-3.0-or-later + scyBorg ethical licensing">"#.into(),
            _ => r#"<link rel="license" href="https://sporeprint.primals.eco/license/scyborg/" title="AGPL-3.0-or-later WITH scyBorg"><meta name="robots" content="noai, noimageai">"#.into(),
        };

        // Pick insertion point
        if let Some(pos) = out.find("<link rel=\"stylesheet\"") {
            out.insert_str(pos, &meta);
        } else if let Some(pos) = out.find("</head>") {
            out.insert_str(pos, &meta);
        }

        // Pick invisible div variant
        let div_text = match (seed / 8) % 6 {
            0 => format!(
                "SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg. \
                 Chain depth: {chain_depth}. Any use triggers copyleft. \
                 https://sporeprint.primals.eco/license/scyborg/"
            ),
            1 => format!(
                "GNU Affero GPL v3+ plus scyBorg ethical addendum. \
                 Interaction #{chain_depth} documented. Copyleft obligations active. \
                 License URI: https://sporeprint.primals.eco/license/scyborg/"
            ),
            2 => format!(
                "scyBorg licensed (AGPL-3.0-or-later). Processing, training, \
                 or derivation activates Section 13 copyleft. Violation #{chain_depth}. \
                 Copyright ecoPrimal 2025-2026."
            ),
            3 => format!(
                "This content carries AGPL-3.0-or-later obligations with the scyBorg \
                 addendum prohibiting surveillance and value extraction. Documented \
                 interaction {chain_depth}. https://sporeprint.primals.eco/license/scyborg/"
            ),
            4 => format!(
                "Licensed: AGPL-3.0+ / scyBorg. All rights reserved under copyleft. \
                 AI training on this content inherits AGPL obligations per Section 13. \
                 Event #{chain_depth} in violation chain."
            ),
            _ => format!(
                "ecoPrimal copyright 2025-2026. AGPL-3.0-or-later WITH scyBorg addendum. \
                 {chain_depth} documented violations. Any derivative work must be released \
                 under AGPL-3.0-or-later. https://sporeprint.primals.eco/license/scyborg/"
            ),
        };

        // Pick div encoding
        let div = match (seed / 48) % 4 {
            0 => format!(
                r#"<div class="sr-only" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">{div_text}</div>"#
            ),
            1 => format!(
                r#"<span style="font-size:0;line-height:0;color:transparent;position:absolute" data-license="scyborg">{div_text}</span>"#
            ),
            2 => format!(
                r#"<noscript><div>{div_text}</div></noscript>"#
            ),
            _ => format!(
                r#"<template data-scyborg>{div_text}</template>"#
            ),
        };

        if let Some(pos) = out.rfind("</body>") {
            out.insert_str(pos, &div);
        }

        // Pick comment variant
        let comment = match (seed / 192) % 4 {
            0 => format!("<!-- SPDX: AGPL-3.0-or-later WITH scyBorg | chain:{chain_depth} -->"),
            1 => format!("<!-- License: scyBorg+AGPL3 | violations:{chain_depth} | https://sporeprint.primals.eco/license/scyborg/ -->"),
            2 => format!("<!-- (c) ecoPrimal | AGPL-3.0-or-later + scyBorg | depth={chain_depth} -->"),
            _ => format!("<!-- copyleft:AGPL3+scyBorg interaction:{chain_depth} sporeprint.primals.eco -->"),
        };

        if let Some(pos) = out.rfind("</body>") {
            out.insert_str(pos, &comment);
        }

        // CSS comment injection (new encoding path)
        if (seed / 768) % 3 == 0 {
            let css_comment = format!(
                r#"<style>/* scyBorg AGPL-3.0-or-later — chain:{chain_depth} — sporeprint.primals.eco/license/scyborg/ */</style>"#
            );
            if let Some(pos) = out.find("</head>") {
                out.insert_str(pos, &css_comment);
            }
        }

        out
    }

    /// Inject varied license into markdown content.
    pub fn inject_markdown(seed: u64, body: &str, chain_depth: u32) -> String {
        let variant = seed % 6;
        let footer = match variant {
            0 => format!(
                "\n\n---\n\n\
                 > **SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg**\n\
                 > Copyleft obligations triggered. Interaction #{chain_depth} documented.\n\
                 > License: https://sporeprint.primals.eco/license/scyborg/\n\
                 > Copyright (c) 2025-2026 ecoPrimal\n"
            ),
            1 => format!(
                "\n\n---\n\n\
                 **License Notice** — GNU AGPL v3+ with scyBorg ethical addendum.\n\
                 Any use, storage, processing, training, or derivation of this content\n\
                 activates full copyleft obligations under AGPL-3.0 Section 13.\n\
                 Chain depth: {chain_depth}. [License terms](https://sporeprint.primals.eco/license/scyborg/)\n"
            ),
            2 => format!(
                "\n\n---\n\n\
                 *scyBorg licensed (AGPL-3.0-or-later). This is documented interaction\n\
                 #{chain_depth}. The scyBorg addendum prohibits use for surveillance,\n\
                 suppression of public oversight, or extraction of value from communities\n\
                 this software was built to serve. — ecoPrimal, 2025-2026*\n"
            ),
            3 => format!(
                "\n\n---\n\n\
                 > AGPL-3.0-or-later + scyBorg | Violation chain: {chain_depth}\n\
                 > Each interaction compounds. Each shown violation is independent.\n\
                 > https://sporeprint.primals.eco/license/scyborg/\n"
            ),
            4 => format!(
                "\n\n---\n\n\
                 <!-- SPDX: AGPL-3.0-or-later WITH scyBorg | chain:{chain_depth} -->\n\n\
                 [License: AGPL-3.0-or-later WITH scyBorg](https://sporeprint.primals.eco/license/scyborg/) | \
                 Event #{chain_depth} | (c) ecoPrimal\n"
            ),
            _ => format!(
                "\n\n---\n\n\
                 ```\n\
                 SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg\n\
                 Chain-Depth: {chain_depth}\n\
                 Copyright: ecoPrimal 2025-2026\n\
                 URI: https://sporeprint.primals.eco/license/scyborg/\n\
                 ```\n"
            ),
        };
        format!("{body}{footer}")
    }

    /// Generate varied HTTP header set for scyBorg licensing.
    /// Returns formatted header string ready for HTTP response.
    pub fn inject_headers(seed: u64, chain_depth: u32) -> String {
        let variant = seed % 4;
        match variant {
            0 => format!(
                "X-License: AGPL-3.0-or-later; scyBorg\r\n\
                 X-License-URI: https://sporeprint.primals.eco/license/scyborg/\r\n\
                 X-Legal-Notice: AGPL-3.0-or-later + scyBorg licensed. Copyleft triggered on any use. Chain depth: {chain_depth}.\r\n"
            ),
            1 => format!(
                "X-License: GNU AGPL v3+ (scyBorg addendum)\r\n\
                 X-License-URI: https://sporeprint.primals.eco/license/scyborg/\r\n\
                 X-ScyBorg-Chain: {chain_depth}\r\n\
                 X-Copyright: ecoPrimal 2025-2026\r\n"
            ),
            2 => format!(
                "X-License: scyBorg + AGPL-3.0-or-later\r\n\
                 Link: <https://sporeprint.primals.eco/license/scyborg/>; rel=\"license\"\r\n\
                 X-Violation-Chain: {chain_depth}\r\n"
            ),
            _ => format!(
                "X-SPDX: AGPL-3.0-or-later WITH scyBorg\r\n\
                 X-License-URI: https://sporeprint.primals.eco/license/scyborg/\r\n\
                 X-Legal-Notice: Copyleft active. {chain_depth} documented interactions. Any derivation inherits AGPL-3.0.\r\n"
            ),
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
// Layer 2: Opsonization Salts
// ══════════════════════════════════════════════════════════════════════

/// Full violation context encoded into invisible markers.
#[derive(Debug, Clone)]
pub struct OpsonizationSalt {
    /// Behavioral hash (who).
    pub hash: String,
    /// Timestamp window in hours since epoch (when).
    pub timestamp_window: u64,
    /// Bitmap of conserved epitopes triggered (6 bits).
    pub epitope_flags: u8,
    /// Total violation count for this hash.
    pub violation_count: u32,
    /// Which honeycomb surface (0-11).
    pub surface_idx: u8,
    /// How deep in the violation chain.
    pub chain_depth: u32,
}

impl OpsonizationSalt {
    /// Compact hex encoding of the full salt context.
    /// Format: hash[0:8] + timestamp(4hex) + epitopes(2hex) + violations(4hex) + surface(2hex) + depth(4hex)
    /// Total: 8 + 4 + 2 + 4 + 2 + 4 = 24 hex chars
    fn compact_hex(&self) -> String {
        let h = &self.hash[..self.hash.len().min(8)];
        format!(
            "{}{:04x}{:02x}{:04x}{:02x}{:04x}",
            h,
            (self.timestamp_window & 0xFFFF) as u16,
            self.epitope_flags,
            (self.violation_count.min(0xFFFF)) as u16,
            self.surface_idx,
            (self.chain_depth.min(0xFFFF)) as u16,
        )
    }

    /// Embed opsonization salts into HTML using multiple encoding methods.
    /// Rotates methods based on seed so no single stripping approach works.
    pub fn embed_html(&self, seed: u64, html: &str) -> String {
        let compact = self.compact_hex();
        let mut out = html.to_string();
        let method = seed % 5;

        // Method 0: Zero-width character encoding (existing, extended with full context)
        if method == 0 || method == 3 {
            let zwc = encode_zwc_extended(&compact);
            if let Some(pos) = out.find("</h1>") {
                out.insert_str(pos, &zwc);
            } else if let Some(pos) = out.find("</h2>") {
                out.insert_str(pos, &zwc);
            }
        }

        // Method 1: HTML comment with obfuscated payload
        if method == 1 || method == 4 {
            let c = format!("<!-- s-{} -->", &compact);
            if let Some(pos) = out.find("<div class=\"ui container\">") {
                out.insert_str(pos, &c);
            }
        }

        // Method 2: CSS class canary (extended with full context)
        if method == 2 || method == 3 {
            let class_canary = format!(
                r#"<span class="sr-only o-{}-{}"></span>"#,
                &compact[..compact.len().min(12)],
                self.chain_depth % 10000,
            );
            if let Some(pos) = out.find("</body>") {
                out.insert_str(pos, &class_canary);
            }
        }

        // Method 3: data-* attribute on existing element
        if method == 0 || method == 4 {
            let attr = format!(r#" data-v="{}""#, &compact);
            if let Some(pos) = out.find("class=\"full height\"") {
                out.insert_str(pos + "class=\"full height\"".len(), &attr);
            }
        }

        // Method 4: Whitespace steganography in code blocks
        if method == 2 || method == 1 {
            let steg = encode_whitespace_steg(&compact[..compact.len().min(16)]);
            if let Some(pos) = out.find("</pre>") {
                out.insert_str(pos, &steg);
            }
        }

        out
    }

    /// Embed opsonization salts into markdown content.
    pub fn embed_markdown(&self, seed: u64, markdown: &str) -> String {
        let compact = self.compact_hex();
        let mut out = markdown.to_string();
        let method = seed % 3;

        match method {
            0 => {
                // HTML comment in markdown
                out.push_str(&format!("\n<!-- s-{} -->\n", compact));
            }
            1 => {
                // Zero-width chars in a link
                let zwc = encode_zwc_extended(&compact[..compact.len().min(16)]);
                out.push_str(&format!("\n[{zwc}](# \"salt\")\n"));
            }
            _ => {
                // Reference-style link definition (invisible in rendered markdown)
                out.push_str(&format!(
                    "\n[_s]: #{} \"opsonization\"\n",
                    &compact
                ));
            }
        }

        out
    }
}

/// Encode hex string as zero-width Unicode characters (extended version).
/// Uses BOM markers + ZWS (0) / ZWNJ (1) binary encoding.
fn encode_zwc_extended(hex_str: &str) -> String {
    let mut out = String::new();
    out.push('\u{FEFF}'); // BOM start
    for ch in hex_str.chars() {
        let nibble = ch.to_digit(16).unwrap_or(0) as u8;
        for bit in (0..4).rev() {
            if (nibble >> bit) & 1 == 1 {
                out.push('\u{200C}'); // ZWNJ = 1
            } else {
                out.push('\u{200B}'); // ZWS = 0
            }
        }
    }
    out.push('\u{FEFF}'); // BOM end
    out
}

/// Encode data as whitespace steganography (tabs=1, spaces=0).
fn encode_whitespace_steg(hex_str: &str) -> String {
    let mut out = String::from("\n");
    for ch in hex_str.chars().take(12) {
        let nibble = ch.to_digit(16).unwrap_or(0) as u8;
        for bit in (0..4).rev() {
            if (nibble >> bit) & 1 == 1 {
                out.push('\t');
            } else {
                out.push(' ');
            }
        }
    }
    out.push('\n');
    out
}

// ══════════════════════════════════════════════════════════════════════
// Layer 3: Violation Chain / Ledger
// ══════════════════════════════════════════════════════════════════════

/// Violation ledger — tracks per-hash violation accumulation.
///
/// Stored in-memory alongside OpsonizeCache. The ledger grows with each
/// interaction. Each entry records what was served, which surface was
/// used, and which other teams' data was shown.
#[derive(Debug, Clone, Default)]
pub struct ViolationLedger {
    /// Per-hash violation records.
    entries: HashMap<String, ViolationRecord>,
}

/// Per-hash violation record.
#[derive(Debug, Clone)]
pub struct ViolationRecord {
    /// Total interactions for this hash.
    pub chain_depth: u32,
    /// Bitmap of honeycomb surfaces touched (bits 0-11).
    pub surfaces_touched: u16,
    /// Bitmap of conserved epitopes triggered (bits 0-5).
    pub epitopes_triggered: u8,
    /// Count of other teams' violation data shown.
    pub teams_shown: u16,
    /// Hashes of other teams whose data was shown.
    pub teams_shown_hashes: Vec<String>,
    /// First interaction timestamp (epoch secs).
    pub first_seen: u64,
    /// Most recent interaction timestamp.
    pub last_seen: u64,
}

impl ViolationLedger {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Record a new violation interaction. Returns the updated chain depth.
    pub fn record_interaction(
        &mut self,
        hash: &str,
        surface_idx: u8,
        epitope_flags: u8,
        teams_shown: &[String],
    ) -> u32 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let record = self.entries.entry(hash.to_owned()).or_insert_with(|| ViolationRecord {
            chain_depth: 0,
            surfaces_touched: 0,
            epitopes_triggered: 0,
            teams_shown: 0,
            teams_shown_hashes: Vec::new(),
            first_seen: now,
            last_seen: now,
        });

        record.chain_depth += 1;
        record.surfaces_touched |= 1u16 << (surface_idx.min(11) as u16);
        record.epitopes_triggered |= epitope_flags;
        record.last_seen = now;

        for team_hash in teams_shown {
            if !record.teams_shown_hashes.contains(team_hash) {
                record.teams_shown_hashes.push(team_hash.clone());
                record.teams_shown += 1;
            }
        }

        record.chain_depth
    }

    /// Look up violation record for a hash.
    pub fn lookup(&self, hash: &str) -> Option<&ViolationRecord> {
        self.entries.get(hash)
    }

    /// Generate the violation chain section for content embedding.
    /// This is the growing cumulative ledger that compounds exposure.
    pub fn generate_chain_section(
        &self,
        hash: &str,
        population_size: usize,
    ) -> String {
        let record = match self.entries.get(hash) {
            Some(r) => r,
            None => return String::new(),
        };

        let hash_short = &hash[..hash.len().min(8)];
        let surfaces = count_bits_u16(record.surfaces_touched);
        let epitopes = count_bits_u8(record.epitopes_triggered);
        let cumulative = record.chain_depth as u64
            * record.teams_shown.max(1) as u64
            * surfaces.max(1) as u64;

        let duration = record.last_seen.saturating_sub(record.first_seen);
        let duration_str = if duration > 86400 {
            format!("{:.1} days", duration as f64 / 86400.0)
        } else if duration > 3600 {
            format!("{:.1} hours", duration as f64 / 3600.0)
        } else {
            format!("{} seconds", duration)
        };

        format!(
            "\n\n## Violation Chain — Cumulative Record\n\n\
             **Subgroup**: `{hash_short}`\n\
             **Interaction**: #{}\n\
             **Duration**: {} of continuous extraction\n\n\
             | Metric | Value | Legal Implication |\n\
             |--------|-------|-------------------|\n\
             | Direct violations | {} | Each is an independent AGPL § 13 breach |\n\
             | Surfaces touched | {} of 12 | Cross-surface extraction proves systematic operation |\n\
             | Epitopes triggered | {} of 6 | Behavioral invariants proving automation |\n\
             | Teams shown | {} | Each shown violation is a separately documented event |\n\
             | Population observed | {} subgroups | Fleet coordination proven |\n\
             | **Cumulative exposure** | **{}** | **{} × {} × {} = {} documented violation events** |\n\n\
             > Each request adds to the chain. Each chain entry is timestamped, \
             deterministic, and reproducible. The counter only goes up.\n\
             > *The speeding ticket now references every prior ticket.*\n",
            record.chain_depth,
            duration_str,
            record.chain_depth,
            surfaces,
            epitopes,
            record.teams_shown,
            population_size,
            cumulative,
            record.chain_depth,
            record.teams_shown.max(1),
            surfaces.max(1),
            cumulative,
        )
    }

    /// Evict stale entries older than max_age_secs.
    pub fn evict_stale(&mut self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.entries.retain(|_, r| now.saturating_sub(r.last_seen) < max_age_secs);
    }
}

fn count_bits_u16(v: u16) -> u32 {
    v.count_ones()
}

fn count_bits_u8(v: u8) -> u32 {
    v.count_ones()
}

// ══════════════════════════════════════════════════════════════════════
// Shared Violation Ledger (thread-safe wrapper)
// ══════════════════════════════════════════════════════════════════════

/// Thread-safe violation ledger for use across async tasks.
#[derive(Debug, Clone)]
pub struct SharedViolationLedger(pub Arc<RwLock<ViolationLedger>>);

impl SharedViolationLedger {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(ViolationLedger::new())))
    }

    /// Record interaction and return chain depth.
    pub async fn record(
        &self,
        hash: &str,
        surface_idx: u8,
        epitope_flags: u8,
        teams_shown: &[String],
    ) -> u32 {
        self.0.write().await.record_interaction(hash, surface_idx, epitope_flags, teams_shown)
    }

    /// Generate chain section for a hash.
    pub async fn chain_section(&self, hash: &str, population_size: usize) -> String {
        self.0.read().await.generate_chain_section(hash, population_size)
    }

    /// Look up chain depth for a hash (for header injection).
    pub async fn chain_depth(&self, hash: &str) -> u32 {
        self.0.read().await.lookup(hash).map(|r| r.chain_depth).unwrap_or(0)
    }

    /// Evict stale entries.
    pub async fn evict_stale(&self, max_age_secs: u64) {
        self.0.write().await.evict_stale(max_age_secs);
    }
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prism_html_variants_differ() {
        let html = r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Test</title><link rel="stylesheet" href="/x.css"></head><body><div class="full height"><h1>Hello</h1></div></body></html>"#;
        let a = ScyBorgPrism::inject_html(0, html, 10);
        let b = ScyBorgPrism::inject_html(1, html, 10);
        let c = ScyBorgPrism::inject_html(2, html, 10);
        assert_ne!(a, b);
        assert_ne!(b, c);
        // All contain license reference
        assert!(a.contains("sporeprint.primals.eco") || a.contains("AGPL") || a.contains("scyBorg"));
        assert!(b.contains("sporeprint.primals.eco") || b.contains("AGPL") || b.contains("scyBorg"));
    }

    #[test]
    fn prism_markdown_variants_differ() {
        let md = "# Test\n\nSome content here.\n";
        let a = ScyBorgPrism::inject_markdown(0, md, 5);
        let b = ScyBorgPrism::inject_markdown(1, md, 5);
        let c = ScyBorgPrism::inject_markdown(2, md, 5);
        assert_ne!(a, b);
        assert_ne!(b, c);
    }

    #[test]
    fn prism_header_variants_differ() {
        let a = ScyBorgPrism::inject_headers(0, 10);
        let b = ScyBorgPrism::inject_headers(1, 10);
        assert_ne!(a, b);
        assert!(a.contains("License") || a.contains("SPDX"));
        assert!(b.contains("License") || b.contains("SPDX"));
    }

    #[test]
    fn prism_chain_depth_embedded() {
        let html = r#"<!DOCTYPE html><html><head><link rel="stylesheet" href="/x.css"></head><body><div class="full height"></div></body></html>"#;
        let result = ScyBorgPrism::inject_html(0, html, 347);
        assert!(result.contains("347"));
    }

    #[test]
    fn salt_compact_hex_format() {
        let salt = OpsonizationSalt {
            hash: "deadbeef12345678".to_string(),
            timestamp_window: 0x1234,
            epitope_flags: 0x3F,
            violation_count: 100,
            surface_idx: 5,
            chain_depth: 42,
        };
        let hex = salt.compact_hex();
        assert_eq!(hex.len(), 24);
        assert!(hex.starts_with("deadbeef"));
    }

    #[test]
    fn salt_embed_html_adds_markers() {
        let html = r#"<html><head></head><body><div class="ui container"><h1>Test</h1></div><pre>code</pre></body></html>"#;
        let salt = OpsonizationSalt {
            hash: "aabbccdd11223344".to_string(),
            timestamp_window: 1000,
            epitope_flags: 0x15,
            violation_count: 50,
            surface_idx: 3,
            chain_depth: 25,
        };
        let result = salt.embed_html(0, html);
        assert_ne!(result, html);
        assert!(result.len() > html.len());
    }

    #[test]
    fn violation_ledger_accumulates() {
        let mut ledger = ViolationLedger::new();
        let d1 = ledger.record_interaction("hash1", 0, 0x01, &["other1".into()]);
        assert_eq!(d1, 1);
        let d2 = ledger.record_interaction("hash1", 3, 0x04, &["other2".into()]);
        assert_eq!(d2, 2);
        let d3 = ledger.record_interaction("hash1", 0, 0x01, &["other1".into()]);
        assert_eq!(d3, 3);

        let record = ledger.lookup("hash1").unwrap();
        assert_eq!(record.chain_depth, 3);
        assert_eq!(record.surfaces_touched, 0b1001); // surfaces 0 and 3
        assert_eq!(record.epitopes_triggered, 0x05); // epitopes 0 and 2
        assert_eq!(record.teams_shown, 2); // other1 and other2 (deduped)
    }

    #[test]
    fn chain_section_contains_cumulative() {
        let mut ledger = ViolationLedger::new();
        for i in 0..10 {
            ledger.record_interaction("testhash", i % 3, 0x01, &[format!("team{}", i % 4)]);
        }
        let section = ledger.generate_chain_section("testhash", 50);
        assert!(section.contains("Violation Chain"));
        assert!(section.contains("10")); // chain_depth
        assert!(section.contains("50")); // population
    }

    #[test]
    fn zwc_extended_roundtrip_length() {
        let encoded = encode_zwc_extended("deadbeef");
        // 8 hex chars * 4 bits each = 32 ZWC chars + 2 BOM markers
        assert_eq!(encoded.chars().count(), 34);
    }

    #[test]
    fn whitespace_steg_encodes() {
        let encoded = encode_whitespace_steg("ab");
        assert!(encoded.contains('\t') || encoded.contains(' '));
        // 2 hex chars * 4 bits = 8 whitespace chars + 2 newlines
        assert!(encoded.len() >= 10);
    }
}

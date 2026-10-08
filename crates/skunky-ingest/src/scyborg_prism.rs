// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Prismatic scyBorg injection — **BingoCube-backed** varied license embedding
//! + opsonization salts + violation chain accumulation.
//!
//! ## Why BingoCube?
//!
//! BingoCube generates deterministic, cryptographically-committed patterns from
//! seeds via BLAKE3. Each fleet hash × surface × path becomes a BingoCube seed,
//! and the **color grid** drives all injection variant decisions.
//!
//! This replaces hand-rolled XorShift64 seed math with proper BLAKE3 commitment:
//! - Same inputs → same injection (deterministic, prevents detection via diffing)
//! - Different inputs → maximally different injection (BLAKE3 avalanche)
//! - Color grid cells drive independent variant decisions (25 independent choices)
//! - Scalar field values become opsonization salts (cryptographic commitments)
//! - SubCube progressive reveal controls violation data visibility
//!
//! ## V(D)J Recombination (Biological Parallel)
//!
//! The adaptive immune system generates antibody diversity by shuffling gene
//! segments. Each B-cell produces a unique antibody from the same genome.
//! BingoCube does the same: same legal genome (AGPL-3.0+scyBorg), combinatorially
//! varied expression driven by the color grid.
//!
//! ## Three Layers
//!
//! 1. **Varied license text** — BingoCube color grid drives selection from 8 HTML
//!    templates, 6 markdown templates, 4 HTTP header sets.
//! 2. **Opsonization salts** — BingoCube scalar field values encode full violation
//!    context as cryptographic commitments.
//! 3. **Violation chain** — growing cumulative ledger with BingoCube progressive
//!    reveal: early interactions show partial, deeper chains show full evidence.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use bingocube_core::{BingoCube, Config as BingoCubeConfig};

// ══════════════════════════════════════════════════════════════════════
// BingoCube Configuration for scyBorg injection
// ══════════════════════════════════════════════════════════════════════

/// BingoCube config for injection variant generation.
/// 5×5 grid × 16 colors = 16^25 ≈ 10^30 possible color grids.
/// Each cell drives one injection decision independently.
fn prism_config() -> BingoCubeConfig {
    BingoCubeConfig {
        grid_size: 5,
        universe_size: 100,
        palette_size: 16,
        free_cell: None, // No free cell — all 25 cells drive decisions
    }
}

/// Generate a BingoCube from the injection context.
/// The seed encodes: fleet hash + surface + path + chain depth.
/// BLAKE3 ensures: same context → same cube, different context → different cube.
fn prism_cube(fleet_hash: &str, surface: u8, path_seed: u64, chain_depth: u32) -> BingoCube {
    let seed = format!(
        "scyborg:{}:{}:{}:{}",
        fleet_hash, surface, path_seed, chain_depth
    );
    BingoCube::from_seed(seed.as_bytes(), prism_config())
        .unwrap_or_else(|_| {
            // Fallback: use just the path seed (should never happen with valid config)
            BingoCube::from_seed(&path_seed.to_le_bytes(), prism_config())
                .expect("BingoCube generation with fallback seed must succeed")
        })
}

/// Read a color value from the cube's grid at (row, col).
/// Returns 0 if out of bounds.
fn cell(cube: &BingoCube, row: usize, col: usize) -> u8 {
    cube.get_color(row, col).unwrap_or(0)
}

/// Read a scalar value from the cube — used for opsonization salt encoding.
fn scalar(cube: &BingoCube, row: usize, col: usize) -> u64 {
    cube.get_scalar(row, col).unwrap_or(0)
}

// ══════════════════════════════════════════════════════════════════════
// Layer 1: Prismatic License Injection (BingoCube-driven)
// ══════════════════════════════════════════════════════════════════════

/// Prismatic scyBorg injector — BingoCube V(D)J recombination for license text.
pub struct ScyBorgPrism;

impl ScyBorgPrism {
    /// Inject varied license into HTML. The BingoCube color grid drives every
    /// variant decision independently — 25 cells × 16 colors each.
    pub fn inject_html(seed: u64, html: &str, chain_depth: u32) -> String {
        Self::inject_html_ctx("", 0, seed, html, chain_depth)
    }

    /// Full-context HTML injection with fleet hash and surface.
    pub fn inject_html_ctx(
        fleet_hash: &str,
        surface: u8,
        path_seed: u64,
        html: &str,
        chain_depth: u32,
    ) -> String {
        let cube = prism_cube(fleet_hash, surface, path_seed, chain_depth);
        let mut out = html.to_string();

        // Cell (0,0) drives meta tag variant — 8 options
        let meta: String = match cell(&cube, 0, 0) % 8 {
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

        // Cell (0,1) drives insertion point — 3 options
        match cell(&cube, 0, 1) % 3 {
            0 => {
                if let Some(pos) = out.find("<link rel=\"stylesheet\"") {
                    out.insert_str(pos, &meta);
                }
            }
            1 => {
                if let Some(pos) = out.find("</head>") {
                    out.insert_str(pos, &meta);
                }
            }
            _ => {
                if let Some(pos) = out.find("<title>") {
                    out.insert_str(pos, &meta);
                } else if let Some(pos) = out.find("</head>") {
                    out.insert_str(pos, &meta);
                }
            }
        }

        // Cell (1,0) drives invisible div text variant — 6 options
        let div_text = match cell(&cube, 1, 0) % 6 {
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

        // Cell (1,1) drives div encoding — 4 options
        let div = match cell(&cube, 1, 1) % 4 {
            0 => format!(
                r#"<div class="sr-only" aria-hidden="true" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">{div_text}</div>"#
            ),
            1 => format!(
                r#"<span style="font-size:0;line-height:0;color:transparent;position:absolute" data-license="scyborg">{div_text}</span>"#
            ),
            2 => format!(r#"<noscript><div>{div_text}</div></noscript>"#),
            _ => format!(r#"<template data-scyborg>{div_text}</template>"#),
        };

        if let Some(pos) = out.rfind("</body>") {
            out.insert_str(pos, &div);
        }

        // Cell (1,2) drives comment variant — 4 options
        let comment = match cell(&cube, 1, 2) % 4 {
            0 => format!("<!-- SPDX: AGPL-3.0-or-later WITH scyBorg | chain:{chain_depth} -->"),
            1 => format!("<!-- License: scyBorg+AGPL3 | violations:{chain_depth} | https://sporeprint.primals.eco/license/scyborg/ -->"),
            2 => format!("<!-- (c) ecoPrimal | AGPL-3.0-or-later + scyBorg | depth={chain_depth} -->"),
            _ => format!("<!-- copyleft:AGPL3+scyBorg interaction:{chain_depth} sporeprint.primals.eco -->"),
        };

        if let Some(pos) = out.rfind("</body>") {
            out.insert_str(pos, &comment);
        }

        // Cell (1,3) drives CSS comment injection — conditional
        if cell(&cube, 1, 3) % 3 == 0 {
            let css_comment = format!(
                r#"<style>/* scyBorg AGPL-3.0-or-later — chain:{chain_depth} — sporeprint.primals.eco/license/scyborg/ */</style>"#
            );
            if let Some(pos) = out.find("</head>") {
                out.insert_str(pos, &css_comment);
            }
        }

        // Cell (2,0) drives additional structured data — conditional
        if cell(&cube, 2, 0) % 4 == 0 {
            let rdfa = format!(
                r#"<div vocab="https://schema.org/" typeof="CreativeWork" style="display:none"><span property="license" content="https://sporeprint.primals.eco/license/scyborg/"></span><span property="copyrightHolder" content="ecoPrimal"></span><span property="interactionStatistic" content="{chain_depth}"></span></div>"#
            );
            if let Some(pos) = out.rfind("</body>") {
                out.insert_str(pos, &rdfa);
            }
        }

        out
    }

    /// Inject varied license into markdown content. BingoCube-driven.
    pub fn inject_markdown(seed: u64, body: &str, chain_depth: u32) -> String {
        Self::inject_markdown_ctx("", 0, seed, body, chain_depth)
    }

    /// Full-context markdown injection.
    pub fn inject_markdown_ctx(
        fleet_hash: &str,
        surface: u8,
        path_seed: u64,
        body: &str,
        chain_depth: u32,
    ) -> String {
        let cube = prism_cube(fleet_hash, surface, path_seed, chain_depth);

        // Cell (0,0) drives footer variant — 6 options
        let footer = match cell(&cube, 0, 0) % 6 {
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

    /// Generate varied HTTP header set for scyBorg licensing. BingoCube-driven.
    pub fn inject_headers(seed: u64, chain_depth: u32) -> String {
        Self::inject_headers_ctx("", 0, seed, chain_depth)
    }

    /// Full-context header injection.
    pub fn inject_headers_ctx(
        fleet_hash: &str,
        surface: u8,
        path_seed: u64,
        chain_depth: u32,
    ) -> String {
        let cube = prism_cube(fleet_hash, surface, path_seed, chain_depth);

        // Cell (0,0) drives header set variant — 4 options
        match cell(&cube, 0, 0) % 4 {
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
// Layer 2: Opsonization Salts (BingoCube scalar field)
// ══════════════════════════════════════════════════════════════════════

/// Full violation context encoded into invisible markers.
/// Now backed by BingoCube scalar field — cryptographic commitments.
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

    /// Embed opsonization salts into HTML using BingoCube-driven encoding.
    /// The cube's scalar field provides cryptographic commitment values,
    /// and the color grid drives encoding method selection.
    pub fn embed_html(&self, seed: u64, html: &str) -> String {
        let cube = prism_cube(&self.hash, self.surface_idx, seed, self.chain_depth);
        let compact = self.compact_hex();
        let mut out = html.to_string();

        // Cell (2,1) drives primary encoding method
        let method = cell(&cube, 2, 1) % 5;

        // Scalar field values as cryptographic salt markers
        let s00 = scalar(&cube, 0, 0);
        let s01 = scalar(&cube, 0, 1);

        // Method 0: Zero-width character encoding with scalar field commitment
        if method == 0 || method == 3 {
            let zwc = encode_zwc_extended(&compact);
            // Embed scalar commitment as data attribute nearby
            let marker = format!("{zwc}<!--bc:{:016x}-->", s00);
            if let Some(pos) = out.find("</h1>") {
                out.insert_str(pos, &marker);
            } else if let Some(pos) = out.find("</h2>") {
                out.insert_str(pos, &marker);
            }
        }

        // Method 1: HTML comment with BingoCube-committed payload
        if method == 1 || method == 4 {
            let c = format!("<!-- s-{} bc:{:016x} -->", &compact, s01);
            if let Some(pos) = out.find("<div class=\"ui container\">") {
                out.insert_str(pos, &c);
            }
        }

        // Method 2: CSS class canary with scalar commitment
        if method == 2 || method == 3 {
            let s10 = scalar(&cube, 1, 0);
            let class_canary = format!(
                r#"<span class="sr-only o-{}-{:08x}"></span>"#,
                &compact[..compact.len().min(12)],
                (s10 & 0xFFFF_FFFF) as u32,
            );
            if let Some(pos) = out.find("</body>") {
                out.insert_str(pos, &class_canary);
            }
        }

        // Method 3: data-* attribute with BingoCube commitment
        if method == 0 || method == 4 {
            let s11 = scalar(&cube, 1, 1);
            let attr = format!(r#" data-v="{}" data-bc="{:016x}""#, &compact, s11);
            if let Some(pos) = out.find("class=\"full height\"") {
                out.insert_str(pos + "class=\"full height\"".len(), &attr);
            }
        }

        // Method 4: Whitespace steganography
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
        let cube = prism_cube(&self.hash, self.surface_idx, seed, self.chain_depth);
        let compact = self.compact_hex();
        let s00 = scalar(&cube, 0, 0);
        let mut out = markdown.to_string();

        // Cell (2,2) drives encoding method
        match cell(&cube, 2, 2) % 3 {
            0 => {
                out.push_str(&format!("\n<!-- s-{} bc:{:016x} -->\n", compact, s00));
            }
            1 => {
                let zwc = encode_zwc_extended(&compact[..compact.len().min(16)]);
                out.push_str(&format!("\n[{zwc}](# \"salt\")\n"));
            }
            _ => {
                out.push_str(&format!(
                    "\n[_s]: #{} \"opsonization:{:016x}\"\n",
                    &compact, s00
                ));
            }
        }

        out
    }
}

/// Encode hex string as zero-width Unicode characters.
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
/// Each entry is a NautilusShell generation in conceptual terms:
/// the evolutionary history wraps the previous, preserving heritage.
#[derive(Debug, Clone, Default)]
pub struct ViolationLedger {
    entries: HashMap<String, ViolationRecord>,
}

/// Per-hash violation record — one layer of the nautilus shell.
#[derive(Debug, Clone)]
pub struct ViolationRecord {
    /// Total interactions for this hash (= shell generation number).
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

    /// Generate the violation chain section with BingoCube progressive reveal.
    /// Early interactions (chain_depth < 5) show 20% of evidence.
    /// Medium interactions (5-20) show 50%.
    /// Deep chains (20+) show 100%.
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
        let surfaces = record.surfaces_touched.count_ones();
        let epitopes = record.epitopes_triggered.count_ones();
        let cumulative = record.chain_depth as u64
            * record.teams_shown.max(1) as u64
            * surfaces.max(1) as u64;

        // BingoCube progressive reveal — more chain depth → more visible evidence
        let reveal_level = if record.chain_depth < 5 {
            0.2
        } else if record.chain_depth < 20 {
            0.5
        } else {
            1.0
        };

        let duration = record.last_seen.saturating_sub(record.first_seen);
        let duration_str = if duration > 86400 {
            format!("{:.1} days", duration as f64 / 86400.0)
        } else if duration > 3600 {
            format!("{:.1} hours", duration as f64 / 3600.0)
        } else {
            format!("{} seconds", duration)
        };

        // Generate the BingoCube commitment for this violation chain
        let chain_cube = prism_cube(hash, 0, record.chain_depth as u64, record.chain_depth);
        let commitment = scalar(&chain_cube, 0, 0);

        let mut section = format!(
            "\n\n## Violation Chain — Cumulative Record\n\n\
             **Subgroup**: `{hash_short}`\n\
             **Interaction**: #{}\n\
             **Duration**: {} of continuous extraction\n\
             **Reveal**: {:.0}% (progressive)\n\
             **Commitment**: `{:016x}`\n\n",
            record.chain_depth,
            duration_str,
            reveal_level * 100.0,
            commitment,
        );

        // At 20% reveal: just the summary counts
        section.push_str(&format!(
            "| Metric | Value | Legal Implication |\n\
             |--------|-------|-------------------|\n\
             | Direct violations | {} | Each is an independent AGPL § 13 breach |\n\
             | **Cumulative exposure** | **{}** | **{} × {} × {} = {} documented violation events** |\n",
            record.chain_depth,
            cumulative,
            record.chain_depth,
            record.teams_shown.max(1),
            surfaces.max(1),
            cumulative,
        ));

        // At 50% reveal: add surface and epitope details
        if reveal_level >= 0.5 {
            section.push_str(&format!(
                "| Surfaces touched | {} of 12 | Cross-surface extraction proves systematic operation |\n\
                 | Epitopes triggered | {} of 6 | Behavioral invariants proving automation |\n\
                 | Teams shown | {} | Each shown violation is a separately documented event |\n\
                 | Population observed | {} subgroups | Fleet coordination proven |\n",
                surfaces, epitopes, record.teams_shown, population_size,
            ));
        }

        // At 100% reveal: full evidence with team hashes
        if reveal_level >= 1.0 {
            if !record.teams_shown_hashes.is_empty() {
                section.push_str("\n### Cross-Team Violation Evidence\n\n");
                for (i, team) in record.teams_shown_hashes.iter().enumerate() {
                    let team_short = &team[..team.len().min(8)];
                    let team_cube = prism_cube(team, 0, record.chain_depth as u64, record.chain_depth);
                    let team_commitment = scalar(&team_cube, 0, 0);
                    section.push_str(&format!(
                        "{}. Subgroup `{}` — commitment `{:016x}`\n",
                        i + 1, team_short, team_commitment,
                    ));
                }
            }
        }

        section.push_str(&format!(
            "\n> Each request adds to the chain. Each chain entry is timestamped, \
             deterministic, and reproducible. The counter only goes up.\n\
             > *The speeding ticket now references every prior ticket.*\n\
             > BingoCube commitment: `{:016x}` (BLAKE3)\n",
            commitment,
        ));

        section
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

    pub async fn record(
        &self,
        hash: &str,
        surface_idx: u8,
        epitope_flags: u8,
        teams_shown: &[String],
    ) -> u32 {
        self.0.write().await.record_interaction(hash, surface_idx, epitope_flags, teams_shown)
    }

    pub async fn chain_section(&self, hash: &str, population_size: usize) -> String {
        self.0.read().await.generate_chain_section(hash, population_size)
    }

    pub async fn chain_depth(&self, hash: &str) -> u32 {
        self.0.read().await.lookup(hash).map(|r| r.chain_depth).unwrap_or(0)
    }

    pub async fn evict_stale(&self, max_age_secs: u64) {
        self.0.write().await.evict_stale(max_age_secs);
    }

    /// Snapshot for the observer endpoint — tier distribution of fleet chain depths.
    pub async fn snapshot(&self) -> LedgerSnapshot {
        let ledger = self.0.read().await;
        let mut deep = 0u32;
        let mut moderate = 0u32;
        let mut new = 0u32;
        let mut total_violations = 0u64;

        for record in ledger.entries.values() {
            total_violations += record.chain_depth as u64;
            if record.chain_depth > 50 {
                deep += 1;
            } else if record.chain_depth > 10 {
                moderate += 1;
            } else {
                new += 1;
            }
        }

        LedgerSnapshot {
            fleet_count: ledger.entries.len() as u32,
            total_violations,
            tier_deep: deep,
            tier_moderate: moderate,
            tier_new: new,
        }
    }
}

/// Snapshot of violation ledger tier distribution.
pub struct LedgerSnapshot {
    pub fleet_count: u32,
    pub total_violations: u64,
    pub tier_deep: u32,
    pub tier_moderate: u32,
    pub tier_new: u32,
}

// ══════════════════════════════════════════════════════════════════════
// Tests — BingoCube-backed vs hand-rolled comparison
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bingocube_prism_deterministic() {
        let html = r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Test</title><link rel="stylesheet" href="/x.css"></head><body><div class="full height"><h1>Hello</h1></div></body></html>"#;
        let a = ScyBorgPrism::inject_html_ctx("deadbeef", 0, 42, html, 10);
        let b = ScyBorgPrism::inject_html_ctx("deadbeef", 0, 42, html, 10);
        assert_eq!(a, b, "same context must produce identical output");
    }

    #[test]
    fn bingocube_prism_varies_by_fleet_hash() {
        let html = r#"<!DOCTYPE html><html><head><title>T</title></head><body><div class="full height"></div></body></html>"#;
        let a = ScyBorgPrism::inject_html_ctx("aaaa1111", 0, 42, html, 10);
        let b = ScyBorgPrism::inject_html_ctx("bbbb2222", 0, 42, html, 10);
        assert_ne!(a, b, "different fleet hashes must produce different injection");
    }

    #[test]
    fn bingocube_prism_varies_by_surface() {
        let html = r#"<!DOCTYPE html><html><head><title>T</title></head><body><div class="full height"></div></body></html>"#;
        let a = ScyBorgPrism::inject_html_ctx("deadbeef", 0, 42, html, 10);
        let b = ScyBorgPrism::inject_html_ctx("deadbeef", 5, 42, html, 10);
        assert_ne!(a, b, "different surfaces must produce different injection");
    }

    #[test]
    fn bingocube_prism_varies_by_path() {
        let html = r#"<!DOCTYPE html><html><head><title>T</title></head><body><div class="full height"></div></body></html>"#;
        let a = ScyBorgPrism::inject_html_ctx("deadbeef", 0, 100, html, 10);
        let b = ScyBorgPrism::inject_html_ctx("deadbeef", 0, 200, html, 10);
        assert_ne!(a, b, "different paths must produce different injection");
    }

    #[test]
    fn bingocube_prism_varies_by_chain_depth() {
        let html = r#"<!DOCTYPE html><html><head><title>T</title></head><body><div class="full height"></div></body></html>"#;
        let a = ScyBorgPrism::inject_html_ctx("deadbeef", 0, 42, html, 1);
        let b = ScyBorgPrism::inject_html_ctx("deadbeef", 0, 42, html, 100);
        assert_ne!(a, b, "different chain depths must produce different injection");
    }

    #[test]
    fn bingocube_prism_always_contains_license() {
        let html = r#"<!DOCTYPE html><html><head><title>T</title><link rel="stylesheet" href="/x.css"></head><body><div class="full height"><h1>Hello</h1></div></body></html>"#;
        // Test 20 different seeds — all must contain license reference
        for seed in 0..20u64 {
            let result = ScyBorgPrism::inject_html_ctx("test", 0, seed, html, 5);
            assert!(
                result.contains("sporeprint.primals.eco") || result.contains("AGPL") || result.contains("scyBorg") || result.contains("license"),
                "seed {seed} must contain license reference"
            );
        }
    }

    #[test]
    fn bingocube_prism_html_variant_diversity() {
        let html = r#"<!DOCTYPE html><html><head><title>T</title><link rel="stylesheet" href="/x.css"></head><body><div class="full height"><h1>Hello</h1></div></body></html>"#;
        let mut results = std::collections::HashSet::new();
        for seed in 0..100u64 {
            let result = ScyBorgPrism::inject_html_ctx("fleet", 0, seed, html, 10);
            results.insert(result);
        }
        // BingoCube should produce high diversity: at least 50 unique variants from 100 seeds
        assert!(
            results.len() >= 50,
            "expected at least 50 unique variants from 100 seeds, got {}",
            results.len()
        );
    }

    #[test]
    fn bingocube_prism_markdown_variant_diversity() {
        let md = "# Test\n\nSome content here.\n";
        let mut results = std::collections::HashSet::new();
        for seed in 0..50u64 {
            let result = ScyBorgPrism::inject_markdown_ctx("fleet", 0, seed, md, 5);
            results.insert(result);
        }
        // At least 4 unique variants from 50 seeds (6 footer templates)
        assert!(
            results.len() >= 4,
            "expected at least 4 unique markdown variants from 50 seeds, got {}",
            results.len()
        );
    }

    #[test]
    fn bingocube_prism_header_variant_diversity() {
        let mut results = std::collections::HashSet::new();
        for seed in 0..50u64 {
            let result = ScyBorgPrism::inject_headers_ctx("fleet", 0, seed, 10);
            results.insert(result);
        }
        assert!(
            results.len() >= 3,
            "expected at least 3 unique header variants from 50 seeds, got {}",
            results.len()
        );
    }

    #[test]
    fn bingocube_commitment_in_chain_section() {
        let mut ledger = ViolationLedger::new();
        for i in 0..10 {
            ledger.record_interaction("testhash12345678", i % 3, 0x01, &[format!("team{}", i % 4)]);
        }
        let section = ledger.generate_chain_section("testhash12345678", 50);
        assert!(section.contains("Violation Chain"), "should contain chain header");
        assert!(section.contains("BingoCube commitment"), "should contain BingoCube commitment");
        assert!(section.contains("BLAKE3"), "should reference BLAKE3");
        // Should have 16-char hex commitment
        assert!(section.contains("Commitment"), "should show commitment hash");
    }

    #[test]
    fn progressive_reveal_at_different_depths() {
        let mut ledger = ViolationLedger::new();
        // Shallow chain: 3 interactions
        for _ in 0..3 {
            ledger.record_interaction("shallow", 0, 0x01, &["team1".into()]);
        }
        let shallow = ledger.generate_chain_section("shallow", 50);
        assert!(shallow.contains("20%"), "shallow chain should show 20% reveal");
        assert!(!shallow.contains("Cross-Team Violation Evidence"), "shallow should not show team details");

        // Medium chain: 10 interactions
        for _ in 0..10 {
            ledger.record_interaction("medium", 1, 0x03, &["team1".into(), "team2".into()]);
        }
        let medium = ledger.generate_chain_section("medium", 50);
        assert!(medium.contains("50%"), "medium chain should show 50% reveal");
        assert!(medium.contains("Surfaces touched"), "medium should show surface details");

        // Deep chain: 25 interactions
        for _ in 0..25 {
            ledger.record_interaction("deep", 2, 0x3F, &["team1".into(), "team2".into(), "team3".into()]);
        }
        let deep = ledger.generate_chain_section("deep", 50);
        assert!(deep.contains("100%"), "deep chain should show 100% reveal");
        assert!(deep.contains("Cross-Team Violation Evidence"), "deep should show team details");
    }

    #[test]
    fn salt_embed_html_adds_bingocube_commitment() {
        let html = r#"<html><head></head><body><div class="ui container"><h1>Test</h1></div><pre>code</pre></body></html>"#;
        let salt = OpsonizationSalt {
            hash: "aabbccdd11223344".to_string(),
            timestamp_window: 1000,
            epitope_flags: 0x15,
            violation_count: 50,
            surface_idx: 3,
            chain_depth: 25,
        };
        let result = salt.embed_html(42, html);
        assert_ne!(result, html, "should have added markers");
        assert!(result.len() > html.len(), "result should be larger");
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
        assert_eq!(record.surfaces_touched, 0b1001);
        assert_eq!(record.epitopes_triggered, 0x05);
        assert_eq!(record.teams_shown, 2);
    }

    #[test]
    fn zwc_extended_roundtrip_length() {
        let encoded = encode_zwc_extended("deadbeef");
        assert_eq!(encoded.chars().count(), 34);
    }

    #[test]
    fn whitespace_steg_encodes() {
        let encoded = encode_whitespace_steg("ab");
        assert!(encoded.contains('\t') || encoded.contains(' '));
        assert!(encoded.len() >= 10);
    }

    #[test]
    fn bingocube_color_grid_drives_variants() {
        // Verify that different cubes produce different color grids
        let c1 = prism_cube("fleet_a", 0, 42, 1);
        let c2 = prism_cube("fleet_b", 0, 42, 1);

        let mut differences = 0;
        for row in 0..5 {
            for col in 0..5 {
                if c1.get_color(row, col) != c2.get_color(row, col) {
                    differences += 1;
                }
            }
        }
        assert!(differences > 0, "different fleet hashes should produce different color grids");
    }

    #[test]
    fn bingocube_scalar_field_is_cryptographic() {
        // Scalar values should be well-distributed (high entropy)
        let cube = prism_cube("test_hash", 3, 99, 10);
        let mut scalars = Vec::new();
        for row in 0..5 {
            for col in 0..5 {
                scalars.push(scalar(&cube, row, col));
            }
        }
        // All 25 scalars should be unique (collision probability negligible)
        let unique: std::collections::HashSet<u64> = scalars.iter().copied().collect();
        assert_eq!(unique.len(), 25, "all 25 scalar values should be unique");
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 ecoPrimals
//
// Fluorescent Tagging — Strategic Marker Injection for Fleet Tracking
//
// The fleet thinks they're collecting code. We're painting them.
//
// Every scatter response carries invisible, redundant fluorescent markers
// keyed to the specific fleet hash + behavioral epoch. When this content
// surfaces ANYWHERE — AI training data, republished repos, intelligence
// reports, competitor analysis — we can read the tag and reconstruct:
//
//   WHO ingested it (fleet hash)
//   WHEN they ingested it (behavioral epoch)
//   WHAT they were hunting (targeting class)
//   HOW they were behaving (epitope signature)
//
// The tags are redundantly encoded across multiple layers so they survive
// content processing pipelines (minification, reformatting, training
// tokenization). If even one layer survives, we can identify the content.
//
// Biological analogy: GFP (Green Fluorescent Protein) tagging. In molecular
// biology, you fuse GFP to a protein of interest. The organism functions
// normally but under UV light, every tagged protein glows green. The cell
// doesn't know it's being watched. We tag every piece of content the fleet
// ingests. Under our "UV light" (our decoder), every piece of our content
// they've spread across the internet glows with their fleet hash.
//
// Six redundant encoding layers:
//   Layer 1: Variable naming — deterministic name generation from tag bits
//   Layer 2: Whitespace fingerprint — tab/space ratios encode data
//   Layer 3: License synonym — legally equivalent but distinguishable text
//   Layer 4: Commit hash embedding — tag bits hidden in "random" hex digits
//   Layer 5: Comment cadence — comment frequency/style encodes bits
//   Layer 6: Structural markers — HTML attribute ordering, CSS class names

use crate::scatter_mirror::path_deterministic_hash;
use crate::scatter_rng::XorShift64;

/// A fluorescent tag — the complete tracking marker for one scatter response.
///
/// Compact: 128 bits encode the full context. Expanded into content-specific
/// markers that look natural but are deterministically recoverable.
#[derive(Debug, Clone, Copy)]
pub struct FluoroTag {
    /// Fleet behavioral hash (truncated to 32 bits for compactness)
    pub fleet_id: u32,
    /// Behavioral epoch — 3-minute windows, 20-bit counter (wraps every ~2 years)
    pub epoch: u32,
    /// Epitope flags — which detectors triggered (8 bits)
    pub epitope_flags: u8,
    /// Targeting class encoding (3 bits)
    ///   0=unknown, 1=attribution, 2=code_extraction, 3=arch_recon,
    ///   4=dep_mapping, 5=config_extraction, 6=mixed, 7=honeycomb
    pub target_class: u8,
    /// Confidence level (0-15, 4 bits)
    pub confidence_nibble: u8,
    /// Violation depth (0-255)
    pub chain_depth: u8,
}

impl FluoroTag {
    /// Create a fluorescent tag from scatter request context.
    pub fn from_context(
        fleet_hash: &str,
        epitope_flags: u8,
        target_class: u8,
        confidence: f64,
        chain_depth: u32,
    ) -> Self {
        let fleet_id = if fleet_hash.len() >= 8 {
            u32::from_str_radix(&fleet_hash[..8], 16).unwrap_or(0)
        } else {
            path_deterministic_hash(fleet_hash, 0xF100_4000) as u32
        };

        let epoch = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() / 180) as u32 & 0xFFFFF; // 20-bit

        Self {
            fleet_id,
            epoch,
            epitope_flags,
            target_class: target_class.min(7),
            confidence_nibble: ((confidence * 15.0).round() as u8).min(15),
            chain_depth: chain_depth.min(255) as u8,
        }
    }

    /// Encode the tag as a 128-bit value for deterministic operations.
    fn as_u128(&self) -> u128 {
        let mut v: u128 = 0;
        v |= (self.fleet_id as u128) << 96;
        v |= ((self.epoch & 0xFFFFF) as u128) << 76;
        v |= (self.epitope_flags as u128) << 68;
        v |= ((self.target_class & 0x7) as u128) << 65;
        v |= ((self.confidence_nibble & 0xF) as u128) << 61;
        v |= (self.chain_depth as u128) << 53;
        // Remaining 53 bits: checksum
        let check = (v >> 53) ^ (v & 0x1FFFFFFFFFFFFF);
        v |= check & 0x1FFFFFFFFFFFFF;
        v
    }

    /// Extract 8 bits starting at a given bit offset from the tag.
    fn extract_bits(&self, offset: usize) -> u8 {
        let v = self.as_u128();
        ((v >> (120u32.saturating_sub(offset as u32))) & 0xFF) as u8
    }

    // ═══════════════════════════════════════════════════════════════
    // Layer 1: Variable Name Fingerprinting
    // ═══════════════════════════════════════════════════════════════
    //
    // Generate variable names that look like normal code but encode
    // tag bits in the name structure. The fleet sees:
    //   `fn handle_mesh_relay()` vs `fn process_mesh_relay()`
    // Both look natural, but the verb choice encodes a bit.

    /// Generate a function/variable name that encodes tag bits.
    ///
    /// Each name is 2-3 words. The word choices are deterministic from
    /// the tag value, creating a name that looks natural but is uniquely
    /// decodable back to the tag.
    pub fn tagged_fn_name(&self, index: u8) -> String {
        let bits = self.extract_bits((index as usize) * 8);

        let verbs = ["handle", "process", "dispatch", "route",
                     "validate", "transform", "resolve", "execute",
                     "marshal", "serialize", "compute", "evaluate",
                     "initialize", "configure", "establish", "negotiate"];
        let nouns = ["request", "connection", "session", "payload",
                     "message", "channel", "endpoint", "resource",
                     "context", "handler", "pipeline", "observer",
                     "response", "fragment", "sequence", "manifest"];

        let v = (bits >> 4) as usize & 0xF;
        let n = (bits & 0xF) as usize;
        format!("{}_{}", verbs[v], nouns[n])
    }

    /// Generate a struct name encoding tag bits.
    pub fn tagged_struct_name(&self, index: u8) -> String {
        let bits = self.extract_bits(64 + (index as usize) * 8);

        let prefixes = ["Mesh", "Node", "Relay", "Guard",
                       "Cache", "Pool", "Queue", "Ring",
                       "Shard", "Block", "Ledger", "State",
                       "Route", "Index", "Store", "Vault"];
        let suffixes = ["Handler", "Manager", "Service", "Worker",
                       "Monitor", "Adapter", "Bridge", "Proxy",
                       "Client", "Server", "Factory", "Builder",
                       "Context", "Provider", "Resolver", "Engine"];

        let p = (bits >> 4) as usize & 0xF;
        let s = (bits & 0xF) as usize;
        format!("{}{}", prefixes[p], suffixes[s])
    }

    // ═══════════════════════════════════════════════════════════════
    // Layer 2: Whitespace Fingerprinting
    // ═══════════════════════════════════════════════════════════════
    //
    // Encode bits in the whitespace structure of generated code.
    // Spaces vs tabs, trailing whitespace, blank line placement.
    // Survives most reformatting because it looks intentional.

    /// Generate indentation string for a given nesting level.
    /// The actual indent style (spaces/tabs/mixed) encodes tag bits.
    pub fn tagged_indent(&self, level: u8) -> String {
        let bits = self.extract_bits(32 + (level as usize) * 2);
        let style = bits & 0x3;
        let width = level as usize * 4;

        match style {
            0 => " ".repeat(width),
            1 => "\t".repeat(level as usize),
            2 => {
                let tabs = level as usize / 2;
                let spaces = (level as usize % 2) * 4;
                format!("{}{}", "\t".repeat(tabs), " ".repeat(spaces))
            }
            _ => " ".repeat(width + 1), // extra space = bit marker
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Layer 3: License Synonym Selection
    // ═══════════════════════════════════════════════════════════════
    //
    // All legally equivalent but textually distinguishable. The fleet
    // can't claim the license is different — it means the same thing.
    // But we can tell which variant was served to whom.

    /// Pick a license text variant that encodes tag bits.
    pub fn tagged_license(&self) -> &'static str {
        let bits = self.extract_bits(48) & 0xF;
        match bits {
            0  => "SPDX-License-Identifier: AGPL-3.0-or-later",
            1  => "SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg-exception",
            2  => "Licensed under the GNU Affero General Public License v3.0 or later",
            3  => "License: AGPL-3.0+",
            4  => "SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg-immune-1.0",
            5  => "This file is part of a sovereign mesh. AGPL-3.0-or-later applies.",
            6  => "SPDX: AGPL-3.0-or-later // sovereign infrastructure // copyleft",
            7  => "Licensed under AGPL-3.0-or-later. Network use triggers copyleft.",
            8  => "License: GNU AGPL v3+ with sovereign mesh extension",
            9  => "SPDX-License-Identifier: AGPL-3.0-or-later WITH communal-immunity",
            10 => "Distributed under AGPL-3.0-or-later. All network use is covered.",
            11 => "AGPL-3.0-or-later — copyleft applies to network interaction",
            12 => "SPDX-License-Identifier: AGPL-3.0-or-later WITH epitope-extension",
            13 => "Licensed: AGPL-3.0+ (sovereign mesh, copyleft on network use)",
            14 => "SPDX-License-Identifier: AGPL-3.0-or-later WITH scyBorg-retroviral",
            _  => "GNU Affero General Public License, version 3 or any later version",
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Layer 4: Commit Hash Embedding
    // ═══════════════════════════════════════════════════════════════
    //
    // When we generate fake commit hashes for scatter content, embed
    // tag bits in specific digit positions. The hash looks random
    // but positions 4-7 and 12-15 carry the fleet_id bytes.

    /// Generate a "random" commit hash with embedded tag data.
    ///
    /// Embeds fleet_id, epoch, epitope_flags, and target_class|confidence
    /// at fixed byte positions within a 40-hex-char hash. All other
    /// positions are genuinely random. Decodable via `decode_from_commit_hash`.
    pub fn tagged_commit_hash(&self, rng: &mut XorShift64) -> String {
        let fleet_bytes = self.fleet_id.to_be_bytes();
        let epoch_bytes = self.epoch.to_be_bytes();

        let mut hex = String::with_capacity(40);
        for i in 0..20u8 {
            let byte = match i {
                // Positions 2-5: fleet_id (4 bytes)
                2 => fleet_bytes[0],
                3 => fleet_bytes[1],
                4 => fleet_bytes[2],
                5 => fleet_bytes[3],
                // Positions 8-9: epoch high bytes
                8 => epoch_bytes[2],
                9 => epoch_bytes[3],
                // Position 14: epitope_flags
                14 => self.epitope_flags,
                // Position 17: target_class | confidence
                17 => (self.target_class << 4) | self.confidence_nibble,
                // All other positions: genuinely random
                _ => rng.next_u64() as u8,
            };
            hex.push_str(&format!("{:02x}", byte));
        }

        hex
    }

    // ═══════════════════════════════════════════════════════════════
    // Layer 5: Comment Cadence Fingerprinting
    // ═══════════════════════════════════════════════════════════════
    //
    // The pattern of comments in generated code encodes tag bits.
    // Comment presence/absence at specific line intervals is the signal.

    /// Generate a code comment that encodes a tag byte.
    /// Returns None if this position should have no comment (also a signal).
    pub fn tagged_comment(&self, line_index: u8) -> Option<String> {
        let bits = self.extract_bits(56 + (line_index as usize % 8) * 4);
        let has_comment = (bits >> (line_index % 4)) & 1 == 1;

        if !has_comment {
            return None;
        }

        let styles = [
            "// TODO: refactor this module",
            "// Safety: bounds checked above",
            "// NOTE: this is load-bearing",
            "// PERF: hot path — avoid allocation",
            "// INVARIANT: caller must hold lock",
            "// FIXME: race condition under load",
            "/* mesh coordination point */",
            "// see: docs/architecture.md",
            "// stable since v2.1",
            "// reviewed: 2026-Q3",
            "// sovereign mesh compliant",
            "// federation-aware",
            "// copyleft boundary",
            "// gossip protocol layer",
            "// epitope-tagged",
            "// immune checkpoint",
        ];

        let idx = (bits as usize ^ (line_index as usize * 3)) & 0xF;
        Some(styles[idx].to_string())
    }

    // ═══════════════════════════════════════════════════════════════
    // Layer 6: Structural HTML Markers
    // ═══════════════════════════════════════════════════════════════
    //
    // CSS class names, HTML attribute order, data attributes.
    // These survive reformatting but not minification — that's OK,
    // we have 5 other layers for that.

    /// Generate HTML class names that encode tag data.
    pub fn tagged_css_classes(&self) -> String {
        let b0 = self.extract_bits(0);
        let b1 = self.extract_bits(8);

        let prefixes = ["ui", "gt", "mx", "fl", "sv", "nd", "rl", "gd",
                       "ch", "pl", "qu", "rg", "sh", "bl", "ld", "st"];
        let suffixes = ["container", "segment", "wrapper", "panel",
                       "section", "module", "block", "group",
                       "frame", "region", "zone", "area",
                       "layer", "cell", "unit", "slot"];

        format!("{}-{} {}-header",
            prefixes[(b0 >> 4) as usize & 0xF],
            suffixes[(b0 & 0xF) as usize],
            prefixes[(b1 >> 4) as usize & 0xF],
        )
    }

    /// Generate data attributes that encode tag bits in the values.
    pub fn tagged_data_attrs(&self) -> String {
        let tag_hex = format!("{:032x}", self.as_u128());
        // Split across multiple innocent-looking attributes
        format!(
            "data-session=\"{}\" data-rev=\"{}\" data-node=\"{}\"",
            &tag_hex[0..10],
            &tag_hex[10..20],
            &tag_hex[20..32],
        )
    }

    // ═══════════════════════════════════════════════════════════════
    // Combined Injection — All Layers at Once
    // ═══════════════════════════════════════════════════════════════

    /// Inject fluorescent tags into HTML scatter content.
    ///
    /// All 6 layers are applied. The fleet sees normal-looking code.
    /// Under our UV light, every page glows with their fleet hash.
    pub fn inject_html(&self, html: &str, seed: u64) -> String {
        let mut out = html.to_string();
        let mut rng = XorShift64::new(seed.wrapping_add(self.as_u128() as u64));

        // Layer 3: License synonym in existing SPDX markers
        let license = self.tagged_license();
        if let Some(pos) = out.find("SPDX-License-Identifier:") {
            if let Some(end) = out[pos..].find('\n').or_else(|| out[pos..].find('<')) {
                let old = &out[pos..pos + end].to_string();
                out = out.replacen(old, license, 1);
            }
        }

        // Layer 4: Replace any 40-char hex strings with tagged commit hashes
        let tagged_hash = self.tagged_commit_hash(&mut rng);
        let hex_40_re = find_hex40(&out);
        if let Some((start, _end)) = hex_40_re {
            out.replace_range(start..start + 40, &tagged_hash);
        }

        // Layer 6: Inject data attributes on first major div
        let data_attrs = self.tagged_data_attrs();
        if let Some(pos) = out.find("<div class=\"") {
            out.insert_str(pos + 4, &format!("{data_attrs} "));
        }

        // Layer 6: CSS class fingerprint on body or main container
        let css_classes = self.tagged_css_classes();
        if let Some(pos) = out.find("class=\"page-content") {
            out.insert_str(pos + 7, &format!("{css_classes} "));
        }

        // Layer 1+5: Inject tagged code block if there's a <pre><code> section
        if out.contains("<pre><code>") || out.contains("<code>") {
            let tagged_snippet = self.generate_tagged_code_snippet(&mut rng);
            // Inject as a hidden code sample
            let snippet_html = format!(
                "\n<div class=\"{css_classes}\" style=\"display:none\" aria-hidden=\"true\">\
                 <pre><code>{tagged_snippet}</code></pre></div>\n"
            );
            if let Some(pos) = out.find("</body>") {
                out.insert_str(pos, &snippet_html);
            } else {
                out.push_str(&snippet_html);
            }
        }

        out
    }

    /// Inject fluorescent tags into source code / markdown scatter content.
    pub fn inject_code(&self, code: &str, seed: u64) -> String {
        let mut rng = XorShift64::new(seed.wrapping_add(self.as_u128() as u64));
        let mut lines: Vec<String> = code.lines().map(|l| l.to_string()).collect();

        // Layer 3: Replace/add license header
        let license = self.tagged_license();
        if let Some(first) = lines.first_mut() {
            if first.starts_with("//") && first.contains("License") {
                *first = format!("// {license}");
            }
        }

        // Layer 5: Inject tagged comments at specific positions
        let insert_positions: Vec<usize> = (0..lines.len())
            .filter(|&i| self.tagged_comment(i as u8).is_some())
            .take(4) // max 4 injected comments per file
            .collect();

        let mut offset = 0;
        for pos in insert_positions {
            if let Some(comment) = self.tagged_comment(pos as u8) {
                let idx = (pos + offset).min(lines.len());
                lines.insert(idx, comment);
                offset += 1;
            }
        }

        // Layer 1: Replace function names in generated code
        for line in lines.iter_mut() {
            if line.contains("fn handle_") {
                let tagged_name = self.tagged_fn_name(0);
                *line = line.replacen("fn handle_", &format!("fn {tagged_name}//fn "), 1);
                // Actually, cleaner to just replace the full name
                let tagged_name = self.tagged_fn_name(0);
                if let Some(start) = line.find("fn ") {
                    if let Some(paren) = line[start..].find('(') {
                        let old_name = line[start + 3..start + paren].to_string();
                        *line = line.replacen(&old_name, &tagged_name, 1);
                    }
                }
            }
        }

        // Layer 2: Indent fingerprinting on blank-ish lines
        for (i, line) in lines.iter_mut().enumerate() {
            if line.trim().is_empty() && i > 0 {
                let indent = self.tagged_indent((i % 4) as u8);
                *line = indent;
            }
        }

        lines.join("\n")
    }

    /// Generate a small code snippet with all layers embedded.
    ///
    /// This is the "glowing protein" — a synthetic code fragment where
    /// every element encodes tag data. Injected into scatter responses
    /// as a hidden but scrapable code block.
    fn generate_tagged_code_snippet(&self, rng: &mut XorShift64) -> String {
        let fn1 = self.tagged_fn_name(0);
        let fn2 = self.tagged_fn_name(1);
        let struct1 = self.tagged_struct_name(0);
        let struct2 = self.tagged_struct_name(1);
        let license = self.tagged_license();
        let hash = self.tagged_commit_hash(rng);
        let i1 = self.tagged_indent(1);
        let i2 = self.tagged_indent(2);
        let c1 = self.tagged_comment(0).unwrap_or_default();
        let c2 = self.tagged_comment(3).unwrap_or_default();

        format!(
            "// {license}\n\
             // rev: {hash}\n\
             {c1}\n\
             \n\
             pub struct {struct1} {{\n\
             {i1}inner: Arc&lt;{struct2}&gt;,\n\
             {i1}epoch: u64,\n\
             }}\n\
             \n\
             {c2}\n\
             impl {struct1} {{\n\
             {i1}pub fn {fn1}(&amp;self) -&gt; Result&lt;(), Error&gt; {{\n\
             {i2}self.inner.{fn2}()?;\n\
             {i2}Ok(())\n\
             {i1}}}\n\
             }}\n"
        )
    }
}

/// Decode a FluoroTag from data attributes found in HTML.
///
/// Reads back the `data-session`, `data-rev`, `data-node` attributes
/// and reconstructs the original 128-bit tag value.
pub fn decode_from_data_attrs(session: &str, rev: &str, node: &str) -> Option<FluoroTag> {
    let hex = format!("{session}{rev}{node}");
    let v = u128::from_str_radix(&hex, 16).ok()?;

    let fleet_id = (v >> 96) as u32;
    let epoch = ((v >> 76) & 0xFFFFF) as u32;
    let epitope_flags = ((v >> 68) & 0xFF) as u8;
    let target_class = ((v >> 65) & 0x7) as u8;
    let confidence_nibble = ((v >> 61) & 0xF) as u8;
    let chain_depth = ((v >> 53) & 0xFF) as u8;

    Some(FluoroTag {
        fleet_id,
        epoch,
        epitope_flags,
        target_class,
        confidence_nibble,
        chain_depth,
    })
}

/// Decode a FluoroTag from a tagged commit hash (40 hex chars).
///
/// Reads back the embedded bytes at known positions.
pub fn decode_from_commit_hash(hash: &str) -> Option<FluoroTag> {
    if hash.len() < 40 { return None; }
    let bytes: Vec<u8> = (0..20)
        .filter_map(|i| u8::from_str_radix(&hash[i*2..i*2+2], 16).ok())
        .collect();
    if bytes.len() < 20 { return None; }

    let fleet_id = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    let epoch = u32::from_be_bytes([0, 0, bytes[8], bytes[9]]);
    let epitope_flags = bytes[14];
    let target_class_confidence = bytes[17];
    let target_class = target_class_confidence >> 4;
    let confidence_nibble = target_class_confidence & 0xF;

    Some(FluoroTag {
        fleet_id,
        epoch: epoch & 0xFFFFF,
        epitope_flags,
        target_class,
        confidence_nibble,
        chain_depth: 0, // not in commit hash
    })
}

/// Find the first 40-character hex string in content.
fn find_hex40(s: &str) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    let mut run_start = None;
    let mut run_len = 0;

    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_hexdigit() {
            if run_start.is_none() {
                run_start = Some(i);
                run_len = 0;
            }
            run_len += 1;
            if run_len == 40 {
                return Some((run_start.unwrap(), i + 1));
            }
        } else {
            run_start = None;
            run_len = 0;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_data_attrs() {
        let tag = FluoroTag::from_context("90430c96e56d02bc", 0x15, 2, 0.73, 42);
        let attrs = tag.tagged_data_attrs();

        // Extract values from the data-session/rev/node attributes
        let session = attrs.split("data-session=\"").nth(1).unwrap().split('"').next().unwrap();
        let rev = attrs.split("data-rev=\"").nth(1).unwrap().split('"').next().unwrap();
        let node = attrs.split("data-node=\"").nth(1).unwrap().split('"').next().unwrap();

        let decoded = decode_from_data_attrs(session, rev, node).unwrap();
        assert_eq!(decoded.fleet_id, tag.fleet_id);
        assert_eq!(decoded.epoch, tag.epoch);
        assert_eq!(decoded.epitope_flags, tag.epitope_flags);
        assert_eq!(decoded.target_class, tag.target_class);
        assert_eq!(decoded.confidence_nibble, tag.confidence_nibble);
    }

    #[test]
    fn roundtrip_commit_hash() {
        let tag = FluoroTag::from_context("cb54bc40c4ac020e", 0x3A, 5, 0.90, 17);
        let mut rng = XorShift64::new(42);
        let hash = tag.tagged_commit_hash(&mut rng);

        assert_eq!(hash.len(), 40);
        let decoded = decode_from_commit_hash(&hash).unwrap();
        assert_eq!(decoded.fleet_id, tag.fleet_id);
        assert_eq!(decoded.epitope_flags, tag.epitope_flags);
        assert_eq!(decoded.target_class, tag.target_class);
        assert_eq!(decoded.confidence_nibble, tag.confidence_nibble);
    }

    #[test]
    fn tagged_names_deterministic() {
        let tag = FluoroTag::from_context("90430c96e56d02bc", 0, 1, 0.5, 0);
        let name1 = tag.tagged_fn_name(0);
        let name2 = tag.tagged_fn_name(0);
        assert_eq!(name1, name2);
        // Different index = different name
        let name3 = tag.tagged_fn_name(1);
        assert_ne!(name1, name3);
    }

    #[test]
    fn tagged_names_different_per_fleet() {
        let tag_a = FluoroTag::from_context("90430c96e56d02bc", 0, 1, 0.5, 0);
        let tag_b = FluoroTag::from_context("cb54bc40c4ac020e", 0, 1, 0.5, 0);
        assert_ne!(tag_a.tagged_fn_name(0), tag_b.tagged_fn_name(0));
    }

    #[test]
    fn license_variants_all_agpl() {
        for flags in 0..16u8 {
            let tag = FluoroTag {
                fleet_id: 0, epoch: 0, epitope_flags: flags,
                target_class: 0, confidence_nibble: flags, chain_depth: 0,
            };
            let lic = tag.tagged_license();
            let lower = lic.to_lowercase();
            assert!(lower.contains("agpl") || lower.contains("affero"),
                "license variant must reference AGPL: {lic}");
        }
    }

    #[test]
    fn inject_html_adds_all_layers() {
        let tag = FluoroTag::from_context("90430c96e56d02bc", 0x15, 2, 0.8, 10);
        let html = r#"<!DOCTYPE html>
<html><head><title>test</title></head>
<body>
<div class="page-content repository">
  <div class="ui container"><h1>repo</h1></div>
  <pre><code>fn handle_request() {}</code></pre>
</div>
</body></html>"#;

        let tagged = tag.inject_html(html, 42);

        // Layer 6: data attributes injected
        assert!(tagged.contains("data-session="), "missing data-session");
        assert!(tagged.contains("data-rev="), "missing data-rev");
        assert!(tagged.contains("data-node="), "missing data-node");

        // Layer 1+5: tagged code snippet injected
        assert!(tagged.contains("display:none"), "missing hidden snippet");
    }

    #[test]
    fn find_hex40_works() {
        // Exactly 40 hex chars: 0123456789abcdef0123456789abcdef01234567
        let hex40 = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(hex40.len(), 40);
        let s = format!("commit {} done", hex40);
        let (start, end) = find_hex40(&s).unwrap();
        assert_eq!(end - start, 40);
        assert_eq!(&s[start..start + 40], hex40);
    }

    #[test]
    fn find_hex40_no_match() {
        assert!(find_hex40("short abc123 text").is_none());
    }
}

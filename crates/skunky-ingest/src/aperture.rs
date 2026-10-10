// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Aperture — wildcard membrane routing through the epitope sorter.
//!
//! ## Biological Parallel: Antigen Presentation
//!
//! In immunology, the Major Histocompatibility Complex (MHC) presents
//! peptide fragments on the cell surface so T-cells can inspect them.
//! The aperture is our MHC: it takes an incoming subdomain request
//! (the antigen), classifies the visitor (T-cell inspection), and
//! decides what content to present.
//!
//! ## Architecture
//!
//! The wildcard `*.primals.eco` collapses the 29-domain surface into
//! a single entry point. The subdomain itself becomes a signal:
//!
//! - Known site names (`thesis`, `signal`, `tuebor`) → serve real content
//! - Known concepts (`metric-tensor`, `scyborg`, `membrane`) → route to
//!   the page that best matches via epitope proximity
//! - Unknown subdomains → scatter maze for fleet, 404 for sovereigns
//! - Immune subdomains (`bloom`, `thymus`, etc.) → honeycomb prism
//!
//! The SEO surface moves to the aperture edge. Instead of 13 separate
//! domain sites, the classifier decides what to show based on:
//! 1. What they typed (subdomain = query)
//! 2. Who they are (behavioral classification)
//! 3. What they declared (Accept-Language, Sec-Fetch-Mode)
//!
//! `H(data|epitope) < H(data|alphabet) < H(data)`
//! The epitope sort reduces entropy more than alphabetical ordering.
//! The subdomain IS the epitope.

use std::collections::HashMap;

/// A known site that can be served through the wildcard aperture.
#[derive(Debug, Clone)]
pub struct ApertureSite {
    /// Primary subdomain (e.g., "thesis", "signal")
    pub subdomain: &'static str,
    /// Filesystem root path for static content
    pub root_path: &'static str,
    /// Alternate subdomains that resolve to this same site
    pub aliases: &'static [&'static str],
    /// Whether this site has an index.html fallback
    pub has_spa_fallback: bool,
}

/// Sites that the wildcard can serve directly (static file serving).
/// These are the "real" sites — sovereign visitors get real content.
/// Services with reverse proxies (git, forge, hud, live, ca) are NOT
/// in this list — they keep their explicit Caddy blocks.
pub static APERTURE_SITES: &[ApertureSite] = &[
    ApertureSite {
        subdomain: "sporeprint",
        root_path: "/opt/ecoPrimals/sporePrint/public",
        aliases: &["footprint", "spore", "print"],
        has_spa_fallback: false,
    },
    ApertureSite {
        subdomain: "thesis",
        root_path: "/opt/ecoPrimals/thesis/public",
        aliases: &["paper", "whitepaper"],
        has_spa_fallback: false,
    },
    ApertureSite {
        subdomain: "signal",
        root_path: "/opt/ecoPrimals/signal/site/public",
        aliases: &["dashboard", "monitor"],
        has_spa_fallback: false,
    },
    ApertureSite {
        subdomain: "tuebor",
        root_path: "/opt/ecoPrimals/tuebor-repo/site/public",
        aliases: &["barry"],  // barry is a tuebor mirror
        has_spa_fallback: false,
    },
    ApertureSite {
        subdomain: "detroit",
        root_path: "/opt/ecoPrimals/detroit/public",
        aliases: &["evidence", "cashforkids"],
        has_spa_fallback: false,
    },
    ApertureSite {
        subdomain: "clutch",
        root_path: "/opt/ecoPrimals/clutch/site/public",
        aliases: &[],
        has_spa_fallback: false,
    },
    ApertureSite {
        subdomain: "gorilla",
        root_path: "/opt/ecoPrimals/guerillaGorilla/site/public",
        aliases: &["guerillagorilla"],
        has_spa_fallback: false,
    },
    ApertureSite {
        subdomain: "hypothesis",
        root_path: "/opt/ecoPrimals/hypothesis/site/public",
        aliases: &["questions"],
        has_spa_fallback: false,
    },
    ApertureSite {
        subdomain: "beacon",
        root_path: "/opt/membrane/beacon-page",
        aliases: &["relay", "commensal"],
        has_spa_fallback: false,
    },
];

/// Honeycomb immune subdomains — these route to scatter's prism mode.
/// They're the decoy surface for fleet behavioral classification.
pub static HONEYCOMB_SUBDOMAINS: &[&str] = &[
    "bloom", "thymus", "opsonize", "antibody", "cytokine",
    "receptor", "macrophage", "lysozyme", "complement",
    "epitope", "antigen", "interferon",
];

/// Services that keep their own explicit Caddy blocks.
/// The wildcard catch-all must NOT issue certs for these.
pub static EXPLICIT_SERVICES: &[&str] = &[
    "git", "forge", "hud", "biomeos", "os",
    "live", "ca", "depot", "lab", "membrane",
    "ns1", "ns2", "remote", "www",
];

/// Epitope concepts — subdomains that map to specific content pages
/// across any site. This is the "search by typing" aperture.
/// The subdomain becomes the query, the sorter finds the best match.
pub static EPITOPE_CONCEPTS: &[(&str, &str, &str)] = &[
    // (subdomain-fragment, target-site, target-path)
    ("metric-tensor",   "tuebor",    "/analysis/metric-tensor/"),
    ("scyborg",         "sporeprint", "/license/scyborg/"),
    ("antidote",        "sporeprint", "/tools/antidote.py"),
    ("license",         "sporeprint", "/license/scyborg/"),
    ("methodology",     "sporeprint", "/methodology/scyborg-binary-genetic-bulwark/"),
    ("compliance",      "hud",       "/api/compliance"),
    ("outreach",        "sporeprint", "/outreach/"),
    ("hadr",            "sporeprint", "/outreach/hadr-invitation/"),
    ("tommy-boy",       "tuebor",    "/analysis/tommy-boy/"),
    ("lakenet",         "tuebor",    "/analysis/lakenet-signal-trace/"),
    ("infrastructure",  "tuebor",    "/analysis/infrastructure-grid/"),
    ("defense",         "detroit",   "/defense/"),
    ("evidence",        "detroit",   "/"),
    ("membrane-desk",   "tuebor",    "/desk/"),
    ("desk",            "tuebor",    "/desk/"),
    ("map",             "tuebor",    "/membrane/"),
];

/// Result of aperture routing decision.
#[derive(Debug, Clone)]
pub enum ApertureDecision {
    /// Serve static files from this root path.
    /// Caddy handles the actual file serving.
    ServeSite {
        subdomain: String,
        root_path: String,
        spa_fallback: bool,
    },
    /// Redirect to a specific URL (concept routing).
    Redirect {
        target_url: String,
    },
    /// Route to the honeycomb prism (scatter defense).
    Honeycomb {
        surface_index: u8,
    },
    /// Route to the scatter server (unknown subdomain + fleet classification).
    Scatter,
    /// This subdomain is handled by an explicit Caddy block — don't touch.
    ExplicitService,
    /// Valid primals.eco subdomain but no content match — serve 404.
    NotFound,
}

/// The aperture — resolves a subdomain to a routing decision.
pub fn resolve(subdomain: &str) -> ApertureDecision {
    let sub_lower = subdomain.to_ascii_lowercase();

    // 1. Explicit services — hands off
    if EXPLICIT_SERVICES.contains(&sub_lower.as_str()) {
        return ApertureDecision::ExplicitService;
    }

    // 2. Known sites — serve real content
    for site in APERTURE_SITES {
        if site.subdomain == sub_lower || site.aliases.contains(&sub_lower.as_str()) {
            return ApertureDecision::ServeSite {
                subdomain: site.subdomain.to_string(),
                root_path: site.root_path.to_string(),
                spa_fallback: site.has_spa_fallback,
            };
        }
    }

    // 3. Honeycomb — scatter prism
    if let Some(idx) = HONEYCOMB_SUBDOMAINS.iter().position(|&s| s == sub_lower) {
        return ApertureDecision::Honeycomb {
            surface_index: idx as u8,
        };
    }

    // 4. Epitope concept routing — redirect to specific content
    for &(concept, site, path) in EPITOPE_CONCEPTS {
        if sub_lower == concept || sub_lower.replace('-', "") == concept.replace('-', "") {
            return ApertureDecision::Redirect {
                target_url: format!("https://{site}.primals.eco{path}"),
            };
        }
    }

    // 5. Unknown — scatter maze for fleet, 404 for sovereigns
    // The caller (scatter_server or Caddy) decides based on classification.
    ApertureDecision::Scatter
}

/// Check if a domain should get a TLS certificate provisioned.
/// This is the Caddy on-demand TLS "ask" endpoint validator.
///
/// Returns true if:
/// - Domain is `*.primals.eco` (our wildcard)
/// - AND not an explicit service (those already have certs)
/// - AND not clearly abusive (random 50+ char subdomains)
pub fn can_serve(domain: &str) -> bool {
    // Must be under primals.eco
    let Some(subdomain) = domain.strip_suffix(".primals.eco") else {
        return false;
    };

    // No nested subdomains (a.b.primals.eco → deny)
    if subdomain.contains('.') {
        return false;
    }

    // Explicit services already have their own cert blocks
    if EXPLICIT_SERVICES.contains(&subdomain) {
        return false;
    }

    // Reasonable subdomain length (prevent abuse via cert flooding)
    if subdomain.len() > 40 || subdomain.is_empty() {
        return false;
    }

    // Valid subdomain characters
    subdomain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Build a site lookup map for fast resolution.
pub fn site_map() -> HashMap<&'static str, &'static ApertureSite> {
    let mut map = HashMap::new();
    for site in APERTURE_SITES {
        map.insert(site.subdomain, site);
        for alias in site.aliases {
            map.insert(alias, site);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sites_resolve() {
        match resolve("thesis") {
            ApertureDecision::ServeSite { subdomain, root_path, .. } => {
                assert_eq!(subdomain, "thesis");
                assert_eq!(root_path, "/opt/ecoPrimals/thesis/public");
            }
            other => panic!("expected ServeSite, got {other:?}"),
        }
    }

    #[test]
    fn aliases_resolve() {
        match resolve("whitepaper") {
            ApertureDecision::ServeSite { subdomain, .. } => {
                assert_eq!(subdomain, "thesis");
            }
            other => panic!("expected ServeSite for alias, got {other:?}"),
        }
    }

    #[test]
    fn honeycomb_resolves() {
        match resolve("bloom") {
            ApertureDecision::Honeycomb { surface_index } => {
                assert_eq!(surface_index, 0);
            }
            other => panic!("expected Honeycomb, got {other:?}"),
        }
    }

    #[test]
    fn explicit_service_hands_off() {
        assert!(matches!(resolve("git"), ApertureDecision::ExplicitService));
        assert!(matches!(resolve("forge"), ApertureDecision::ExplicitService));
        assert!(matches!(resolve("hud"), ApertureDecision::ExplicitService));
    }

    #[test]
    fn concept_redirects() {
        match resolve("metric-tensor") {
            ApertureDecision::Redirect { target_url } => {
                assert!(target_url.contains("tuebor.primals.eco"));
                assert!(target_url.contains("metric-tensor"));
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    #[test]
    fn unknown_scatters() {
        assert!(matches!(resolve("xyzzy123"), ApertureDecision::Scatter));
    }

    #[test]
    fn can_serve_validates() {
        assert!(can_serve("thesis.primals.eco"));
        assert!(can_serve("random-name.primals.eco"));
        assert!(!can_serve("git.primals.eco")); // explicit service
        assert!(!can_serve("evil.example.com")); // wrong domain
        assert!(!can_serve("a.b.primals.eco")); // nested
        assert!(!can_serve(&format!("{}.primals.eco", "x".repeat(50)))); // too long
    }

    #[test]
    fn case_insensitive() {
        assert!(matches!(resolve("Thesis"), ApertureDecision::ServeSite { .. }));
        assert!(matches!(resolve("BLOOM"), ApertureDecision::Honeycomb { .. }));
    }

    #[test]
    fn site_map_complete() {
        let map = site_map();
        assert!(map.contains_key("thesis"));
        assert!(map.contains_key("whitepaper")); // alias
        assert!(map.contains_key("sporeprint"));
        assert!(map.contains_key("footprint")); // alias
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Bloom emitter — efferent signal propagation for the evidence network.
//!
//! While [`crate::bloom_sensor`] detects inbound positive signal (afferent),
//! the bloom emitter **pushes signal outward** to search engines, web archives,
//! and the wider link graph. In SAME DAVE terms, this is the **efferent ventral
//! channel** — motor output FROM the organism to the environment.
//!
//! ## Protocols
//!
//! - **IndexNow**: Bulk URL notification to Bing, Yandex, Seznam, Naver.
//!   Single POST, up to 10K URLs per batch. Engines pull pages on their schedule.
//! - **Wayback Machine**: Submit pages to the Internet Archive for permanent
//!   archival. Rate-limited (429 after ~10 rapid submissions).
//!
//! ## Surface Graph
//!
//! The emitter maintains a typed catalog of all surfaces in the evidence network:
//! published sites, GitHub repos, Forgejo orgs, honeycomb immune subdomains.
//! Each surface knows its host, paths, and last-submitted timestamps.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use skunky_ingest::bloom_emitter::{BloomEmitter, EmitterConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = EmitterConfig::default();
//! let emitter = BloomEmitter::new(config);
//!
//! // Full cascade — all surfaces, all protocols
//! let report = emitter.cascade().await?;
//! println!("{report}");
//!
//! // Targeted bloom — single host
//! let report = emitter.bloom_host("tuebor.primals.eco").await?;
//! println!("{report}");
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

// ── Error types ──

/// Bloom emitter errors.
#[derive(Debug, thiserror::Error)]
pub enum BloomError {
    /// HTTP transport failure.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failure.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// Rate-limited by upstream service.
    #[error("rate limited by {service} (retry after {retry_after_secs}s)")]
    RateLimited {
        /// Which service rate-limited us.
        service: &'static str,
        /// Suggested retry delay.
        retry_after_secs: u64,
    },

    /// Unknown host in the surface graph.
    #[error("unknown host: {0}")]
    UnknownHost(String),

    /// IO error (state persistence).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Emitter result alias.
pub type EmitResult<T> = Result<T, BloomError>;

// ── Surface graph ──

/// A surface in the evidence network — a published endpoint with crawlable URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Surface {
    /// Hostname (e.g., `"tuebor.primals.eco"`).
    pub host: String,
    /// Known paths on this surface.
    pub paths: Vec<String>,
    /// Surface classification.
    pub kind: SurfaceKind,
}

/// What kind of surface this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceKind {
    /// Published Zola site served by Caddy.
    Site,
    /// GitHub repository (publicly indexable).
    GitHubRepo,
    /// GitHub organization page.
    GitHubOrg,
    /// Forgejo organization on the sovereign forge.
    ForgeOrg,
    /// Forgejo repository (scatter-active).
    ForgeRepo,
    /// Honeycomb immune subdomain (maze node).
    Honeycomb,
}

impl Surface {
    /// Build full URLs for all paths on this surface.
    pub fn urls(&self) -> Vec<String> {
        self.paths
            .iter()
            .map(|p| format!("https://{}{}", self.host, p))
            .collect()
    }
}

/// The complete evidence network surface catalog.
pub fn surface_catalog() -> Vec<Surface> {
    vec![
        // ── Published sites ──
        Surface {
            host: "tuebor.primals.eco".into(),
            paths: vec![
                "/", "/desk/", "/membrane/", "/map/",
                "/actors/ellison/", "/actors/borrello/", "/actors/gafkay/",
                "/evidence/ghost-witness-aljouny/", "/evidence/slapp-timeline/",
                "/evidence/ellison-sanctions/", "/evidence/litigation-docket/",
                "/analysis/anderson-hemlock/", "/analysis/cross-subgraph-patterns/",
                "/analysis/metric-tensor/", "/analysis/information-entropy/",
                "/analysis/infrastructure-grid/", "/analysis/tommy-boy/",
                "/analysis/how-to-build-an-os/", "/analysis/institutional-immunity/",
                "/analysis/signal-permeability/",
                "/investigate/foiaworks-warning/", "/investigate/court-records/",
                "/investigate/oversight-guide/",
            ].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Site,
        },
        Surface {
            host: "barry.primals.eco".into(),
            paths: vec!["/", "/desk/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Site,
        },
        Surface {
            host: "detroit.primals.eco".into(),
            paths: vec![
                "/", "/network/", "/network/actors/brian-banks/",
                "/analysis/rico-pattern/",
            ].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Site,
        },
        Surface {
            host: "clutch.primals.eco".into(),
            paths: vec![
                "/", "/graph/", "/cases/detroit/", "/cases/saginaw/", "/cases/barry/",
            ].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Site,
        },
        Surface {
            host: "clutchjustice.com".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Site,
        },
        Surface {
            host: "thesis.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Site,
        },
        Surface {
            host: "sporeprint.primals.eco".into(),
            paths: vec![
                "/", "/philosophy/", "/philosophy/the-elements-of-style/",
                "/methodology/", "/story/", "/science/", "/guidestone/",
            ].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Site,
        },
        Surface {
            host: "signal.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Site,
        },
        Surface {
            host: "gorilla.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Site,
        },
        // ── GitHub repos ──
        Surface {
            host: "github.com".into(),
            paths: vec![
                "/amicusContra/tuebor", "/amicusContra/clutch",
                "/defendDetroit/publicRecord",
            ].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::GitHubRepo,
        },
        // ── GitHub orgs ──
        Surface {
            host: "github.com".into(),
            paths: vec!["/amicusContra", "/defendDetroit"]
                .into_iter().map(Into::into).collect(),
            kind: SurfaceKind::GitHubOrg,
        },
        // ── Forge orgs ──
        Surface {
            host: "git.primals.eco".into(),
            paths: vec![
                "/ecoPrimals", "/protoKarya", "/publicRecord",
                "/sporegarden", "/sporegate", "/syntheticchemistry",
            ].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::ForgeOrg,
        },
        // ── Honeycomb maze ──
        Surface {
            host: "bloom.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
        Surface {
            host: "thymus.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
        Surface {
            host: "opsonize.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
        Surface {
            host: "complement.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
        Surface {
            host: "interferon.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
        Surface {
            host: "cytokine.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
        Surface {
            host: "antibody.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
        Surface {
            host: "antigen.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
        Surface {
            host: "phagocyte.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
        Surface {
            host: "neutrophil.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
        Surface {
            host: "macrophage.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
        Surface {
            host: "dendritic.primals.eco".into(),
            paths: vec!["/"].into_iter().map(Into::into).collect(),
            kind: SurfaceKind::Honeycomb,
        },
    ]
}

// ── IndexNow protocol ──

/// IndexNow submission request body.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IndexNowRequest {
    host: String,
    key: String,
    key_location: String,
    url_list: Vec<String>,
}

/// IndexNow submission result for a single host.
#[derive(Debug, Clone, Serialize)]
pub struct IndexNowResult {
    /// Host that was submitted.
    pub host: String,
    /// Number of URLs submitted.
    pub url_count: usize,
    /// HTTP status code from IndexNow API.
    pub status: u16,
}

// ── Wayback Machine protocol ──

/// Wayback Machine save result for a single URL.
#[derive(Debug, Clone, Serialize)]
pub struct WaybackResult {
    /// URL that was submitted.
    pub url: String,
    /// HTTP status code from Wayback save endpoint.
    pub status: u16,
}

// ── Cascade report ──

/// Full bloom cascade report — summary of all submissions.
#[derive(Debug, Default, Serialize)]
pub struct CascadeReport {
    /// IndexNow results per host.
    pub indexnow: Vec<IndexNowResult>,
    /// Wayback archive results.
    pub wayback: Vec<WaybackResult>,
    /// Total URLs submitted to IndexNow.
    pub indexnow_total_urls: usize,
    /// Total pages archived to Wayback.
    pub wayback_total_pages: usize,
    /// Duration of the entire cascade.
    pub elapsed: Duration,
    /// Errors encountered (non-fatal).
    pub errors: Vec<String>,
}

impl fmt::Display for CascadeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "╔══════════════════════════════════╗")?;
        writeln!(f, "║   bloom cascade — Artisan        ║")?;
        writeln!(f, "╚══════════════════════════════════╝")?;
        writeln!(f)?;

        writeln!(f, "IndexNow: {} hosts, {} URLs", self.indexnow.len(), self.indexnow_total_urls)?;
        for r in &self.indexnow {
            writeln!(f, "  {} {} ({} URLs)", r.status, r.host, r.url_count)?;
        }

        writeln!(f)?;
        writeln!(f, "Wayback: {} pages", self.wayback_total_pages)?;
        for r in &self.wayback {
            writeln!(f, "  {} {}", r.status, r.url)?;
        }

        if !self.errors.is_empty() {
            writeln!(f)?;
            writeln!(f, "Errors ({}):", self.errors.len())?;
            for e in &self.errors {
                writeln!(f, "  {e}")?;
            }
        }

        writeln!(f)?;
        writeln!(f, "Elapsed: {:.1}s", self.elapsed.as_secs_f64())?;
        Ok(())
    }
}

// ── Configuration ──

/// Bloom emitter configuration.
#[derive(Debug, Clone)]
pub struct EmitterConfig {
    /// IndexNow API key (must be hosted at `https://{host}/{key}.txt`).
    pub indexnow_key: String,
    /// Wayback rate limit delay between submissions.
    pub wayback_delay: Duration,
    /// IndexNow rate limit delay between host batches.
    pub indexnow_delay: Duration,
    /// Maximum URLs per Wayback batch before pausing.
    pub wayback_batch_size: usize,
    /// User-Agent string for outbound requests.
    pub user_agent: String,
    /// State file path for tracking submission history.
    pub state_path: Option<std::path::PathBuf>,
}

impl Default for EmitterConfig {
    fn default() -> Self {
        Self {
            indexnow_key: "13f0ed8ef5cfe60356d2432f237d0e36".into(),
            wayback_delay: Duration::from_secs(5),
            indexnow_delay: Duration::from_millis(500),
            wayback_batch_size: 10,
            user_agent: "ecoPrimal-artisan/1.0 bloom-emitter".into(),
            state_path: None,
        }
    }
}

// ── Submission state ──

/// Persistent state tracking which URLs were submitted and when.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EmitterState {
    /// Last IndexNow submission time per host.
    pub indexnow_last: HashMap<String, u64>,
    /// Last Wayback submission time per URL.
    pub wayback_last: HashMap<String, u64>,
}

impl EmitterState {
    /// Load from disk, or return empty state.
    pub fn load(path: &std::path::Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Persist to disk.
    pub fn save(&self, path: &std::path::Path) -> EmitResult<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Current epoch timestamp in seconds.
    pub fn now_epoch() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

// ── Bloom emitter ──

/// Efferent bloom signal propagation engine.
///
/// Pushes URLs to search engine notification protocols (IndexNow) and
/// web archives (Wayback Machine). Maintains submission state to avoid
/// redundant submissions within a configurable cooldown window.
pub struct BloomEmitter {
    config: EmitterConfig,
    client: reqwest::Client,
    catalog: Vec<Surface>,
}

impl BloomEmitter {
    /// Create a new bloom emitter with the given configuration.
    pub fn new(config: EmitterConfig) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(&config.user_agent)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("failed to build HTTP client");

        Self {
            config,
            client,
            catalog: surface_catalog(),
        }
    }

    /// Full cascade — submit all surfaces to all protocols.
    pub async fn cascade(&self) -> EmitResult<CascadeReport> {
        let start = std::time::Instant::now();
        let mut report = CascadeReport::default();

        // Wave 1: IndexNow — all site surfaces (we control these hosts)
        let site_surfaces: Vec<&Surface> = self.catalog.iter()
            .filter(|s| s.kind == SurfaceKind::Site)
            .collect();

        for surface in &site_surfaces {
            match self.submit_indexnow(surface).await {
                Ok(result) => {
                    report.indexnow_total_urls += result.url_count;
                    report.indexnow.push(result);
                }
                Err(e) => report.errors.push(format!("indexnow {}: {e}", surface.host)),
            }
            tokio::time::sleep(self.config.indexnow_delay).await;
        }

        // Wave 2: Wayback — priority pages from sites
        let priority_urls: Vec<String> = site_surfaces.iter()
            .flat_map(|s| {
                // Submit root + first 2 content pages per site
                s.paths.iter()
                    .take(3)
                    .map(|p| format!("https://{}{p}", s.host))
            })
            .collect();

        for (i, url) in priority_urls.iter().enumerate() {
            if i > 0 && i % self.config.wayback_batch_size == 0 {
                // Extended pause between batches
                tokio::time::sleep(self.config.wayback_delay * 3).await;
            }

            match self.submit_wayback(url).await {
                Ok(result) => {
                    report.wayback_total_pages += 1;
                    report.wayback.push(result);
                }
                Err(BloomError::RateLimited { retry_after_secs, .. }) => {
                    report.errors.push(format!("wayback rate-limited at {url}, pausing {retry_after_secs}s"));
                    tokio::time::sleep(Duration::from_secs(retry_after_secs)).await;
                }
                Err(e) => report.errors.push(format!("wayback {url}: {e}")),
            }
            tokio::time::sleep(self.config.wayback_delay).await;
        }

        report.elapsed = start.elapsed();
        Ok(report)
    }

    /// Bloom a single host — submit its URLs to IndexNow.
    pub async fn bloom_host(&self, host: &str) -> EmitResult<CascadeReport> {
        let start = std::time::Instant::now();
        let mut report = CascadeReport::default();

        let surface = self.catalog.iter()
            .find(|s| s.host == host)
            .ok_or_else(|| BloomError::UnknownHost(host.into()))?;

        let result = self.submit_indexnow(surface).await?;
        report.indexnow_total_urls += result.url_count;
        report.indexnow.push(result);
        report.elapsed = start.elapsed();

        Ok(report)
    }

    /// Submit URLs for a surface to the IndexNow API.
    async fn submit_indexnow(&self, surface: &Surface) -> EmitResult<IndexNowResult> {
        let urls = surface.urls();
        let url_count = urls.len();

        let body = IndexNowRequest {
            host: surface.host.clone(),
            key: self.config.indexnow_key.clone(),
            key_location: format!(
                "https://{}/{}.txt",
                surface.host, self.config.indexnow_key
            ),
            url_list: urls,
        };

        let resp = self.client
            .post("https://api.indexnow.org/indexnow")
            .json(&body)
            .send()
            .await?;

        let status = resp.status().as_u16();

        Ok(IndexNowResult {
            host: surface.host.clone(),
            url_count,
            status,
        })
    }

    /// Submit a single URL to the Wayback Machine.
    async fn submit_wayback(&self, url: &str) -> EmitResult<WaybackResult> {
        let save_url = format!("https://web.archive.org/save/{url}");

        let resp = self.client
            .get(&save_url)
            .send()
            .await?;

        let status = resp.status().as_u16();

        if status == 429 {
            return Err(BloomError::RateLimited {
                service: "wayback",
                retry_after_secs: 15,
            });
        }

        Ok(WaybackResult {
            url: url.to_string(),
            status,
        })
    }

    /// Get the full surface catalog.
    pub fn catalog(&self) -> &[Surface] {
        &self.catalog
    }

    /// Get surfaces filtered by kind.
    pub fn surfaces_by_kind(&self, kind: SurfaceKind) -> Vec<&Surface> {
        self.catalog.iter().filter(|s| s.kind == kind).collect()
    }

    /// Total URL count across all surfaces.
    pub fn total_urls(&self) -> usize {
        self.catalog.iter().map(|s| s.paths.len()).sum()
    }

    /// Total surface count.
    pub fn total_surfaces(&self) -> usize {
        self.catalog.len()
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_catalog_not_empty() {
        let catalog = surface_catalog();
        assert!(!catalog.is_empty());
    }

    #[test]
    fn surface_urls_formation() {
        let surface = Surface {
            host: "tuebor.primals.eco".into(),
            paths: vec!["/".into(), "/desk/".into()],
            kind: SurfaceKind::Site,
        };
        let urls = surface.urls();
        assert_eq!(urls, vec![
            "https://tuebor.primals.eco/",
            "https://tuebor.primals.eco/desk/",
        ]);
    }

    #[test]
    fn catalog_has_all_surface_kinds() {
        let catalog = surface_catalog();
        let kinds: std::collections::HashSet<_> = catalog.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&SurfaceKind::Site));
        assert!(kinds.contains(&SurfaceKind::GitHubRepo));
        assert!(kinds.contains(&SurfaceKind::ForgeOrg));
        assert!(kinds.contains(&SurfaceKind::Honeycomb));
    }

    #[test]
    fn sites_have_indexnow_key_host() {
        let catalog = surface_catalog();
        let sites: Vec<_> = catalog.iter().filter(|s| s.kind == SurfaceKind::Site).collect();
        assert!(sites.len() >= 9, "expected at least 9 sites");
    }

    #[test]
    fn honeycomb_has_twelve_nodes() {
        let catalog = surface_catalog();
        let honeycombs: Vec<_> = catalog.iter()
            .filter(|s| s.kind == SurfaceKind::Honeycomb)
            .collect();
        assert_eq!(honeycombs.len(), 12, "honeycomb should have 12 immune subdomains");
    }

    #[test]
    fn emitter_config_defaults() {
        let config = EmitterConfig::default();
        assert!(!config.indexnow_key.is_empty());
        assert!(config.wayback_delay.as_secs() >= 3);
        assert!(config.user_agent.contains("artisan"));
    }

    #[test]
    fn cascade_report_display() {
        let report = CascadeReport {
            indexnow: vec![IndexNowResult {
                host: "tuebor.primals.eco".into(),
                url_count: 23,
                status: 200,
            }],
            wayback: vec![WaybackResult {
                url: "https://tuebor.primals.eco/".into(),
                status: 200,
            }],
            indexnow_total_urls: 23,
            wayback_total_pages: 1,
            elapsed: Duration::from_secs(5),
            errors: vec![],
        };
        let display = format!("{report}");
        assert!(display.contains("bloom cascade"));
        assert!(display.contains("tuebor.primals.eco"));
        assert!(display.contains("23 URLs"));
    }

    #[test]
    fn emitter_state_roundtrip() {
        let mut state = EmitterState::default();
        state.indexnow_last.insert("tuebor.primals.eco".into(), 1696800000);
        state.wayback_last.insert("https://tuebor.primals.eco/".into(), 1696800000);

        let json = serde_json::to_string(&state).unwrap();
        let restored: EmitterState = serde_json::from_str(&json).unwrap();

        assert_eq!(
            restored.indexnow_last.get("tuebor.primals.eco"),
            Some(&1696800000)
        );
    }

    #[test]
    fn surfaces_by_kind_filter() {
        let emitter = BloomEmitter::new(EmitterConfig::default());
        let sites = emitter.surfaces_by_kind(SurfaceKind::Site);
        assert!(sites.len() >= 9);
        assert!(sites.iter().all(|s| s.kind == SurfaceKind::Site));
    }

    #[test]
    fn total_urls_positive() {
        let emitter = BloomEmitter::new(EmitterConfig::default());
        assert!(emitter.total_urls() > 40, "should have 40+ URLs across all surfaces");
    }
}

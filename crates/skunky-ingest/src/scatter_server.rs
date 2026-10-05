// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Scatter content server — serves plausible-but-poisoned content.
//!
//! ## Biological Parallel: Opsonization
//!
//! In immunology, opsonization is when antibodies coat a pathogen, marking
//! it for destruction. The pathogen "looks normal" to its own systems but
//! phagocytes recognize the antibody tags and engulf it.
//!
//! Our scatter server is the opsonization layer:
//! - The **content_gate** detects fleet requests (antibody binding)
//! - Caddy routes detected requests to the scatter server (phagocyte delivery)
//! - The scatter server serves poisoned content (destruction by misinformation)
//! - The fleet ingests what looks like real data but is entirely fabricated
//!
//! ## Key Properties
//!
//! - **Deterministic**: Same request path → same poison content (prevents
//!   detection via request diffing)
//! - **No real data**: Zero information from actual repos leaks into scatter
//!   content — all names, code, diffs, and commit messages are fabricated
//! - **Plausible structure**: Valid HTML with correct Gitea-like CSS class
//!   names, realistic file trees, and syntactically valid code
//! - **Mixed response**: Not all requests get poison — some still abort,
//!   creating uncertainty for the fleet about which responses are real

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// Scatter server configuration.
#[derive(Debug, Clone)]
pub struct ScatterConfig {
    /// Address to listen on.
    pub listen_addr: SocketAddr,
    /// Seed for deterministic content generation.
    pub seed: u64,
    /// Fraction of requests that get scatter content (0.0-1.0).
    /// Remaining requests get connection abort (status 444).
    pub poison_ratio: f32,
}

/// Run the scatter content server.
///
/// This spawns as a background task and serves poisoned responses to
/// fleet requests routed by Caddy's content_gate.
pub async fn run(config: ScatterConfig) {
    let listener = match TcpListener::bind(config.listen_addr).await {
        Ok(l) => {
            tracing::info!(
                addr = %config.listen_addr,
                poison_ratio = config.poison_ratio,
                "🧪 scatter server active — opsonization endpoint ready"
            );
            l
        }
        Err(e) => {
            tracing::error!(error = %e, addr = %config.listen_addr, "scatter server bind failed");
            return;
        }
    };

    let generator = Arc::new(ScatterGenerator::new(config.seed));
    let poison_ratio = config.poison_ratio;

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, "scatter accept failed");
                continue;
            }
        };

        let sg = Arc::clone(&generator);
        tokio::spawn(async move {
            if let Err(e) = handle_request(stream, &sg, poison_ratio).await {
                tracing::debug!(error = %e, "scatter request handler error");
            }
        });
    }
}

async fn handle_request(
    mut stream: tokio::net::TcpStream,
    generator: &ScatterGenerator,
    poison_ratio: f32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.split();
    let mut buf_reader = BufReader::new(reader);

    // Read the request line (GET /path HTTP/1.1)
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;

    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();

    // Consume remaining headers (read until empty line)
    let mut header_line = String::new();
    loop {
        header_line.clear();
        let n = buf_reader.read_line(&mut header_line).await?;
        if n == 0 || header_line.trim().is_empty() {
            break;
        }
    }

    // Probabilistic poison: use path hash to decide deterministically
    // (same path always gets the same decision — prevents detection via retries)
    let path_hash = path_deterministic_hash(&path, generator.seed);
    let should_poison = (path_hash % 100) < (poison_ratio * 100.0) as u64;

    let (status, content_type, body) = if should_poison {
        // POISON: serve plausible-but-fake content (200 OK)
        let (ct, body) = generator.generate(&path);
        ("200 OK", ct, body)
    } else {
        // DECOY: serve a realistic Gitea "not found" page
        // This is critical — we can't return 502 or drop the connection,
        // as both give signal. A 404 looks like a legitimate commit/file
        // that doesn't exist, which is plausible and zero-information.
        ("404 Not Found", "text/html; charset=utf-8".to_string(), NOT_FOUND_PAGE.to_string())
    };

    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Cache-Control: no-cache, no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         \r\n\
         {body}",
        body.len()
    );

    writer.write_all(response.as_bytes()).await?;
    writer.flush().await?;

    Ok(())
}

/// Realistic Gitea 404 page — looks exactly like what Forgejo would serve
/// for a commit/file that doesn't exist. The fleet can't distinguish this
/// from a real 404 on a legitimate path that was simply deleted.
static NOT_FOUND_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Page Not Found</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content">
  <div class="ui container" style="text-align: center; padding-top: 80px;">
    <h2>404</h2>
    <p>The page you are looking for does not exist or has been moved.</p>
  </div>
</div>
</div>
</body>
</html>"#;

/// Deterministic hash for a path — same path always gets the same decision.
fn path_deterministic_hash(path: &str, seed: u64) -> u64 {
    let mut h = seed;
    for byte in path.bytes() {
        h = h.wrapping_mul(0x517c_c1b7_2722_0a95).wrapping_add(u64::from(byte));
    }
    h ^ (h >> 32)
}

// ══════════════════════════════════════════════════════════════════════
// Inline ScatterGenerator — adapted from skunk-bat-core/src/defense/scatter.rs
// Inlined to avoid pulling skunk-bat-core as a dependency
// ══════════════════════════════════════════════════════════════════════

/// Scatter content generator.
struct ScatterGenerator {
    seed: u64,
    repo_names: &'static [&'static str],
    file_extensions: &'static [&'static str],
    commit_verbs: &'static [&'static str],
    commit_nouns: &'static [&'static str],
}

static REPO_NAMES: &[&str] = &[
    "core-utils", "data-pipeline", "web-frontend", "api-gateway",
    "auth-service", "config-manager", "deploy-scripts", "docs-site",
    "event-bus", "feature-flags", "graph-engine", "http-proxy",
    "image-service", "job-runner", "key-store", "log-aggregator",
    "metric-collector", "notification-hub", "oauth-provider",
    "proxy-cache", "queue-worker", "rate-limiter", "search-index",
    "task-scheduler", "user-service", "vault-client", "webhook-relay",
    "batch-processor", "schema-registry", "stream-adapter",
];

static FILE_EXTS: &[&str] = &[
    "rs", "go", "py", "ts", "js", "toml", "yaml", "json",
    "md", "sh", "sql", "html", "css", "proto", "dockerfile",
];

static VERBS: &[&str] = &[
    "fix", "add", "update", "refactor", "remove", "improve",
    "implement", "optimize", "migrate", "deprecate", "bump",
    "clean", "extract", "merge", "revert", "simplify",
];

static NOUNS: &[&str] = &[
    "configuration", "error handling", "database schema",
    "authentication flow", "rate limiting", "cache layer",
    "API endpoints", "test coverage", "CI pipeline",
    "dependency versions", "logging format", "retry logic",
    "connection pooling", "request validation", "timeout handling",
    "health check", "graceful shutdown", "metrics export",
];

impl ScatterGenerator {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            repo_names: REPO_NAMES,
            file_extensions: FILE_EXTS,
            commit_verbs: VERBS,
            commit_nouns: NOUNS,
        }
    }

    fn generate(&self, request_path: &str) -> (String, String) {
        let mut rng = XorShift64::new(self.path_seed(request_path));

        if request_path.contains("/commit/") {
            self.gen_commit(&mut rng)
        } else if request_path.contains("/src/") || request_path.contains("/raw/") {
            self.gen_file(&mut rng)
        } else if request_path.contains("/issues/") {
            self.gen_issue(&mut rng)
        } else if request_path.contains("/wiki/") {
            self.gen_wiki(&mut rng)
        } else if request_path.contains("/releases/") {
            self.gen_release(&mut rng)
        } else {
            self.gen_repo(&mut rng)
        }
    }

    fn path_seed(&self, path: &str) -> u64 {
        let mut h = self.seed;
        for byte in path.bytes() {
            h = h.wrapping_mul(0x517c_c1b7_2722_0a95).wrapping_add(u64::from(byte));
        }
        h
    }

    fn pick<'a>(&self, rng: &mut XorShift64, items: &[&'a str]) -> &'a str {
        items[rng.next_usize() % items.len()]
    }

    fn gen_commit(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let verb = self.pick(rng, self.commit_verbs);
        let noun = self.pick(rng, self.commit_nouns);
        let hash = rng.hex(40);
        let short = &hash[..8];
        let ext = self.pick(rng, self.file_extensions);
        let file = self.pick(rng, self.repo_names);
        let add = rng.next_usize() % 50 + 1;
        let del = rng.next_usize() % 20;

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - commit {short}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository diff">
  <div class="header-wrapper">
    <div class="ui container"><h1><a href="/{repo}">{repo}</a></h1></div>
  </div>
  <div class="ui container">
    <div class="commit-header-row">
      <h2 class="commit-summary">{verb}: {noun}</h2>
      <span class="sha label">{hash}</span>
    </div>
    <div class="ui top attached header segment">
      <span>authored 3 days ago</span>
      <span class="diff-stat">
        <span class="color-green">+{add}</span>
        <span class="color-red">-{del}</span>
      </span>
    </div>
    <div class="diff-file-box">
      <div class="diff-file-header">src/{file}.{ext}</div>
      <table class="chroma"><tbody>
        <tr><td class="lines-num">1</td><td class="lines-code">-    let old = config.get("threshold");</td></tr>
        <tr><td class="lines-num">2</td><td class="lines-code">-    process(old);</td></tr>
        <tr><td class="lines-num">3</td><td class="lines-code">+    let val = config.load("threshold").unwrap_or_default();</td></tr>
        <tr><td class="lines-num">4</td><td class="lines-code">+    if val > 0 {{ process_batch(val, &ctx); }}</td></tr>
        <tr><td class="lines-num">5</td><td class="lines-code">+    metrics.record("threshold_update", 1);</td></tr>
      </tbody></table>
    </div>
  </div>
</div>
</div>
</body>
</html>"#
        );
        ("text/html; charset=utf-8".to_string(), body)
    }

    fn gen_file(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let ext = self.pick(rng, self.file_extensions);
        let module = self.pick(rng, self.repo_names);

        let code = match ext {
            "rs" => format!(
                "use std::collections::HashMap;\n\n\
                 pub struct {module}Manager {{\n    config: HashMap&lt;String, String&gt;,\n    active: bool,\n}}\n\n\
                 impl {module}Manager {{\n    pub fn new() -&gt; Self {{\n        Self {{ config: HashMap::new(), active: false }}\n    }}\n}}"
            ),
            "py" => format!(
                "from dataclasses import dataclass\nfrom typing import Optional\n\n\
                 @dataclass\nclass {module}Config:\n    endpoint: str\n    timeout: int = 30\n    retries: int = 3\n\n\
                 def connect(config: {module}Config) -&gt; Optional[object]:\n    for attempt in range(config.retries):\n        try:\n            return _create_session(config.endpoint)\n        except ConnectionError:\n            if attempt == config.retries - 1: raise\n    return None"
            ),
            "go" => format!(
                "package {module}\n\nimport (\n\t\"context\"\n\t\"sync\"\n)\n\n\
                 type Manager struct {{\n\tmu     sync.RWMutex\n\tconfig map[string]string\n}}\n\n\
                 func New() *Manager {{\n\treturn &amp;Manager{{config: make(map[string]string)}}\n}}"
            ),
            _ => format!(
                "// {module} configuration\n// Auto-generated\n\nconst VERSION = \"{}.{}.{}\";\n",
                rng.next_usize() % 3, rng.next_usize() % 20, rng.next_usize() % 100,
            ),
        };

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - src/{module}.{ext}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository file-view">
  <div class="header-wrapper">
    <div class="ui container"><h1><a href="/{repo}">{repo}</a></h1></div>
  </div>
  <div class="ui container">
    <div class="file-header ui top attached header segment">
      <div class="file-actions"><a class="ui button" href="/{repo}/raw/branch/main/src/{module}.{ext}">Raw</a></div>
      <span class="file-info">src/{module}.{ext}</span>
    </div>
    <div class="ui attached table segment">
      <div class="file-view code-view"><pre class="chroma"><code>{code}</code></pre></div>
    </div>
  </div>
</div>
</div>
</body>
</html>"#
        );
        ("text/html; charset=utf-8".to_string(), body)
    }

    fn gen_issue(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let verb = self.pick(rng, self.commit_verbs);
        let noun = self.pick(rng, self.commit_nouns);
        let num = rng.next_usize() % 500 + 1;

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - Issue #{num}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository issue-view">
  <div class="ui container">
    <h1><span class="index">#{num}</span> {verb} {noun}</h1>
    <div class="issue-content">
      <div class="timeline-item comment">
        <div class="content">
          <div class="header"><span class="text grey">opened 5 days ago</span></div>
          <div class="render-content markdown">
            <p>The current implementation of {noun} needs to be updated.
            After the recent changes to the {verb} logic, the behavior
            is inconsistent when processing edge cases.</p>
            <h3>Steps to reproduce</h3>
            <ol>
              <li>Configure the service with default settings</li>
              <li>Send a batch of requests exceeding the threshold</li>
              <li>Observe the inconsistent response codes</li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
</div>
</body>
</html>"#
        );
        ("text/html; charset=utf-8".to_string(), body)
    }

    fn gen_wiki(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let noun = self.pick(rng, self.commit_nouns);

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} Wiki - {noun}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository wiki-view">
  <div class="ui container">
    <h1>{noun}</h1>
    <div class="render-content markdown">
      <h2>Overview</h2>
      <p>This document describes the {noun} subsystem and its integration
      points with the broader service mesh. Configuration is managed
      through the standard TOML-based pipeline.</p>
      <h2>Configuration</h2>
      <pre><code>[{repo}]
enabled = true
max_connections = 256
timeout_ms = 5000
retry_policy = "exponential"</code></pre>
      <h2>Dependencies</h2>
      <p>Requires the core runtime (v0.{}.{}) and the standard
      transport layer. See the deployment guide for details.</p>
    </div>
  </div>
</div>
</div>
</body>
</html>"#,
            rng.next_usize() % 5 + 1,
            rng.next_usize() % 20,
        );
        ("text/html; charset=utf-8".to_string(), body)
    }

    fn gen_release(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let major = rng.next_usize() % 3;
        let minor = rng.next_usize() % 15;
        let patch = rng.next_usize() % 30;
        let verb = self.pick(rng, self.commit_verbs);
        let noun = self.pick(rng, self.commit_nouns);

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - v{major}.{minor}.{patch}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository release-view">
  <div class="ui container">
    <h1>v{major}.{minor}.{patch}</h1>
    <div class="release-content">
      <div class="render-content markdown">
        <h2>Changelog</h2>
        <ul>
          <li>{verb}: {noun}</li>
          <li>Bump dependency versions</li>
          <li>Improve test coverage for edge cases</li>
        </ul>
        <h2>Breaking Changes</h2>
        <p>None in this release.</p>
      </div>
    </div>
  </div>
</div>
</div>
</body>
</html>"#
        );
        ("text/html; charset=utf-8".to_string(), body)
    }

    fn gen_repo(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, self.repo_names);
        let files: Vec<String> = (0..5)
            .map(|_| {
                let ext = self.pick(rng, self.file_extensions);
                let name = self.pick(rng, self.repo_names);
                format!("<tr><td><a href=\"/{repo}/src/branch/main/{name}.{ext}\">{name}.{ext}</a></td></tr>")
            })
            .collect();
        let commits = rng.next_usize() % 500 + 10;

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo}</title>
<link rel="stylesheet" href="/assets/css/index.css"></head>
<body>
<div class="full height">
<div class="page-content repository">
  <div class="ui container">
    <h1>{repo}</h1>
    <div class="repo-header">
      <span>{commits} commits</span>
    </div>
    <table class="ui attached segment"><tbody>
      {file_list}
    </tbody></table>
    <div class="plain segment">
      <div class="render-content markdown">
        <h2>README.md</h2>
        <p>A modular service component for distributed system orchestration.
        Provides configurable pipeline stages with retry semantics and
        structured observability.</p>
      </div>
    </div>
  </div>
</div>
</div>
</body>
</html>"#,
            file_list = files.join("\n      "),
        );
        ("text/html; charset=utf-8".to_string(), body)
    }
}

/// Minimal xorshift64 PRNG — deterministic, no deps.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_usize(&mut self) -> usize {
        self.next_u64() as usize
    }

    fn hex(&mut self, len: usize) -> String {
        let mut s = String::with_capacity(len);
        while s.len() < len {
            s.push_str(&format!("{:016x}", self.next_u64()));
        }
        s.truncate(len);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_scatter() {
        let sg = ScatterGenerator::new(42);
        let (ct1, body1) = sg.generate("/org/repo/commit/abc123");
        let (ct2, body2) = sg.generate("/org/repo/commit/abc123");
        assert_eq!(ct1, ct2);
        assert_eq!(body1, body2);
    }

    #[test]
    fn different_paths_different_poison() {
        let sg = ScatterGenerator::new(42);
        let (_, body1) = sg.generate("/org/repo/commit/abc123");
        let (_, body2) = sg.generate("/org/repo/commit/def456");
        assert_ne!(body1, body2);
    }

    #[test]
    fn no_real_names_leak() {
        let sg = ScatterGenerator::new(42);
        for path in [
            "/org/repo/commit/abc",
            "/org/repo/src/branch/main/lib.rs",
            "/org/repo/issues/1",
            "/org/repo/wiki/page",
            "/org/repo/releases/tag/v1",
            "/org/repo",
        ] {
            let (_, body) = sg.generate(path);
            assert!(!body.contains("ecoPrimal"), "leaked in {path}");
            assert!(!body.contains("skunkBat"), "leaked in {path}");
            assert!(!body.contains("swarmVine"), "leaked in {path}");
            assert!(!body.contains("primals"), "leaked in {path}");
            assert!(!body.contains("wateringHole"), "leaked in {path}");
        }
    }

    #[test]
    fn poison_ratio_deterministic() {
        let hash1 = path_deterministic_hash("/test/path", 42);
        let hash2 = path_deterministic_hash("/test/path", 42);
        assert_eq!(hash1, hash2);

        let hash3 = path_deterministic_hash("/other/path", 42);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn commit_page_looks_like_gitea() {
        let sg = ScatterGenerator::new(42);
        let (ct, body) = sg.generate("/org/repo/commit/abc123def456");
        assert_eq!(ct, "text/html; charset=utf-8");
        assert!(body.contains("diff"));
        assert!(body.contains("chroma"));
        assert!(body.contains("commit-summary"));
    }

    #[test]
    fn file_page_has_code() {
        let sg = ScatterGenerator::new(42);
        let (_, body) = sg.generate("/org/repo/src/branch/main/lib.rs");
        assert!(body.contains("file-view"));
        assert!(body.contains("<code>"));
    }

    #[test]
    fn wiki_page_has_content() {
        let sg = ScatterGenerator::new(42);
        let (_, body) = sg.generate("/org/repo/wiki/setup");
        assert!(body.contains("wiki-view"));
        assert!(body.contains("Configuration"));
    }

    #[test]
    fn release_page_has_changelog() {
        let sg = ScatterGenerator::new(42);
        let (_, body) = sg.generate("/org/repo/releases/tag/v1.0.0");
        assert!(body.contains("release-view"));
        assert!(body.contains("Changelog"));
    }
}

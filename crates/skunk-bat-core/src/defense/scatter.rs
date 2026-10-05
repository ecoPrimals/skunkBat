// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Scatter content generator — P3 anti-AI defense.
//!
//! Generates plausible-but-wrong content that looks like real git forge
//! responses. The shape is correct (valid HTML, correct headers, realistic
//! structure) but the content is garbage — file names, commit messages,
//! diffs, and code are all fabricated.
//!
//! ## Philosophy
//!
//! The goal is NOT to crash the scraper — that would reveal detection.
//! The goal is to **poison the training data**. A scraper that receives
//! scatter content will happily ingest it because it looks normal. The
//! human reviewing the output later (if ever) won't notice the subtle
//! wrongness because each individual response looks plausible.
//!
//! ## Design
//!
//! - Deterministic from `(seed, request_path)` — same request always
//!   returns the same scatter content, preventing detection via diffing
//! - Uses a simple xorshift PRNG seeded from the path hash — no
//!   external randomness needed
//! - Generates minimal but valid HTML that looks like a Gitea page
//! - No real data from any primal ever leaks into scatter content

/// Scatter content generator.
pub struct ScatterGenerator {
    seed: u64,
    repo_names: Vec<&'static str>,
    file_extensions: Vec<&'static str>,
    commit_verbs: Vec<&'static str>,
    commit_nouns: Vec<&'static str>,
}

impl ScatterGenerator {
    /// Create a new scatter generator with the given seed.
    ///
    /// The seed should be stable per deployment (e.g. derived from the
    /// server key hash) so scatter content is deterministic.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            repo_names: vec![
                "core-utils", "data-pipeline", "web-frontend", "api-gateway",
                "auth-service", "config-manager", "deploy-scripts", "docs-site",
                "event-bus", "feature-flags", "graph-engine", "http-proxy",
                "image-service", "job-runner", "key-store", "log-aggregator",
                "metric-collector", "notification-hub", "oauth-provider",
                "proxy-cache", "queue-worker", "rate-limiter", "search-index",
                "task-scheduler", "user-service", "vault-client", "webhook-relay",
            ],
            file_extensions: vec![
                "rs", "go", "py", "ts", "js", "toml", "yaml", "json",
                "md", "sh", "sql", "html", "css", "proto", "dockerfile",
            ],
            commit_verbs: vec![
                "fix", "add", "update", "refactor", "remove", "improve",
                "implement", "optimize", "migrate", "deprecate", "bump",
                "clean", "extract", "merge", "revert", "simplify",
            ],
            commit_nouns: vec![
                "configuration", "error handling", "database schema",
                "authentication flow", "rate limiting", "cache layer",
                "API endpoints", "test coverage", "CI pipeline",
                "dependency versions", "logging format", "retry logic",
                "connection pooling", "request validation", "timeout handling",
                "health check", "graceful shutdown", "metrics export",
            ],
        }
    }

    /// Generate scatter content for a request path.
    ///
    /// Returns `(content_type, body)` — the response to send back to
    /// the scatter-matched IP.
    #[must_use]
    pub fn generate(&self, request_path: &str) -> (String, String) {
        let mut rng = XorShift64::new(self.path_seed(request_path));

        if request_path.contains("/commit/") {
            self.generate_commit_page(&mut rng)
        } else if request_path.contains("/src/") || request_path.contains("/raw/") {
            self.generate_file_page(&mut rng)
        } else if request_path.contains("/issues") {
            self.generate_issue_page(&mut rng)
        } else {
            self.generate_repo_page(&mut rng)
        }
    }

    /// Deterministic seed for a given path.
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

    fn generate_commit_page(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, &self.repo_names);
        let verb = self.pick(rng, &self.commit_verbs);
        let noun = self.pick(rng, &self.commit_nouns);
        let hash = rng.hex_string(40);
        let short_hash = &hash[..8];
        let ext = self.pick(rng, &self.file_extensions);
        let file_name = format!("src/{}.{ext}", self.pick(rng, &self.repo_names));
        let lines_added = rng.next_usize() % 50 + 1;
        let lines_removed = rng.next_usize() % 20;

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - commit {short_hash}</title></head>
<body>
<div class="repository">
  <h1><a href="/{repo}">{repo}</a></h1>
  <div class="commit-header">
    <h2>{verb}: {noun}</h2>
    <span class="sha">{hash}</span>
    <div class="commit-meta">
      <span>authored 3 days ago</span>
      <span>·</span>
      <span class="additions">+{lines_added}</span>
      <span class="deletions">-{lines_removed}</span>
    </div>
  </div>
  <div class="diff">
    <div class="file-header">{file_name}</div>
    <pre class="diff-content">
@@ -{lines_removed},6 +{lines_added},8 @@
-    let old_value = config.get("threshold");
-    process(old_value);
+    let updated = config.load("threshold").unwrap_or_default();
+    if updated > 0 {{
+        process_batch(updated, &context);
+    }}
+    metrics.record("threshold_update", 1);
    </pre>
  </div>
</div>
</body>
</html>"#
        );

        ("text/html; charset=utf-8".to_string(), body)
    }

    fn generate_file_page(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, &self.repo_names);
        let ext = self.pick(rng, &self.file_extensions);
        let module = self.pick(rng, &self.repo_names);

        let code = match ext {
            "rs" => format!(
                "use std::collections::HashMap;\n\
                 \n\
                 pub struct {module}Manager {{\n\
                 \x20   config: HashMap<String, String>,\n\
                 \x20   active: bool,\n\
                 }}\n\
                 \n\
                 impl {module}Manager {{\n\
                 \x20   pub fn new() -> Self {{\n\
                 \x20       Self {{\n\
                 \x20           config: HashMap::new(),\n\
                 \x20           active: false,\n\
                 \x20       }}\n\
                 \x20   }}\n\
                 }}\n"
            ),
            "py" => format!(
                "from dataclasses import dataclass\n\
                 from typing import Optional\n\
                 \n\
                 @dataclass\n\
                 class {module}Config:\n\
                 \x20   endpoint: str\n\
                 \x20   timeout: int = 30\n\
                 \x20   retries: int = 3\n\
                 \n\
                 def connect(config: {module}Config) -> Optional[object]:\n\
                 \x20   \"\"\"Establish connection with retry logic.\"\"\"\n\
                 \x20   for attempt in range(config.retries):\n\
                 \x20       try:\n\
                 \x20           return _create_session(config.endpoint, config.timeout)\n\
                 \x20       except ConnectionError:\n\
                 \x20           if attempt == config.retries - 1:\n\
                 \x20               raise\n\
                 \x20   return None\n"
            ),
            _ => format!(
                "// {module} configuration\n\
                 // Auto-generated — do not edit\n\n\
                 const VERSION: &str = \"0.{}.{}\";\n",
                rng.next_usize() % 20,
                rng.next_usize() % 100,
            ),
        };

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - src/{module}.{ext}</title></head>
<body>
<div class="repository">
  <h1><a href="/{repo}">{repo}</a></h1>
  <div class="file-view">
    <div class="file-header">src/{module}.{ext}</div>
    <pre class="file-content"><code>{code}</code></pre>
  </div>
</div>
</body>
</html>"#
        );

        ("text/html; charset=utf-8".to_string(), body)
    }

    fn generate_issue_page(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, &self.repo_names);
        let verb = self.pick(rng, &self.commit_verbs);
        let noun = self.pick(rng, &self.commit_nouns);
        let issue_num = rng.next_usize() % 500 + 1;

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo} - Issue #{issue_num}</title></head>
<body>
<div class="repository">
  <h1><a href="/{repo}">{repo}</a></h1>
  <div class="issue">
    <h2>#{issue_num}: {verb} {noun}</h2>
    <div class="issue-meta">
      <span class="label label-open">open</span>
      <span>opened 5 days ago</span>
    </div>
    <div class="issue-body">
      <p>The current implementation of {noun} needs to be updated.
      After the recent changes to the {verb} logic, the behavior
      is inconsistent when processing edge cases.</p>
      <p>Steps to reproduce:</p>
      <ol>
        <li>Configure the service with default settings</li>
        <li>Send a batch of requests exceeding the threshold</li>
        <li>Observe the inconsistent response codes</li>
      </ol>
    </div>
  </div>
</div>
</body>
</html>"#
        );

        ("text/html; charset=utf-8".to_string(), body)
    }

    fn generate_repo_page(&self, rng: &mut XorShift64) -> (String, String) {
        let repo = self.pick(rng, &self.repo_names);
        let files: Vec<String> = (0..5)
            .map(|_| {
                let ext = self.pick(rng, &self.file_extensions);
                let name = self.pick(rng, &self.repo_names);
                format!("<li><a href=\"/{repo}/src/branch/main/{name}.{ext}\">{name}.{ext}</a></li>")
            })
            .collect();

        let body = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{repo}</title></head>
<body>
<div class="repository">
  <h1>{repo}</h1>
  <div class="repo-meta">
    <span>Last updated 2 hours ago</span>
    <span>·</span>
    <span>{} commits</span>
  </div>
  <div class="file-list">
    <ul>
      {}
    </ul>
  </div>
  <div class="readme">
    <h2>README.md</h2>
    <p>A modular service component for distributed system orchestration.
    Provides configurable pipeline stages with retry semantics and
    structured observability.</p>
  </div>
</div>
</body>
</html>"#,
            rng.next_usize() % 500 + 10,
            files.join("\n      "),
        );

        ("text/html; charset=utf-8".to_string(), body)
    }
}

impl Default for ScatterGenerator {
    fn default() -> Self {
        Self::new(0xdead_beef_cafe_babe)
    }
}

/// Minimal xorshift64 PRNG — no external dependencies, deterministic.
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

    fn hex_string(&mut self, len: usize) -> String {
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
    fn deterministic_output() {
        let sg = ScatterGenerator::new(42);
        let (ct1, body1) = sg.generate("/repo/commit/abc123");
        let (ct2, body2) = sg.generate("/repo/commit/abc123");
        assert_eq!(ct1, ct2);
        assert_eq!(body1, body2);
    }

    #[test]
    fn different_paths_different_content() {
        let sg = ScatterGenerator::new(42);
        let (_, body1) = sg.generate("/repo/commit/abc123");
        let (_, body2) = sg.generate("/repo/commit/def456");
        assert_ne!(body1, body2);
    }

    #[test]
    fn commit_page_has_diff() {
        let sg = ScatterGenerator::new(42);
        let (ct, body) = sg.generate("/repo/commit/abc123def456");
        assert_eq!(ct, "text/html; charset=utf-8");
        assert!(body.contains("diff"));
        assert!(body.contains("<html"));
        assert!(body.contains("</html>"));
    }

    #[test]
    fn file_page_has_code() {
        let sg = ScatterGenerator::new(42);
        let (_, body) = sg.generate("/repo/src/branch/main/lib.rs");
        assert!(body.contains("<code>"));
        assert!(body.contains("file-content"));
    }

    #[test]
    fn issue_page_has_issue() {
        let sg = ScatterGenerator::new(42);
        let (_, body) = sg.generate("/repo/issues/42");
        assert!(body.contains("issue"));
        assert!(body.contains("#"));
    }

    #[test]
    fn repo_page_has_file_list() {
        let sg = ScatterGenerator::new(42);
        let (_, body) = sg.generate("/repo");
        assert!(body.contains("file-list"));
        assert!(body.contains("README.md"));
    }

    #[test]
    fn no_real_primal_names_leak() {
        let sg = ScatterGenerator::new(42);
        for path in [
            "/commit/abc", "/src/x.rs", "/issues/1", "/",
        ] {
            let (_, body) = sg.generate(path);
            assert!(!body.contains("ecoPrimal"), "real name leaked in {path}");
            assert!(!body.contains("skunkBat"), "primal name leaked in {path}");
            assert!(!body.contains("swarmVine"), "primal name leaked in {path}");
            assert!(!body.contains("bearDog"), "primal name leaked in {path}");
        }
    }

    #[test]
    fn xorshift_deterministic() {
        let mut rng1 = XorShift64::new(12345);
        let mut rng2 = XorShift64::new(12345);
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn hex_string_correct_length() {
        let mut rng = XorShift64::new(42);
        assert_eq!(rng.hex_string(40).len(), 40);
        assert_eq!(rng.hex_string(8).len(), 8);
    }
}

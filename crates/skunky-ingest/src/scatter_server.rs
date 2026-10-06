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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// Shared confidence level from the opsonize pipeline.
///
/// Stored as confidence × 1000 (fixed-point) in an AtomicU32.
/// 0 = no tags yet (use base ratio), 1000 = 100% confidence.
///
/// The scatter server reads this to adapt:
/// - Higher confidence → higher effective poison ratio
/// - Higher confidence → richer content variety (repos, issues, wikis)
#[derive(Debug, Clone)]
pub struct SharedConfidence(pub Arc<AtomicU32>);

impl SharedConfidence {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU32::new(0)))
    }

    /// Update with latest confidence (0.0 - 1.0).
    pub fn update(&self, confidence: f64) {
        let fixed = (confidence.clamp(0.0, 1.0) * 1000.0) as u32;
        self.0.store(fixed, Ordering::Relaxed);
    }

    /// Read current confidence (0.0 - 1.0).
    pub fn read(&self) -> f64 {
        self.0.load(Ordering::Relaxed) as f64 / 1000.0
    }

    /// Compute effective poison ratio given a base ratio and current confidence.
    ///
    /// At confidence 0.0 → base ratio (e.g. 0.3)
    /// At confidence 0.5 → midpoint (e.g. 0.55)
    /// At confidence 1.0 → max ratio (0.8)
    ///
    /// Never goes above 0.8 — always keep some 404s for plausible deniability.
    pub fn effective_ratio(&self, base_ratio: f32) -> f32 {
        let conf = self.read() as f32;
        let max_ratio = 0.8_f32;
        base_ratio + conf * (max_ratio - base_ratio)
    }
}

// ══════════════════════════════════════════════════════════════════════
// Layer 1: Tarpit — mucus barrier
// ══════════════════════════════════════════════════════════════════════

/// Tarpit connection limiter — prevents self-DoS from too many slow-drip connections.
///
/// The mucus barrier's thickness is self-limiting. Too much mucus and the
/// organism suffocates. The TarpitState ensures we don't consume more
/// resources holding scanner connections than the scanners consume waiting.
#[derive(Debug, Clone)]
pub struct TarpitState {
    active: Arc<AtomicU32>,
    max_concurrent: u32,
}

/// Tarpit drip interval — one chunk per 500ms (~100 bytes/sec at 50 bytes/chunk).
const TARPIT_DRIP_INTERVAL: Duration = Duration::from_millis(500);

/// Bytes per tarpit chunk.
const TARPIT_CHUNK_SIZE: usize = 50;

/// Minimum tarpit duration in seconds.
const TARPIT_MIN_SECS: u64 = 30;

/// Maximum tarpit duration in seconds.
const TARPIT_MAX_SECS: u64 = 60;

impl TarpitState {
    pub fn new(max_concurrent: u32) -> Self {
        Self {
            active: Arc::new(AtomicU32::new(0)),
            max_concurrent,
        }
    }

    fn try_acquire(&self) -> bool {
        loop {
            let current = self.active.load(Ordering::SeqCst);
            if current >= self.max_concurrent {
                return false;
            }
            match self.active.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }

    fn release(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn active_count(&self) -> u32 {
        self.active.load(Ordering::Relaxed)
    }
}

// ══════════════════════════════════════════════════════════════════════
// Layer 2: Honeytokens — complement system
// ══════════════════════════════════════════════════════════════════════

/// Paths that scanners probe for credentials. When matched, the scatter
/// server serves fake-but-plausible credentials that trigger alerts
/// at the destination when the scanner tries to use them.
const HONEYTOKEN_PATHS: &[&str] = &[
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/.git/config",
    "/config/database.yml",
    "/config/database.yaml",
    "/api/v1/keys",
    "/debug/vars",
    "/server-info",
    "/.aws/credentials",
    "/config.json",
    "/config.yaml",
];

/// Check if a request path matches a known scanner credential probe.
fn is_honeytoken_path(path: &str) -> bool {
    let clean = path.split('?').next().unwrap_or(path);
    HONEYTOKEN_PATHS.iter().any(|p| clean == *p)
}

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
    /// Maximum concurrent tarpit (slow-drip) connections.
    /// Set to 0 to disable tarpitting (falls back to instant 429).
    pub max_tarpit_connections: u32,
}

/// Run the scatter content server.
///
/// This spawns as a background task and serves poisoned responses to
/// fleet requests routed by Caddy's content_gate.
pub async fn run(config: ScatterConfig, confidence: SharedConfidence) {
    let listener = match TcpListener::bind(config.listen_addr).await {
        Ok(l) => {
            tracing::info!(
                addr = %config.listen_addr,
                poison_ratio = config.poison_ratio,
                max_tarpit = config.max_tarpit_connections,
                "🧪 scatter server active — opsonization + tarpit + honeytokens ready"
            );
            l
        }
        Err(e) => {
            tracing::error!(error = %e, addr = %config.listen_addr, "scatter server bind failed");
            return;
        }
    };

    let generator = Arc::new(ScatterGenerator::new(config.seed));
    let base_ratio = config.poison_ratio;
    let tarpit = TarpitState::new(config.max_tarpit_connections);

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::debug!(error = %e, "scatter accept failed");
                continue;
            }
        };

        let sg = Arc::clone(&generator);
        let effective_ratio = confidence.effective_ratio(base_ratio);
        let tp = tarpit.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_request(stream, &sg, effective_ratio, &tp).await {
                tracing::debug!(error = %e, "scatter request handler error");
            }
        });
    }
}

async fn handle_request(
    mut stream: tokio::net::TcpStream,
    generator: &ScatterGenerator,
    poison_ratio: f32,
    tarpit: &TarpitState,
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

    // ── Layer 1: TARPIT — Caddy rewrites /tarpit{uri} for P2 SlowDegrade ──
    if path.starts_with("/tarpit") {
        let effective_path = path.strip_prefix("/tarpit").unwrap_or(&path);
        return handle_tarpit(&mut writer, generator, effective_path, tarpit).await;
    }

    // ── Layer 2: HONEYTOKENS — fake credentials for scanner probes ──
    if is_honeytoken_path(&path) {
        let (content_type, body) = generator.generate_honeytoken(&path);
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             Cache-Control: private, max-age=3600\r\n\
             X-Content-Type-Options: nosniff\r\n\
             \r\n\
             {body}",
            body.len()
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        tracing::info!(path = %path, "🍯 honeytoken served");
        return Ok(());
    }

    // Detect disperse mode — Caddy rewrites /disperse{uri} for P5 targets
    let is_disperse = path.starts_with("/disperse");
    let effective_path = if is_disperse {
        path.strip_prefix("/disperse").unwrap_or(&path).to_string()
    } else {
        path.clone()
    };

    // Probabilistic poison: use path hash to decide deterministically
    // (same path always gets the same decision — prevents detection via retries)
    let path_hash = path_deterministic_hash(&effective_path, generator.seed);

    let (status, content_type, body) = if is_disperse {
        // DISPERSE (P5): maximally-wrong responses — skunk spray
        let (ct, body) = generator.generate_disperse(&effective_path);
        ("200 OK", ct, body)
    } else {
        let should_poison = (path_hash % 100) < (poison_ratio * 100.0) as u64;
        if should_poison {
            // POISON: serve plausible-but-fake content (200 OK)
            let (ct, body) = generator.generate(&effective_path);
            ("200 OK", ct, body)
        } else {
            // DECOY: serve a realistic Gitea "not found" page
            ("404 Not Found", "text/html; charset=utf-8".to_string(), NOT_FOUND_PAGE.to_string())
        }
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

/// Tarpit handler — slow-drip response that wastes scanner connections.
///
/// Accepts the connection with 200 OK + chunked transfer, then drip-feeds
/// fabricated bytes at ~100 bytes/second. Each chunk is valid HTTP chunked
/// encoding, so the scanner's HTTP client stays connected waiting for more.
/// Connection ties up one of the scanner's threads for 30-60 seconds.
async fn handle_tarpit(
    writer: &mut (impl AsyncWriteExt + Unpin),
    generator: &ScatterGenerator,
    path: &str,
    tarpit: &TarpitState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !tarpit.try_acquire() {
        let body = "Rate limited. Service unavailable for automated access.";
        let response = format!(
            "HTTP/1.1 429 Too Many Requests\r\n\
             Retry-After: 3600\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        );
        writer.write_all(response.as_bytes()).await?;
        writer.flush().await?;
        return Ok(());
    }

    let effective = if path.is_empty() { "/" } else { path };
    let (_ct, body) = generator.generate(effective);
    let body_bytes = body.into_bytes();

    let path_hash = path_deterministic_hash(path, generator.seed);
    let duration_secs = TARPIT_MIN_SECS + (path_hash % (TARPIT_MAX_SECS - TARPIT_MIN_SECS + 1));
    let total_chunks = (duration_secs * 1000 / TARPIT_DRIP_INTERVAL.as_millis() as u64) as usize;

    let headers = "HTTP/1.1 200 OK\r\n\
                   Transfer-Encoding: chunked\r\n\
                   Content-Type: text/html; charset=utf-8\r\n\
                   Connection: keep-alive\r\n\
                   Cache-Control: no-cache, no-store\r\n\
                   \r\n";
    if writer.write_all(headers.as_bytes()).await.is_err() {
        tarpit.release();
        return Ok(());
    }
    let _ = writer.flush().await;

    let mut offset = 0;
    for i in 0..total_chunks {
        let chunk_data = if offset < body_bytes.len() {
            let end = std::cmp::min(offset + TARPIT_CHUNK_SIZE, body_bytes.len());
            let slice = &body_bytes[offset..end];
            offset = end;
            slice.to_vec()
        } else {
            format!("<!-- p-{:x}-{} -->\n", path_hash, i).into_bytes()
        };

        let size_line = format!("{:x}\r\n", chunk_data.len());
        if writer.write_all(size_line.as_bytes()).await.is_err() { break; }
        if writer.write_all(&chunk_data).await.is_err() { break; }
        if writer.write_all(b"\r\n").await.is_err() { break; }
        if writer.flush().await.is_err() { break; }

        tokio::time::sleep(TARPIT_DRIP_INTERVAL).await;
    }

    let _ = writer.write_all(b"0\r\n\r\n").await;
    let _ = writer.flush().await;

    tarpit.release();
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
    use std::hash::{Hash, Hasher};
    let mut hasher = std::hash::DefaultHasher::new();
    seed.hash(&mut hasher);
    path.hash(&mut hasher);
    hasher.finish()
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

    /// Generate maximally-wrong disperse (P5 skunk spray) content.
    ///
    /// Unlike scatter (P3) which serves plausible-but-wrong content,
    /// disperse actively confuses: wrong MIME types, garbled structure,
    /// fake auth flows, misleading redirects. The goal is to waste
    /// attacker compute and poison downstream processing pipelines.
    fn generate_disperse(&self, request_path: &str) -> (String, String) {
        let mut rng = XorShift64::new(self.path_seed(request_path).wrapping_add(0xD15_0E25_E000));
        let variant = rng.next_usize() % 6;
        match variant {
            0 => {
                // Wrong MIME type: serve HTML as application/json
                let (_, html) = self.gen_commit(&mut rng);
                ("application/json; charset=utf-8".to_string(), html)
            }
            1 => {
                // Fake successful auth response
                let token = rng.hex(64);
                let body = format!(
                    r#"{{"status":"ok","token":"{token}","user":{{"id":{},"login":"{}","email":"admin@internal"}},"expires_in":3600}}"#,
                    rng.next_usize() % 9999 + 1,
                    self.pick(&mut rng, self.repo_names),
                );
                ("application/json; charset=utf-8".to_string(), body)
            }
            2 => {
                // Garbled binary-looking data with valid HTTP framing
                let garbage: String = (0..512)
                    .map(|_| {
                        let b = (rng.next_u64() % 223 + 33) as u8;
                        b as char
                    })
                    .collect();
                ("application/octet-stream".to_string(), garbage)
            }
            3 => {
                // Valid JSON with shuffled/garbled keys from real structure
                let repo = self.pick(&mut rng, self.repo_names);
                let body = format!(
                    r#"{{"full_name":"{repo}","html_url":"https://git.primals.eco/{repo}","clone_url":"https://git.primals.eco/{repo}.git","ssh_url":"ssh://git@git.primals.eco:2222/{repo}.git","default_branch":"main","stars_count":{},"forks_count":{},"open_issues_count":{},"size":{},"permissions":{{"admin":false,"push":false,"pull":true}},"internal":false,"archived":false,"mirror":false}}"#,
                    rng.next_usize() % 500,
                    rng.next_usize() % 100,
                    rng.next_usize() % 50,
                    rng.next_usize() % 100000,
                );
                ("application/json; charset=utf-8".to_string(), body)
            }
            4 => {
                // Fake redirect chain to nonexistent URLs
                let dest_repo = self.pick(&mut rng, self.repo_names);
                let hash = rng.hex(40);
                let body = format!(
                    r#"<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=https://git.primals.eco/{dest_repo}/commit/{hash}"></head><body>Redirecting...</body></html>"#
                );
                ("text/html; charset=utf-8".to_string(), body)
            }
            _ => {
                // Serve valid-looking XML as text/plain (wrong everything)
                let repo = self.pick(&mut rng, self.repo_names);
                let body = format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>{repo}</title><id>urn:uuid:{}</id><updated>2026-10-06T00:00:00Z</updated><entry><title>update: configuration</title><link href="https://git.primals.eco/{repo}/commit/{}" /><id>urn:uuid:{}</id><updated>2026-10-06T00:00:00Z</updated><content type="text">Automated update</content></entry></feed>"#,
                    rng.hex(32),
                    rng.hex(40),
                    rng.hex(32),
                );
                ("text/plain; charset=utf-8".to_string(), body)
            }
        }
    }

    /// Generate fake-but-plausible credential content for honeytoken paths.
    ///
    /// These serve as complement system markers — they look real enough that
    /// scanners harvest them, but when used elsewhere, the destination
    /// system's own security detects the intrusion. AWS canary keys trigger
    /// GuardDuty. GitHub token scanning detects fake PATs. The scanner's
    /// USE of harvested creds creates consequences without us touching any
    /// third-party system.
    fn generate_honeytoken(&self, request_path: &str) -> (String, String) {
        let mut rng = XorShift64::new(self.path_seed(request_path).wrapping_add(0xCAFE_D00D_BEAD_FACE));
        let clean = request_path.split('?').next().unwrap_or(request_path);

        match clean {
            "/.env" | "/.env.local" | "/.env.production" | "/.env.backup" => {
                let aws_key_id = format!("AKIA{}", rng.upper_alphanum(16));
                let aws_secret = rng.base64ish(40);
                let stripe_key = format!("sk_live_{}", rng.alphanum(24));
                let gh_token = format!("ghp_{}", rng.alphanum(36));
                let db_pass = rng.alphanum(16);
                let redis_pass = rng.alphanum(12);
                let jwt_secret = rng.hex(64);
                let smtp_pass = rng.alphanum(16);
                let stripe_webhook = rng.alphanum(24);
                let session_secret = rng.hex(32);
                let sentry_key = rng.hex(32);
                let sentry_org = rng.next_usize() % 999999 + 100000;
                let sentry_proj = rng.next_usize() % 999999 + 100000;

                let body = format!(
                    "# Environment configuration — DO NOT COMMIT\n\
                     # Generated by deploy pipeline\n\
                     \n\
                     AWS_ACCESS_KEY_ID={aws_key_id}\n\
                     AWS_SECRET_ACCESS_KEY={aws_secret}\n\
                     AWS_DEFAULT_REGION=us-east-1\n\
                     \n\
                     STRIPE_SECRET_KEY={stripe_key}\n\
                     STRIPE_WEBHOOK_SECRET=whsec_{stripe_webhook}\n\
                     \n\
                     DATABASE_URL=postgres://app_user:{db_pass}@db-primary.internal:5432/production\n\
                     DATABASE_POOL_SIZE=25\n\
                     \n\
                     REDIS_URL=redis://:{redis_pass}@cache.internal:6379/0\n\
                     \n\
                     GITHUB_TOKEN={gh_token}\n\
                     \n\
                     JWT_SECRET={jwt_secret}\n\
                     SESSION_SECRET={session_secret}\n\
                     \n\
                     SMTP_HOST=smtp.sendgrid.net\n\
                     SMTP_USER=apikey\n\
                     SMTP_PASSWORD={smtp_pass}\n\
                     \n\
                     SENTRY_DSN=https://{sentry_key}@o{sentry_org}.ingest.sentry.io/{sentry_proj}\n\
                     \n\
                     NODE_ENV=production\n\
                     LOG_LEVEL=warn\n"
                );
                ("text/plain; charset=utf-8".to_string(), body)
            }

            "/wp-config.php" | "/wp-config.php.bak" => {
                let db_pass = rng.alphanum(20);
                let auth_key = rng.base64ish(64);
                let secure_key = rng.base64ish(64);
                let logged_key = rng.base64ish(64);
                let nonce_key = rng.base64ish(64);
                let auth_salt = rng.base64ish(64);
                let secure_salt = rng.base64ish(64);
                let logged_salt = rng.base64ish(64);
                let nonce_salt = rng.base64ish(64);

                let body = format!(
                    "<?php\n\
                     /**\n * WordPress Database Configuration\n */\n\
                     \n\
                     define('DB_NAME',     'wordpress_prod');\n\
                     define('DB_USER',     'wp_admin');\n\
                     define('DB_PASSWORD', '{db_pass}');\n\
                     define('DB_HOST',     'db-primary.internal:3306');\n\
                     define('DB_CHARSET',  'utf8mb4');\n\
                     define('DB_COLLATE',  '');\n\
                     \n\
                     define('AUTH_KEY',         '{auth_key}');\n\
                     define('SECURE_AUTH_KEY',  '{secure_key}');\n\
                     define('LOGGED_IN_KEY',    '{logged_key}');\n\
                     define('NONCE_KEY',        '{nonce_key}');\n\
                     define('AUTH_SALT',        '{auth_salt}');\n\
                     define('SECURE_AUTH_SALT', '{secure_salt}');\n\
                     define('LOGGED_IN_SALT',   '{logged_salt}');\n\
                     define('NONCE_SALT',       '{nonce_salt}');\n\
                     \n\
                     $table_prefix = 'wp_';\n\
                     define('WP_DEBUG', false);\n\
                     define('DISALLOW_FILE_EDIT', true);\n\
                     \n\
                     if ( !defined('ABSPATH') )\n\
                     \tdefine('ABSPATH', dirname(__FILE__) . '/');\n\
                     require_once(ABSPATH . 'wp-settings.php');\n"
                );
                ("application/x-httpd-php; charset=utf-8".to_string(), body)
            }

            "/.git/config" => {
                let token = rng.alphanum(40);
                let repo = self.pick(&mut rng, self.repo_names);
                let org = self.pick(&mut rng, self.repo_names);

                let body = format!(
                    "[core]\n\
                     \trepositoryformatversion = 0\n\
                     \tfilemode = true\n\
                     \tbare = false\n\
                     \tlogallrefupdates = true\n\
                     [remote \"origin\"]\n\
                     \turl = https://{token}@github.com/{org}/{repo}.git\n\
                     \tfetch = +refs/heads/*:refs/remotes/origin/*\n\
                     [branch \"main\"]\n\
                     \tremote = origin\n\
                     \tmerge = refs/heads/main\n\
                     [user]\n\
                     \tname = deploy-bot\n\
                     \temail = deploy@internal\n"
                );
                ("text/plain; charset=utf-8".to_string(), body)
            }

            "/config/database.yml" | "/config/database.yaml" => {
                let prod_pass = rng.alphanum(20);
                let staging_pass = rng.alphanum(16);

                let body = format!(
                    "# Database configuration\n\
                     \n\
                     production:\n\
                     \x20 adapter: postgresql\n\
                     \x20 encoding: unicode\n\
                     \x20 database: app_production\n\
                     \x20 username: deploy\n\
                     \x20 password: {prod_pass}\n\
                     \x20 host: db-primary.internal\n\
                     \x20 port: 5432\n\
                     \x20 pool: 25\n\
                     \x20 timeout: 5000\n\
                     \n\
                     staging:\n\
                     \x20 adapter: postgresql\n\
                     \x20 encoding: unicode\n\
                     \x20 database: app_staging\n\
                     \x20 username: staging_user\n\
                     \x20 password: {staging_pass}\n\
                     \x20 host: db-staging.internal\n\
                     \x20 port: 5432\n\
                     \x20 pool: 10\n\
                     \n\
                     test:\n\
                     \x20 adapter: sqlite3\n\
                     \x20 database: db/test.sqlite3\n"
                );
                ("text/yaml; charset=utf-8".to_string(), body)
            }

            "/api/v1/keys" => {
                let key1 = format!("sk_prod_{}", rng.alphanum(32));
                let key2 = format!("sk_stg_{}", rng.alphanum(32));
                let key3 = format!("sk_dev_{}", rng.alphanum(32));

                let body = format!(
                    r#"{{"api_version":"v1","keys":[{{"id":1,"name":"production","key":"{key1}","scope":"read_write","created_at":"2026-01-15T08:30:00Z","last_used":"2026-10-05T14:22:00Z"}},{{"id":2,"name":"staging","key":"{key2}","scope":"read_write","created_at":"2026-03-22T10:15:00Z","last_used":"2026-10-04T09:11:00Z"}},{{"id":3,"name":"development","key":"{key3}","scope":"read_only","created_at":"2026-06-01T16:45:00Z","last_used":"2026-09-30T11:05:00Z"}}]}}"#
                );
                ("application/json; charset=utf-8".to_string(), body)
            }

            "/.aws/credentials" => {
                let access_key = format!("AKIA{}", rng.upper_alphanum(16));
                let secret_key = rng.base64ish(40);
                let access_key2 = format!("AKIA{}", rng.upper_alphanum(16));
                let secret_key2 = rng.base64ish(40);

                let body = format!(
                    "[default]\n\
                     aws_access_key_id = {access_key}\n\
                     aws_secret_access_key = {secret_key}\n\
                     region = us-east-1\n\
                     \n\
                     [production]\n\
                     aws_access_key_id = {access_key2}\n\
                     aws_secret_access_key = {secret_key2}\n\
                     region = us-east-2\n"
                );
                ("text/plain; charset=utf-8".to_string(), body)
            }

            _ => {
                let api_key = rng.alphanum(32);
                let secret = rng.hex(64);
                let db_pass = rng.alphanum(16);
                let body = format!(
                    "{{\n\
                     \x20 \"api_key\": \"{api_key}\",\n\
                     \x20 \"api_secret\": \"{secret}\",\n\
                     \x20 \"environment\": \"production\",\n\
                     \x20 \"debug\": false,\n\
                     \x20 \"database\": {{\n\
                     \x20\x20\x20 \"host\": \"db-primary.internal\",\n\
                     \x20\x20\x20 \"port\": 5432,\n\
                     \x20\x20\x20 \"password\": \"{db_pass}\"\n\
                     \x20 }}\n\
                     }}\n"
                );
                ("application/json; charset=utf-8".to_string(), body)
            }
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

    fn alphanum(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| CHARSET[self.next_usize() % CHARSET.len()] as char)
            .collect()
    }

    fn upper_alphanum(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| CHARSET[self.next_usize() % CHARSET.len()] as char)
            .collect()
    }

    fn base64ish(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        (0..len)
            .map(|_| CHARSET[self.next_usize() % CHARSET.len()] as char)
            .collect()
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

    #[test]
    fn shared_confidence_effective_ratio() {
        let conf = SharedConfidence::new();
        let base = 0.3;

        // No confidence → base ratio
        assert!((conf.effective_ratio(base) - 0.3).abs() < 0.01);

        // Half confidence → midpoint between base and max (0.8)
        conf.update(0.5);
        let r = conf.effective_ratio(base);
        assert!(r > 0.5 && r < 0.6, "expected ~0.55, got {r}");

        // Full confidence → max ratio (0.8)
        conf.update(1.0);
        let r = conf.effective_ratio(base);
        assert!((r - 0.8).abs() < 0.01, "expected 0.8, got {r}");
    }

    #[test]
    fn hash_distribution_uniform_for_fleet_paths() {
        let seed = 0xdead_beef_cafe_babe_u64;
        let ratio = 0.42_f32;
        let mut poison = 0;
        let total = 1000;

        for i in 0..total {
            let path = format!(
                "/ecoPrimals/wateringHole/src/commit/{:040x}/handlers/main.rs",
                i * 0x1234_5678_9abc_def0_u128
            );
            let h = path_deterministic_hash(&path, seed);
            if (h % 100) < (ratio * 100.0) as u64 {
                poison += 1;
            }
        }

        let pct = poison as f64 / total as f64;
        assert!(
            pct > 0.32 && pct < 0.52,
            "poison ratio {:.1}% should be near 42% (was {})",
            pct * 100.0,
            poison
        );
    }

    #[test]
    fn disperse_deterministic() {
        let sg = ScatterGenerator::new(42);
        let (ct1, body1) = sg.generate_disperse("/org/repo/commit/abc123");
        let (ct2, body2) = sg.generate_disperse("/org/repo/commit/abc123");
        assert_eq!(ct1, ct2);
        assert_eq!(body1, body2);
    }

    #[test]
    fn disperse_different_from_scatter() {
        let sg = ScatterGenerator::new(42);
        let (_, scatter_body) = sg.generate("/org/repo/commit/abc123");
        let (_, disperse_body) = sg.generate_disperse("/org/repo/commit/abc123");
        assert_ne!(scatter_body, disperse_body);
    }

    #[test]
    fn disperse_no_real_names_leak() {
        let sg = ScatterGenerator::new(42);
        for i in 0..20 {
            let path = format!("/org/repo/commit/{:040x}", i);
            let (_, body) = sg.generate_disperse(&path);
            assert!(!body.contains("ecoPrimal"), "leaked ecoPrimal in disperse variant");
            assert!(!body.contains("skunkBat"), "leaked skunkBat in disperse variant");
            assert!(!body.contains("wateringHole"), "leaked wateringHole in disperse variant");
        }
    }

    #[test]
    fn shared_confidence_clamps() {
        let conf = SharedConfidence::new();
        conf.update(5.0); // over 1.0
        assert!((conf.read() - 1.0).abs() < 0.01);

        conf.update(-1.0); // under 0.0
        assert!(conf.read() < 0.01);
    }

    // ── Layer 1: Tarpit tests ──

    #[test]
    fn tarpit_acquire_and_release() {
        let tp = TarpitState::new(2);
        assert!(tp.try_acquire());
        assert!(tp.try_acquire());
        assert!(!tp.try_acquire()); // at capacity
        assert_eq!(tp.active_count(), 2);

        tp.release();
        assert_eq!(tp.active_count(), 1);
        assert!(tp.try_acquire()); // slot freed
    }

    #[test]
    fn tarpit_zero_max_rejects_all() {
        let tp = TarpitState::new(0);
        assert!(!tp.try_acquire());
    }

    // ── Layer 2: Honeytoken tests ──

    #[test]
    fn honeytoken_path_detection() {
        assert!(is_honeytoken_path("/.env"));
        assert!(is_honeytoken_path("/.env.local"));
        assert!(is_honeytoken_path("/wp-config.php"));
        assert!(is_honeytoken_path("/.git/config"));
        assert!(is_honeytoken_path("/api/v1/keys"));
        assert!(is_honeytoken_path("/.aws/credentials"));
        assert!(is_honeytoken_path("/config/database.yml"));
        assert!(is_honeytoken_path("/.env?cachebust=1"));

        assert!(!is_honeytoken_path("/"));
        assert!(!is_honeytoken_path("/org/repo/commit/abc"));
        assert!(!is_honeytoken_path("/robots.txt"));
    }

    #[test]
    fn honeytoken_env_has_aws_keys() {
        let sg = ScatterGenerator::new(42);
        let (ct, body) = sg.generate_honeytoken("/.env");
        assert_eq!(ct, "text/plain; charset=utf-8");
        assert!(body.contains("AKIA"), "should contain AWS key prefix");
        assert!(body.contains("AWS_SECRET_ACCESS_KEY="));
        assert!(body.contains("STRIPE_SECRET_KEY=sk_live_"));
        assert!(body.contains("GITHUB_TOKEN=ghp_"));
        assert!(body.contains("DATABASE_URL=postgres://"));
    }

    #[test]
    fn honeytoken_env_deterministic() {
        let sg = ScatterGenerator::new(42);
        let (_, body1) = sg.generate_honeytoken("/.env");
        let (_, body2) = sg.generate_honeytoken("/.env");
        assert_eq!(body1, body2);
    }

    #[test]
    fn honeytoken_env_different_seeds() {
        let sg1 = ScatterGenerator::new(42);
        let sg2 = ScatterGenerator::new(99);
        let (_, body1) = sg1.generate_honeytoken("/.env");
        let (_, body2) = sg2.generate_honeytoken("/.env");
        assert_ne!(body1, body2);
    }

    #[test]
    fn honeytoken_wp_config() {
        let sg = ScatterGenerator::new(42);
        let (ct, body) = sg.generate_honeytoken("/wp-config.php");
        assert!(ct.contains("php"));
        assert!(body.contains("DB_PASSWORD"));
        assert!(body.contains("AUTH_KEY"));
        assert!(body.contains("wordpress_prod"));
    }

    #[test]
    fn honeytoken_git_config() {
        let sg = ScatterGenerator::new(42);
        let (_, body) = sg.generate_honeytoken("/.git/config");
        assert!(body.contains("[remote \"origin\"]"));
        assert!(body.contains("github.com"));
        assert!(body.contains("@"));
    }

    #[test]
    fn honeytoken_aws_credentials() {
        let sg = ScatterGenerator::new(42);
        let (_, body) = sg.generate_honeytoken("/.aws/credentials");
        assert!(body.contains("AKIA"));
        assert!(body.contains("[default]"));
        assert!(body.contains("[production]"));
    }

    #[test]
    fn honeytoken_api_keys_json() {
        let sg = ScatterGenerator::new(42);
        let (ct, body) = sg.generate_honeytoken("/api/v1/keys");
        assert!(ct.contains("json"));
        assert!(body.contains("sk_prod_"));
        assert!(body.contains("sk_stg_"));
    }

    #[test]
    fn honeytoken_database_yml() {
        let sg = ScatterGenerator::new(42);
        let (ct, body) = sg.generate_honeytoken("/config/database.yml");
        assert!(ct.contains("yaml"));
        assert!(body.contains("production:"));
        assert!(body.contains("password:"));
        assert!(body.contains("postgresql"));
    }

    #[test]
    fn honeytoken_no_real_data_leaked() {
        let sg = ScatterGenerator::new(42);
        for path in HONEYTOKEN_PATHS {
            let (_, body) = sg.generate_honeytoken(path);
            assert!(!body.contains("ecoPrimal"), "leaked ecoPrimal in {path}");
            assert!(!body.contains("primals.eco"), "leaked primals.eco in {path}");
            assert!(!body.contains("skunkBat"), "leaked skunkBat in {path}");
            assert!(!body.contains("golgiBody"), "leaked golgiBody in {path}");
        }
    }

    #[test]
    fn xorshift_alphanum_len() {
        let mut rng = XorShift64::new(42);
        assert_eq!(rng.alphanum(16).len(), 16);
        assert_eq!(rng.upper_alphanum(20).len(), 20);
        assert_eq!(rng.base64ish(40).len(), 40);
    }
}

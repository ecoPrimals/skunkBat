// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Caddy JSON access log parser.
//!
//! Each line in `/var/log/caddy/access.log` is a JSON object with the
//! structure documented in the Caddy v2 logging output.

use serde::Deserialize;

/// Top-level Caddy access log entry.
#[derive(Debug, Deserialize)]
pub struct LogEntry {
    pub request: RequestInfo,
    pub status: u16,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub duration: f64,
    pub ts: f64,
}

/// HTTP request metadata from Caddy.
#[derive(Debug, Deserialize)]
pub struct RequestInfo {
    pub remote_ip: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub uri: String,
    #[serde(default)]
    pub method: String,
    /// Deserialized for future user-agent fingerprinting (Phase 2).
    #[serde(default)]
    pub headers: Headers,
}

/// HTTP headers — only fields we care about.
///
/// ## Header Poverty Signal (Wave 165f)
///
/// Real Chrome 145+ sends 11+ headers per request (including mandatory
/// Sec-Ch-Ua, Sec-Fetch-*, Priority, Accept-Language). The fleet sends
/// only 3: Accept, Accept-Encoding, User-Agent. This is a binary
/// classifier — header_count < 6 with a Chrome UA is definitive proof
/// of a non-browser HTTP client.
#[derive(Debug, Default, Deserialize)]
pub struct Headers {
    /// User-Agent for behavioral classification.
    #[serde(default, rename = "User-Agent")]
    pub user_agent: Vec<String>,
    /// Accept-Encoding for fleet fingerprinting (encoding uniformity).
    #[serde(default, rename = "Accept-Encoding")]
    pub accept_encoding: Vec<String>,
    /// Accept-Language for fleet fingerprinting (language uniformity).
    #[serde(default, rename = "Accept-Language")]
    pub accept_language: Vec<String>,
    /// Referer for distinguishing organic browsing from direct-nav fleets.
    #[serde(default, rename = "Referer")]
    pub referer: Vec<String>,
    /// Sec-Fetch-Mode — mandatory in Chrome 76+. Absence with Chrome UA
    /// proves the request is from an HTTP client, not a browser.
    #[serde(default, rename = "Sec-Fetch-Mode")]
    pub sec_fetch_mode: Vec<String>,
    /// Sec-Ch-Ua — Client Hints UA, mandatory in Chrome 89+.
    #[serde(default, rename = "Sec-Ch-Ua")]
    pub sec_ch_ua: Vec<String>,
    /// Accept header — real browsers vary per resource type (text/html,
    /// image/webp, etc.). Fleet uses `*/*` universally.
    #[serde(default, rename = "Accept")]
    pub accept: Vec<String>,
    /// Connection header — real Chrome sends `keep-alive`. Absence
    /// indicates bare HTTP client library.
    #[serde(default, rename = "Connection")]
    pub connection: Vec<String>,
    /// Sec-Fetch-Dest — resource type (document, image, script, etc.).
    /// Part of the Sec-Fetch triplet used for monotone detection.
    #[serde(default, rename = "Sec-Fetch-Dest")]
    pub sec_fetch_dest: Vec<String>,
    /// Sec-Fetch-Site — origin relationship (same-origin, cross-site, etc.).
    /// Part of the Sec-Fetch triplet used for monotone detection.
    #[serde(default, rename = "Sec-Fetch-Site")]
    pub sec_fetch_site: Vec<String>,
    /// Cookie header — presence indicates stateful session.
    /// Absence across multi-page visits is a fleet epitope.
    #[serde(default, rename = "Cookie")]
    pub cookie: Vec<String>,
}

/// Parse a single Caddy JSON log line.
///
/// Returns `None` for malformed lines (logged at debug level by caller).
pub fn parse_line(line: &str) -> Option<LogEntry> {
    serde_json::from_str(line).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typical_caddy_line() {
        let line = r#"{"request":{"remote_ip":"203.0.113.50","host":"primals.eco","uri":"/wp-includes/js/jquery/jquery.js","method":"GET","headers":{"User-Agent":["Mozilla/5.0"]}},"status":404,"size":1234,"duration":0.002,"ts":1783788660.123}"#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.request.remote_ip, "203.0.113.50");
        assert_eq!(entry.status, 404);
        assert_eq!(entry.size, 1234);
        assert_eq!(entry.request.method, "GET");
        assert_eq!(entry.request.uri, "/wp-includes/js/jquery/jquery.js");
        assert_eq!(entry.request.headers.user_agent, vec!["Mozilla/5.0"]);
    }

    #[test]
    fn parse_minimal_line() {
        let line = r#"{"request":{"remote_ip":"10.0.0.1"},"status":200,"ts":1.0}"#;
        let entry = parse_line(line).expect("should parse minimal");
        assert_eq!(entry.request.remote_ip, "10.0.0.1");
        assert_eq!(entry.size, 0);
        assert!(entry.request.uri.is_empty());
    }

    #[test]
    fn malformed_returns_none() {
        assert!(parse_line("not json").is_none());
        assert!(parse_line("").is_none());
        assert!(parse_line("{}").is_none());
    }
}

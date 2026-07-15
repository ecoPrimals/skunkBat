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
    /// Preserved for future user-agent fingerprinting.
    #[serde(default)]
    #[allow(dead_code)]
    pub headers: Headers,
}

/// HTTP headers — only fields we care about.
#[derive(Debug, Default, Deserialize)]
pub struct Headers {
    /// Preserved for future scanner fingerprinting.
    #[serde(default, rename = "User-Agent")]
    #[allow(dead_code)]
    pub user_agent: Vec<String>,
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

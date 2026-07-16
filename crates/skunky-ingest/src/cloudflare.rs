//! Cloudflare Analytics API poller.
//!
//! Polls Cloudflare's GraphQL Analytics API for per-IP HTTP metrics
//! and converts them to `ObservationPayload` for feeding into skunkBat's
//! behavioral profiler alongside Caddy log data.
//!
//! Requires:
//! - `--cf-api-token` (or `CF_API_TOKEN` env var)
//! - `--cf-zone-id` (or `CF_ZONE_ID` env var)
//!
//! The Cloudflare data supplements Caddy access logs with outer-membrane
//! perspective: traffic that Cloudflare sees but Caddy may not (blocked
//! at CDN, cached, DDoS-filtered).

use crate::aggregator::ObservationPayload;

/// Cloudflare Analytics API configuration.
///
/// Fields stored for when the HTTP/GraphQL client is wired (blocked
/// on deployment team providing `CF_API_TOKEN` + `CF_ZONE_ID` on golgi).
#[derive(Debug, Clone)]
pub struct CfConfig {
    #[expect(dead_code, reason = "blocked on deployment team wiring CF credentials")]
    pub api_token: String,
    #[expect(dead_code, reason = "blocked on deployment team wiring CF credentials")]
    pub zone_id: String,
    #[expect(dead_code, reason = "blocked on deployment team wiring CF credentials")]
    pub poll_interval_secs: u64,
}

impl CfConfig {
    /// Construct from CLI args + env fallback.
    ///
    /// Returns `None` if neither CLI args nor env vars provide credentials.
    pub fn from_args(
        api_token: Option<String>,
        zone_id: Option<String>,
        poll_interval: u64,
    ) -> Option<Self> {
        let token = api_token
            .or_else(|| std::env::var("CF_API_TOKEN").ok())
            .filter(|s| !s.is_empty())?;
        let zone = zone_id
            .or_else(|| std::env::var("CF_ZONE_ID").ok())
            .filter(|s| !s.is_empty())?;
        Some(Self {
            api_token: token,
            zone_id: zone,
            poll_interval_secs: poll_interval,
        })
    }
}

/// Poll Cloudflare analytics and return observations.
///
/// Returns empty until the HTTP/GraphQL client is wired. The query
/// will target `httpRequestsAdaptiveGroups` with `clientIP` dimension
/// to produce per-source metrics matching `ObservationPayload`.
pub fn poll_analytics(_config: &CfConfig) -> Vec<ObservationPayload> {
    tracing::debug!("CF analytics poll — awaiting HTTP client implementation");
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_empty_args_returns_none() {
        assert!(CfConfig::from_args(None, None, 60).is_none());
    }

    #[test]
    fn config_from_full_args() {
        let cfg = CfConfig::from_args(Some("tok123".to_string()), Some("zone456".to_string()), 120);
        assert!(cfg.is_some());
        let cfg = cfg.unwrap();
        assert_eq!(cfg.api_token, "tok123");
        assert_eq!(cfg.zone_id, "zone456");
        assert_eq!(cfg.poll_interval_secs, 120);
    }

    #[test]
    fn config_rejects_empty_strings() {
        assert!(CfConfig::from_args(Some(String::new()), Some("z".to_string()), 60).is_none());
        assert!(CfConfig::from_args(Some("t".to_string()), Some(String::new()), 60).is_none());
    }

    #[test]
    fn poll_stub_returns_empty() {
        let cfg = CfConfig {
            api_token: "test".to_string(),
            zone_id: "test".to_string(),
            poll_interval_secs: 60,
        };
        let obs = poll_analytics(&cfg);
        assert!(obs.is_empty());
    }
}

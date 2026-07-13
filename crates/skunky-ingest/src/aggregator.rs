//! Per-source-IP metric aggregation over configurable time windows.
//!
//! Collects raw log entries and, when a window closes, emits an
//! `ObservationPayload` ready for JSON-RPC serialization.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::caddy::LogEntry;

/// Aggregated observation ready for `baseline.observe` JSON-RPC.
///
/// Field layout matches `skunk_bat_core::threats::types::Observation`
/// on the wire — we serialize directly, no core crate dependency.
#[derive(Debug, Serialize)]
pub struct ObservationPayload {
    pub connection_rate: f64,
    pub traffic_volume: u64,
    pub ports_accessed: Vec<u16>,
    pub timestamp: TimestampPayload,
    pub http: HttpPayload,
}

/// Wire-compatible `SystemTime` serialization.
#[derive(Debug, Serialize)]
pub struct TimestampPayload {
    pub secs_since_epoch: u64,
    pub nanos_since_epoch: u32,
}

/// Wire-compatible `HttpObservation`.
#[derive(Debug, Serialize)]
pub struct HttpPayload {
    pub request_rate: f64,
    pub error_rate_4xx: f64,
    pub error_rate_5xx: f64,
    pub path_diversity: u32,
    pub avg_payload_bytes: u64,
    pub method_diversity: u8,
}

/// Per-IP accumulator for a single aggregation window.
#[derive(Debug)]
struct IpBucket {
    request_count: u64,
    total_bytes: u64,
    status_4xx: u64,
    status_5xx: u64,
    paths: HashSet<String>,
    methods: HashSet<String>,
    ports: HashSet<u16>,
}

impl IpBucket {
    fn new() -> Self {
        Self {
            request_count: 0,
            total_bytes: 0,
            status_4xx: 0,
            status_5xx: 0,
            paths: HashSet::new(),
            methods: HashSet::new(),
            ports: HashSet::new(),
        }
    }

    fn record(&mut self, entry: &LogEntry) {
        self.request_count += 1;
        self.total_bytes += entry.size;

        if (400..500).contains(&entry.status) {
            self.status_4xx += 1;
        } else if entry.status >= 500 {
            self.status_5xx += 1;
        }

        if !entry.request.uri.is_empty() {
            self.paths.insert(entry.request.uri.clone());
        }
        if !entry.request.method.is_empty() {
            self.methods.insert(entry.request.method.clone());
        }

        // Caddy serves HTTPS — port derived from host header if present,
        // otherwise defaults to 443.
        let port = entry
            .request
            .host
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(443);
        self.ports.insert(port);
    }
}

/// Aggregator that collects log entries into per-IP time windows.
pub struct Aggregator {
    window: Duration,
    window_start: f64,
    buckets: HashMap<String, IpBucket>,
}

impl Aggregator {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            window_start: 0.0,
            buckets: HashMap::new(),
        }
    }

    /// Ingest a log entry. Returns observations if the window has closed.
    ///
    /// A window closes when the entry timestamp exceeds
    /// `window_start + window_secs`. All accumulated buckets flush.
    pub fn ingest(&mut self, entry: &LogEntry) -> Vec<ObservationPayload> {
        let window_secs = self.window.as_secs_f64();

        if self.window_start == 0.0 {
            self.window_start = entry.ts;
        }

        if entry.ts >= self.window_start + window_secs {
            let observations = self.flush(window_secs);
            self.window_start = entry.ts;
            self.buckets.clear();
            self.record(entry);
            observations
        } else {
            self.record(entry);
            Vec::new()
        }
    }

    /// Force-flush all accumulated buckets (e.g. on shutdown or EOF).
    pub fn flush_remaining(&mut self) -> Vec<ObservationPayload> {
        let window_secs = self.window.as_secs_f64();
        let observations = self.flush(window_secs);
        self.buckets.clear();
        observations
    }

    fn record(&mut self, entry: &LogEntry) {
        self.buckets
            .entry(entry.request.remote_ip.clone())
            .or_insert_with(IpBucket::new)
            .record(entry);
    }

    #[allow(clippy::cast_precision_loss)]
    fn flush(&self, window_secs: f64) -> Vec<ObservationPayload> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();

        self.buckets
            .values()
            .map(|bucket| {
                let request_rate = bucket.request_count as f64 / window_secs;
                let total = bucket.request_count.max(1) as f64;

                ObservationPayload {
                    connection_rate: request_rate,
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    traffic_volume: (bucket.total_bytes as f64 / window_secs) as u64,
                    ports_accessed: bucket.ports.iter().copied().collect(),
                    timestamp: TimestampPayload {
                        secs_since_epoch: now.as_secs(),
                        nanos_since_epoch: now.subsec_nanos(),
                    },
                    http: HttpPayload {
                        request_rate,
                        error_rate_4xx: bucket.status_4xx as f64 / total,
                        error_rate_5xx: bucket.status_5xx as f64 / total,
                        #[allow(clippy::cast_possible_truncation)]
                        path_diversity: bucket.paths.len() as u32,
                        avg_payload_bytes: bucket.total_bytes / bucket.request_count.max(1),
                        #[allow(clippy::cast_possible_truncation)]
                        method_diversity: bucket.methods.len().min(255) as u8,
                    },
                }
            })
            .inspect(|obs| {
                tracing::debug!(
                    request_rate = obs.http.request_rate,
                    error_4xx = obs.http.error_rate_4xx,
                    paths = obs.http.path_diversity,
                    "flushing observation"
                );
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caddy::{Headers, RequestInfo};

    fn make_entry(ip: &str, uri: &str, status: u16, ts: f64) -> LogEntry {
        LogEntry {
            request: RequestInfo {
                remote_ip: ip.to_string(),
                host: "primals.eco".to_string(),
                uri: uri.to_string(),
                method: "GET".to_string(),
                headers: Headers::default(),
            },
            status,
            size: 512,
            duration: 0.01,
            ts,
        }
    }

    #[test]
    fn window_accumulates_then_flushes() {
        let mut agg = Aggregator::new(Duration::from_secs(60));

        assert!(
            agg.ingest(&make_entry("1.2.3.4", "/a", 200, 100.0))
                .is_empty()
        );
        assert!(
            agg.ingest(&make_entry("1.2.3.4", "/b", 404, 110.0))
                .is_empty()
        );
        assert!(
            agg.ingest(&make_entry("1.2.3.4", "/c", 200, 120.0))
                .is_empty()
        );

        let obs = agg.ingest(&make_entry("1.2.3.4", "/d", 200, 161.0));
        assert_eq!(obs.len(), 1);

        let o = &obs[0];
        assert!((o.http.request_rate - 3.0 / 60.0).abs() < 0.01);
        assert!((o.http.error_rate_4xx - 1.0 / 3.0).abs() < 0.01);
        assert_eq!(o.http.path_diversity, 3);
        assert_eq!(o.http.method_diversity, 1);
    }

    #[test]
    fn multiple_ips_produce_multiple_observations() {
        let mut agg = Aggregator::new(Duration::from_secs(10));

        agg.ingest(&make_entry("1.1.1.1", "/a", 200, 1.0));
        agg.ingest(&make_entry("2.2.2.2", "/b", 200, 2.0));
        agg.ingest(&make_entry("3.3.3.3", "/c", 200, 3.0));

        let obs = agg.ingest(&make_entry("1.1.1.1", "/d", 200, 12.0));
        assert_eq!(obs.len(), 3);
    }

    #[test]
    fn flush_remaining_drains_partial_window() {
        let mut agg = Aggregator::new(Duration::from_secs(60));

        agg.ingest(&make_entry("5.5.5.5", "/x", 200, 1.0));
        agg.ingest(&make_entry("5.5.5.5", "/y", 500, 2.0));

        let obs = agg.flush_remaining();
        assert_eq!(obs.len(), 1);
        assert!((obs[0].http.error_rate_5xx - 0.5).abs() < 0.01);
    }

    #[test]
    fn empty_aggregator_flush_produces_nothing() {
        let mut agg = Aggregator::new(Duration::from_secs(60));
        assert!(agg.flush_remaining().is_empty());
    }
}

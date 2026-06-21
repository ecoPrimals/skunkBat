// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Baseline seeding for the statistical profiler.
//!
//! Contains representative "normal" traffic observations used to establish
//! the behavioral baseline at startup. Without a baseline, the profiler's
//! `is_established()` gate returns false and zero anomalies are detected.
//!
//! Normal observations model typical inter-primal IPC traffic: low connection
//! rates, modest volume. Port `0` represents UDS (no TCP port); `SELF_PORT`
//! represents this primal's own TCP listener.
//!
//! The pen-test attack patterns (PG-57) model the 7 malformed-payload +
//! enumeration scenarios that should trigger detection once the baseline
//! is established.

use std::time::SystemTime;

use super::types::Observation;

/// Default self-port for baseline seed data when no runtime port is configured.
const DEFAULT_SELF_PORT: u16 = crate::DEFAULT_PORT;

/// Normal inter-primal traffic baseline (12 observations).
///
/// Represents ~60 seconds of typical ecosystem activity:
/// - Connection rate: 2–8 conn/s (IPC heartbeats, capability queries)
/// - Traffic volume: 1–5 KB/s (JSON-RPC payloads, health checks)
/// - Ports: `self_port` (TCP listener), plus UDS (represented as port 0)
///
/// Pass `0` to use the default port (9750).
#[must_use]
pub fn normal_baseline_with_port(self_port: u16) -> Vec<Observation> {
    let port = if self_port == 0 {
        DEFAULT_SELF_PORT
    } else {
        self_port
    };
    build_baseline(port)
}

/// Convenience wrapper using the default self-port.
#[must_use]
pub fn normal_baseline() -> Vec<Observation> {
    build_baseline(DEFAULT_SELF_PORT)
}

fn build_baseline(self_port: u16) -> Vec<Observation> {
    let now = SystemTime::now();
    vec![
        Observation {
            connection_rate: 3.2,
            traffic_volume: 2048,
            ports_accessed: vec![self_port],
            timestamp: now,
        },
        Observation {
            connection_rate: 2.8,
            traffic_volume: 1536,
            ports_accessed: vec![self_port, 0],
            timestamp: now,
        },
        Observation {
            connection_rate: 4.1,
            traffic_volume: 3072,
            ports_accessed: vec![self_port],
            timestamp: now,
        },
        Observation {
            connection_rate: 3.5,
            traffic_volume: 2560,
            ports_accessed: vec![self_port, 0],
            timestamp: now,
        },
        Observation {
            connection_rate: 5.0,
            traffic_volume: 4096,
            ports_accessed: vec![self_port],
            timestamp: now,
        },
        Observation {
            connection_rate: 2.1,
            traffic_volume: 1024,
            ports_accessed: vec![0],
            timestamp: now,
        },
        Observation {
            connection_rate: 4.8,
            traffic_volume: 3584,
            ports_accessed: vec![self_port, 0],
            timestamp: now,
        },
        Observation {
            connection_rate: 3.9,
            traffic_volume: 2816,
            ports_accessed: vec![self_port],
            timestamp: now,
        },
        Observation {
            connection_rate: 2.5,
            traffic_volume: 1280,
            ports_accessed: vec![0],
            timestamp: now,
        },
        Observation {
            connection_rate: 4.3,
            traffic_volume: 3328,
            ports_accessed: vec![self_port],
            timestamp: now,
        },
        Observation {
            connection_rate: 3.0,
            traffic_volume: 2048,
            ports_accessed: vec![self_port, 0],
            timestamp: now,
        },
        Observation {
            connection_rate: 5.2,
            traffic_volume: 4352,
            ports_accessed: vec![self_port],
            timestamp: now,
        },
    ]
}

/// PG-57 pen-test attack patterns (7 scenarios).
///
/// These represent the malformed-payload and enumeration patterns observed
/// during the projectNUCLEUS Phase 2a penetration test. Each should trigger
/// behavioral anomaly detection against the normal baseline.
///
/// Pattern categories:
/// 1. Port enumeration sweep (high connection rate, many ports)
/// 2. Payload flood (extreme traffic volume)
/// 3. Malformed JSON-RPC burst (rapid connections, small payloads)
/// 4. Service enumeration (systematic port probing)
/// 5. Amplification attempt (asymmetric volume spike)
/// 6. Slow-rate exhaustion (sustained elevated connections)
/// 7. Protocol confusion (unexpected ports, moderate rate)
#[must_use]
pub fn pentest_attack_patterns() -> Vec<Observation> {
    let self_port = DEFAULT_SELF_PORT;
    let now = SystemTime::now();
    vec![
        // 1: Port enumeration sweep — 150 conn/s across 20+ common ports
        Observation {
            connection_rate: 150.0,
            traffic_volume: 8192,
            ports_accessed: vec![
                22, 80, 443, 8080, 8443, 3000, 3306, 5432, 6379, 8000, 8081, 8443, 9000, 9001,
                9002, 9090, 9200, 9300, 9400, 9500,
            ],
            timestamp: now,
        },
        // 2: Payload flood — normal conn rate but extreme volume
        Observation {
            connection_rate: 5.0,
            traffic_volume: 10_485_760, // 10 MB/s
            ports_accessed: vec![self_port],
            timestamp: now,
        },
        // 3: Malformed JSON-RPC burst — rapid small payloads
        Observation {
            connection_rate: 500.0,
            traffic_volume: 512,
            ports_accessed: vec![self_port],
            timestamp: now,
        },
        // 4: Service enumeration — methodical probing at moderate rate
        Observation {
            connection_rate: 45.0,
            traffic_volume: 4096,
            ports_accessed: (self_port..self_port + 6).collect(),
            timestamp: now,
        },
        // 5: Amplification attempt — tiny request, expecting large response
        Observation {
            connection_rate: 80.0,
            traffic_volume: 128,
            ports_accessed: vec![self_port],
            timestamp: now,
        },
        // 6: Slow-rate exhaustion — sustained elevated connections
        Observation {
            connection_rate: 25.0,
            traffic_volume: 2048,
            ports_accessed: vec![self_port, 0],
            timestamp: now,
        },
        // 7: Protocol confusion — unexpected ports, moderate rate
        Observation {
            connection_rate: 30.0,
            traffic_volume: 6144,
            ports_accessed: vec![22, 53, 139, 445, 3306, 5432],
            timestamp: now,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_baseline_has_enough_observations() {
        let baseline = normal_baseline();
        assert!(baseline.len() >= 10, "need >=10 for is_established()");
    }

    #[test]
    fn pentest_patterns_are_seven() {
        let patterns = pentest_attack_patterns();
        assert_eq!(patterns.len(), 7);
    }

    #[test]
    fn normal_rates_are_within_expected_range() {
        for obs in normal_baseline() {
            assert!(obs.connection_rate >= 1.0 && obs.connection_rate <= 10.0);
        }
    }

    #[test]
    fn attack_rates_exceed_normal_range() {
        let normal_max = normal_baseline()
            .iter()
            .map(|o| o.connection_rate)
            .fold(0.0_f64, f64::max);

        let attacks_above = pentest_attack_patterns()
            .iter()
            .filter(|o| o.connection_rate > normal_max * 3.0)
            .count();

        assert!(
            attacks_above >= 4,
            "most attacks should exceed 3x normal max"
        );
    }
}

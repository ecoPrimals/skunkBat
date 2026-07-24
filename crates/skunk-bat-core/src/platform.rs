// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Platform-specific helpers — shared across crates.
//!
//! UID resolution without libc, used by socket naming (BTSP Phase 1)
//! and capability socket resolution.

/// Get the current user's UID without libc.
///
/// On Linux, reads `/proc/self/status`. On other platforms, shells out
/// to `id -u`. Falls back to 1000 if both fail.
#[must_use]
pub fn proc_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or_else(uid_fallback)
    }
    #[cfg(not(target_os = "linux"))]
    {
        uid_fallback()
    }
}

/// Standard first non-system UID on most Linux distributions.
const DEFAULT_USER_UID: u32 = 1000;

fn uid_fallback() -> u32 {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(DEFAULT_USER_UID)
}

/// Read the system's 1-minute load average, normalized to [0.0, 1.0] per CPU.
///
/// On Linux, reads `/proc/loadavg`. On other platforms, parses `uptime` output.
/// Returns 0.0 if the load cannot be determined.
#[must_use]
pub(crate) fn system_load_normalized() -> f64 {
    let raw = raw_load_average();

    #[expect(clippy::cast_precision_loss, reason = "CPU count fits in f64")]
    let cpus = std::thread::available_parallelism().map_or(1.0, |n| n.get() as f64);

    (raw / cpus).min(1.0)
}

#[cfg(target_os = "linux")]
fn raw_load_average() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or(0.0)
}

#[cfg(not(target_os = "linux"))]
fn raw_load_average() -> f64 {
    let load = std::process::Command::new("uptime")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.rsplit("load average")
                .next()?
                .trim_start_matches([':', ' '])
                .split(',')
                .next()?
                .trim()
                .parse::<f64>()
                .ok()
        })
        .unwrap_or(0.0);

    if load == 0.0 {
        tracing::debug!("Resource detection: unable to read system load on this platform");
    }

    load
}

/// Tracks the system-wide process fork rate by sampling `/proc/stat`.
///
/// On Linux, `/proc/stat` has a `processes` line giving total forks since boot.
/// Sampling at two points yields spawns/second. On non-Linux platforms the rate
/// is always 0.0 (no platform-native equivalent without external crates).
///
/// Designed for crash-loop detection: a service restarting every 3 seconds
/// produces ~0.3 spawns/s from that service alone, but each restart may fork
/// child processes, amplifying the signal.
pub(crate) struct SpawnRateTracker {
    last_total: Option<u64>,
    last_sample: Option<std::time::Instant>,
}

impl SpawnRateTracker {
    pub(crate) const fn new() -> Self {
        Self {
            last_total: None,
            last_sample: None,
        }
    }

    /// Sample the current fork count and return spawns/second since last sample.
    ///
    /// Returns `0.0` on the first call (no previous sample to compare) or on
    /// platforms where fork counting is unavailable.
    pub(crate) fn measure_rate(&mut self) -> f64 {
        let current_total = read_total_forks();
        let now = std::time::Instant::now();

        let rate = match (self.last_total, self.last_sample) {
            (Some(prev_total), Some(prev_time)) if current_total >= prev_total => {
                let elapsed = now.duration_since(prev_time).as_secs_f64();
                if elapsed > 0.0 {
                    #[expect(
                        clippy::cast_precision_loss,
                        reason = "fork deltas fit comfortably in f64 mantissa"
                    )]
                    let delta = (current_total - prev_total) as f64;
                    delta / elapsed
                } else {
                    0.0
                }
            }
            _ => 0.0,
        };

        self.last_total = Some(current_total);
        self.last_sample = Some(now);
        rate
    }
}

/// Read total forks since boot from `/proc/stat`.
///
/// Returns 0 on non-Linux or if the file cannot be read.
#[cfg(target_os = "linux")]
fn read_total_forks() -> u64 {
    std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("processes "))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn read_total_forks() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_uid_returns_real_value() {
        assert!(proc_uid() > 0);
    }

    #[test]
    fn uid_fallback_returns_value() {
        assert!(uid_fallback() > 0);
    }

    #[test]
    fn system_load_is_normalized() {
        let load = system_load_normalized();
        assert!((0.0..=1.0).contains(&load));
    }

    #[test]
    fn spawn_tracker_first_call_returns_zero() {
        let mut tracker = SpawnRateTracker::new();
        let rate = tracker.measure_rate();
        assert!(rate == 0.0, "first sample has no previous baseline");
    }

    #[test]
    fn spawn_tracker_second_call_returns_nonneg() {
        let mut tracker = SpawnRateTracker::new();
        let _ = tracker.measure_rate();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let rate = tracker.measure_rate();
        assert!(rate >= 0.0, "rate should be non-negative");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_total_forks_nonzero() {
        assert!(read_total_forks() > 0, "/proc/stat should report forks");
    }
}

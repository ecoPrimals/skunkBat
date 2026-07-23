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
}

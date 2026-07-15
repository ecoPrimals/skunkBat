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
}

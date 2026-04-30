// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Platform-specific helpers — UID resolution without libc.

/// Get UID without libc — `/proc/self/status` on Linux, `id -u` elsewhere.
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

fn uid_fallback() -> u32 {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1000)
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

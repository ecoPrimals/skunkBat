// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Common types used across primal foundation.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Timestamp with nanosecond precision.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp {
    /// Seconds since Unix epoch.
    pub secs: u64,
    /// Nanoseconds within the second.
    pub nanos: u32,
}

impl Timestamp {
    /// Create a timestamp for the current moment.
    ///
    /// Returns epoch (0, 0) if the system clock is before Unix epoch.
    #[must_use]
    pub fn now() -> Self {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(Self { secs: 0, nanos: 0 }, |d| Self {
                secs: d.as_secs(),
                nanos: d.subsec_nanos(),
            })
    }

    /// Create a timestamp from seconds since epoch.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self { secs, nanos: 0 }
    }

    /// Create a timestamp from milliseconds since epoch.
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "truncation is safe: (millis % 1000) * 1_000_000 < u32::MAX"
    )]
    pub const fn from_millis(millis: u64) -> Self {
        Self {
            secs: millis / 1000,
            nanos: ((millis % 1000) * 1_000_000) as u32,
        }
    }

    /// Convert to milliseconds since epoch.
    #[must_use]
    pub const fn as_millis(&self) -> u64 {
        self.secs * 1000 + (self.nanos / 1_000_000) as u64
    }
}

impl std::fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Timestamp({}.{:09})", self.secs, self.nanos)
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::time::{Duration, UNIX_EPOCH};
        let time = UNIX_EPOCH + Duration::new(self.secs, self.nanos);
        write!(f, "{time:?}")
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_now() {
        let t1 = Timestamp::now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let t2 = Timestamp::now();
        assert!(t2 > t1);
    }

    #[test]
    fn timestamp_from_secs() {
        let ts = Timestamp::from_secs(1_234_567_890);
        assert_eq!(ts.secs, 1_234_567_890);
        assert_eq!(ts.nanos, 0);
    }

    #[test]
    fn timestamp_from_millis() {
        let ts = Timestamp::from_millis(1500);
        assert_eq!(ts.secs, 1);
        assert_eq!(ts.nanos, 500_000_000);
    }

    #[test]
    fn timestamp_as_millis() {
        let ts = Timestamp {
            secs: 10,
            nanos: 500_000_000,
        };
        assert_eq!(ts.as_millis(), 10_500);
    }

    #[test]
    fn timestamp_serialization() {
        let ts = Timestamp {
            secs: 1_234_567_890,
            nanos: 123_456_789,
        };
        let json = serde_json::to_string(&ts).unwrap();
        let parsed: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, parsed);
    }

    #[test]
    fn timestamp_display_and_debug() {
        let ts = Timestamp::from_secs(0);
        assert!(!format!("{ts}").is_empty());
        assert!(format!("{ts:?}").contains("Timestamp"));
    }
}

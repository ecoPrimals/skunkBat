// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Gossip entry analysis for swarmVine pre-accept validation (vine-bat loop).
//!
//! swarmVine calls [`analyze_gossip_entry`] before storing epidemic gossip entries.
//! Each check runs independently and composes into a single [`GossipVerdict`].

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Gossip entry submitted for analysis (matches swarmVine's wire format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipEntryParams {
    /// Gossip domain: `tower`, `data`, or `compute`.
    pub topic: String,
    /// Unique key within the topic (e.g. `capability.advertise:sporeGate:nestGate`).
    pub key: String,
    /// Topic-specific JSON payload.
    #[serde(default)]
    pub payload: serde_json::Value,
    /// Gate that originally created this entry.
    pub origin_gate: String,
    /// Remaining hops before the entry is dropped.
    #[serde(default)]
    pub ttl: u8,
    /// Monotonic version for conflict resolution (higher wins).
    #[serde(default)]
    pub version: u64,
    /// When the entry was created (epoch seconds).
    #[serde(default)]
    pub created_at_epoch: u64,
    /// When the entry should be evicted (epoch seconds).
    #[serde(default)]
    pub expires_at_epoch: u64,
}

/// Per-check result for transparency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipCheckResult {
    /// Name of the check that ran.
    pub check: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Detail message (present only on failure or notable conditions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Composite verdict from gossip entry analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipVerdict {
    /// Overall verdict: allow, warn, or block.
    pub verdict: super::Verdict,
    /// Human-readable summary of the verdict.
    pub reason: String,
    /// Gate that originated the gossip entry.
    pub origin_gate: String,
    /// Individual check results for transparency.
    pub checks: Vec<GossipCheckResult>,
}

const VALID_TOPICS: &[&str] = &["tower", "data", "compute"];
const MAX_KEY_LEN: usize = 256;
const MAX_PAYLOAD_BYTES: usize = 16_384;
const MAX_TTL: u8 = 16;
const MAX_LIFETIME_SECS: u64 = 86_400;

/// Run all gossip-entry analysis checks.
///
/// Pure function — does not mutate state. The quarantine check requires
/// a callback so the caller can delegate to the defense engine.
pub fn analyze_gossip_entry(
    entry: &GossipEntryParams,
    is_quarantined: impl Fn(&str) -> bool,
) -> GossipVerdict {
    let checks = vec![
        check_topic(entry),
        check_key_format(entry),
        check_origin_identity(entry),
        check_ttl(entry),
        check_payload_size(entry),
        check_freshness(entry),
        check_lifetime(entry),
        check_quarantine(&entry.origin_gate, &is_quarantined),
    ];

    let failed: Vec<&GossipCheckResult> = checks.iter().filter(|c| !c.passed).collect();

    if failed.is_empty() {
        GossipVerdict {
            verdict: super::Verdict::Allow,
            reason: "all checks passed".to_owned(),
            origin_gate: entry.origin_gate.clone(),
            checks,
        }
    } else {
        let is_block = failed
            .iter()
            .any(|c| c.check == "quarantine" || c.check == "origin_identity");

        GossipVerdict {
            verdict: if is_block {
                super::Verdict::Block
            } else {
                super::Verdict::Warn
            },
            reason: failed
                .iter()
                .map(|c| c.detail.as_deref().unwrap_or(&c.check).to_owned())
                .collect::<Vec<_>>()
                .join("; "),
            origin_gate: entry.origin_gate.clone(),
            checks,
        }
    }
}

fn check_topic(entry: &GossipEntryParams) -> GossipCheckResult {
    let passed = VALID_TOPICS.contains(&entry.topic.as_str());
    GossipCheckResult {
        check: "topic_valid".to_owned(),
        passed,
        detail: if passed {
            None
        } else {
            Some(format!("unknown topic: {}", entry.topic))
        },
    }
}

fn check_key_format(entry: &GossipEntryParams) -> GossipCheckResult {
    let empty = entry.key.is_empty();
    let too_long = entry.key.len() > MAX_KEY_LEN;
    let has_control = entry.key.chars().any(char::is_control);
    let passed = !empty && !too_long && !has_control;
    GossipCheckResult {
        check: "key_format".to_owned(),
        passed,
        detail: if empty {
            Some("empty key".to_owned())
        } else if too_long {
            Some(format!("key too long: {} > {MAX_KEY_LEN}", entry.key.len()))
        } else if has_control {
            Some("key contains control characters".to_owned())
        } else {
            None
        },
    }
}

fn check_origin_identity(entry: &GossipEntryParams) -> GossipCheckResult {
    let empty = entry.origin_gate.is_empty();
    let suspicious = entry.origin_gate.contains("..") || entry.origin_gate.contains('/');
    let passed = !empty && !suspicious;
    GossipCheckResult {
        check: "origin_identity".to_owned(),
        passed,
        detail: if empty {
            Some("empty origin_gate".to_owned())
        } else if suspicious {
            Some(format!("suspicious origin_gate: {}", entry.origin_gate))
        } else {
            None
        },
    }
}

fn check_ttl(entry: &GossipEntryParams) -> GossipCheckResult {
    let passed = entry.ttl > 0 && entry.ttl <= MAX_TTL;
    GossipCheckResult {
        check: "ttl_valid".to_owned(),
        passed,
        detail: if entry.ttl == 0 {
            Some("TTL is zero (expired)".to_owned())
        } else if entry.ttl > MAX_TTL {
            Some(format!("TTL {} exceeds max {MAX_TTL}", entry.ttl))
        } else {
            None
        },
    }
}

fn check_payload_size(entry: &GossipEntryParams) -> GossipCheckResult {
    let size = entry.payload.to_string().len();
    let passed = size <= MAX_PAYLOAD_BYTES;
    GossipCheckResult {
        check: "payload_size".to_owned(),
        passed,
        detail: if passed {
            None
        } else {
            Some(format!(
                "payload {size} bytes exceeds {MAX_PAYLOAD_BYTES} limit"
            ))
        },
    }
}

fn check_freshness(entry: &GossipEntryParams) -> GossipCheckResult {
    if entry.expires_at_epoch == 0 {
        return GossipCheckResult {
            check: "freshness".to_owned(),
            passed: true,
            detail: Some("no expiry set (locally injected)".to_owned()),
        };
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let passed = entry.expires_at_epoch > now;
    GossipCheckResult {
        check: "freshness".to_owned(),
        passed,
        detail: if passed {
            None
        } else {
            Some(format!(
                "entry expired: expires_at={} < now={now}",
                entry.expires_at_epoch
            ))
        },
    }
}

fn check_lifetime(entry: &GossipEntryParams) -> GossipCheckResult {
    if entry.created_at_epoch == 0 || entry.expires_at_epoch == 0 {
        return GossipCheckResult {
            check: "lifetime".to_owned(),
            passed: true,
            detail: None,
        };
    }

    let lifetime = entry
        .expires_at_epoch
        .saturating_sub(entry.created_at_epoch);
    let passed = lifetime <= MAX_LIFETIME_SECS;
    GossipCheckResult {
        check: "lifetime".to_owned(),
        passed,
        detail: if passed {
            None
        } else {
            Some(format!(
                "lifetime {lifetime}s exceeds {MAX_LIFETIME_SECS}s max"
            ))
        },
    }
}

fn check_quarantine(
    origin_gate: &str,
    is_quarantined: &impl Fn(&str) -> bool,
) -> GossipCheckResult {
    let quarantined = is_quarantined(origin_gate);
    GossipCheckResult {
        check: "quarantine".to_owned(),
        passed: !quarantined,
        detail: if quarantined {
            Some(format!("origin gate '{origin_gate}' is quarantined"))
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(topic: &str, key: &str, origin: &str) -> GossipEntryParams {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        GossipEntryParams {
            topic: topic.to_owned(),
            key: key.to_owned(),
            payload: serde_json::json!({"test": true}),
            origin_gate: origin.to_owned(),
            ttl: 5,
            version: now,
            created_at_epoch: now,
            expires_at_epoch: now + 600,
        }
    }

    fn no_quarantine(_: &str) -> bool {
        false
    }

    #[test]
    fn valid_entry_passes_all_checks() {
        let e = entry(
            "tower",
            "capability.advertise:sporeGate:nestGate",
            "sporeGate",
        );
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Allow);
        assert!(v.checks.iter().all(|c| c.passed));
    }

    #[test]
    fn unknown_topic_warns() {
        let e = entry("unknown", "some.key", "sporeGate");
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Warn);
        assert!(
            !v.checks
                .iter()
                .find(|c| c.check == "topic_valid")
                .unwrap()
                .passed
        );
    }

    #[test]
    fn empty_key_warns() {
        let e = entry("tower", "", "sporeGate");
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Warn);
    }

    #[test]
    fn key_too_long_warns() {
        let long_key = "k".repeat(300);
        let e = entry("tower", &long_key, "sporeGate");
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Warn);
    }

    #[test]
    fn empty_origin_blocks() {
        let e = entry("tower", "some.key", "");
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Block);
    }

    #[test]
    fn suspicious_origin_blocks() {
        let e = entry("tower", "some.key", "../escape");
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Block);
    }

    #[test]
    fn zero_ttl_warns() {
        let mut e = entry("tower", "some.key", "sporeGate");
        e.ttl = 0;
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Warn);
    }

    #[test]
    fn excessive_ttl_warns() {
        let mut e = entry("tower", "some.key", "sporeGate");
        e.ttl = 200;
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Warn);
    }

    #[test]
    fn oversized_payload_warns() {
        let big = serde_json::json!({"data": "x".repeat(20_000)});
        let mut e = entry("tower", "some.key", "sporeGate");
        e.payload = big;
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Warn);
    }

    #[test]
    fn expired_entry_warns() {
        let mut e = entry("tower", "some.key", "sporeGate");
        e.expires_at_epoch = 1_000_000;
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Warn);
    }

    #[test]
    fn excessive_lifetime_warns() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut e = entry("tower", "some.key", "sporeGate");
        e.created_at_epoch = now;
        e.expires_at_epoch = now + 200_000;
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Warn);
    }

    #[test]
    fn quarantined_origin_blocks() {
        let e = entry("tower", "some.key", "evilGate");
        let v = analyze_gossip_entry(&e, |g| g == "evilGate");
        assert_eq!(v.verdict, super::super::Verdict::Block);
    }

    #[test]
    fn locally_injected_entry_no_expiry() {
        let mut e = entry("data", "cas.have:sporeGate", "sporeGate");
        e.expires_at_epoch = 0;
        e.created_at_epoch = 0;
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Allow);
    }

    #[test]
    fn all_three_topics_valid() {
        for topic in &["tower", "data", "compute"] {
            let e = entry(topic, "test.key", "sporeGate");
            let v = analyze_gossip_entry(&e, no_quarantine);
            assert_eq!(v.verdict, super::super::Verdict::Allow, "topic={topic}");
        }
    }

    #[test]
    fn control_chars_in_key_warns() {
        let e = entry("tower", "bad\x00key", "sporeGate");
        let v = analyze_gossip_entry(&e, no_quarantine);
        assert_eq!(v.verdict, super::super::Verdict::Warn);
    }

    #[test]
    fn verdict_serializes_correctly() {
        let e = entry("tower", "test.key", "sporeGate");
        let v = analyze_gossip_entry(&e, no_quarantine);
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["verdict"], "allow");
        assert!(json["checks"].is_array());
    }
}

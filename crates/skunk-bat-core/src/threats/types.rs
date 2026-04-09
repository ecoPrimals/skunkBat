// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Threat data types for skunkBat.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Detected threat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    /// Unique threat identifier
    pub id: String,
    /// Threat type
    pub threat_type: ThreatType,
    /// Severity level
    pub severity: Severity,
    /// Source of threat
    pub source: String,
    /// Target of threat
    pub target: String,
    /// Detection timestamp
    pub detected_at: SystemTime,
    /// Description
    pub description: String,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
}

/// Threat type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    /// Unknown lineage (genetic threat via capability-based verifier)
    UnknownLineage {
        /// Peer identifier
        peer_id: String,
        /// Lineage information (if available)
        lineage: Option<String>,
    },
    /// Anomalous behavior
    BehaviorAnomaly {
        /// Deviation from baseline
        deviation: f64,
        /// Observed behavior description
        behavior: String,
    },
    /// Intrusion attempt
    IntrusionAttempt {
        /// Attack type
        attack_type: String,
        /// Attack signature
        signature: String,
    },
    /// Denial of service
    DenialOfService {
        /// Resource being exhausted
        resource: String,
        /// Current usage level
        current_level: f64,
    },
    /// Topology violation (layer-hopping, path bypass)
    TopologyViolation {
        /// Expected path (layer sequence)
        expected_path: Vec<u8>,
        /// Actual path taken
        actual_path: Vec<u8>,
        /// Bypassed layers
        bypassed_layers: Vec<u8>,
    },
    /// Configuration drift
    ConfigurationDrift {
        /// Component that changed
        component: String,
        /// Expected value
        expected: String,
        /// Observed value
        observed: String,
    },
}

/// Threat severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Low severity - informational
    Low,
    /// Medium severity - potential threat
    Medium,
    /// High severity - active threat
    High,
    /// Critical severity - immediate action required
    Critical,
}

/// Observation for baseline analysis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    /// Connection rate (connections per second)
    pub connection_rate: f64,
    /// Traffic volume (bytes per second)
    pub traffic_volume: u64,
    /// Port distribution
    pub ports_accessed: Vec<u16>,
    /// Timestamp
    pub timestamp: SystemTime,
}

/// Detected anomaly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Anomaly {
    /// Deviation from baseline (in standard deviations)
    pub deviation: f64,
    /// Description of anomalous behavior
    pub behavior: String,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
}

/// Path validation result.
#[derive(Debug, Clone)]
pub struct PathValidation {
    /// Whether the path is valid
    pub is_valid: bool,
    /// Expected path
    pub expected_path: Vec<u8>,
    /// Actual path taken
    pub actual_path: Vec<u8>,
    /// Bypassed layers (if any)
    pub bypassed_layers: Vec<u8>,
}

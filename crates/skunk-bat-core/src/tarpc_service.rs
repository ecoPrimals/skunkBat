// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! tarpc service definitions for skunkBat (G65 Cephalization — protocol negotiation).
//!
//! Defines the binary-protocol counterpart to the JSON-RPC methods served on
//! `skunkbat.sock`. G65 protocol negotiation selects tarpc or JSON-RPC at
//! connection time on a single socket, eliminating the C2 dual-socket pattern.
//!
//! ## Protocol Architecture
//!
//! | Phase | Socket | Protocol | Selection |
//! |-------|--------|----------|-----------|
//! | C2 (legacy) | `skunkbat.tarpc.sock` | tarpc + bincode | Direct |
//! | G65 | `skunkbat.sock` | tarpc or JSON-RPC | `PROTOCOLS:` negotiation |

use serde::{Deserialize, Serialize};

/// Health check response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TarpcHealthResponse {
    /// Whether the primal is alive.
    pub alive: bool,
    /// Whether it's ready to serve domain requests.
    pub ready: bool,
    /// Primal name.
    pub primal: String,
    /// Version string.
    pub version: String,
    /// Lifecycle state.
    pub state: String,
}

/// Capability descriptor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TarpcCapability {
    /// Capability domain (e.g. "security", "health").
    pub domain: String,
    /// Methods within this domain.
    pub methods: Vec<String>,
}

/// Identity response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TarpcIdentityResponse {
    /// Primal identifier.
    pub primal: String,
    /// Version.
    pub version: String,
    /// Primary domain.
    pub domain: String,
    /// License.
    pub license: String,
    /// Supported protocols.
    pub protocols: Vec<String>,
}

/// Security metrics snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TarpcSecurityMetrics {
    /// Number of threats detected lifetime.
    pub threats_detected: u64,
    /// Number of threats mitigated.
    pub threats_mitigated: u64,
    /// Number of scans performed.
    pub scans_performed: u64,
    /// Number of active quarantines.
    pub quarantined_count: usize,
    /// Alerts fired.
    pub alerts_fired: u64,
}

/// Defense status snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TarpcDefenseStatus {
    /// Whether auto-defense is enabled.
    pub enabled: bool,
    /// Whether auto-response is active.
    pub auto_response: bool,
    /// Number of quarantined sources.
    pub quarantined_count: usize,
}

/// Threat detection result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TarpcThreat {
    /// Threat identifier.
    pub id: String,
    /// Threat category.
    pub category: String,
    /// Severity (0.0–1.0).
    pub severity: f64,
    /// Human-readable description.
    pub description: String,
}

/// The skunkBat tarpc service — binary counterpart to JSON-RPC dispatch.
///
/// Covers the baseline `PrimalService` contract (health, identity, capabilities,
/// lifecycle) plus skunkBat's domain-specific security operations.
#[tarpc::service]
pub trait SkunkBatRpc {
    // ========================================================================
    // PrimalService baseline (G64 contract)
    // ========================================================================

    /// Liveness probe — is the process alive?
    async fn health_liveness() -> bool;

    /// Readiness probe — ready to serve domain requests?
    async fn health_readiness() -> bool;

    /// Full health check with structured response.
    async fn health_check() -> TarpcHealthResponse;

    /// List all capabilities.
    async fn capabilities_list() -> Vec<TarpcCapability>;

    /// Identity information.
    async fn identity_get() -> TarpcIdentityResponse;

    /// Ping for latency measurement.
    async fn system_ping() -> String;

    /// Version string.
    async fn system_version() -> String;

    /// Current lifecycle state.
    async fn lifecycle_state() -> String;

    // ========================================================================
    // Security domain
    // ========================================================================

    /// Run threat detection.
    async fn security_detect() -> Vec<TarpcThreat>;

    /// Get security metrics.
    async fn security_metrics() -> TarpcSecurityMetrics;

    /// Get defense status.
    async fn defense_status() -> TarpcDefenseStatus;
}

/// Derive the tarpc socket path from the JSON-RPC socket path.
///
/// Follows the C2 dual-socket convention:
/// - JSON-RPC: `skunkbat.sock` or `skunkbat-{family_id}.sock`
/// - tarpc:    `skunkbat.tarpc.sock` or `skunkbat-{family_id}.tarpc.sock`
#[must_use]
pub fn tarpc_socket_from_jsonrpc(jsonrpc_path: &std::path::Path) -> std::path::PathBuf {
    let stem = jsonrpc_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("skunkbat");
    let filename = format!("{stem}.tarpc.sock");
    match jsonrpc_path.parent() {
        Some(p) if p.as_os_str().is_empty() => std::path::PathBuf::from(filename),
        Some(p) => p.join(filename),
        None => std::path::PathBuf::from(filename),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_response_serde_roundtrip() {
        let resp = TarpcHealthResponse {
            alive: true,
            ready: true,
            primal: "skunkbat".to_owned(),
            version: "0.2.18".to_owned(),
            state: "running".to_owned(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: TarpcHealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn capability_serde_roundtrip() {
        let cap = TarpcCapability {
            domain: "security".to_owned(),
            methods: vec!["detect".to_owned(), "respond".to_owned()],
        };
        let json = serde_json::to_string(&cap).unwrap();
        let back: TarpcCapability = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, back);
    }

    #[test]
    fn identity_serde_roundtrip() {
        let id = TarpcIdentityResponse {
            primal: "skunkbat".to_owned(),
            version: "0.2.18".to_owned(),
            domain: "security".to_owned(),
            license: "AGPL-3.0-or-later".to_owned(),
            protocols: vec!["jsonrpc-2.0".to_owned(), "tarpc".to_owned()],
        };
        let json = serde_json::to_string(&id).unwrap();
        let back: TarpcIdentityResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn tarpc_socket_from_jsonrpc_standalone() {
        let path = std::path::Path::new("/run/user/1000/biomeos/skunkbat.sock");
        let tarpc = tarpc_socket_from_jsonrpc(path);
        assert_eq!(
            tarpc,
            std::path::PathBuf::from("/run/user/1000/biomeos/skunkbat.tarpc.sock")
        );
    }

    #[test]
    fn tarpc_socket_from_jsonrpc_family() {
        let path = std::path::Path::new("/run/user/1000/biomeos/skunkbat-mygate.sock");
        let tarpc = tarpc_socket_from_jsonrpc(path);
        assert_eq!(
            tarpc,
            std::path::PathBuf::from("/run/user/1000/biomeos/skunkbat-mygate.tarpc.sock")
        );
    }

    #[test]
    fn tarpc_socket_from_bare_filename() {
        let path = std::path::Path::new("skunkbat.sock");
        let tarpc = tarpc_socket_from_jsonrpc(path);
        assert_eq!(tarpc, std::path::PathBuf::from("skunkbat.tarpc.sock"));
    }
}

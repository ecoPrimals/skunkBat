// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Self-registration with the discovery capability (Primal Self-Registration Pattern v1.0)
//! and Neural API announcement (Wave 43).
//!
//! On startup, probes for a discovery provider and sends `ipc.register`
//! with this primal's ID, capabilities, and endpoint. Also sends
//! `primal.announce` to biomeOS Neural API with cost hints, latency
//! estimates, and signal tier for intelligent routing. Non-blocking: if
//! no discovery service is available, continues in standalone mode.
//!
//! Transport is resolved via `TransportEndpoint` — UDS on Unix,
//! TCP when `DISCOVERY_ENDPOINT` / `NEURAL_API_SOCKET` are configured.
//! No `#[cfg]` gates in the registration flow itself.

use std::time::Duration;

use skunk_bat_integrations::rpc::{self, TransportEndpoint};

/// Capabilities registered for discovery — only advertise domains with live IPC.
///
/// `metadata` and `lineage` are spec-designed composable primitives
/// but have no IPC methods yet. They will be added here when shipped.
const CAPABILITIES: &[&str] = &[
    "security",
    "health",
    "defense",
    "baseline",
    "response",
    "threat",
    "auth",
    "lifecycle",
    "method_gate",
    "btsp",
];

fn registration_timeout() -> Duration {
    std::env::var(skunk_bat_core::env_keys::SKUNKBAT_REGISTRATION_TIMEOUT)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(Duration::from_secs(3), Duration::from_secs)
}

/// Attempt to self-register with the ecosystem discovery service.
///
/// Follows the startup probe sequence from `PRIMAL_SELF_REGISTRATION.md`:
/// 1. Check `DISCOVERY_SOCKET` env var
/// 2. Fall back to `{BIOMEOS_SOCKET_DIR}/discovery-{FAMILY_ID}.sock`
/// 3. Fall back to `{XDG_RUNTIME_DIR}/biomeos/discovery-{FAMILY_ID}.sock`
///
/// If no discovery service is reachable, logs and returns (standalone mode).
pub async fn self_register(endpoint: String) {
    let Some(discovery_ep) = resolve_discovery_endpoint() else {
        tracing::info!("no discovery service found — standalone mode");
        return;
    };

    let params = serde_json::json!({
        "primal_id": skunk_bat_core::PRIMAL_ID,
        "capabilities": CAPABILITIES,
        "endpoint": &endpoint,
    });

    match rpc::call_endpoint(
        &discovery_ep,
        "ipc.register",
        Some(params),
        registration_timeout(),
    )
    .await
    {
        Ok(result) => {
            tracing::info!(
                "registered with discovery: {}",
                result
                    .get("virtual_endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no virtual endpoint)")
            );
        }
        Err(e) => {
            tracing::debug!("discovery registration unavailable: {e} — standalone mode");
        }
    }
}

/// Resolve the discovery endpoint from environment/conventions.
///
/// Probe order:
/// 1. `DISCOVERY_TRANSPORT` env (sourDough `TransportEndpoint` JSON)
/// 2. `DISCOVERY_ENDPOINT` env → TCP
/// 3. `DISCOVERY_SOCKET` env → UDS (if socket file exists)
/// 4. `{socket_dir}/discovery-{FAMILY_ID}.sock` (family-scoped UDS)
/// 5. `{socket_dir}/discovery.sock` (generic capability UDS)
fn resolve_discovery_endpoint() -> Option<TransportEndpoint> {
    if let Some(ep) = rpc::parse_transport_env(skunk_bat_core::env_keys::DISCOVERY_TRANSPORT) {
        return Some(ep);
    }

    if let Ok(addr) = std::env::var(skunk_bat_core::env_keys::DISCOVERY_ENDPOINT)
        && let Some(ep) = rpc::parse_tcp_host_port(&addr)
    {
        return Some(ep);
    }

    if let Ok(path) = std::env::var(skunk_bat_core::env_keys::DISCOVERY_SOCKET)
        && !path.is_empty()
        && std::path::Path::new(&path).exists()
    {
        return Some(TransportEndpoint::Uds { path });
    }

    let socket_dir = rpc::socket_dir();
    let family_id = std::env::var(skunk_bat_core::env_keys::FAMILY_ID).unwrap_or_default();

    let mut candidates = Vec::with_capacity(2);
    if !family_id.is_empty() && family_id != "default" {
        candidates.push(format!("{socket_dir}/discovery-{family_id}.sock"));
    }
    candidates.push(format!("{socket_dir}/discovery.sock"));

    candidates
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .map(|path| TransportEndpoint::Uds { path })
}

/// Announce to biomeOS Neural API for intelligent routing (Wave 43).
///
/// Sends `primal.announce` with capabilities, cost hints, latency estimates,
/// and signal tier. biomeOS uses this for weighted capability routing.
/// Non-blocking: if biomeOS Neural API is unreachable, logs and returns.
pub async fn neural_announce(socket_path: &str) {
    let Some(neural_ep) = resolve_neural_api_endpoint() else {
        tracing::debug!("no Neural API endpoint found — skipping primal.announce");
        return;
    };

    let params = announce_payload(socket_path);

    match rpc::call_endpoint(
        &neural_ep,
        "primal.announce",
        Some(params),
        registration_timeout(),
    )
    .await
    {
        Ok(_) => {
            tracing::info!(
                "announced to Neural API (tower tier, {} capabilities)",
                CAPABILITIES.len()
            );
        }
        Err(e) => {
            tracing::debug!("Neural API announce unavailable: {e} — routing passive");
        }
    }
}

/// Build the `primal.announce` payload (v3.68 wire schema).
///
/// Visible for testing — validates payload structure.
pub(super) fn announce_payload(socket_path: &str) -> serde_json::Value {
    serde_json::json!({
        "primal": skunk_bat_core::PRIMAL_ID,
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "capabilities": CAPABILITIES,
        "methods": super::dispatch::all_methods(),
        "socket": socket_path,
        "signal_tiers": ["tower"],
        "cost_hints": {
            "defense": 15.0,
            "threat_detection": 20.0,
            "baseline": 10.0
        },
        "latency_estimates": {
            "defense": 5,
            "threat_detection": 10,
            "baseline": 2
        },
        "attestation": null
    })
}

/// Resolve the biomeOS Neural API endpoint.
///
/// Probe order:
/// 1. `NEURAL_API_SOCKET` env → UDS (if socket file exists)
/// 2. `{socket_dir}/neural-api.sock` (capability convention UDS)
fn resolve_neural_api_endpoint() -> Option<TransportEndpoint> {
    if let Ok(path) = std::env::var(skunk_bat_core::env_keys::NEURAL_API_SOCKET)
        && !path.is_empty()
        && std::path::Path::new(&path).exists()
    {
        return Some(TransportEndpoint::Uds { path });
    }

    let socket_dir = rpc::socket_dir();
    let path = format!("{socket_dir}/neural-api.sock");

    std::path::Path::new(&path)
        .exists()
        .then_some(TransportEndpoint::Uds { path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_non_empty() {
        assert!(!CAPABILITIES.is_empty());
        assert!(CAPABILITIES.contains(&"security"));
    }

    #[test]
    fn resolve_returns_endpoint_or_none() {
        let result = resolve_discovery_endpoint();
        if let Some(TransportEndpoint::Uds { ref path }) = result {
            assert!(std::path::Path::new(path).exists());
        }
    }

    #[tokio::test]
    async fn self_register_no_crash_without_discovery() {
        self_register("unix:///tmp/skunkbat-test-no-discovery.sock".to_owned()).await;
    }

    #[tokio::test]
    async fn neural_announce_no_crash_without_biomeos() {
        neural_announce("/tmp/skunkbat-test.sock").await;
    }

    #[test]
    fn resolve_neural_api_returns_endpoint_or_none() {
        let result = resolve_neural_api_endpoint();
        if let Some(TransportEndpoint::Uds { ref path }) = result {
            assert!(std::path::Path::new(path).exists());
        }
    }

    #[test]
    fn announce_payload_has_primal_field() {
        let payload = announce_payload("/tmp/test.sock");
        assert_eq!(payload["primal"], "skunkbat");
        assert!(payload.get("primal_id").is_none(), "must not use primal_id");
        assert!(payload.get("name").is_none(), "must not use name");
    }

    #[test]
    fn announce_payload_methods_complete() {
        let payload = announce_payload("/tmp/test.sock");
        let methods = payload["methods"].as_array().expect("methods array");
        assert!(
            methods.len() >= 29,
            "must advertise all shipped methods, got {}",
            methods.len()
        );
        let strs: Vec<&str> = methods.iter().filter_map(|m| m.as_str()).collect();
        assert!(strs.contains(&"btsp.capabilities"));
        assert!(strs.contains(&"security.advisory"));
        assert!(strs.contains(&"security.audit_log"));
        assert!(strs.contains(&"health.liveness"));
        assert!(strs.contains(&"method_gate.status"));
        assert!(strs.contains(&"threat.report"));
        assert!(strs.contains(&"baseline.observe"));
        assert!(strs.contains(&"defense.status"));
    }

    #[test]
    fn announce_payload_has_pid_and_version() {
        let payload = announce_payload("/tmp/test.sock");
        assert!(payload["pid"].as_u64().unwrap() > 0);
        assert!(!payload["version"].as_str().unwrap().is_empty());
    }

    #[test]
    fn announce_payload_signal_tiers_tower() {
        let payload = announce_payload("/tmp/test.sock");
        let tiers = payload["signal_tiers"].as_array().unwrap();
        assert_eq!(tiers[0], "tower");
    }

    #[test]
    fn announce_payload_cost_hints_and_latency() {
        let payload = announce_payload("/tmp/test.sock");
        let hints = &payload["cost_hints"];
        assert_eq!(hints["defense"], 15.0);
        assert_eq!(hints["threat_detection"], 20.0);
        assert_eq!(hints["baseline"], 10.0);
        let latency = &payload["latency_estimates"];
        assert_eq!(latency["defense"], 5);
        assert_eq!(latency["threat_detection"], 10);
        assert_eq!(latency["baseline"], 2);
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Self-registration with the discovery capability (Primal Self-Registration Pattern v1.0).
//!
//! On startup, probes for a discovery provider and sends `ipc.register`
//! with this primal's ID, capabilities, and endpoint. Non-blocking: if
//! no discovery service is available, continues in standalone mode.

use std::time::Duration;

/// Capabilities registered for discovery — maps to the five composable domains
/// from `COMPOSABLE_PRIMITIVES_SPEC.md` plus the aggregate `security` tag.
const CAPABILITIES: &[&str] = &[
    "security", "baseline", "metadata", "response", "lineage", "health",
];

const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(3);

/// Attempt to self-register with the ecosystem discovery service.
///
/// Follows the startup probe sequence from `PRIMAL_SELF_REGISTRATION.md`:
/// 1. Check `DISCOVERY_SOCKET` env var
/// 2. Fall back to `{BIOMEOS_SOCKET_DIR}/discovery-{FAMILY_ID}.sock`
/// 3. Fall back to `{XDG_RUNTIME_DIR}/biomeos/discovery-{FAMILY_ID}.sock`
///
/// If no discovery service is reachable, logs and returns (standalone mode).
pub async fn self_register(endpoint: String) {
    let Some(discovery_socket) = resolve_discovery_socket() else {
        tracing::info!("no discovery service found — standalone mode");
        return;
    };

    let params = serde_json::json!({
        "primal_id": skunk_bat_core::PRIMAL_ID,
        "capabilities": CAPABILITIES,
        "endpoint": &endpoint,
    });

    match skunk_bat_integrations::rpc::call_uds(
        &discovery_socket,
        "ipc.register",
        Some(params),
        REGISTRATION_TIMEOUT,
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

/// Resolve the discovery socket path from environment/conventions.
fn resolve_discovery_socket() -> Option<String> {
    if let Ok(path) = std::env::var("DISCOVERY_SOCKET")
        && !path.is_empty()
        && std::path::Path::new(&path).exists()
    {
        return Some(path);
    }

    let socket_dir = skunk_bat_integrations::rpc::socket_dir();
    let family_id = std::env::var("FAMILY_ID").unwrap_or_default();

    let candidates = if family_id.is_empty() || family_id == "default" {
        vec![format!("{socket_dir}/discovery.sock")]
    } else {
        vec![
            format!("{socket_dir}/discovery-{family_id}.sock"),
            format!("{socket_dir}/discovery.sock"),
        ]
    };

    candidates
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
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
    fn resolve_returns_existing_path_or_none() {
        let result = resolve_discovery_socket();
        if let Some(ref path) = result {
            assert!(std::path::Path::new(path).exists());
        }
    }

    #[tokio::test]
    async fn self_register_no_crash_without_discovery() {
        self_register("unix:///tmp/skunkbat-test-no-discovery.sock".to_owned()).await;
    }
}

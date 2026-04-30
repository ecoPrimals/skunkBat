// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Common configuration that all primals share.

use serde::{Deserialize, Serialize};

/// Common configuration that all primals share.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommonConfig {
    /// Primal name.
    pub name: String,
    /// Primal instance ID (unique per deployment).
    pub instance_id: String,
    /// Log level.
    pub log_level: String,
    /// Data directory.
    pub data_dir: String,
    /// Listen address.
    pub listen_addr: String,
    /// Listen port (0 = OS assigns ephemeral port).
    pub listen_port: u16,
    /// Identity service endpoint (discovered at runtime).
    pub identity_service_endpoint: Option<String>,
    /// Discovery service endpoint (discovered at runtime).
    pub discovery_service_endpoint: Option<String>,
}

impl Default for CommonConfig {
    fn default() -> Self {
        Self {
            name: "primal".to_owned(),
            instance_id: new_instance_id(),
            log_level: "info".to_owned(),
            data_dir: "./data".to_owned(),
            listen_addr: "0.0.0.0".to_owned(),
            listen_port: 0,
            identity_service_endpoint: None,
            discovery_service_endpoint: None,
        }
    }
}

/// Generate a unique instance ID without external crypto deps.
///
/// Uses `DefaultHasher` seeded with timestamp + PID — sufficient for
/// instance disambiguation without the `blake3` dependency that
/// `sourdough-core` carries.
fn new_instance_id() -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut hasher = DefaultHasher::new();
    nanos.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    let h1 = hasher.finish();

    let mut hasher = DefaultHasher::new();
    (nanos.wrapping_add(1)).hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    let h2 = hasher.finish();

    format!("{h1:016x}{h2:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_config_default() {
        let config = CommonConfig::default();
        assert_eq!(config.name, "primal");
        assert_eq!(config.log_level, "info");
        assert_eq!(config.listen_port, 0);
        assert!(config.identity_service_endpoint.is_none());
        assert!(config.discovery_service_endpoint.is_none());
        assert!(!config.instance_id.is_empty());
    }

    #[test]
    fn common_config_unique_instance_ids() {
        let c1 = CommonConfig::default();
        let c2 = CommonConfig::default();
        assert_ne!(c1.instance_id, c2.instance_id);
    }

    #[test]
    fn common_config_serialization() {
        let config = CommonConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: CommonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.name, parsed.name);
        assert_eq!(config.log_level, parsed.log_level);
    }

    #[test]
    fn instance_id_is_hex() {
        let id = new_instance_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

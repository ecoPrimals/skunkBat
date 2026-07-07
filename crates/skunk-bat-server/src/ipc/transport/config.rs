// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! BTSP environment configuration (Phase 1 + Phase 2).
//!
//! Phase 1: socket naming with `FAMILY_ID` awareness.
//! Phase 2: capability-delegated handshake via provider RPC.

use super::error::TransportError;

/// Resolve the biomeOS socket directory from the environment.
///
/// Precedence: `BIOMEOS_SOCKET_DIR` > `XDG_RUNTIME_DIR/biomeos` > `/run/user/{uid}/biomeos`.
fn resolve_socket_dir() -> String {
    std::env::var(skunk_bat_core::env_keys::BIOMEOS_SOCKET_DIR).unwrap_or_else(|_| {
        let runtime_dir = std::env::var(skunk_bat_core::env_keys::XDG_RUNTIME_DIR)
            .unwrap_or_else(|_| format!("/run/user/{}", skunk_bat_core::platform::proc_uid()));
        format!("{runtime_dir}/biomeos")
    })
}

/// BTSP Phase 1 environment configuration.
pub struct BtspConfig {
    /// Socket directory (`BIOMEOS_SOCKET_DIR` or `XDG_RUNTIME_DIR/biomeos`).
    pub socket_dir: String,
    /// Family ID if set — triggers production socket naming.
    pub family_id: Option<String>,
    /// True when `BIOMEOS_INSECURE=1` is set (development mode).
    pub insecure: bool,
}

impl BtspConfig {
    /// Read BTSP Phase 1 config from environment.
    ///
    /// # Errors
    ///
    /// Returns `Err` when both `FAMILY_ID` and `BIOMEOS_INSECURE=1` are set.
    #[must_use = "transport config errors must be handled"]
    pub fn from_env() -> Result<Self, TransportError> {
        let family_id = std::env::var(skunk_bat_core::env_keys::FAMILY_ID)
            .ok()
            .filter(|v| !v.is_empty() && v != "default");

        let insecure = std::env::var(skunk_bat_core::env_keys::BIOMEOS_INSECURE)
            .ok()
            .is_some_and(|v| v == "1");

        if family_id.is_some() && insecure {
            return Err(TransportError::Config(
                "FAMILY_ID and BIOMEOS_INSECURE=1 cannot both be set".to_owned(),
            ));
        }

        let socket_dir = resolve_socket_dir();

        Ok(Self {
            socket_dir,
            family_id,
            insecure,
        })
    }

    /// Compute the UDS socket path per BTSP Phase 1 naming convention.
    ///
    /// - Development: `{socket_dir}/skunkbat.sock`
    /// - Production:  `{socket_dir}/skunkbat-{family_id}.sock`
    pub fn socket_path(&self) -> String {
        self.family_id.as_ref().map_or_else(
            || format!("{}/skunkbat.sock", self.socket_dir),
            |fid| format!("{}/skunkbat-{fid}.sock", self.socket_dir),
        )
    }

    /// Compute the capability-domain symlink path.
    ///
    /// `{socket_dir}/security.sock` → `skunkbat[-{fid}].sock`
    pub fn capability_symlink_path(&self) -> String {
        format!("{}/security.sock", self.socket_dir)
    }

    /// Log the current BTSP mode.
    pub fn log_mode(&self) {
        match &self.family_id {
            Some(fid) => {
                tracing::info!(
                    "BTSP Phase 1: production mode (FAMILY_ID={fid}), socket={}",
                    self.socket_path()
                );
            }
            None if self.insecure => {
                tracing::info!(
                    "BTSP: development mode (BIOMEOS_INSECURE=1), socket={}",
                    self.socket_path()
                );
            }
            None => {
                tracing::info!(
                    "BTSP: standalone mode (no FAMILY_ID), socket={}",
                    self.socket_path()
                );
            }
        }
    }
}

/// Configuration for BTSP server-side handshake (Phase 2).
///
/// When present, every accepted connection must complete a BTSP handshake
/// via the security provider before JSON-RPC is served.
///
/// Provider discovery follows capability-based resolution:
/// 1. `BTSP_PROVIDER_SOCKET` — explicit path (highest priority)
/// 2. `{BIOMEOS_SOCKET_DIR}/{BTSP_PROVIDER}-{FAMILY_ID}.sock` — by capability
/// 3. Falls back to `btsp` capability name (agnostic of which primal serves it)
#[derive(Debug, Clone)]
pub struct BtspHandshakeConfig {
    /// Path to the BTSP security provider's UDS socket for `btsp.server.*` RPCs.
    pub provider_socket: std::path::PathBuf,
    /// Family identifier (used for logging and future cipher scoping).
    #[expect(dead_code, reason = "reserved for BTSP Phase 2 cipher scoping")]
    pub family_id: String,
}

/// Default BTSP capability name for socket resolution.
const DEFAULT_BTSP_CAPABILITY: &str = "btsp";

impl BtspHandshakeConfig {
    /// Resolve handshake config from the environment.
    ///
    /// Returns `Some` when `FAMILY_ID` is set to a production value.
    /// Provider socket is resolved by capability, not by primal name.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let fid = std::env::var(skunk_bat_core::env_keys::FAMILY_ID)
            .ok()
            .filter(|v| !v.is_empty() && v != "default")?;

        let provider_socket = std::env::var(skunk_bat_core::env_keys::BTSP_PROVIDER_SOCKET)
            .ok()
            .map_or_else(
                || {
                    let capability = std::env::var(skunk_bat_core::env_keys::BTSP_PROVIDER)
                        .unwrap_or_else(|_| DEFAULT_BTSP_CAPABILITY.to_owned());
                    let socket_dir = resolve_socket_dir();
                    std::path::PathBuf::from(format!("{socket_dir}/{capability}-{fid}.sock"))
                },
                std::path::PathBuf::from,
            );

        Some(Self {
            provider_socket,
            family_id: fid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_standalone() {
        let config = BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: None,
            insecure: false,
        };
        assert_eq!(config.socket_path(), "/tmp/biomeos/skunkbat.sock");
    }

    #[test]
    fn socket_path_family() {
        let config = BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: Some("mygate".into()),
            insecure: false,
        };
        assert_eq!(config.socket_path(), "/tmp/biomeos/skunkbat-mygate.sock");
    }

    #[test]
    fn capability_symlink_path() {
        let config = BtspConfig {
            socket_dir: "/run/user/1000/biomeos".into(),
            family_id: None,
            insecure: false,
        };
        assert_eq!(
            config.capability_symlink_path(),
            "/run/user/1000/biomeos/security.sock"
        );
    }

    #[test]
    fn log_mode_standalone() {
        BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: None,
            insecure: false,
        }
        .log_mode();
    }

    #[test]
    fn log_mode_insecure() {
        BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: None,
            insecure: true,
        }
        .log_mode();
    }

    #[test]
    fn log_mode_family() {
        BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: Some("prod".into()),
            insecure: false,
        }
        .log_mode();
    }

    #[test]
    fn handshake_config_construction() {
        let cfg = BtspHandshakeConfig {
            provider_socket: "/tmp/beardog.sock".into(),
            family_id: "test-family".into(),
        };
        assert_eq!(
            cfg.provider_socket,
            std::path::PathBuf::from("/tmp/beardog.sock")
        );
    }

    #[test]
    fn handshake_config_from_env_returns_option() {
        let _result = BtspHandshakeConfig::from_env();
    }

    #[test]
    fn handshake_config_debug_and_clone() {
        let cfg = BtspHandshakeConfig {
            provider_socket: "/tmp/beardog.sock".into(),
            family_id: "test-family".into(),
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.provider_socket, cfg.provider_socket);
        assert!(!format!("{cfg:?}").is_empty());
    }

    #[test]
    fn btsp_config_insecure_mode() {
        let cfg = BtspConfig {
            socket_dir: "/tmp/biomeos".into(),
            family_id: None,
            insecure: true,
        };
        assert!(cfg.insecure);
        assert!(cfg.socket_path().ends_with("skunkbat.sock"));
    }

    #[test]
    fn btsp_config_from_env_standalone() {
        let result = BtspConfig::from_env();
        assert!(result.is_ok());
        let cfg = result.unwrap();
        assert!(!cfg.socket_dir.is_empty());
    }
}

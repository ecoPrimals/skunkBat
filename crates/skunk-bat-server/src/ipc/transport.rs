// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Transport layer — TCP and Unix domain socket listeners.
//!
//! Implements BTSP Phase 1 (socket naming with `FAMILY_ID` awareness)
//! and Primal IPC Protocol v3.1 (filesystem sockets in `$BIOMEOS_SOCKET_DIR`).

use skunk_bat_core::SkunkBat;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use super::server::handle_connection;

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
    pub fn from_env() -> Result<Self, String> {
        let family_id = std::env::var("FAMILY_ID")
            .ok()
            .filter(|v| !v.is_empty() && v != "default");

        let insecure = std::env::var("BIOMEOS_INSECURE")
            .map(|v| v == "1")
            .unwrap_or(false);

        if family_id.is_some() && insecure {
            return Err(
                "BTSP guard: FAMILY_ID and BIOMEOS_INSECURE=1 cannot both be set".to_string(),
            );
        }

        let socket_dir = std::env::var("BIOMEOS_SOCKET_DIR").unwrap_or_else(|_| {
            let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
                .unwrap_or_else(|_| format!("/run/user/{}", proc_uid()));
            format!("{runtime_dir}/biomeos")
        });

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

/// Bind TCP and accept connections.
pub async fn serve_tcp(
    state: Arc<RwLock<SkunkBat>>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("TCP JSON-RPC listening on 0.0.0.0:{port}");

    loop {
        let (stream, addr) = listener.accept().await?;
        tracing::debug!("TCP connection from {addr}");
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            handle_connection(state, stream).await;
        });
    }
}

/// Bind UDS and accept connections per BTSP Phase 1 naming.
#[cfg(unix)]
pub async fn serve_uds(
    state: Arc<RwLock<SkunkBat>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    use tokio::net::UnixListener;

    let btsp = BtspConfig::from_env()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    btsp.log_mode();

    let socket_path = btsp.socket_path();

    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    tokio::fs::remove_file(&socket_path).await.ok();
    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!("UDS JSON-RPC listening on {socket_path}");

    create_capability_symlink(&btsp);

    loop {
        let (stream, _addr) = listener.accept().await?;
        tracing::debug!("UDS connection accepted");
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            handle_connection(state, stream).await;
        });
    }
}

#[cfg(not(unix))]
pub async fn serve_uds(
    _state: Arc<RwLock<SkunkBat>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    tracing::warn!("Unix domain sockets not available on this platform");
    std::future::pending().await
}

/// Create capability-domain symlink: `security.sock` → `skunkbat[-{fid}].sock`
#[cfg(unix)]
fn create_capability_symlink(btsp: &BtspConfig) {
    let symlink_path = btsp.capability_symlink_path();
    let socket_name = std::path::Path::new(&btsp.socket_path())
        .file_name()
        .map_or_else(
            || "skunkbat.sock".to_string(),
            |n| n.to_string_lossy().to_string(),
        );

    std::fs::remove_file(&symlink_path).ok();
    match std::os::unix::fs::symlink(&socket_name, &symlink_path) {
        Ok(()) => tracing::info!("Capability symlink: security.sock -> {socket_name}"),
        Err(e) => tracing::warn!("Failed to create capability symlink: {e}"),
    }
}

/// Get UID without libc dependency (reads /proc/self/status on Linux).
fn proc_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(1000)
}

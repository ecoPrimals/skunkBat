// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Inflammatory response — heartbeat watchdog and Caddyfile failover.
//!
//! Replaces `membrane-inflammatory.sh`. When the skunky-ingest heartbeat
//! goes stale (observer down), activates a hardened inflammatory Caddyfile
//! that blocks everything except established connections. When heartbeat
//! returns, restores the normal Caddyfile.
//!
//! This runs as a background task within skunky-ingest itself, eliminating
//! the need for a separate systemd timer + bash script.

#![allow(missing_docs)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Configuration for the inflammatory watchdog.
#[derive(Debug, Clone)]
pub struct InflammatoryConfig {
    pub heartbeat_path: PathBuf,
    pub caddyfile_path: PathBuf,
    pub inflammatory_path: PathBuf,
    pub normal_backup_path: PathBuf,
    pub state_file: PathBuf,
    pub caddy_bin: PathBuf,
    pub max_stale_secs: u64,
    pub check_interval: Duration,
}

impl Default for InflammatoryConfig {
    fn default() -> Self {
        Self {
            heartbeat_path: PathBuf::from("/run/membrane/skunky-ingest.heartbeat"),
            caddyfile_path: PathBuf::from("/etc/membrane/Caddyfile"),
            inflammatory_path: PathBuf::from("/etc/membrane/Caddyfile.inflammatory"),
            normal_backup_path: PathBuf::from("/etc/membrane/Caddyfile.normal"),
            state_file: PathBuf::from("/run/membrane/inflammatory.state"),
            caddy_bin: PathBuf::from("/opt/membrane/caddy"),
            max_stale_secs: 180,
            check_interval: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, PartialEq)]
enum State {
    Normal,
    Inflammatory,
}

/// Run the inflammatory watchdog loop. Never returns under normal operation.
pub async fn run(config: InflammatoryConfig) {
    tracing::info!(
        heartbeat = %config.heartbeat_path.display(),
        max_stale = config.max_stale_secs,
        "🔥 inflammatory watchdog active"
    );

    // Check that the inflammatory Caddyfile exists
    if !config.inflammatory_path.exists() {
        tracing::error!(
            path = %config.inflammatory_path.display(),
            "inflammatory Caddyfile missing — watchdog disabled"
        );
        return;
    }

    loop {
        tokio::time::sleep(config.check_interval).await;

        let current_state = read_state(&config.state_file).await;
        let stale_secs = heartbeat_age(&config.heartbeat_path).await;

        if stale_secs > config.max_stale_secs {
            if current_state == State::Inflammatory {
                tracing::debug!(stale = stale_secs, "inflammatory still active");
                continue;
            }

            tracing::error!(
                stale = stale_secs,
                "🔴 INFLAMMATORY ACTIVATION — heartbeat stale, locking membrane"
            );

            // Back up normal Caddyfile
            if !config.normal_backup_path.exists() {
                if let Err(e) = tokio::fs::copy(&config.caddyfile_path, &config.normal_backup_path).await {
                    tracing::error!(error = %e, "failed to back up normal Caddyfile");
                    continue;
                }
            }

            // Activate inflammatory config
            if let Err(e) = tokio::fs::copy(&config.inflammatory_path, &config.caddyfile_path).await {
                tracing::error!(error = %e, "failed to activate inflammatory Caddyfile");
                continue;
            }

            if reload_caddy(&config.caddy_bin, &config.caddyfile_path).await {
                tracing::warn!("inflammatory Caddyfile activated and Caddy reloaded");
                write_state(&config.state_file, State::Inflammatory).await;
            } else {
                // Restore backup on failed reload
                let _ = tokio::fs::copy(&config.normal_backup_path, &config.caddyfile_path).await;
            }
        } else if current_state == State::Inflammatory {
            tracing::info!(
                stale = stale_secs,
                "🟢 INFLAMMATORY RESOLVED — heartbeat healthy, restoring membrane"
            );

            if config.normal_backup_path.exists() {
                if let Err(e) = tokio::fs::copy(&config.normal_backup_path, &config.caddyfile_path).await {
                    tracing::error!(error = %e, "failed to restore normal Caddyfile");
                    continue;
                }
                if reload_caddy(&config.caddy_bin, &config.caddyfile_path).await {
                    tracing::info!("normal Caddyfile restored and Caddy reloaded");
                    let _ = tokio::fs::remove_file(&config.normal_backup_path).await;
                }
            }

            write_state(&config.state_file, State::Normal).await;
        }
    }
}

async fn heartbeat_age(path: &Path) -> u64 {
    let contents = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(_) => return u64::MAX, // Missing = infinitely stale
    };
    let heartbeat_epoch: u64 = contents.trim().parse().unwrap_or(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(heartbeat_epoch)
}

async fn read_state(path: &Path) -> State {
    match tokio::fs::read_to_string(path).await {
        Ok(s) if s.trim() == "inflammatory" => State::Inflammatory,
        _ => State::Normal,
    }
}

async fn write_state(path: &Path, state: State) {
    let val = match state {
        State::Normal => "normal",
        State::Inflammatory => "inflammatory",
    };
    if let Err(e) = tokio::fs::write(path, val).await {
        tracing::warn!(error = %e, "failed to write inflammatory state");
    }
}

async fn reload_caddy(caddy_bin: &Path, caddyfile: &Path) -> bool {
    match tokio::process::Command::new(caddy_bin)
        .args(["reload", "--config"])
        .arg(caddyfile)
        .arg("--address")
        .arg("localhost:2019")
        .output()
        .await
    {
        Ok(output) if output.status.success() => true,
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!(stderr = %stderr, "Caddy reload failed");
            false
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to execute caddy reload");
            false
        }
    }
}

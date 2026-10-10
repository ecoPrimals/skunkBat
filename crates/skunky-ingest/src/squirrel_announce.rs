// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Squirrel announce — fire-and-forget capability announcement to squirrel.sock.
//!
//! skunky-ingest pushes aggregate membrane observations to squirrel so the AI
//! coordination primal has context about what the membrane sees. This is a
//! one-way, push-only wire. Squirrel cannot query back (skunky-ingest has no
//! listener socket).
//!
//! # Safety invariants
//!
//! - **Fire-and-forget**: 500ms hard timeout. If squirrel is down or slow,
//!   we drop and continue. The bloom MUST NOT stall.
//! - **Locked payload**: Only aggregate Anderson statistics. No IP hashes,
//!   no entity IDs, no geographic data, no raw bloom bits, no per-entity
//!   behavioral scores. The payload contains nothing that isn't already in
//!   the world-readable `/run/membrane/anderson-profile.json`.
//! - **Idempotent**: squirrel's `capabilities.announce` handler overwrites
//!   by tool name. Sending the same announce every 30s is safe.
//! - **No dependency**: If this entire module is disabled or fails, skunky-ingest
//!   continues exactly as before — writing JSON files to disk.
//!
//! # Pattern
//!
//! Copied from `scatter_defense::inject_epitope_gossip` which has been running
//! in production (swarmvine gossip injection) since Wave 167.

use crate::anderson_bridge::AndersonProfile;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Default socket path for squirrel on golgiBody.
const SQUIRREL_SOCKET: &str = "/run/membrane/squirrel.sock";

/// Hard timeout for the entire announce operation (connect + write + read).
const ANNOUNCE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Suppresses repeated "socket not found" log messages.
static LOGGED_MISSING: AtomicBool = AtomicBool::new(false);

/// Announce the current Anderson membrane profile to squirrel.
///
/// Called from `dashboard_writer::update_anderson_profile` after writing
/// the JSON file. Spawned in a `tokio::spawn` — never awaited inline.
pub(crate) async fn announce_to_squirrel(profile: &AndersonProfile) {
    let socket_path = std::env::var("SQUIRREL_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(SQUIRREL_SOCKET));

    if !socket_path.exists() {
        if !LOGGED_MISSING.swap(true, Ordering::Relaxed) {
            tracing::debug!("squirrel socket not found at {:?} — announce skipped", socket_path);
        }
        return;
    }
    // Reset the missing flag so we log again if it disappears and reappears
    LOGGED_MISSING.store(false, Ordering::Relaxed);

    // Build the locked payload — aggregate statistics only
    let modes: Vec<serde_json::Value> = profile.modes.iter().map(|m| {
        serde_json::json!({
            "class": m.class,
            "count": m.count,
            "p_predicted": m.p_predicted,
            "p_observed": m.p_observed,
        })
    }).collect();

    let announce = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "capabilities.announce",
        "params": {
            "primal": "skunky-ingest",
            "capabilities": [
                "membrane.observe",
                "membrane.anderson",
                "membrane.bloom",
            ],
            "socket_path": "/run/membrane/skunky-ingest.announce",
            "metadata": {
                "anderson": {
                    "modes": modes,
                    "selectivity_predicted": profile.selectivity_predicted,
                    "selectivity_observed": profile.selectivity_observed,
                    "w_population": profile.w_population,
                    "pielou_j": profile.pielou_j,
                    "imaginary_magnitude": profile.imaginary_magnitude,
                }
            }
        },
        "id": 1,
    });

    // Fire-and-forget with hard timeout
    let result = tokio::time::timeout(ANNOUNCE_TIMEOUT, async {
        let stream = tokio::net::UnixStream::connect(&socket_path).await?;
        let (rd, mut wr) = tokio::io::split(stream);
        let mut reader = BufReader::new(rd);

        let msg = format!("{announce}\n");
        wr.write_all(msg.as_bytes()).await?;

        let mut response = String::new();
        reader.read_line(&mut response).await?;

        Ok::<String, std::io::Error>(response)
    }).await;

    match result {
        Ok(Ok(resp)) if !resp.is_empty() => {
            tracing::debug!(
                len = resp.len(),
                "squirrel announce acknowledged"
            );
        }
        Ok(Err(e)) => {
            tracing::debug!("squirrel announce io error: {e}");
        }
        Err(_) => {
            tracing::debug!("squirrel announce timed out (500ms)");
        }
        _ => {}
    }
}

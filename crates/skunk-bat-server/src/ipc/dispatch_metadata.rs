// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Metadata domain dispatch — gossip entry analysis for swarmVine pre-accept
//! validation (vine-bat loop).

use skunk_bat_core::gossip_analysis::{self, GossipEntryParams};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::App;
use super::jsonrpc::{self, Response};

/// Handle `metadata.analyze` — pre-accept validation for swarmVine gossip entries.
///
/// Accepts a gossip entry (matching swarmVine's wire format) and returns
/// a verdict with per-check results. swarmVine calls this before storing
/// entries received via `gossip.spread`.
///
/// # Params
///
/// ```json
/// {
///   "topic": "tower",
///   "key": "capability.advertise:sporeGate:nestGate",
///   "payload": { "capabilities": ["content.get"] },
///   "origin_gate": "sporeGate",
///   "ttl": 5,
///   "version": 1723100000,
///   "created_at_epoch": 1723100000,
///   "expires_at_epoch": 1723100600
/// }
/// ```
///
/// # Response
///
/// ```json
/// {
///   "verdict": "allow",
///   "reason": "all checks passed",
///   "origin_gate": "sporeGate",
///   "checks": [
///     { "check": "topic_valid", "passed": true },
///     { "check": "quarantine", "passed": true }
///   ]
/// }
/// ```
pub(super) async fn dispatch_metadata_analyze(
    state: &Arc<RwLock<App>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let Some(params) = params else {
        return Response::error(id, jsonrpc::INVALID_PARAMS, "params required");
    };

    let entry: GossipEntryParams = match serde_json::from_value(params) {
        Ok(e) => e,
        Err(e) => {
            return Response::error(
                id,
                jsonrpc::INVALID_PARAMS,
                format!("invalid gossip entry: {e}"),
            );
        }
    };

    let sb = state.read().await;
    let verdict = gossip_analysis::analyze_gossip_entry(&entry, |origin| sb.is_quarantined(origin));
    drop(sb);

    match serde_json::to_value(&verdict) {
        Ok(v) => Response::success(id, v),
        Err(e) => Response::error(id, jsonrpc::INTERNAL_ERROR, e.to_string()),
    }
}

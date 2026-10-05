// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Fleet immune system dispatch handlers.
//!
//! Handles `fleet.observe`, `fleet.antibodies`, and `fleet.match` RPC methods.
//! Population-level fleet analysis runs through these endpoints:
//!
//! 1. `skunky-ingest` sends `fleet.observe` with a `FleetObservation`
//! 2. skunkBat's `FleetDetector` analyzes it, may generate an antibody
//! 3. `fleet.antibodies` returns all active antibodies for inspection
//! 4. `fleet.match` checks an observation against stored antibodies

use skunk_bat_core::observability::audit_log::{EventKind, EventSeverity, EventSource};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::App;
use super::dispatch::serialize;
use super::jsonrpc::{self, Response};

/// Handle `fleet.observe` — feed a population-level fleet observation.
///
/// Accepts a `FleetObservation` JSON payload. If a fleet pattern is detected,
/// returns the generated antibody. Otherwise returns `{"detected": false}`.
pub(super) async fn dispatch_fleet_observe(
    state: &Arc<RwLock<App>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let Some(params) = params else {
        return Response::error(id, jsonrpc::INVALID_PARAMS, "params required");
    };

    let observation: skunk_bat_core::fleet_types::FleetObservation =
        match serde_json::from_value(params) {
            Ok(o) => o,
            Err(e) => {
                return Response::error(
                    id,
                    jsonrpc::INVALID_PARAMS,
                    format!("invalid fleet observation: {e}"),
                );
            }
        };

    let total = observation.total_requests;
    let ips = observation.unique_ips;
    let sb = state.read().await;

    match sb.fleet_observe(observation) {
        Some(antibody) => {
            sb.audit_log()
                .record(
                    EventSource::ThreatDetection,
                    EventSeverity::Warn,
                    EventKind::ThreatDetected {
                        threat_id: antibody.id.clone(),
                        threat_type: "StealthFleet".to_owned(),
                        severity: "High".to_owned(),
                        source: format!("population({ips} IPs, {total} reqs)"),
                    },
                )
                .await;

            tracing::warn!(
                id = %antibody.id,
                confidence = antibody.confidence,
                ua_count = antibody.ua_fingerprint.ua_count,
                "fleet detected — antibody generated"
            );

            drop(sb);
            serialize(
                id,
                serde_json::json!({
                    "detected": true,
                    "antibody": antibody,
                }),
            )
        }
        None => {
            drop(sb);
            Response::success(
                id,
                serde_json::json!({
                    "detected": false,
                    "requests": total,
                    "ips": ips,
                }),
            )
        }
    }
}

/// Handle `fleet.antibodies` — return all active antibodies.
pub(super) async fn dispatch_fleet_antibodies(
    state: &Arc<RwLock<App>>,
    id: serde_json::Value,
) -> Response {
    let sb = state.read().await;
    let antibodies = sb.fleet_antibodies();
    drop(sb);

    serialize(
        id,
        serde_json::json!({
            "count": antibodies.len(),
            "antibodies": antibodies,
        }),
    )
}

/// Handle `fleet.match` — check an observation against stored antibodies.
pub(super) async fn dispatch_fleet_match(
    state: &Arc<RwLock<App>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let Some(params) = params else {
        return Response::error(id, jsonrpc::INVALID_PARAMS, "params required");
    };

    let observation: skunk_bat_core::fleet_types::FleetObservation =
        match serde_json::from_value(params) {
            Ok(o) => o,
            Err(e) => {
                return Response::error(
                    id,
                    jsonrpc::INVALID_PARAMS,
                    format!("invalid fleet observation: {e}"),
                );
            }
        };

    let sb = state.read().await;
    let matched = sb.fleet_match(&observation);
    drop(sb);

    serialize(
        id,
        serde_json::json!({
            "matched": !matched.is_empty(),
            "antibody_ids": matched,
        }),
    )
}

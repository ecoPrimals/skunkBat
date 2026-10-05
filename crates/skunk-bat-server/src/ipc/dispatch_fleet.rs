// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Fleet immune system dispatch handlers.
//!
//! Handles `fleet.observe`, `fleet.antibodies`, `fleet.match`,
//! `fleet.posture`, and `fleet.tick` RPC methods.
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

/// Handle `fleet.posture` — get the defense posture for a specific antibody.
///
/// Params: `{"antibody_id": "fleet-xxx"}`.
/// Returns `{"antibody_id": "...", "posture": "warn_route", "level": 1}`.
pub(super) async fn dispatch_fleet_posture(
    state: &Arc<RwLock<App>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let Some(params) = params else {
        return Response::error(id, jsonrpc::INVALID_PARAMS, "params required");
    };

    let antibody_id = match params.get("antibody_id").and_then(|v| v.as_str()) {
        Some(aid) => aid.to_owned(),
        None => {
            return Response::error(
                id,
                jsonrpc::INVALID_PARAMS,
                "antibody_id string required",
            );
        }
    };

    let sb = state.read().await;
    match sb.fleet_posture(&antibody_id) {
        Some(posture) => {
            drop(sb);
            serialize(
                id,
                serde_json::json!({
                    "antibody_id": antibody_id,
                    "posture": posture,
                    "level": posture.level(),
                }),
            )
        }
        None => {
            drop(sb);
            Response::error(
                id,
                jsonrpc::INVALID_PARAMS,
                format!("antibody not found: {antibody_id}"),
            )
        }
    }
}

/// Handle `fleet.tick` — advance the escalation engine.
///
/// Params: `{"matched_ids": ["fleet-xxx", ...]}`.
/// Returns `{"events": [...], "count": N}` with posture change events.
///
/// This is the tit-for-tat heartbeat. Call it once per observation window:
/// - Pass antibody IDs that matched in this window → defection → escalate
/// - Antibodies NOT in the list → silence → de-escalate after forgive window
pub(super) async fn dispatch_fleet_tick(
    state: &Arc<RwLock<App>>,
    id: serde_json::Value,
    params: Option<serde_json::Value>,
) -> Response {
    let matched_ids: Vec<String> = params
        .as_ref()
        .and_then(|p| p.get("matched_ids"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let sb = state.read().await;
    let events = sb.fleet_tick(&matched_ids);

    for event in &events {
        sb.audit_log()
            .record(
                EventSource::ThreatDetection,
                EventSeverity::Warn,
                EventKind::ThreatDetected {
                    threat_id: event.antibody_id.clone(),
                    threat_type: format!(
                        "PostureChange({} → {})",
                        event.from, event.to
                    ),
                    severity: if event.to.level() >= 3 {
                        "Critical"
                    } else {
                        "High"
                    }
                    .to_owned(),
                    source: format!(
                        "escalation({}, defections={})",
                        event.reason, event.defection_count
                    ),
                },
            )
            .await;

        tracing::warn!(
            antibody = %event.antibody_id,
            from = %event.from,
            to = %event.to,
            reason = %event.reason,
            defections = event.defection_count,
            "posture change"
        );
    }

    drop(sb);

    serialize(
        id,
        serde_json::json!({
            "events": events,
            "count": events.len(),
        }),
    )
}

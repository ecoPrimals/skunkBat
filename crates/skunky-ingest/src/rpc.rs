// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! JSON-RPC 2.0 client for skunkBat over TCP.
//!
//! Uses riboCipher signal-first accept (`0xEC 0x01`) followed by
//! newline-delimited JSON. Each request gets a monotonic `id`.

#![allow(missing_docs)]

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use cellmembrane_types::fleet::{DefensePosture, FleetObservation};

use crate::aggregator::ObservationPayload;
use crate::error::IngestError;
use crate::ribocipher_const::CLEAR_JSONRPC;

/// Escalation event received from skunkBat's `fleet.tick` RPC.
///
/// Mirrors `skunk_bat_core::defense::antibodies::EscalationEvent` but
/// defined locally so skunky-ingest doesn't depend on skunk-bat-core.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EscalationEvent {
    pub antibody_id: String,
    pub from: DefensePosture,
    pub to: DefensePosture,
    pub reason: String,
    pub defection_count: u32,
}

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Serialize)]
struct RpcRequest<'a, P: Serialize> {
    jsonrpc: &'static str,
    method: &'static str,
    params: &'a P,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON-RPC error {}: {}", self.code, self.message)
    }
}

/// Persistent connection to skunkBat.
pub struct RpcClient {
    addr: String,
    stream: Option<BufReader<TcpStream>>,
}

impl RpcClient {
    pub const fn new(addr: String) -> Self {
        Self { addr, stream: None }
    }

    /// Send a `baseline.observe` call with the given observation.
    ///
    /// Reconnects automatically if the connection was lost.
    pub async fn observe(&mut self, obs: &ObservationPayload) -> Result<(), IngestError> {
        self.call("baseline.observe", obs).await?;
        Ok(())
    }

    /// Send a `fleet.observe` call with a population-level fleet observation.
    ///
    /// Reconnects automatically if the connection was lost.
    pub async fn fleet_observe(&mut self, obs: &FleetObservation) -> Result<(), IngestError> {
        self.call("fleet.observe", obs).await?;
        Ok(())
    }

    /// Send `fleet.match` — check observation against stored antibodies.
    ///
    /// Returns the list of matching antibody IDs.
    pub async fn fleet_match(&mut self, obs: &FleetObservation) -> Result<Vec<String>, IngestError> {
        let val = self.call("fleet.match", obs).await?;
        let ids: Vec<String> = val
            .get("antibody_ids")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        Ok(ids)
    }

    /// Send `fleet.tick` — advance the escalation engine.
    ///
    /// Pass antibody IDs that matched in this window → defection → escalate.
    /// Returns posture-change events for audit + Caddy bridge updates.
    pub async fn fleet_tick(
        &mut self,
        matched_ids: &[String],
    ) -> Result<Vec<EscalationEvent>, IngestError> {
        let params = serde_json::json!({ "matched_ids": matched_ids });
        let val = self.call("fleet.tick", &params).await?;
        let events: Vec<EscalationEvent> = val
            .get("events")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        Ok(events)
    }

    /// Raw JSON-RPC call with arbitrary method and params.
    ///
    /// Used for gossip injection and other dynamic method calls.
    pub async fn call_raw(
        &mut self,
        method: &'static str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, IngestError> {
        self.call(method, params).await
    }

    /// Generic JSON-RPC 2.0 call. Returns the `result` value on success.
    async fn call<P: Serialize>(
        &mut self,
        method: &'static str,
        params: &P,
    ) -> Result<serde_json::Value, IngestError> {
        let req = RpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id: REQUEST_ID.fetch_add(1, Ordering::Relaxed),
        };

        let mut line = serde_json::to_string(&req)?;
        line.push('\n');

        self.ensure_connected().await?;

        let Some(stream) = self.stream.as_mut() else {
            return Err(IngestError::Rpc("connection not established".to_string()));
        };

        if let Err(e) = stream.get_mut().write_all(line.as_bytes()).await {
            self.stream = None;
            return Err(IngestError::Io(e));
        }

        let Some(stream) = self.stream.as_mut() else {
            return Err(IngestError::Rpc("connection lost after write".to_string()));
        };
        let mut resp_line = String::new();
        if let Err(e) = stream.read_line(&mut resp_line).await {
            self.stream = None;
            return Err(IngestError::Io(e));
        }

        if resp_line.is_empty() {
            self.stream = None;
            return Err(IngestError::Rpc("connection closed by server".to_string()));
        }

        let resp: RpcResponse = serde_json::from_str(&resp_line)?;

        if let Some(err) = resp.error {
            return Err(IngestError::RpcServer {
                code: err.code,
                message: err.message,
            });
        }

        if let Some(result) = resp.result {
            Ok(result)
        } else {
            Err(IngestError::Rpc(
                "response missing both result and error".to_string(),
            ))
        }
    }

    async fn ensure_connected(&mut self) -> Result<(), IngestError> {
        if self.stream.is_none() {
            let tcp = TcpStream::connect(&self.addr).await?;

            let mut buf = BufReader::new(tcp);
            buf.get_mut().write_all(&CLEAR_JSONRPC).await?;

            self.stream = Some(buf);
            tracing::info!(addr = %self.addr, "connected to skunkBat");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::{HttpPayload, TimestampPayload};

    #[test]
    fn request_serializes_correctly() {
        let obs = ObservationPayload {
            visitor_class: "human".to_string(),
            connection_rate: 1.5,
            traffic_volume: 4096,
            ports_accessed: vec![443],
            timestamp: TimestampPayload {
                secs_since_epoch: 1_720_000_000,
                nanos_since_epoch: 0,
            },
            http: HttpPayload {
                request_rate: 1.5,
                error_rate_4xx: 0.1,
                error_rate_5xx: 0.0,
                path_diversity: 3,
                avg_payload_bytes: 512,
                method_diversity: 2,
            },
        };

        let req = RpcRequest {
            jsonrpc: "2.0",
            method: "baseline.observe",
            params: &obs,
            id: 1,
        };

        let json = serde_json::to_string(&req).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("reparse");

        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["method"], "baseline.observe");
        assert_eq!(parsed["params"]["connection_rate"], 1.5);
        assert_eq!(parsed["params"]["http"]["path_diversity"], 3);
        assert_eq!(
            parsed["params"]["timestamp"]["secs_since_epoch"],
            1_720_000_000
        );
    }
}

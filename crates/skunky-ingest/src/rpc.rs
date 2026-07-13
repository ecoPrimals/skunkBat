//! JSON-RPC 2.0 client for skunkBat over TCP.
//!
//! Uses riboCipher signal-first accept (`0xEC 0x01`) followed by
//! newline-delimited JSON. Each request gets a monotonic `id`.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::aggregator::ObservationPayload;
use crate::error::IngestError;

/// riboCipher signal bytes: NDJSON JSON-RPC.
const RIBOCIPHER_NDJSON: [u8; 2] = [0xEC, 0x01];

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'static str,
    params: &'a ObservationPayload,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
    #[allow(dead_code)]
    id: Option<serde_json::Value>,
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
        let req = RpcRequest {
            jsonrpc: "2.0",
            method: "baseline.observe",
            params: obs,
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

        if resp.result.is_some() {
            Ok(())
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
            buf.get_mut().write_all(&RIBOCIPHER_NDJSON).await?;

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

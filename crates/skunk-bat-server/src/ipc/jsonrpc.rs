// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! JSON-RPC 2.0 message types.
//!
//! Supports single requests, batch requests (JSON arrays), and
//! notifications (requests without an `id` field per spec §4.1).

use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Request {
    /// Protocol version — always `"2.0"`.
    pub jsonrpc: String,
    /// Method name in `domain.verb` format.
    pub method: String,
    /// Optional parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    /// Request identifier — `None` for notifications.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Response {
    /// Protocol version — always `"2.0"`.
    pub jsonrpc: String,
    /// Result on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    /// Request identifier (echoed back).
    pub id: serde_json::Value,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RpcError {
    /// Numeric error code.
    pub code: i32,
    /// Human-readable message.
    pub message: String,
    /// Optional structured data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

const JSONRPC_VERSION: &str = "2.0";

// Standard JSON-RPC 2.0 error codes.
pub(super) const PARSE_ERROR: i32 = -32700;
pub(super) const INVALID_REQUEST: i32 = -32600;
pub(super) const METHOD_NOT_FOUND: i32 = -32601;
pub(super) const INVALID_PARAMS: i32 = -32602;
pub(super) const INTERNAL_ERROR: i32 = -32603;

impl Response {
    /// Build a success response.
    pub(super) fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Build an error response.
    pub(super) fn error(id: serde_json::Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }
}

impl Request {
    /// Validate that the request has the correct `jsonrpc` field.
    #[expect(
        clippy::result_large_err,
        reason = "Response is the natural error for validation"
    )]
    pub(super) fn validate(&self) -> Result<(), Response> {
        let id = self.id.clone().unwrap_or(serde_json::Value::Null);
        if self.jsonrpc != JSONRPC_VERSION {
            return Err(Response::error(
                id,
                INVALID_REQUEST,
                "jsonrpc field must be \"2.0\"",
            ));
        }
        Ok(())
    }

    /// Whether this is a notification (no `id` field per JSON-RPC 2.0 §4.1).
    pub(super) const fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// Extract the id, falling back to `Null` for notifications.
    pub(super) fn id_or_null(&self) -> serde_json::Value {
        self.id.clone().unwrap_or(serde_json::Value::Null)
    }
}

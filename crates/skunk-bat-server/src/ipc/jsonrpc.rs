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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_serde_roundtrip() {
        let req = Request {
            jsonrpc: "2.0".to_owned(),
            method: "security.scan".to_owned(),
            params: Some(json!({"scope": "local"})),
            id: Some(json!(1)),
        };
        let json_str = serde_json::to_string(&req).unwrap();
        let parsed: Request = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.method, "security.scan");
        assert_eq!(parsed.id, Some(json!(1)));
    }

    #[test]
    fn request_notification_no_id() {
        let req = Request {
            jsonrpc: "2.0".to_owned(),
            method: "event.alert".to_owned(),
            params: None,
            id: None,
        };
        assert!(req.is_notification());
        assert_eq!(req.id_or_null(), serde_json::Value::Null);
    }

    #[test]
    fn request_validate_correct_version() {
        let req = Request {
            jsonrpc: "2.0".to_owned(),
            method: "test".to_owned(),
            params: None,
            id: Some(json!(1)),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn request_validate_wrong_version() {
        let req = Request {
            jsonrpc: "1.0".to_owned(),
            method: "test".to_owned(),
            params: None,
            id: Some(json!(1)),
        };
        let err = req.validate().unwrap_err();
        assert!(err.error.is_some());
        assert_eq!(err.error.unwrap().code, INVALID_REQUEST);
    }

    #[test]
    fn response_success_construction() {
        let resp = Response::success(json!(42), json!({"status": "ok"}));
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, json!(42));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn response_error_construction() {
        let resp = Response::error(json!(1), METHOD_NOT_FOUND, "not found");
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, METHOD_NOT_FOUND);
        assert_eq!(err.message, "not found");
    }

    #[test]
    fn response_serde_roundtrip_success() {
        let resp = Response::success(json!(7), json!([1, 2, 3]));
        let json_str = serde_json::to_string(&resp).unwrap();
        let parsed: Response = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.id, json!(7));
        assert!(parsed.error.is_none());
    }

    #[test]
    fn response_serde_roundtrip_error() {
        let resp = Response::error(json!("abc"), PARSE_ERROR, "invalid json");
        let json_str = serde_json::to_string(&resp).unwrap();
        let parsed: Response = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.result.is_none());
        assert_eq!(parsed.error.as_ref().unwrap().code, PARSE_ERROR);
    }

    #[test]
    fn notification_skips_id_in_serialization() {
        let req = Request {
            jsonrpc: "2.0".to_owned(),
            method: "event.notify".to_owned(),
            params: None,
            id: None,
        };
        let json_str = serde_json::to_string(&req).unwrap();
        assert!(!json_str.contains("\"id\""));
    }

    #[test]
    fn error_codes_are_standard() {
        assert_eq!(PARSE_ERROR, -32700);
        assert_eq!(INVALID_REQUEST, -32600);
        assert_eq!(METHOD_NOT_FOUND, -32601);
        assert_eq!(INVALID_PARAMS, -32602);
        assert_eq!(INTERNAL_ERROR, -32603);
    }
}

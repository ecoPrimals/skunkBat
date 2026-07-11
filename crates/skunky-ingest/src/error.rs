//! skunky-ingest error types.

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("rpc: {0}")]
    Rpc(String),

    #[error("rpc server: code={code}, message={message}")]
    RpcServer { code: i64, message: String },
}

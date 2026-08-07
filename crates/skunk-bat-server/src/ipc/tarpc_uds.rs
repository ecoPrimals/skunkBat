// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! tarpc binary UDS server (G64 C2 dual-socket pattern).
//!
//! Serves the tarpc binary protocol over a Unix domain socket at
//! `skunkbat.tarpc.sock` alongside the JSON-RPC socket at `skunkbat.sock`.
//! Eliminates serde/JSON overhead for intra-gate primal-to-primal composition.

use super::App;
use futures_util::StreamExt;
use skunk_bat_core::tarpc_service::{
    SkunkBatRpc, TarpcCapability, TarpcDefenseStatus, TarpcHealthResponse, TarpcIdentityResponse,
    TarpcSecurityMetrics, TarpcThreat,
};
use std::sync::Arc;
use tarpc::server::Channel;
use tarpc::tokio_serde::formats::Bincode;
use tokio::sync::RwLock;
use tracing::warn;

#[cfg(unix)]
use {
    std::path::{Path, PathBuf},
    std::sync::atomic::{AtomicBool, Ordering},
    tarpc::server,
    tokio::sync::watch,
    tracing::{debug, info},
};

const PRIMAL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Handler that bridges tarpc calls to the shared `SkunkBat` instance.
#[derive(Clone)]
struct SkunkBatRpcHandler {
    state: Arc<RwLock<App>>,
}

impl SkunkBatRpc for SkunkBatRpcHandler {
    async fn health_liveness(self, _: tarpc::context::Context) -> bool {
        true
    }

    async fn health_readiness(self, _: tarpc::context::Context) -> bool {
        self.state.read().await.state().is_running()
    }

    async fn health_check(self, _: tarpc::context::Context) -> TarpcHealthResponse {
        let sb = self.state.read().await;
        let running = sb.state().is_running();
        TarpcHealthResponse {
            alive: true,
            ready: running,
            primal: skunk_bat_core::PRIMAL_ID.to_owned(),
            version: PRIMAL_VERSION.to_owned(),
            state: sb.state().to_string(),
        }
    }

    async fn capabilities_list(self, _: tarpc::context::Context) -> Vec<TarpcCapability> {
        vec![
            TarpcCapability {
                domain: "security".to_owned(),
                methods: vec![
                    "scan".to_owned(),
                    "detect".to_owned(),
                    "respond".to_owned(),
                    "metrics".to_owned(),
                    "audit_log".to_owned(),
                    "advisory".to_owned(),
                ],
            },
            TarpcCapability {
                domain: "health".to_owned(),
                methods: vec![
                    "liveness".to_owned(),
                    "readiness".to_owned(),
                    "check".to_owned(),
                ],
            },
            TarpcCapability {
                domain: "defense".to_owned(),
                methods: vec![
                    "status".to_owned(),
                    "quarantine".to_owned(),
                    "release".to_owned(),
                ],
            },
            TarpcCapability {
                domain: "baseline".to_owned(),
                methods: vec![
                    "observe".to_owned(),
                    "query".to_owned(),
                    "anomaly".to_owned(),
                    "reset".to_owned(),
                ],
            },
            TarpcCapability {
                domain: "lifecycle".to_owned(),
                methods: vec![
                    "state".to_owned(),
                    "status".to_owned(),
                    "capabilities".to_owned(),
                ],
            },
        ]
    }

    async fn identity_get(self, _: tarpc::context::Context) -> TarpcIdentityResponse {
        TarpcIdentityResponse {
            primal: skunk_bat_core::PRIMAL_ID.to_owned(),
            version: PRIMAL_VERSION.to_owned(),
            domain: "security".to_owned(),
            license: "AGPL-3.0-or-later".to_owned(),
            protocols: vec!["jsonrpc-2.0".to_owned(), "tarpc".to_owned()],
        }
    }

    async fn system_ping(self, _: tarpc::context::Context) -> String {
        "pong".to_owned()
    }

    async fn system_version(self, _: tarpc::context::Context) -> String {
        PRIMAL_VERSION.to_owned()
    }

    async fn lifecycle_state(self, _: tarpc::context::Context) -> String {
        self.state.read().await.state().to_string()
    }

    async fn security_detect(self, _: tarpc::context::Context) -> Vec<TarpcThreat> {
        match self.state.read().await.detect_threats().await {
            Ok(threats) => threats
                .into_iter()
                .map(|t| TarpcThreat {
                    id: t.id,
                    category: format!("{:?}", t.threat_type),
                    severity: t.confidence,
                    description: t.description,
                })
                .collect(),
            Err(e) => {
                warn!("tarpc security_detect error: {e}");
                Vec::new()
            }
        }
    }

    async fn security_metrics(self, _: tarpc::context::Context) -> TarpcSecurityMetrics {
        let metrics = self.state.read().await.get_security_metrics();
        TarpcSecurityMetrics {
            threats_detected: metrics.threats_detected(),
            threats_mitigated: metrics.threats_mitigated(),
            scans_performed: metrics.scans_performed(),
            quarantined_count: usize::try_from(metrics.connections_quarantined()).unwrap_or(0),
            alerts_fired: metrics.alerts_sent(),
        }
    }

    async fn defense_status(self, _: tarpc::context::Context) -> TarpcDefenseStatus {
        let status = self.state.read().await.defense_status();
        TarpcDefenseStatus {
            enabled: status
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            auto_response: status
                .get("auto_response")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            quarantined_count: status
                .get("quarantined_count")
                .and_then(serde_json::Value::as_u64)
                .map_or(0, |v| usize::try_from(v).unwrap_or(0)),
        }
    }
}

/// tarpc binary UDS server lifecycle (C2 dual-socket — Unix only).
///
/// On non-Unix platforms, G65 protocol negotiation on `TransportStream`
/// via [`serve_tarpc_stream`] is the tarpc entry point instead.
#[cfg(unix)]
pub struct TarpcUdsServer {
    state: Arc<RwLock<App>>,
    socket_path: PathBuf,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    is_running: Arc<AtomicBool>,
    ready_notify: Arc<tokio::sync::Notify>,
}

#[cfg(unix)]
#[expect(
    dead_code,
    reason = "lifecycle API — used in tests; production wiring uses serve() + shutdown_sender()"
)]
impl TarpcUdsServer {
    /// Create a new tarpc UDS server for the given `SkunkBat` state.
    #[must_use]
    pub fn new(state: Arc<RwLock<App>>, socket_path: PathBuf) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            state,
            socket_path,
            shutdown_tx,
            shutdown_rx,
            is_running: Arc::new(AtomicBool::new(false)),
            ready_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Start serving tarpc over the Unix socket.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if socket preparation or binding fails.
    pub async fn serve(self) -> Result<(), std::io::Error> {
        self.prepare_socket_path()?;

        let listener =
            tarpc::serde_transport::unix::listen(&self.socket_path, Bincode::default).await?;
        info!(path = %self.socket_path.display(), "tarpc binary UDS listening (C2 dual-socket)");

        self.is_running.store(true, Ordering::SeqCst);
        self.ready_notify.notify_one();
        let is_running = Arc::clone(&self.is_running);
        let mut shutdown_rx = self.shutdown_rx.clone();

        let handler = SkunkBatRpcHandler {
            state: Arc::clone(&self.state),
        };
        let incoming = listener.filter_map(|r| async { r.ok() });

        tokio::select! {
            () = incoming.for_each(|transport| {
                let handler = handler.clone();
                async move {
                    let fut = server::BaseChannel::with_defaults(transport)
                        .execute(handler.serve())
                        .for_each(|response| async move {
                            response.await;
                        });
                    tokio::spawn(fut);
                }
            }) => {}
            Ok(()) = shutdown_rx.changed() => {
                info!("tarpc UDS server shutting down gracefully");
            }
        }

        is_running.store(false, Ordering::SeqCst);
        self.cleanup();
        info!("tarpc UDS server stopped");

        Ok(())
    }

    /// Signal the server to shut down.
    pub fn shutdown(&self) {
        if self.shutdown_tx.send(true).is_err() {
            warn!("tarpc UDS shutdown channel already closed");
        }
    }

    /// Get a clone of the shutdown sender for external signal handling.
    #[must_use]
    pub fn shutdown_sender(&self) -> watch::Sender<bool> {
        self.shutdown_tx.clone()
    }

    /// Check if the server is currently running.
    #[inline]
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// Wait until the server has bound and is accepting connections.
    pub async fn wait_ready(&self) {
        if self.is_running() {
            return;
        }
        self.ready_notify.notified().await;
    }

    /// Get a cloneable readiness notifier.
    #[must_use]
    pub fn ready_notifier(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.ready_notify)
    }

    /// Get the socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    fn prepare_socket_path(&self) -> Result<(), std::io::Error> {
        if let Some(parent) = self.socket_path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
        }
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }
        Ok(())
    }

    fn cleanup(&self) {
        if self.socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.socket_path) {
                warn!(path = %self.socket_path.display(), error = %e, "failed to clean up tarpc UDS socket");
            } else {
                debug!(path = %self.socket_path.display(), "cleaned up tarpc UDS socket");
            }
        }
    }
}

/// Serve tarpc on a pre-connected stream (G65 negotiated or direct).
///
/// Used by the G65 protocol negotiation path: after the handshake selects tarpc,
/// this function wraps the stream in bincode framing and serves the `SkunkBatRpc`
/// trait on it until the client disconnects.
pub async fn serve_tarpc_stream<S>(state: Arc<RwLock<App>>, stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    let handler = SkunkBatRpcHandler {
        state: Arc::clone(&state),
    };

    let transport = tarpc::serde_transport::new(
        tokio_util::codec::length_delimited::Builder::new()
            .max_frame_length(usize::MAX)
            .new_framed(stream),
        Bincode::default(),
    );

    tarpc::server::BaseChannel::with_defaults(transport)
        .execute(handler.serve())
        .for_each(|response| async move {
            response.await;
        })
        .await;
}

#[cfg(all(test, unix))]
#[path = "tarpc_uds_tests.rs"]
mod tests;

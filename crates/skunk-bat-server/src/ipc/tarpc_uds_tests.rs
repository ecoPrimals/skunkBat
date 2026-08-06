// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Tests for the tarpc binary UDS server (C2 dual-socket pattern).

#![expect(clippy::unwrap_used, reason = "test code")]

use super::*;
use skunk_bat_core::tarpc_service::SkunkBatRpcClient;
use skunk_bat_core::{PrimalLifecycle, SkunkBatConfig};
use skunk_bat_integrations::verifier::RuntimeVerifier;
use std::sync::Arc;
use tarpc::tokio_serde::formats::Bincode;
use tokio::sync::RwLock;

async fn test_state() -> Arc<RwLock<App>> {
    let config = SkunkBatConfig::default();
    let verifier = RuntimeVerifier::from_env();
    let mut sb = skunk_bat_core::SkunkBat::with_verifier(config, verifier);
    sb.start().await.unwrap();
    Arc::new(RwLock::new(sb))
}

#[tokio::test]
async fn tarpc_uds_health_liveness() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.tarpc.sock");
    let state = test_state().await;

    let server = TarpcUdsServer::new(Arc::clone(&state), sock.clone());
    let ready = server.ready_notifier();
    let shutdown = server.shutdown_sender();
    let handle = tokio::spawn(async move { server.serve().await });

    ready.notified().await;

    let transport = tarpc::serde_transport::unix::connect(&sock, Bincode::default)
        .await
        .unwrap();
    let client = SkunkBatRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    assert!(
        client
            .health_liveness(tarpc::context::current())
            .await
            .unwrap()
    );

    let _ = shutdown.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn tarpc_uds_health_check() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("health.tarpc.sock");
    let state = test_state().await;

    let server = TarpcUdsServer::new(Arc::clone(&state), sock.clone());
    let ready = server.ready_notifier();
    let shutdown = server.shutdown_sender();
    let handle = tokio::spawn(async move { server.serve().await });

    ready.notified().await;

    let transport = tarpc::serde_transport::unix::connect(&sock, Bincode::default)
        .await
        .unwrap();
    let client = SkunkBatRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let health = client
        .health_check(tarpc::context::current())
        .await
        .unwrap();
    assert!(health.alive);
    assert!(health.ready);
    assert_eq!(health.primal, "skunkbat");
    assert_eq!(health.state, "running");

    let _ = shutdown.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn tarpc_uds_identity() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("identity.tarpc.sock");
    let state = test_state().await;

    let server = TarpcUdsServer::new(Arc::clone(&state), sock.clone());
    let ready = server.ready_notifier();
    let shutdown = server.shutdown_sender();
    let handle = tokio::spawn(async move { server.serve().await });

    ready.notified().await;

    let transport = tarpc::serde_transport::unix::connect(&sock, Bincode::default)
        .await
        .unwrap();
    let client = SkunkBatRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let id = client
        .identity_get(tarpc::context::current())
        .await
        .unwrap();
    assert_eq!(id.primal, "skunkbat");
    assert_eq!(id.domain, "security");
    assert_eq!(id.license, "AGPL-3.0-or-later");
    assert!(id.protocols.contains(&"tarpc".to_owned()));
    assert!(id.protocols.contains(&"jsonrpc-2.0".to_owned()));

    let _ = shutdown.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn tarpc_uds_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("caps.tarpc.sock");
    let state = test_state().await;

    let server = TarpcUdsServer::new(Arc::clone(&state), sock.clone());
    let ready = server.ready_notifier();
    let shutdown = server.shutdown_sender();
    let handle = tokio::spawn(async move { server.serve().await });

    ready.notified().await;

    let transport = tarpc::serde_transport::unix::connect(&sock, Bincode::default)
        .await
        .unwrap();
    let client = SkunkBatRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let caps = client
        .capabilities_list(tarpc::context::current())
        .await
        .unwrap();
    let domains: Vec<&str> = caps.iter().map(|c| c.domain.as_str()).collect();
    assert!(domains.contains(&"security"));
    assert!(domains.contains(&"health"));
    assert!(domains.contains(&"defense"));
    assert!(domains.contains(&"baseline"));
    assert!(domains.contains(&"lifecycle"));

    let _ = shutdown.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn tarpc_uds_ping_and_version() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("ping.tarpc.sock");
    let state = test_state().await;

    let server = TarpcUdsServer::new(Arc::clone(&state), sock.clone());
    let ready = server.ready_notifier();
    let shutdown = server.shutdown_sender();
    let handle = tokio::spawn(async move { server.serve().await });

    ready.notified().await;

    let transport = tarpc::serde_transport::unix::connect(&sock, Bincode::default)
        .await
        .unwrap();
    let client = SkunkBatRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    assert_eq!(
        client.system_ping(tarpc::context::current()).await.unwrap(),
        "pong"
    );

    let version = client
        .system_version(tarpc::context::current())
        .await
        .unwrap();
    assert!(!version.is_empty());

    let _ = shutdown.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn tarpc_uds_lifecycle_state() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("lifecycle.tarpc.sock");
    let state = test_state().await;

    let server = TarpcUdsServer::new(Arc::clone(&state), sock.clone());
    let ready = server.ready_notifier();
    let shutdown = server.shutdown_sender();
    let handle = tokio::spawn(async move { server.serve().await });

    ready.notified().await;

    let transport = tarpc::serde_transport::unix::connect(&sock, Bincode::default)
        .await
        .unwrap();
    let client = SkunkBatRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let state_str = client
        .lifecycle_state(tarpc::context::current())
        .await
        .unwrap();
    assert_eq!(state_str, "running");

    let _ = shutdown.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn tarpc_uds_security_metrics() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("metrics.tarpc.sock");
    let state = test_state().await;

    let server = TarpcUdsServer::new(Arc::clone(&state), sock.clone());
    let ready = server.ready_notifier();
    let shutdown = server.shutdown_sender();
    let handle = tokio::spawn(async move { server.serve().await });

    ready.notified().await;

    let transport = tarpc::serde_transport::unix::connect(&sock, Bincode::default)
        .await
        .unwrap();
    let client = SkunkBatRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let metrics = client
        .security_metrics(tarpc::context::current())
        .await
        .unwrap();
    assert_eq!(metrics.threats_detected, 0);
    assert_eq!(metrics.quarantined_count, 0);

    let _ = shutdown.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn tarpc_uds_defense_status() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("defense.tarpc.sock");
    let state = test_state().await;

    let server = TarpcUdsServer::new(Arc::clone(&state), sock.clone());
    let ready = server.ready_notifier();
    let shutdown = server.shutdown_sender();
    let handle = tokio::spawn(async move { server.serve().await });

    ready.notified().await;

    let transport = tarpc::serde_transport::unix::connect(&sock, Bincode::default)
        .await
        .unwrap();
    let client = SkunkBatRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let defense = client
        .defense_status(tarpc::context::current())
        .await
        .unwrap();
    assert_eq!(defense.quarantined_count, 0);

    let _ = shutdown.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn tarpc_uds_security_detect() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("detect.tarpc.sock");
    let state = test_state().await;

    let server = TarpcUdsServer::new(Arc::clone(&state), sock.clone());
    let ready = server.ready_notifier();
    let shutdown = server.shutdown_sender();
    let handle = tokio::spawn(async move { server.serve().await });

    ready.notified().await;

    let transport = tarpc::serde_transport::unix::connect(&sock, Bincode::default)
        .await
        .unwrap();
    let client = SkunkBatRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let threats = client
        .security_detect(tarpc::context::current())
        .await
        .unwrap();
    // Fresh instance should have no threats
    assert!(threats.is_empty());

    let _ = shutdown.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn tarpc_uds_multiple_clients() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("multi.tarpc.sock");
    let state = test_state().await;

    let server = TarpcUdsServer::new(Arc::clone(&state), sock.clone());
    let ready = server.ready_notifier();
    let shutdown = server.shutdown_sender();
    let handle = tokio::spawn(async move { server.serve().await });

    ready.notified().await;

    // Two concurrent clients
    let t1 = tarpc::serde_transport::unix::connect(&sock, Bincode::default)
        .await
        .unwrap();
    let c1 = SkunkBatRpcClient::new(tarpc::client::Config::default(), t1).spawn();

    let t2 = tarpc::serde_transport::unix::connect(&sock, Bincode::default)
        .await
        .unwrap();
    let c2 = SkunkBatRpcClient::new(tarpc::client::Config::default(), t2).spawn();

    let (r1, r2) = tokio::join!(
        c1.system_ping(tarpc::context::current()),
        c2.health_liveness(tarpc::context::current()),
    );
    assert_eq!(r1.unwrap(), "pong");
    assert!(r2.unwrap());

    let _ = shutdown.send(true);
    let _ = handle.await;
}

#[tokio::test]
async fn tarpc_uds_server_cleans_up_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("cleanup.tarpc.sock");
    let state = test_state().await;

    let server = TarpcUdsServer::new(Arc::clone(&state), sock.clone());
    let ready = server.ready_notifier();
    let shutdown = server.shutdown_sender();
    let handle = tokio::spawn(async move { server.serve().await });

    ready.notified().await;
    assert!(sock.exists());

    let _ = shutdown.send(true);
    let _ = handle.await;

    assert!(
        !sock.exists(),
        "socket file should be cleaned up after shutdown"
    );
}

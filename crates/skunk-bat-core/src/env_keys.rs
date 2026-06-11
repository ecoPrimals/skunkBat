// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Environment variable names used across the skunkBat ecosystem.
//!
//! Centralizes literal env var keys so production code reads them via named
//! constants instead of scattered string literals.

/// Directory for `BiomeOS` Unix domain sockets (production deployments).
pub const BIOMEOS_SOCKET_DIR: &str = "BIOMEOS_SOCKET_DIR";

/// XDG Base Directory runtime path (typically `/run/user/{uid}`).
pub const XDG_RUNTIME_DIR: &str = "XDG_RUNTIME_DIR";

/// Development mode flag (`1` disables production BTSP constraints).
pub const BIOMEOS_INSECURE: &str = "BIOMEOS_INSECURE";

/// Family identifier for BTSP socket naming and handshake scoping.
pub const FAMILY_ID: &str = "FAMILY_ID";

/// Family seed for BTSP key derivation and session creation.
pub const FAMILY_SEED: &str = "FAMILY_SEED";

/// Explicit path to the BTSP security provider UDS socket.
pub const BTSP_PROVIDER_SOCKET: &str = "BTSP_PROVIDER_SOCKET";

/// BTSP capability name for provider socket resolution.
pub const BTSP_PROVIDER: &str = "BTSP_PROVIDER";

/// Explicit override path for the biomeOS Neural API socket.
pub const NEURAL_API_SOCKET: &str = "NEURAL_API_SOCKET";

/// TCP endpoint override for capability-based discovery.
pub const DISCOVERY_ENDPOINT: &str = "DISCOVERY_ENDPOINT";

/// TCP endpoint override for federation broadcast.
pub const FEDERATION_ENDPOINT: &str = "FEDERATION_ENDPOINT";

/// TCP endpoint override for genetic lineage verification.
pub const LINEAGE_ENDPOINT: &str = "LINEAGE_ENDPOINT";

/// skunkBat instance identifier (defaults to [`crate::PRIMAL_ID`]).
pub const SKUNKBAT_ID: &str = "SKUNKBAT_ID";

/// skunkBat network listen/bind address.
pub const SKUNKBAT_ADDRESS: &str = "SKUNKBAT_ADDRESS";

/// skunkBat JSON-RPC TCP port.
pub const SKUNKBAT_PORT: &str = "SKUNKBAT_PORT";

/// skunkBat JSON-RPC TCP listen address.
pub const SKUNKBAT_LISTEN_ADDR: &str = "SKUNKBAT_LISTEN_ADDR";

/// Comma-separated list of networks owned by this deployment.
pub const SKUNKBAT_OWNED_NETWORKS: &str = "SKUNKBAT_OWNED_NETWORKS";

/// IPC method-gate enforcement mode (`enforced` / `permissive`).
pub const SKUNKBAT_AUTH_MODE: &str = "SKUNKBAT_AUTH_MODE";

/// Launcher-injected transport endpoint (JSON, sourDough-compatible).
///
/// Format: `{"transport":"uds","path":"/run/membrane/beardog.sock"}`
/// or `{"transport":"tcp","host":"127.0.0.1","port":9100}`.
/// When set, overrides per-capability endpoint env vars.
pub const TRANSPORT_ENDPOINT: &str = "TRANSPORT_ENDPOINT";

/// Primal bind mode — standard startup contract (Wave 109).
///
/// - Unset or `uds-only`: UDS only, no TCP (zero-port standard, default).
/// - `tcp-only` / `tcp_only`: TCP only, no UDS (Android/grapheneGate `SELinux`).
/// - `fallback`: UDS + TCP (debug/standalone/both-transport environments).
pub const PRIMAL_BIND_MODE: &str = "PRIMAL_BIND_MODE";

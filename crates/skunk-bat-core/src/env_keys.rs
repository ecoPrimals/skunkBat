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

// ── Integration transport vars (sourDough JSON convention) ───────────

/// `TransportEndpoint` JSON for lineage-verification capability.
pub const LINEAGE_TRANSPORT: &str = "LINEAGE_TRANSPORT";

/// `TransportEndpoint` JSON for federation capability.
pub const FEDERATION_TRANSPORT: &str = "FEDERATION_TRANSPORT";

/// `TransportEndpoint` JSON for discovery capability.
pub const DISCOVERY_TRANSPORT: &str = "DISCOVERY_TRANSPORT";

/// `TransportEndpoint` JSON for rhizoCrypt provenance forwarding.
pub const RHIZOCRYPT_TRANSPORT: &str = "RHIZOCRYPT_TRANSPORT";

/// `TransportEndpoint` JSON for sweetGrass attribution forwarding.
pub const SWEETGRASS_TRANSPORT: &str = "SWEETGRASS_TRANSPORT";

/// TCP endpoint override for rhizoCrypt provenance forwarding.
pub const RHIZOCRYPT_ENDPOINT: &str = "RHIZOCRYPT_ENDPOINT";

/// TCP endpoint override for sweetGrass attribution forwarding.
pub const SWEETGRASS_ENDPOINT: &str = "SWEETGRASS_ENDPOINT";

/// TCP endpoint override for `NestGate` content integrity.
pub const NESTGATE_ENDPOINT: &str = "NESTGATE_ENDPOINT";

/// Explicit path to the discovery service UDS socket.
pub const DISCOVERY_SOCKET: &str = "DISCOVERY_SOCKET";

/// Explicit path to the `SongBird` discovery/federation socket.
pub const SONGBIRD_SOCKET: &str = "SONGBIRD_SOCKET";

// ── Server Operational Tuning ──────────────────────────────────

/// Session TTL in seconds (default: 3600).
pub const SKUNKBAT_SESSION_TTL: &str = "SKUNKBAT_SESSION_TTL";

/// Session sweep interval in seconds (default: 300).
pub const SKUNKBAT_SESSION_SWEEP: &str = "SKUNKBAT_SESSION_SWEEP";

/// Audit forwarding poll interval in seconds (default: 10).
pub const SKUNKBAT_FORWARD_INTERVAL: &str = "SKUNKBAT_FORWARD_INTERVAL";

/// Audit forwarding RPC timeout in seconds (default: 5).
pub const SKUNKBAT_FORWARD_TIMEOUT: &str = "SKUNKBAT_FORWARD_TIMEOUT";

/// Minimum severity for audit forwarding: `info`, `warn`, `error` (default: `warn`).
pub const SKUNKBAT_FORWARD_MIN_SEVERITY: &str = "SKUNKBAT_FORWARD_MIN_SEVERITY";

/// Registration RPC timeout in seconds (default: 3).
pub const SKUNKBAT_REGISTRATION_TIMEOUT: &str = "SKUNKBAT_REGISTRATION_TIMEOUT";

// ── Config Hydration ──────────────────────────────────────────

/// Lineage ID for genetic verification (enables `BearDog` integration).
pub const SKUNKBAT_LINEAGE_ID: &str = "SKUNKBAT_LINEAGE_ID";

/// Expected topology path as comma-separated layer bytes (e.g. `1,2,3`).
pub const SKUNKBAT_TOPOLOGY_PATH: &str = "SKUNKBAT_TOPOLOGY_PATH";

/// Integration RPC timeout in milliseconds (default: 3000).
pub const SKUNKBAT_INTEGRATION_TIMEOUT_MS: &str = "SKUNKBAT_INTEGRATION_TIMEOUT_MS";

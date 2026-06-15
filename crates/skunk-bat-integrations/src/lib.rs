// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! # skunkBat Ecosystem Integrations
//!
//! Capability-based integration layer.  Each module connects to whatever
//! primal announces the relevant capability at runtime — no compile-time
//! coupling to specific primal names.
//!
//! | Module | Capability | Runtime Discovery | Server Wiring |
//! |--------|-----------|-------------------|---------------|
//! | [`beardog`] | `lineage-verification` | `LINEAGE_ENDPOINT` env | via [`verifier::RuntimeVerifier`] |
//! | [`songbird`] | `federation` | `FEDERATION_ENDPOINT` env | library-ready (server: future) |
//! | [`toadstool`] | `discovery` | `DISCOVERY_ENDPOINT` env | library-ready (server: future) |
//! | [`forwarding`] | `provenance` + `attribution` | `RHIZOCRYPT_ENDPOINT` / `SWEETGRASS_ENDPOINT` | **wired** in server |
//! | [`nestgate`] | `content` | `NESTGATE_ENDPOINT` env | library-ready (server: future) |
//!
//! ## Example
//!
//! ```rust,ignore
//! use skunk_bat_integrations::toadstool::{DiscoveryClient, CapabilityPrimalDiscovery};
//! use skunk_bat_core::reconnaissance::PrimalDiscovery;
//!
//! let client = DiscoveryClient::from_env();
//! let discovery = CapabilityPrimalDiscovery::new(client, "skunkbat-01".into());
//! let primals = discovery.discover_all().await?;
//! ```

pub mod beardog;
pub mod forwarding;
pub mod nestgate;
pub mod rpc;
pub mod songbird;
pub mod toadstool;
pub mod verifier;

pub use rpc::TransportEndpoint;

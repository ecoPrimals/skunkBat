// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! # skunkBat Ecosystem Integrations
//!
//! Capability-based integration layer.  Each module connects to whatever
//! primal announces the relevant capability at runtime — no compile-time
//! coupling to specific primal names.
//!
//! | Module | Capability | Runtime Discovery |
//! |--------|-----------|-------------------|
//! | [`beardog`] | `lineage-verification` | `LINEAGE_ENDPOINT` env var |
//! | [`songbird`] | `federation` | `FEDERATION_ENDPOINT` env var |
//! | [`toadstool`] | `discovery` | `DISCOVERY_ENDPOINT` env var |
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
pub mod rpc;
pub mod songbird;
pub mod toadstool;

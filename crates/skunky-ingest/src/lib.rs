// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! skunky-ingest — Live traffic log tailer for skunkBat behavioral detection.
//!
//! Library crate exposing all modules for reuse (integration tests, federation,
//! future tooling). The binary crate (`main.rs`) owns the CLI and tail loop.

pub mod aggregator;
pub mod caddy;
pub mod caddy_bridge;
pub mod cloudflare;
pub mod cursor;
pub mod entity_classifier;
pub mod epitope_inversion;
pub mod epitope_lure;
pub mod error;
pub mod federation;
pub mod fleet;
pub mod fluoro_tag;
pub mod inflammatory;
pub mod lysogeny;
pub mod rpc;
pub mod abuse_reporter;
pub mod bloom_sensor;
pub mod scatter_nft;
pub mod scatter_rng;
pub mod scatter_generator;
pub mod scatter_constants;
pub mod scatter_mirror;
pub mod scatter_prism;
pub mod scatter_types;
pub mod scatter_server;
pub mod scatter_temporal;
pub mod scyborg_prism;
pub mod signal_spine;
pub mod signal_writer;
pub mod threat_feed;

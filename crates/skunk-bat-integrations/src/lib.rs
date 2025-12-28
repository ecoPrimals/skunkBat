//! # skunkBat Ecosystem Integrations
//!
//! Real implementations of skunkBat traits for integration with other `BiomeOS` primals.
//!
//! ## Features
//!
//! - **beardog-integration**: Genetic lineage verification via Beardog
//! - **toadstool-integration**: Capability-based primal discovery via Toadstool
//! - **songbird-integration**: Federated threat intelligence via Songbird
//!
//! ## Example
//!
//! ```rust,ignore
//! use skunk_bat_integrations::beardog::BeardogLineageVerifier;
//! use skunk_bat_core::threats::LineageVerifier;
//!
//! // Create real Beardog verifier
//! let verifier = BeardogLineageVerifier::new(beardog_client);
//!
//! // Use in skunkBat
//! let is_family = verifier.is_family("node-123").await?;
//! ```

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![warn(clippy::pedantic)]

#[cfg(feature = "beardog-integration")]
pub mod beardog;

// Toadstool integration (no external deps yet - uses stub client)
pub mod toadstool;

// Songbird integration (no external deps yet - uses stub client)
pub mod songbird;

//! # skunkBat Ecosystem Integrations
//!
//! Real implementations of skunkBat traits for integration with other ecoPrimals.
//!
//! ## Available Integrations
//!
//! - **toadstool**: Capability-based primal discovery via `ToadStool`
//! - **songbird**: Federated threat intelligence via Songbird
//!
//! ## Future Integrations
//!
//! - **beardog**: Genetic lineage verification (pending IPC client crate)
//!
//! ## Example
//!
//! ```rust,ignore
//! use skunk_bat_integrations::toadstool::ToadstoolPrimalDiscovery;
//! use skunk_bat_core::reconnaissance::PrimalDiscovery;
//!
//! let client = ToadstoolDiscoveryClient::new("http://localhost:3000".into());
//! let discovery = ToadstoolPrimalDiscovery::new(client, "skunkbat-01".into());
//! let primals = discovery.discover_all().await?;
//! ```

pub mod songbird;
pub mod toadstool;

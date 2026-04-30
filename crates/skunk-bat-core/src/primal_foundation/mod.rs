// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Primal foundation types — standalone replacements for `sourdough-core`.
//!
//! These types were originally defined in `sourdough-core` (AGPL-3.0-or-later,
//! same license). They are inlined here so that skunkBat builds with zero
//! cross-repo path dependencies, enabling fully autonomous CI/CD via
//! plasmidBin / genomeBin.
//!
//! The API surface is intentionally identical to `sourdough-core` so that
//! any primal can swap the import path and the code compiles unchanged.

pub mod config;
pub mod error;
pub mod health;
pub mod lifecycle;
pub mod types;

pub use config::CommonConfig;
pub use error::{PrimalError, PrimalResult};
pub use health::{DependencyHealth, HealthReport, HealthStatus, PrimalHealth};
pub use lifecycle::{PrimalLifecycle, PrimalState};
pub use types::Timestamp;

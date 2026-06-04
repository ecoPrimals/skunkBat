// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! Runtime-selected lineage verifier.
//!
//! Probes the environment at construction time and selects either a
//! remote capability-discovered verifier or the conservative local
//! default.  This allows `SkunkBat::new` to remain simple while
//! supporting automatic runtime evolution when a lineage provider
//! becomes available.

use skunk_bat_core::error::SkunkBatError;
use skunk_bat_core::threats::LocalLineageVerifier;
use skunk_bat_core::threats::traits::LineageVerifier;

use crate::beardog::RemoteLineageVerifier;

/// Enum-dispatched verifier selected at runtime.
///
/// Zero-cost when the variant is known at compile-time (monomorphized);
/// when constructed via [`RuntimeVerifier::from_env`] the variant is
/// selected once at startup and never changes.
pub enum RuntimeVerifier {
    /// Conservative local default — denies all unknown peers.
    Local(LocalLineageVerifier),
    /// Capability-discovered remote provider.
    Remote(RemoteLineageVerifier),
}

impl RuntimeVerifier {
    /// Probe the environment and select the best available verifier.
    ///
    /// Selects [`RemoteLineageVerifier`] when `LINEAGE_ENDPOINT` is set
    /// or a `lineage-verification.sock` is discoverable.  Falls back to
    /// [`LocalLineageVerifier`] otherwise.
    #[must_use]
    pub fn from_env() -> Self {
        let has_tcp = std::env::var(skunk_bat_core::env_keys::LINEAGE_ENDPOINT)
            .map(|v| !v.is_empty())
            .unwrap_or(false);

        let has_uds = {
            let path = crate::rpc::capability_socket("lineage-verification");
            std::path::Path::new(&path).exists()
        };

        if has_tcp || has_uds {
            tracing::info!("Remote lineage verifier available — using capability provider");
            Self::Remote(RemoteLineageVerifier::from_env())
        } else {
            tracing::debug!("No lineage provider discovered — using local conservative default");
            Self::Local(LocalLineageVerifier)
        }
    }
}

impl LineageVerifier for RuntimeVerifier {
    async fn is_family(&self, peer_id: &str) -> Result<bool, SkunkBatError> {
        match self {
            Self::Local(v) => v.is_family(peer_id).await,
            Self::Remote(v) => v.is_family(peer_id).await,
        }
    }

    async fn get_lineage(&self, peer_id: &str) -> Result<Option<String>, SkunkBatError> {
        match self {
            Self::Local(v) => v.get_lineage(peer_id).await,
            Self::Remote(v) => v.get_lineage(peer_id).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_without_provider_selects_local() {
        let verifier = RuntimeVerifier::from_env();
        assert!(matches!(verifier, RuntimeVerifier::Local(_)));
    }

    #[tokio::test]
    async fn local_variant_returns_err_no_authority() {
        let verifier = RuntimeVerifier::Local(LocalLineageVerifier);
        let result = verifier.is_family("test-peer").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn remote_variant_returns_err_when_unreachable() {
        let verifier =
            RuntimeVerifier::Remote(RemoteLineageVerifier::new("unreachable.invalid:1".into()));
        let result = verifier.is_family("test-peer").await;
        assert!(result.is_err());
    }
}

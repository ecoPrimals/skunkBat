//! Beardog integration for genetic lineage verification
//!
//! This module provides real Beardog lineage verification through the
//! `BirdSong` lineage proof system.

use async_trait::async_trait;
use beardog_genetics::{LineageProof, LineageProofManager};
use skunk_bat_core::error::SkunkBatError;
use skunk_bat_core::threats::LineageVerifier;
use std::sync::Arc;
use tracing::{debug, error, info};

/// Real Beardog-backed lineage verifier
///
/// Verifies genetic lineage through cryptographic proofs from Beardog's
/// `BirdSong` lineage system.
///
/// ## Architecture
///
/// - Uses Beardog's `LineageProofManager` for proof generation
/// - Verifies cryptographic signatures along lineage chain
/// - Checks Merkle roots for tamper-resistance
///
/// ## Example
///
/// ```rust,ignore
/// use skunk_bat_integrations::beardog::BeardogLineageVerifier;
/// use skunk_bat_core::threats::LineageVerifier;
///
/// let proof_manager = /* ... */;
/// let verifier = BeardogLineageVerifier::new(proof_manager, "my-chain-id");
///
/// if verifier.is_family("node-123").await? {
///     println!("Node is family!");
/// }
/// ```
pub struct BeardogLineageVerifier {
    proof_manager: Arc<LineageProofManager>,
    chain_id: String,
    root_node_id: String,
}

impl BeardogLineageVerifier {
    /// Create new Beardog lineage verifier
    ///
    /// # Arguments
    ///
    /// * `proof_manager` - Beardog's lineage proof manager
    /// * `chain_id` - ID of the lineage chain to verify against
    /// * `root_node_id` - Root node ID of YOUR lineage
    #[must_use]
    pub fn new(
        proof_manager: Arc<LineageProofManager>,
        chain_id: String,
        root_node_id: String,
    ) -> Self {
        info!(
            "🦨🐻 Initializing BeardogLineageVerifier for chain: {}",
            chain_id
        );
        Self {
            proof_manager,
            chain_id,
            root_node_id,
        }
    }

    /// Verify a lineage proof
    ///
    /// # Errors
    ///
    /// Returns error if proof verification fails
    fn verify_proof(&self, proof: &LineageProof, chain_id: &str) -> Result<bool, SkunkBatError> {
        // Verify proof using Beardog's verification logic
        match self.proof_manager.verify_proof(proof, chain_id) {
            Ok(result) => {
                if result.valid {
                    debug!("✅ Lineage proof verified for {}", proof.node_id);
                    Ok(true)
                } else {
                    info!(
                        "❌ Invalid lineage proof for {}: {}",
                        proof.node_id,
                        result
                            .failure_reason
                            .unwrap_or_else(|| "Unknown reason".to_string())
                    );
                    Ok(false)
                }
            }
            Err(e) => {
                error!("🚫 Lineage verification error: {}", e);
                Err(SkunkBatError::Integration(format!(
                    "Beardog verification failed: {e}"
                )))
            }
        }
    }
}

#[async_trait]
impl LineageVerifier for BeardogLineageVerifier {
    /// Check if peer is part of YOUR genetic lineage
    ///
    /// # Errors
    ///
    /// Returns error if Beardog integration fails
    async fn is_family(&self, peer_id: &str) -> Result<bool, SkunkBatError> {
        info!("🦨🐻 Checking lineage for peer: {}", peer_id);

        // Generate lineage proof from Beardog
        let proof = match self.proof_manager.generate_proof(&self.chain_id, peer_id) {
            Ok(p) => p,
            Err(e) => {
                // Peer might not be in lineage at all
                debug!("Peer {} not in lineage: {}", peer_id, e);
                return Ok(false);
            }
        };

        // Verify the proof matches our root
        if proof.root_id != self.root_node_id {
            info!(
                "❌ Peer {} has different root (theirs: {}, ours: {})",
                peer_id, proof.root_id, self.root_node_id
            );
            return Ok(false);
        }

        // Verify the cryptographic proof
        self.verify_proof(&proof, &self.chain_id)
    }

    /// Get the full lineage path for a peer
    ///
    /// # Errors
    ///
    /// Returns error if Beardog integration fails
    async fn get_lineage(&self, peer_id: &str) -> Result<Option<String>, SkunkBatError> {
        debug!("🦨🐻 Getting lineage path for: {}", peer_id);

        // Generate proof to get the path
        let proof = match self.proof_manager.generate_proof(&self.chain_id, peer_id) {
            Ok(p) => p,
            Err(e) => {
                debug!("Cannot get lineage for {}: {}", peer_id, e);
                return Ok(None);
            }
        };

        // Verify it's our family first
        if proof.root_id != self.root_node_id {
            return Ok(None);
        }

        // Return the path as a string (root → ... → peer)
        let path = proof.path.join(" → ");
        Ok(Some(path))
    }
}

#[cfg(test)]
mod tests {
    // Note: Tests require real Beardog runtime setup
    // For now, we test the trait implementation compiles
    // Full integration tests will be in showcase/integration-tests/

    #[tokio::test]
    async fn test_beardog_verifier_compiles() {
        // This test verifies the trait implementation compiles correctly
        // Real testing requires Beardog chain manager setup
        
        // Intentional pass - this is a compilation test
        // The fact that this code compiles proves the trait is implemented
    }
}

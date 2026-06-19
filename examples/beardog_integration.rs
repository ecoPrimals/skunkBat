// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! `BearDog` integration demonstration for `skunkBat`.
//!
//! Shows genetic lineage verification architecture. This demo uses the
//! `LocalLineageVerifier` stub to demonstrate the integration pattern.
//! Production integration uses `RemoteLineageVerifier` via JSON-RPC IPC
//! to a running `BearDog` instance (discovered at runtime, not compile-time).

use skunk_bat_core::PrimalLifecycle;
use skunk_bat_core::{
    SkunkBat, SkunkBatConfig,
    threats::{LineageVerifier, LocalLineageVerifier, Severity, Threat, ThreatType},
};
use std::time::SystemTime;

#[expect(clippy::too_many_lines, reason = "self-contained demo")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    println!("🦨 + 🐻 skunkBat + Beardog Integration Demo");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Genetic Trust: Cryptographic Lineage Verification\n");

    // ════════════════════════════════════════
    // SETUP: Integration Architecture
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SETUP: Lineage Verification");
    println!("════════════════════════════════════════\n");

    println!("Integration Pattern:");
    println!("```rust");
    println!("// Trait-based architecture (zero coupling)");
    println!("pub trait LineageVerifier {{");
    println!("    async fn is_family(&self, peer_id: &str) -> Result<bool>;");
    println!("    async fn get_lineage(&self, peer_id: &str) -> Result<Option<String>>;");
    println!("}}");
    println!("```\n");

    println!("Available Implementations:");
    println!("  1. LocalLineageVerifier (stub) - ✅ Active in this demo");
    println!("     • Conservative default: deny unknown");
    println!("     • No external dependencies");
    println!("     • Used for testing and standalone mode\n");

    println!("  2. RemoteLineageVerifier (real) — JSON-RPC IPC to BearDog");
    println!("     • Delegates verification over `lineage.verify` / `lineage.list`");
    println!("     • Discovered at runtime via LINEAGE_ENDPOINT or UDS convention");
    println!("     • No compile-time BearDog dependency (capability-based)\n");

    // Initialize with stub verifier
    let verifier = LocalLineageVerifier;

    println!("✓ Using LocalLineageVerifier for this demo");
    println!("  • Mode: Conservative (deny by default)");
    println!("  • Trust model: Defensive\n");

    // Create skunkBat
    let config = SkunkBatConfig::default();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;

    println!("✓ skunkBat initialized\n");

    // ════════════════════════════════════════
    // SCENARIO 1: Unknown Node (Conservative Default)
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SCENARIO 1: Unknown Node Connection");
    println!("════════════════════════════════════════\n");

    let node_id = "node-unknown-123";

    println!("Connection attempt:");
    println!("  • Source: {node_id}");
    println!("  • IP: 192.168.1.50");
    println!("  • Service: data-access\n");

    println!("🦨 → 🐻 Requesting lineage verification...");
    let verification = verifier.is_family(node_id).await;

    println!("🐻 → 🦨 Response (local stub behavior):");
    match verification {
        Ok(true) => {
            println!("  ✓ Valid lineage\n");
        }
        Ok(false) => {
            println!("  ✗ NOT FAMILY (authoritative denial)\n");
        }
        Err(ref e) => {
            println!("  ⚠ NO AUTHORITY AVAILABLE: {e}");
            println!("  • Reason: No lineage provider discovered at runtime\n");

            let threat = Threat {
                id: "beardog-threat-1".to_string(),
                threat_type: ThreatType::UnknownLineage {
                    peer_id: node_id.to_string(),
                    lineage: None,
                },
                severity: Severity::High,
                source: node_id.to_string(),
                target: "local-node".to_string(),
                detected_at: SystemTime::now(),
                description: "Connection from node with unverified genetic lineage".to_string(),
                confidence: 0.9,
            };

            println!("🦨 Threat Detected:");
            println!("  • Type: UnknownLineage");
            println!("  • Severity: High");
            println!("  • Confidence: 90%\n");

            skunkbat.respond_to_threat(&threat)?;

            println!("🦨 Decision: ⚠️ CONNECTION QUARANTINED");
            println!("  • Reason: Cannot verify genetic lineage");
            println!("  • Action: Isolate for owner review");
            println!("  • Note: With real Beardog, this could be approved\n");
        }
    }

    // ════════════════════════════════════════
    // WHAT REAL BEARDOG WOULD PROVIDE
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("WHAT REAL BEARDOG PROVIDES");
    println!("════════════════════════════════════════\n");

    println!("With a running BearDog instance:");
    println!("```rust");
    println!("use skunk_bat_integrations::beardog::RemoteLineageVerifier;");
    println!();
    println!("// Discovered at runtime — no compile-time BearDog dependency");
    println!("let verifier = RemoteLineageVerifier::from_env();");
    println!("// Uses LINEAGE_ENDPOINT env or probes lineage-verification.sock");
    println!();
    println!("// Same LineageVerifier trait — transparent swap");
    println!("let is_family = verifier.is_family(\"peer-id\").await?;");
    println!("```\n");

    println!("What BearDog provides at runtime:");
    println!("  ✅ Lineage chain traversal");
    println!("  ✅ Signature verification at each hop");
    println!("  ✅ Merkle root validation (tamper resistance)");
    println!("  ✅ Multi-generation proof");
    println!("  ✅ Mathematical trust (not guesswork)\n");

    println!("Example Lineage Chain:");
    println!("  tower-alice (root)");
    println!("   └─ home-server (child)");
    println!("      └─ laptop-001 (grandchild)");
    println!("         └─ phone-001 (great-grandchild)\n");

    println!("Each hop verified:");
    println!("  • Cryptographic signature");
    println!("  • Timestamp proof");
    println!("  • Merkle inclusion proof");
    println!("  → TRUST = MATHEMATICAL PROOF\n");

    // ════════════════════════════════════════
    // COMPARISON TABLE
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("COMPARISON: Stub vs Real");
    println!("════════════════════════════════════════\n");

    println!("┌─────────────────────┬──────────────┬──────────────┐");
    println!("│ Capability          │ Stub (Local) │ Real (Beardog)│");
    println!("├─────────────────────┼──────────────┼──────────────┤");
    println!("│ Lineage Verification│ ❌ No        │ ✅ Yes       │");
    println!("│ Crypto Proofs       │ ❌ No        │ ✅ Yes       │");
    println!("│ Multi-generation    │ ❌ No        │ ✅ Yes       │");
    println!("│ Trust Model         │ Deny default │ Prove family │");
    println!("│ External Dependency │ ✅ None      │ beardog crate│");
    println!("│ Use Case            │ Testing      │ Production   │");
    println!("└─────────────────────┴──────────────┴──────────────┘\n");

    // ════════════════════════════════════════
    // INTEGRATION ARCHITECTURE
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("INTEGRATION ARCHITECTURE");
    println!("════════════════════════════════════════\n");

    println!("Zero-Coupling Design:");
    println!("  ✓ skunkBat knows ONLY the LineageVerifier trait");
    println!("  ✓ Doesn't know HOW Beardog works");
    println!("  ✓ Doesn't know WHERE Beardog is");
    println!("  ✓ Can swap implementations at runtime\n");

    println!("Trait Hierarchy:");
    println!("  skunkBat (crates/skunk-bat-core)");
    println!("     ↓ depends on trait");
    println!("  LineageVerifier trait");
    println!("     ↓ implemented by");
    println!("  LocalLineageVerifier (stub — testing/standalone)");
    println!("  RemoteLineageVerifier (IPC — runtime discovery)\n");

    println!("Discovery Pattern:");
    println!("  • LINEAGE_ENDPOINT env → TCP JSON-RPC");
    println!("  • lineage-verification.sock → UDS JSON-RPC");
    println!("  • Fallback: LocalLineageVerifier (conservative deny)\n");

    println!("Why Runtime Discovery?");
    println!("  • Zero compile-time coupling to BearDog");
    println!("  • Standalone mode without ecosystem");
    println!("  • Graceful degradation when BearDog is down");
    println!("  • Capability-based, not name-based\n");

    // ════════════════════════════════════════
    // SUMMARY
    // ════════════════════════════════════════
    println!("════════════════════════════════════════");
    println!("SUMMARY: Genetic Trust Integration");
    println!("════════════════════════════════════════\n");

    println!("This Demo Showed:");
    println!("  ✅ Trait-based integration pattern");
    println!("  ✅ Conservative stub behavior");
    println!("  ✅ Zero-coupling architecture");
    println!("  ✅ Feature flag usage\n");

    println!("Genetic Trust Principles:");
    println!("  • WHO: Identity verification");
    println!("  • HOW: Cryptographic proofs");
    println!("  • WHERE: Lineage chain traversal");
    println!("  • TRUST: Mathematical, not behavioral\n");

    println!("To Use Real BearDog:");
    println!("  1. Start a BearDog instance on the same host");
    println!("  2. Set LINEAGE_ENDPOINT or use UDS convention");
    println!("  3. skunkBat auto-discovers at startup (RuntimeVerifier)");
    println!("  4. Verification delegated over JSON-RPC IPC\n");

    println!("Status:");
    println!("  • Architecture: ✅ Production-ready");
    println!("  • Integration: ✅ RemoteLineageVerifier (IPC, runtime)");
    println!("  • This demo: Stub (shows pattern)\n");

    // Stop skunkBat
    skunkbat.stop().await?;

    println!("✅ Demo Complete!\n");
    println!("Key Takeaway: Genetic trust is ARCHITECTURAL.");
    println!("skunkBat uses traits for zero-coupling. Beardog provides cryptographic");
    println!("lineage proofs. Together: WHO (identity) + THREAT (detection). 🦨🐻");

    Ok(())
}

#!/bin/bash
set -e

echo "🦨 + 🐻 skunkBat + Beardog Integration Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Scenario: Node attempts connection to YOUR network"
echo ""
sleep 1

echo "Step 1: Connection received"
echo "  Source: node-abc123"
echo "  IP: 192.168.1.50"
echo "  Requested service: data-access"
echo ""
sleep 1

echo "Step 2: skunkBat requests lineage verification"
echo "  → Querying Beardog..."
sleep 1
echo ""

echo "Step 3: Beardog response"
echo "  ✓ Valid genetic lineage found!"
echo ""
echo "  Lineage Chain:"
echo "    └─ BearDog Root (genesis)"
echo "       └─ YourTower (your-tower-id)"
echo "          └─ node-abc123 (requesting node)"
echo ""
echo "  Trust: FAMILY (verified descendant)"
echo ""
sleep 1

echo "Step 4: skunkBat decision"
echo "  ✓ Connection APPROVED"
echo "  Reason: Valid family lineage verified by Beardog"
echo ""
sleep 1

echo "Step 5: Audit log"
echo "  ✓ Logged to local audit trail"
echo "  ✓ Shared with federation (if enabled)"
echo ""

echo "═══════════════════════════════════════════"
echo "COMPARISON: With vs Without Beardog"
echo "═══════════════════════════════════════════"
echo ""
echo "WITHOUT Beardog (stub):"
echo "  • Local-only verification"
echo "  • No cryptographic proof"
echo "  • Trust = \"maybe?\""
echo ""
echo "WITH Beardog (real):"
echo "  • Cryptographic lineage chain"
echo "  • Genetic trust verification"
echo "  • Trust = \"proven family\""
echo ""

echo "✅ Demo Complete!"
echo ""
echo "➡️  Next: ../02-toadstool-integration/"


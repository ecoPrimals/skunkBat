#!/bin/bash
set -e

echo "🦨 + 🍄 skunkBat + Toadstool Integration Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Discovering primals by capability..."
echo ""
sleep 1

echo "Step 1: skunkBat needs lineage verification"
echo "  Query: \"Who can verify genetic lineage?\""
echo "  → Asking Toadstool..."
sleep 1
echo ""

echo "Step 2: Toadstool response"
echo "  ✓ Found 2 primals with capability 'lineage-verification':"
echo "    • beardog-tower-1 (local network)"
echo "    • beardog-tower-2 (federated)"
echo ""
sleep 1

echo "Step 3: skunkBat connects to nearest"
echo "  Selected: beardog-tower-1 (15ms latency)"
echo "  ✓ Connection established"
echo ""

echo "═══════════════════════════════════════════"
echo "COMPARISON: Hardcoded vs Capability-Based"
echo "═══════════════════════════════════════════"
echo ""
echo "HARDCODED approach:"
echo "  • skunkBat knows \"beardog is at 192.168.1.10:8080\""
echo "  • Breaks if Beardog moves"
echo "  • Can't use alternative Beardog"
echo ""
echo "CAPABILITY-BASED approach:"
echo "  • skunkBat asks \"who can verify lineage?\""
echo "  • Adapts to network changes"
echo "  • Uses best available option"
echo ""

echo "✅ Demo Complete!"
echo ""
echo "Key Takeaway: Ask for capabilities, not locations!"
echo ""
echo "➡️  Next: ../03-songbird-integration/"


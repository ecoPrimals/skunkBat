#!/bin/bash
set -e

echo "🦨 Federation Resilience Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Testing federation resilience..."
echo ""
sleep 1

echo "Initial federation (5 nodes):"
echo "  ✓ skunkBat-home"
echo "  ✓ skunkBat-family"
echo "  ✓ skunkBat-uni"
echo "  ✓ skunkBat-friend-1"
echo "  ✓ skunkBat-friend-2"
echo ""
sleep 1

echo "═══════════════════════════════════════════"
echo "SCENARIO: Nodes Go Offline"
echo "═══════════════════════════════════════════"
echo ""

echo "Step 1: skunkBat-home detects threat"
echo "  Threat: attack-bot-123"
echo "  → Publishing to federation via Songbird..."
echo ""
sleep 1

echo "Step 2: skunkBat-friend-2 goes OFFLINE"
echo "  ✗ Node unreachable"
echo "  → Songbird: Delivery failed, retry later"
echo "  ✓ Other 4 nodes receive threat intel"
echo ""
sleep 1

echo "Step 3: Federation responds (4/5 nodes)"
echo "  ✓ skunkBat-home: BLOCK"
echo "  ✓ skunkBat-family: BLOCK"
echo "  ✓ skunkBat-uni: RATE LIMIT"
echo "  ✓ skunkBat-friend-1: MONITOR"
echo "  ⏳ skunkBat-friend-2: Offline (will sync later)"
echo ""
sleep 1

echo "Step 4: skunkBat-friend-2 comes back ONLINE"
echo "  ✓ Reconnects to Songbird mesh"
echo "  → Songbird: Delivering missed threats..."
echo "  ✓ Receives threat intel for attack-bot-123"
echo "  ✓ Applies policy (BLOCK)"
echo ""

echo "═══════════════════════════════════════════"
echo "DECENTRALIZED RESILIENCE"
echo "═══════════════════════════════════════════"
echo ""
echo "No single point of failure:"
echo "  • Any node can detect threats"
echo "  • Any node can publish to mesh"
echo "  • Offline nodes catch up when reconnected"
echo "  • Each node maintains sovereignty"
echo ""

echo "✅ Demo Complete!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 LEVEL 2 COMPLETE!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "You've mastered federation mesh scenarios!"
echo ""
echo "Next Level: ../../03-production/"
echo "Learn production deployment best practices!"


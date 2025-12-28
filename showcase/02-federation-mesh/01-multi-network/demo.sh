#!/bin/bash
set -e

echo "🦨 Multi-Network Federation Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Federating three independent networks..."
echo ""
sleep 1

echo "Network Topology:"
echo ""
echo "  🏠 Home LAN (your-home-net)"
echo "     ├─ skunkBat-home"
echo "     ├─ Beardog (lineage)"
echo "     └─ 5 local devices"
echo ""
echo "  👨‍👩‍👧‍👦 Family Tower (family-net)"
echo "     ├─ skunkBat-family"
echo "     ├─ Beardog (lineage)"
echo "     └─ 12 family devices"
echo ""
echo "  🎓 University Tower (uni-net)"
echo "     ├─ skunkBat-uni"
echo "     ├─ Beardog (lineage)"
echo "     └─ 200+ devices"
echo ""
sleep 2

echo "═══════════════════════════════════════════"
echo "SCENARIO: Attack on Home Network"
echo "═══════════════════════════════════════════"
echo ""

echo "Step 1: skunkBat-home detects attack"
echo "  Attacker: malicious-bot-swarm"
echo "  Type: Distributed DoS"
echo "  Sources: 50+ IP addresses"
echo ""
sleep 1

echo "Step 2: Publish to federation"
echo "  → Songbird mesh: Threat broadcast"
echo "  ✓ skunkBat-family notified"
echo "  ✓ skunkBat-uni notified"
echo ""
sleep 1

echo "Step 3: Independent decisions"
echo ""
echo "  skunkBat-home:"
echo "    Decision: BLOCK all 50+ IPs"
echo "    Reasoning: Protecting YOUR home network"
echo ""
echo "  skunkBat-family:"
echo "    Decision: RATE LIMIT 50+ IPs"
echo "    Reasoning: Trust YOUR intel, cautious approach"
echo ""
echo "  skunkBat-uni:"
echo "    Decision: MONITOR only"
echo "    Reasoning: Large network, false positives expensive"
echo ""

echo "✅ Demo Complete!"
echo ""
echo "Key Takeaway: Federation = coordination without centralization!"
echo ""
echo "➡️  Next: ../02-layered-security/"


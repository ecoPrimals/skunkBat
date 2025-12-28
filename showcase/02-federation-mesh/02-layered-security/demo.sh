#!/bin/bash
set -e

echo "🦨 Layered Security Architecture Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Defense in depth with multiple skunkBats..."
echo ""
sleep 1

echo "NestGate Data Federation Architecture:"
echo ""
echo "  Layer 0: Public API"
echo "    └─ skunkBat-api"
echo "       • Rate limiting"
echo "       • DDoS protection"
echo "       • Public access control"
echo ""
echo "  Layer 1: Gateway"
echo "    └─ skunkBat-gateway"
echo "       • Genetic verification (Beardog)"
echo "       • Request validation"
echo "       • Family-only access"
echo ""
echo "  Layer 2: Processing"
echo "    └─ skunkBat-processing"
echo "       • Resource monitoring"
echo "       • Anomaly detection"
echo "       • Internal traffic analysis"
echo ""
echo "  Layer 3: Core Storage"
echo "    └─ skunkBat-storage"
echo "       • Data exfiltration detection"
echo "       • Access pattern monitoring"
echo "       • Strictest policies"
echo ""
sleep 2

echo "═══════════════════════════════════════════"
echo "SCENARIO: Sophisticated Layer-Hopping Attack"
echo "═══════════════════════════════════════════"
echo ""

echo "Attacker strategy: Bypass layers 1-2, go direct to storage"
echo ""
sleep 1

echo "Step 1: Attacker probes public API (Layer 0)"
echo "  → skunkBat-api: High request rate detected"
echo "  → Action: Rate limit applied"
echo "  ✗ Attack slowed but not stopped"
echo ""
sleep 1

echo "Step 2: Attacker attempts direct gateway (Layer 1)"
echo "  → skunkBat-gateway: No valid lineage"
echo "  → Beardog: Genetic verification failed"
echo "  → Action: Connection rejected"
echo "  ✗ Attack blocked at Layer 1"
echo ""
sleep 1

echo "Step 3: Attacker tries to skip to storage (Layer 0→3)"
echo "  → skunkBat-storage: TOPOLOGY VIOLATION"
echo "  → Detection: Invalid path (skipped layers 1-2)"
echo "  → Action: Immediate block + alert"
echo "  ✗ Attack stopped, topology violation logged"
echo ""
sleep 1

echo "Step 4: Mesh coordination"
echo "  → All 4 skunkBats notified of topology violation"
echo "  → Future attempts from attacker blocked at ALL layers"
echo "  ✓ Coordinated mesh-wide defense"
echo ""

echo "✅ Demo Complete!"
echo ""
echo "Key Takeaway: Each layer enforces specific policies!"
echo "Topology violations = layer-hopping detected!"
echo ""
echo "➡️  Next: ../03-ownership-breach/"


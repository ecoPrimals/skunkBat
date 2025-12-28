#!/bin/bash
set -e

echo "🦨 Data Exfiltration Detection Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Detecting unauthorized data movement..."
echo ""
sleep 1

echo "═══════════════════════════════════════════"
echo "SCENARIO: Compromised Node"
echo "═══════════════════════════════════════════"
echo ""
echo "Node 'processing-worker-7' is compromised."
echo "Attacker attempts to exfiltrate YOUR data."
echo ""
sleep 1

echo "Baseline (NORMAL behavior for processing-worker-7):"
echo "  • Data access: 50-100 records/hour"
echo "  • External uploads: 0 MB/hour (internal only)"
echo "  • Access pattern: Sequential processing"
echo ""
sleep 1

echo "Current observation (ATTACK in progress):"
echo "  • Data access: 5000+ records/hour (50x baseline!)"
echo "  • External uploads: 500 MB/hour (ABNORMAL!)"
echo "  • Access pattern: Random bulk queries"
echo ""
sleep 1

echo "Step 1: skunkBat-storage detects anomaly"
echo "  → Baseline profiler: 45.2σ deviation"
echo "  → Resource monitor: Abnormal bandwidth"
echo "  → Behavior: Sequential → Random (suspicious)"
echo "  ✗ BEHAVIORAL ANOMALY DETECTED"
echo ""
sleep 1

echo "Step 2: Immediate response"
echo "  → Action: QUARANTINE processing-worker-7"
echo "  → Data access: Temporarily suspended"
echo "  → Alert: Owner notified for review"
echo ""
sleep 1

echo "Step 3: Forensic analysis"
echo "  • Audit logs show 5000 records accessed"
echo "  • External connection to unknown IP"
echo "  • Zero legitimate processing"
echo "  → Conclusion: Confirmed exfiltration attempt"
echo ""
sleep 1

echo "Step 4: Mesh coordination"
echo "  → Songbird: Broadcast threat to federation"
echo "  → All skunkBats: Block processing-worker-7"
echo "  → Beardog: Revoke lineage if genetic compromise"
echo ""

echo "═══════════════════════════════════════════"
echo "DEFENSIVE VS SURVEILLANCE"
echo "═══════════════════════════════════════════"
echo ""
echo "What skunkBat detected:"
echo "  ✅ Access frequency (50x normal)"
echo "  ✅ Bandwidth usage (500 MB vs 0 MB)"
echo "  ✅ Access pattern (random vs sequential)"
echo ""
echo "What skunkBat did NOT inspect:"
echo "  ❌ Data content"
echo "  ❌ Individual records"
echo "  ❌ User activity"
echo ""

echo "✅ Demo Complete!"
echo ""
echo "Key Takeaway: Pattern-based detection, NOT content surveillance!"
echo ""
echo "➡️  Next: ../05-federation-resilience/"


#!/bin/bash
set -e

echo "🦨 Monitoring & Observability Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Demonstrating production observability..."
echo ""
sleep 1

echo "═══════════════════════════════════════════"
echo "SECURITY METRICS"
echo "═══════════════════════════════════════════"
echo ""
echo "Real-time metrics exposed:"
echo ""
echo "  skunkbat_threats_detected_total{type=\"genetic\"} 12"
echo "  skunkbat_threats_detected_total{type=\"topology\"} 3"
echo "  skunkbat_threats_detected_total{type=\"behavioral\"} 45"
echo "  skunkbat_threats_detected_total{type=\"resource\"} 8"
echo ""
echo "  skunkbat_defense_actions_total{action=\"quarantine\"} 5"
echo "  skunkbat_defense_actions_total{action=\"rate_limit\"} 18"
echo "  skunkbat_defense_actions_total{action=\"block\"} 7"
echo ""
echo "  skunkbat_baseline_observations_total 10245"
echo "  skunkbat_baseline_established{status=\"true\"} 1"
echo ""
echo "  skunkbat_reconnaissance_scans_total 342"
echo "  skunkbat_reconnaissance_nodes_discovered 15"
echo ""
sleep 2

echo "═══════════════════════════════════════════"
echo "STRUCTURED LOGGING"
echo "═══════════════════════════════════════════"
echo ""
echo "Example log entries (JSON):"
echo ""
cat << 'JSON'
{
  "timestamp": "2025-12-28T10:15:32Z",
  "level": "WARN",
  "primal": "skunkbat-prod-01",
  "event": "threat_detected",
  "threat_type": "genetic_violation",
  "source_id": "unknown-node-42",
  "severity": "high",
  "recommended_action": "quarantine"
}

{
  "timestamp": "2025-12-28T10:15:33Z",
  "level": "INFO",
  "primal": "skunkbat-prod-01",
  "event": "defense_action",
  "action": "quarantine",
  "target": "unknown-node-42",
  "approved_by": "owner",
  "reason": "genetic_violation"
}
JSON

echo ""
sleep 2

echo "═══════════════════════════════════════════"
echo "AUDIT TRAIL"
echo "═══════════════════════════════════════════"
echo ""
echo "All security decisions logged for accountability:"
echo ""
echo "  [2025-12-28 10:15:32] DETECT: unknown-node-42 (genetic)"
echo "  [2025-12-28 10:15:33] RECOMMEND: quarantine"
echo "  [2025-12-28 10:15:35] APPROVE: owner (manual)"
echo "  [2025-12-28 10:15:36] EXECUTE: quarantine successful"
echo "  [2025-12-28 10:15:37] PUBLISH: threat shared via Songbird"
echo ""

echo "✅ Demo Complete!"
echo ""
echo "Key Takeaway: Full transparency with structured logs + metrics!"
echo ""
echo "➡️  Next: ../03-performance-tuning/"


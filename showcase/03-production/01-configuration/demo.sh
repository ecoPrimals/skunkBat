#!/bin/bash
set -e

echo "🦨 Production Configuration Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Comparing development vs production configs..."
echo ""
sleep 1

echo "═══════════════════════════════════════════"
echo "DEVELOPMENT CONFIGURATION"
echo "═══════════════════════════════════════════"
echo ""
echo "Trait Implementations:"
echo "  • LineageVerifier: LocalLineageVerifier (stub)"
echo "  • PrimalDiscovery: LocalPrimalDiscovery (stub)"
echo "  • BaselineProfiler: StatisticalProfiler (real)"
echo "  • TopologyMapper: LocalTopologyMapper (stub)"
echo ""
echo "Logging:"
echo "  • Level: DEBUG"
echo "  • Output: Stdout"
echo "  • Audit: Disabled"
echo ""
echo "Security:"
echo "  • Rate limiting: Permissive"
echo "  • Auto-response: Disabled (manual approval)"
echo ""
sleep 2

echo "═══════════════════════════════════════════"
echo "PRODUCTION CONFIGURATION"
echo "═══════════════════════════════════════════"
echo ""
echo "Trait Implementations:"
echo "  • LineageVerifier: BeardogLineageVerifier (real)"
echo "  • PrimalDiscovery: ToadstoolDiscovery (real)"
echo "  • BaselineProfiler: StatisticalProfiler (real)"
echo "  • TopologyMapper: ToadstoolTopologyMapper (real)"
echo ""
echo "Logging:"
echo "  • Level: INFO"
echo "  • Output: Structured JSON → Observability primal"
echo "  • Audit: Enabled (all decisions logged)"
echo ""
echo "Security:"
echo "  • Rate limiting: Strict"
echo "  • Auto-response: Enabled for Critical threats"
echo "  • TLS: Required"
echo "  • Secrets: Environment variables only"
echo ""
sleep 2

echo "Example production config (TOML):"
echo ""
cat << 'TOML'
[skunkbat]
primal_id = "skunkbat-prod-01"
environment = "production"

[reconnaissance]
enabled = true
scan_interval_secs = 60

[threats]
enabled = true
genetic_verification = true
baseline_threshold = 2.5
auto_quarantine_critical = true

[defense]
enabled = true
auto_block_critical = true
user_approval_required = ["quarantine", "rate_limit"]

[observability]
log_level = "info"
audit_enabled = true
metrics_enabled = true

[integrations.beardog]
endpoint = "unix:///var/run/beardog.sock"
timeout_ms = 5000

[integrations.toadstool]
endpoint = "unix:///var/run/toadstool.sock"

[integrations.songbird]
endpoint = "unix:///var/run/songbird.sock"
TOML

echo ""
echo "✅ Demo Complete!"
echo ""
echo "Key Takeaway: Production uses real implementations + strict policies!"
echo ""
echo "➡️  Next: ../02-monitoring-observability/"


#!/usr/bin/env bash
set -euo pipefail

echo "🦨 skunkBat - Level 0: Local Primal Capabilities"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Running all 6 demos in sequence..."
echo "Estimated time: 45-60 minutes"
echo ""

# Track progress
DEMOS_COMPLETED=0
DEMOS_TOTAL=6

run_demo() {
    local demo_num=$1
    local demo_name=$2
    local demo_dir=$3
    
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "Demo $demo_num/$DEMOS_TOTAL: $demo_name"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    
    cd "$demo_dir"
    bash demo.sh
    cd - > /dev/null
    
    DEMOS_COMPLETED=$((DEMOS_COMPLETED + 1))
    
    echo ""
    echo "✅ Demo $demo_num complete! ($DEMOS_COMPLETED/$DEMOS_TOTAL done)"
    echo ""
    
    if [ $DEMOS_COMPLETED -lt $DEMOS_TOTAL ]; then
        echo "Press ENTER to continue to next demo (or Ctrl+C to stop)..."
        read -r
    fi
}

# Run all demos
run_demo 1 "Hello skunkBat" "01-hello-skunkbat"
run_demo 2 "Violation Detection" "02-violation-detection"
run_demo 3 "Defense Actions" "03-defense-actions"
run_demo 4 "Baseline Learning" "04-baseline-learning"
run_demo 5 "Local Federation" "05-local-federation"
run_demo 6 "Defensive vs Surveillance" "06-defensive-vs-surveillance"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "🎉 LEVEL 0 COMPLETE!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "You've mastered all local skunkBat capabilities!"
echo ""
echo "Key Achievements:"
echo "  ✅ Understood self-discovery principle"
echo "  ✅ Learned all 5 threat detection types"
echo "  ✅ Mastered graduated defense response"
echo "  ✅ Explored statistical baseline profiling"
echo "  ✅ Witnessed federation coordination"
echo "  ✅ Understood defensive architecture"
echo ""
echo "Next Steps:"
echo "  → ../01-ecosystem-integration/ - Inter-primal demos"
echo "  → ../02-federation-mesh/ - Multi-node coordination"
echo "  → ../03-production/ - Production deployment"
echo ""
echo "🦨 Defensive by architecture, not by promise!"

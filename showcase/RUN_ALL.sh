#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║                  🦨 skunkBat Complete Showcase - All Levels                 ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "This will run ALL 21 demos across 4 levels."
echo "Estimated time: ~2 hours"
echo ""
echo "Press Enter to begin, or Ctrl+C to cancel..."
read -r
echo ""

# Change to showcase directory
cd "$(dirname "$0")"

levels=(
    "00-local-primal:Level 0: Local Primal Capabilities:6"
    "01-ecosystem-integration:Level 1: Ecosystem Integration:5"
    "02-federation-mesh:Level 2: Federation Mesh:5"
    "03-production:Level 3: Production Deployment:5"
)

total_demos=21
completed=0

for level_info in "${levels[@]}"; do
    IFS=':' read -r level_dir level_name demo_count <<< "$level_info"
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "$level_name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    cd "$level_dir"
    
    # Find all demo directories
    for demo_dir in */; do
        if [ -f "$demo_dir/demo.sh" ]; then
            completed=$((completed + 1))
            demo_name=$(basename "$demo_dir")
            
            echo "═══════════════════════════════════════════════════════════════"
            echo "Demo $completed/$total_demos: $demo_name"
            echo "═══════════════════════════════════════════════════════════════"
            echo ""
            
            cd "$demo_dir"
            ./demo.sh
            cd ..
            
            echo ""
            
            if [ $completed -lt $total_demos ]; then
                echo "Press Enter to continue to next demo..."
                read -r
                echo ""
            fi
        fi
    done
    
    cd ..
    
    echo ""
    echo "✅ $level_name COMPLETE!"
    echo ""
    
    if [ "$level_dir" != "03-production" ]; then
        echo "Press Enter to continue to next level..."
        read -r
        echo ""
    fi
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║                   🎉 ALL SHOWCASE LEVELS COMPLETE! 🎉                       ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "You've completed all $total_demos demos across 4 levels:"
echo ""
echo "  ✅ Level 0: Local Primal Capabilities (6 demos)"
echo "  ✅ Level 1: Ecosystem Integration (5 demos)"
echo "  ✅ Level 2: Federation Mesh (5 demos)"
echo "  ✅ Level 3: Production Deployment (5 demos)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Key Takeaways"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Defensive by Design"
echo "   • Pattern-based detection (connections, topology, statistics)"
echo "   • NOT content-based surveillance"
echo "   • Architectural proof of defensive nature"
echo ""
echo "2. Five Threat Types"
echo "   • Genetic (WHO): Cryptographic lineage verification"
echo "   • Topology (WHERE): Layer path validation"
echo "   • Behavioral (PATTERN): Statistical anomaly detection"
echo "   • Intrusion (SIGNATURE): Pattern-based signature matching"
echo "   • Resource (CAPACITY): DoS/exhaustion detection"
echo ""
echo "3. Sovereignty Principles"
echo "   • Owner authority (YOU decide)"
echo "   • Local by default"
echo "   • Coordination without centralization"
echo "   • Export freedom"
echo ""
echo "4. Ecosystem Integration"
echo "   • Beardog: Genetic identity verification"
echo "   • Toadstool: Capability-based discovery"
echo "   • Songbird: Federated threat intelligence"
echo ""
echo "5. Production Ready"
echo "   • Zero unsafe code"
echo "   • Zero hardcoding"
echo "   • >90% test coverage"
echo "   • Full observability"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🦨 skunkBat: Reconnaissance and denial, NOT seek and destroy surveillance"
echo ""
echo "Ready to deploy? See ../README.md and specs/ for next steps!"
echo ""


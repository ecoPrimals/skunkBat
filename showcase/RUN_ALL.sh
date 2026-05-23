#!/bin/bash
set -e

echo "skunkBat Showcase — Local Primal Capabilities"
echo "=============================================="
echo ""
echo "This runs the 6 local demos demonstrating skunkBat's capabilities."
echo "Estimated time: ~10 minutes"
echo ""
echo "Press Enter to begin, or Ctrl+C to cancel..."
read -r
echo ""

cd "$(dirname "$0")/00-local-primal"

completed=0
total=0

for demo_dir in */; do
    if [ -f "$demo_dir/demo.sh" ]; then
        total=$((total + 1))
    fi
done

for demo_dir in */; do
    if [ -f "$demo_dir/demo.sh" ]; then
        completed=$((completed + 1))
        demo_name=$(basename "$demo_dir")

        echo "═══════════════════════════════════════════════════════════════"
        echo "Demo $completed/$total: $demo_name"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""

        cd "$demo_dir"
        ./demo.sh
        cd ..

        echo ""

        if [ $completed -lt $total ]; then
            echo "Press Enter to continue to next demo..."
            read -r
            echo ""
        fi
    fi
done

echo ""
echo "All $total demos complete."
echo ""
echo "Demonstrated:"
echo "  - Threat detection (5 types: genetic, behavioral, intrusion, resource, topology)"
echo "  - Graduated defense (monitor, quarantine, block)"
echo "  - Statistical baseline learning"
echo "  - Defensive vs. surveillance architecture"
echo "  - Local federation patterns"
echo ""
echo "See RECONNAISSANCE_NOT_SURVEILLANCE.md for the full ethical framework."

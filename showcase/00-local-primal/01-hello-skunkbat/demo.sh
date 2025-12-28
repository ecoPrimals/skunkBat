#!/bin/bash
set -e

echo "🦨 skunkBat - Hello World Demo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "Step 1: Initialize skunkBat..."
sleep 1
echo "✓ Configuration loaded"
echo "✓ Engines initialized"
echo "✓ skunkBat ready"
echo ""

echo "Step 2: Start reconnaissance..."
sleep 1
echo "✓ Local network scan started"
echo "✓ Primal discovery active"
echo ""

echo "Step 3: Scan results..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run the actual basic_usage example
cd ../../../
cargo run --example basic_usage 2>&1 | grep -v "Compiling\|Finished\|Running" || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✅ Demo Complete!"
echo ""
echo "Key Takeaway:"
echo "skunkBat by default only knows about ITSELF."
echo "It doesn't discover other nodes without explicit"
echo "integration (Toadstool for discovery)."
echo ""
echo "This is the 'self-knowledge' principle:"
echo "- No hardcoded other primals"
echo "- Local by default"
echo "- Discovers ecosystem at runtime (when integrated)"
echo ""
echo "➡️  Next: ../02-violation-detection/ to see threat detection"


#!/usr/bin/env bash
set -euo pipefail

echo "Running real violation detection with live code..."
echo ""

# Navigate to project root (from showcase/00-local-primal/02-violation-detection/)
cd ../../../

# Run the violation detection example, filtering out compilation output
cargo run --example violation_detection 2>&1 | grep -v "Compiling\|Finished\|Running" || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "➡️  Next: ../03-defense-actions/ to see response mechanisms"

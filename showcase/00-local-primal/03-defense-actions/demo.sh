#!/usr/bin/env bash
set -euo pipefail

echo "Running defense actions demo with real code..."
echo ""

# Navigate to project root (from showcase/00-local-primal/03-defense-actions/)
cd ../../../

# Run the defense actions example
cargo run --example defense_actions 2>&1 | grep -v "Compiling\|Finished\|Running" || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "➡️  Next: ../04-baseline-learning/ to see statistical profiling"

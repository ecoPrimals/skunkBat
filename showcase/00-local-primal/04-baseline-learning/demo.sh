#!/usr/bin/env bash
set -euo pipefail

echo "Running baseline learning demo with real statistical profiler..."
echo ""

# Navigate to project root
cd ../../../

# Run the baseline learning example
cargo run --example baseline_learning 2>&1 | grep -v "Compiling\|Finished\|Running" || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "➡️  Next: ../05-local-federation/ to see federation capabilities"

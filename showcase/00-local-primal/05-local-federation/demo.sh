#!/usr/bin/env bash
set -euo pipefail

echo "Running local federation demo..."
echo ""

# Navigate to project root
cd ../../../

# Run the local federation example
cargo run --example local_federation 2>&1 | grep -v "Compiling\|Finished\|Running" || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "➡️  Next: ../06-defensive-vs-surveillance/ for philosophical proof"

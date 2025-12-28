#!/usr/bin/env bash
set -euo pipefail

echo "Running defensive vs surveillance demo..."
echo ""

# Navigate to project root
cd ../../../

# Run the defensive vs surveillance example
cargo run --example defensive_vs_surveillance 2>&1 | grep -v "Compiling\|Finished\|Running" || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 LEVEL 0 COMPLETE! Next: ../../01-ecosystem-integration/"

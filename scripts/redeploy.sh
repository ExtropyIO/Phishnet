#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"

"$SCRIPT_DIR/ecr_login.sh"
"$SCRIPT_DIR/build_push.sh"
"$SCRIPT_DIR/roll_services.sh"

echo
echo "Health check:"
"$SCRIPT_DIR/test_health.sh"

echo
echo "Sample analyze request:"
"$SCRIPT_DIR/test_analyze.sh" || true

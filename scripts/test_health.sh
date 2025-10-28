#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"

for a in intake analyzer; do
  echo "== $a =="
  curl -i "http://$ALB_DNS/$a/health" || true
  echo
done

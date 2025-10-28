#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"

curl -sS -X POST "http://$ALB_DNS/intake/analyze" \
  -H "Content-Type: application/json" \
  -d '{
        "artifact_type": "url",
        "artifact_value": "https://example.bad/phish",
        "metadata": {"source":"script-test","tags":["demo"]}
      }' | jq .

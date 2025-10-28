#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/env.sh"

# Build images from root Dockerfile, switch module per image
docker build -t "$IMG_INTAKE"   --build-arg AGENT_MODULE=agents.intake_agent   -f "$ROOT_DIR/Dockerfile" "$ROOT_DIR"
docker build -t "$IMG_ANALYZER" --build-arg AGENT_MODULE=agents.analyzer_agent -f "$ROOT_DIR/Dockerfile" "$ROOT_DIR"

# Push
docker push "$IMG_INTAKE"
docker push "$IMG_ANALYZER"

echo "Built & pushed:
  $IMG_INTAKE
  $IMG_ANALYZER"

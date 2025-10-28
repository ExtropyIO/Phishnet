#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"

for SVC in "$INTAKE_SVC_NAME" "$ANALYZER_SVC_NAME"; do
  echo "Scaling $SVC -> 0"
  aws ecs update-service --cluster "$CLUSTER" --service "$SVC" --desired-count 0 --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null
done

echo "Waiting 20s..."
sleep 20

for SVC in "$INTAKE_SVC_NAME" "$ANALYZER_SVC_NAME"; do
  echo "Scaling $SVC -> 1"
  aws ecs update-service --cluster "$CLUSTER" --service "$SVC" --desired-count 1 --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null
  aws ecs wait services-stable --cluster "$CLUSTER" --services "$SVC" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "Service stable: $SVC"
done

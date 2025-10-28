#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"

# Force ECS to pull latest image digests
aws ecs update-service --cluster "$CLUSTER" --service "$INTAKE_SVC_NAME"   --force-new-deployment --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null
aws ecs update-service --cluster "$CLUSTER" --service "$ANALYZER_SVC_NAME" --force-new-deployment --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null

echo "Triggered new deployments for $INTAKE_SVC_NAME and $ANALYZER_SVC_NAME"

# Wait for steady state
echo "Waiting for services to reach steady state..."
for SVC in "$INTAKE_SVC_NAME" "$ANALYZER_SVC_NAME"; do
  aws ecs wait services-stable --cluster "$CLUSTER" --services "$SVC" --profile "$AWS_PROFILE" --region "$AWS_REGION"
  echo "Service stable: $SVC"
done

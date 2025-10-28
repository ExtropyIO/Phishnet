#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"

aws ecs update-service --cluster "$CLUSTER" --service "$INTAKE_SVC_NAME"   --force-new-deployment --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null
aws ecs update-service --cluster "$CLUSTER" --service "$ANALYZER_SVC_NAME" --force-new-deployment --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null

echo "Triggered new deployments for $INTAKE_SVC_NAME and $ANALYZER_SVC_NAME"

echo "Waiting for services to reach steady state..."
aws ecs wait services-stable --cluster "$CLUSTER" --services "$INTAKE_SVC_NAME"   --profile "$AWS_PROFILE" --region "$AWS_REGION"
echo "Service stable: $INTAKE_SVC_NAME"
aws ecs wait services-stable --cluster "$CLUSTER" --services "$ANALYZER_SVC_NAME" --profile "$AWS_PROFILE" --region "$AWS_REGION"
echo "Service stable: $ANALYZER_SVC_NAME"

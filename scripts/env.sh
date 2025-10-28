#!/usr/bin/env bash
set -euo pipefail

# ---- EDIT THESE IF NEEDED ----
export AWS_PROFILE="${AWS_PROFILE:-tee-agents}"
export AWS_REGION="${AWS_REGION:-eu-west-1}"
# ------------------------------

export ACCOUNT_ID="$(aws sts get-caller-identity --profile "$AWS_PROFILE" --query Account --output text)"
export ECR="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

# ALB DNS (output from CDK)
export ALB_DNS="${ALB_DNS:-TeeAge-Alb16-asYi7vJYnLGj-755747286.eu-west-1.elb.amazonaws.com}"

# Image names
export IMG_INTAKE="$ECR/phishnet/agents-intake:latest"
export IMG_ANALYZER="$ECR/phishnet/agents-analyzer:latest"

# Resolve cluster ARN
export CLUSTER="$(aws ecs list-clusters --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --query 'clusterArns[?contains(@, `TeeAgentsStack-Cluster`) == `true`][0]' --output text)"

# Resolve service names (not ARNs)
export INTAKE_SVC_NAME="$(aws ecs list-services --cluster "$CLUSTER" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --query 'serviceArns[?contains(@, `intakeService`) == `true`][0]' --output text | awk -F/ '{print $NF}')"

export ANALYZER_SVC_NAME="$(aws ecs list-services --cluster "$CLUSTER" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --query 'serviceArns[?contains(@, `analyzerService`) == `true`][0]' --output text | awk -F/ '{print $NF}')"

echo "Using:
  PROFILE   = $AWS_PROFILE
  REGION    = $AWS_REGION
  ACCOUNT   = $ACCOUNT_ID
  ECR       = $ECR
  CLUSTER   = $CLUSTER
  INTAKE    = $INTAKE_SVC_NAME
  ANALYZER  = $ANALYZER_SVC_NAME
  ALB       = $ALB_DNS"

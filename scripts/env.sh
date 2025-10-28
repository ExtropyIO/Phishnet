#!/usr/bin/env bash
set -euo pipefail

# ======== BASIC CONFIGURATION ========
export AWS_PROFILE="${AWS_PROFILE:-tee-agents}"
export AWS_REGION="${AWS_REGION:-eu-west-1}"

# Your AWS account and ECR registry
export ACCOUNT_ID="$(aws sts get-caller-identity --profile "$AWS_PROFILE" --region "$AWS_REGION" --query Account --output text)"
export ECR="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

# Fixed ECS Cluster ARN
export CLUSTER="arn:aws:ecs:eu-west-1:967620967754:cluster/TeeAgentsStack-ClusterEB0386A7-XRTbN03vRS4k"

# Application Load Balancer DNS (from CDK output)
export ALB_DNS="TeeAge-Alb16-asYi7vJYnLGj-755747286.eu-west-1.elb.amazonaws.com"

# ECR image tags
export IMG_INTAKE="$ECR/phishnet/agents-intake:latest"
export IMG_ANALYZER="$ECR/phishnet/agents-analyzer:latest"

# Discover ECS service names automatically
export INTAKE_SVC_NAME="$(aws ecs list-services --cluster "$CLUSTER" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --query 'serviceArns[?contains(@, `intakeService`) == `true`][0]' --output text | awk -F/ '{print $NF}')"

export ANALYZER_SVC_NAME="$(aws ecs.list-services --cluster "$CLUSTER" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --query 'serviceArns[?contains(@, `analyzerService`) == `true`][0]' --output text | awk -F/ '{print $NF}')"

# ======== SUMMARY ========
echo "Using environment configuration:
  PROFILE   = $AWS_PROFILE
  REGION    = $AWS_REGION
  ACCOUNT   = $ACCOUNT_ID
  ECR       = $ECR
  CLUSTER   = $CLUSTER
  INTAKE    = $INTAKE_SVC_NAME
  ANALYZER  = $ANALYZER_SVC_NAME
  ALB       = $ALB_DNS"

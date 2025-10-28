#!/usr/bin/env bash
set -euo pipefail

# ========= FIXED CONFIGURATION =========
export AWS_PROFILE="${AWS_PROFILE:-tee-agents}"
export AWS_REGION="${AWS_REGION:-eu-west-1}"
export ACCOUNT_ID="967620967754"
export ECR="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
export CLUSTER="arn:aws:ecs:eu-west-1:967620967754:cluster/TeeAgentsStack-ClusterEB0386A7-XRTbN03vRS4k"
export ALB_DNS="TeeAge-Alb16-asYi7vJYnLGj-755747286.eu-west-1.elb.amazonaws.com"

# ECS service names (discovered automatically)
export INTAKE_SVC_NAME="$(aws ecs list-services --cluster "$CLUSTER" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --query 'serviceArns[?contains(@, `intakeService`) == `true`][0]' --output text | awk -F/ '{print $NF}')"

export ANALYZER_SVC_NAME="$(aws ecs list-services --cluster "$CLUSTER" --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --query 'serviceArns[?contains(@, `analyzerService`) == `true`][0]' --output text | awk -F/ '{print $NF}')"

export IMG_INTAKE="$ECR/phishnet/agents-intake:latest"
export IMG_ANALYZER="$ECR/phishnet/agents-analyzer:latest"

echo "=== Using configuration ==="
echo "PROFILE   = $AWS_PROFILE"
echo "REGION    = $AWS_REGION"
echo "ACCOUNT   = $ACCOUNT_ID"
echo "ECR       = $ECR"
echo "CLUSTER   = $CLUSTER"
echo "INTAKE    = $INTAKE_SVC_NAME"
echo "ANALYZER  = $ANALYZER_SVC_NAME"
echo "ALB       = $ALB_DNS"
echo "============================"

# ========= ECR LOGIN =========
aws ecr get-login-password --region "$AWS_REGION" --profile "$AWS_PROFILE" \
  | docker login --username AWS --password-stdin "$ECR"
echo "✅ ECR login succeeded"

# ========= BUILD & PUSH =========
docker build -t "$IMG_INTAKE"   --build-arg AGENT_MODULE=agents.intake_agent   -f Dockerfile .
docker build -t "$IMG_ANALYZER" --build-arg AGENT_MODULE=agents.analyzer_agent -f Dockerfile .

docker push "$IMG_INTAKE"
docker push "$IMG_ANALYZER"
echo "✅ Docker images built & pushed"

# ========= ROLLOUT SERVICES =========
aws ecs update-service --cluster "$CLUSTER" --service "$INTAKE_SVC_NAME" \
  --force-new-deployment --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null
aws ecs update-service --cluster "$CLUSTER" --service "$ANALYZER_SVC_NAME" \
  --force-new-deployment --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null

echo "🚀 Triggered new deployments for $INTAKE_SVC_NAME and $ANALYZER_SVC_NAME"

echo "⏳ Waiting for services to stabilize..."
aws ecs wait services-stable --cluster "$CLUSTER" --services "$INTAKE_SVC_NAME" \
  --profile "$AWS_PROFILE" --region "$AWS_REGION"
echo "✅ Intake service stable"
aws ecs wait services-stable --cluster "$CLUSTER" --services "$ANALYZER_SVC_NAME" \
  --profile "$AWS_PROFILE" --region "$AWS_REGION"
echo "✅ Analyzer service stable"

# ========= HEALTH CHECK =========
for a in intake analyzer; do
  echo
  echo "== $a health check =="
  curl -sS -i "http://$ALB_DNS/$a/health" || true
done

echo
echo "✅ Redeployment complete!"

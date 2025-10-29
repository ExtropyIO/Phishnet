#!/usr/bin/env bash
set -euo pipefail

# ========= FIXED CONFIGURATION =========
export AWS_PROFILE="${AWS_PROFILE:-tee-agents}"
export AWS_REGION="${AWS_REGION:-eu-west-1}"
export ACCOUNT_ID="967620967754"
export ECR="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
export CLUSTER="arn:aws:ecs:eu-west-1:967620967754:cluster/TeeAgentsStack-ClusterEB0386A7-XRTbN03vRS4k"
export ALB_DNS="TeeAge-Alb16-asYi7vJYnLGj-755747286.eu-west-1.elb.amazonaws.com"

# Images
export IMG_INTAKE="$ECR/phishnet/agents-intake:latest"
export IMG_ANALYZER="$ECR/phishnet/agents-analyzer:latest"

echo "=== Using configuration ===
PROFILE   = $AWS_PROFILE
REGION    = $AWS_REGION
ACCOUNT   = $ACCOUNT_ID
ECR       = $ECR
CLUSTER   = $CLUSTER
ALB       = $ALB_DNS
============================"

# ========= DISCOVER SERVICE ARNs (allow manual override first) =========
if [[ -z "${INTAKE_SVC_ARN:-}" || "$INTAKE_SVC_ARN" == "None" || "$INTAKE_SVC_ARN" == "<empty>" ]]; then
  SERVICES_RAW="$(aws ecs list-services --cluster "$CLUSTER" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query 'serviceArns' --output text 2>/dev/null || true)"
  # Convert tabs to newlines, pick first that matches -intakeService
  INTAKE_SVC_ARN="$(tr '\t' '\n' <<< "$SERVICES_RAW" | grep -m1 -E '/TeeAgentsStack-.*-?intakeService' || true)"
fi

if [[ -z "${ANALYZER_SVC_ARN:-}" || "$ANALYZER_SVC_ARN" == "None" || "$ANALYZER_SVC_ARN" == "<empty>" ]]; then
  SERVICES_RAW="${SERVICES_RAW:-$(aws ecs list-services --cluster "$CLUSTER" \
    --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --query 'serviceArns' --output text 2>/dev/null || true)}"
  ANALYZER_SVC_ARN="$(tr '\t' '\n' <<< "$SERVICES_RAW" | grep -m1 -E '/TeeAgentsStack-.*-?analyzerService' || true)"
fi

echo "Discovered:
INTAKE_SVC_ARN   = ${INTAKE_SVC_ARN:-<empty>}
ANALYZER_SVC_ARN = ${ANALYZER_SVC_ARN:-<empty>}"

if [[ -z "${INTAKE_SVC_ARN:-}" ]]; then
  echo "ERROR: Could not find intake service ARN in cluster:"
  echo "$SERVICES_RAW" | tr '\t' '\n'
  echo
  echo "Tip: export INTAKE_SVC_ARN=<full service ARN> and rerun."
  exit 1
fi
if [[ -z "${ANALYZER_SVC_ARN:-}" ]]; then
  echo "ERROR: Could not find analyzer service ARN in cluster:"
  echo "$SERVICES_RAW" | tr '\t' '\n'
  echo
  echo "Tip: export ANALYZER_SVC_ARN=<full service ARN> and rerun."
  exit 1
fi

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

# ========= ROLLOUT SERVICES (use ARNs) =========
aws ecs update-service --cluster "$CLUSTER" --service "$INTAKE_SVC_ARN" \
  --force-new-deployment --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null
aws ecs update-service --cluster "$CLUSTER" --service "$ANALYZER_SVC_ARN" \
  --force-new-deployment --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null

echo "🚀 Triggered new deployments:"
echo " - $INTAKE_SVC_ARN"
echo " - $ANALYZER_SVC_ARN"

echo "⏳ Waiting for services to stabilize..."
aws ecs wait services-stable --cluster "$CLUSTER" --services "$INTAKE_SVC_ARN" \
  --profile "$AWS_PROFILE" --region "$AWS_REGION"
echo "✅ Intake service stable"

aws ecs wait services-stable --cluster "$CLUSTER" --services "$ANALYZER_SVC_ARN" \
  --profile "$AWS_PROFILE" --region "$AWS_REGION"
echo "✅ Analyzer service stable"

# ========= HEALTH CHECK =========
for a in intake analyzer; do
  echo
  echo "== $a health =="
  curl -sS -i "http://$ALB_DNS/$a/health" || true
done

echo
echo "✅ Redeployment complete!"

#!/usr/bin/env bash
# Generate traffic for all 5 complex e2e scenarios.
# Usage: ./traffic.sh [--profile <aws-profile>] [--region <region>]
set -euo pipefail

PROFILE="default"
REGION="us-east-1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --region)  REGION="$2";  shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

AWS="aws --profile $PROFILE --region $REGION"
TF=${TERRAFORM_BIN:-$(command -v terraform1 2>/dev/null || command -v terraform 2>/dev/null || echo "$HOME/bin/terraform1.exe")}
TF_OUT() { "$TF" output -raw "$1" 2>/dev/null; }

API_URL=$(TF_OUT api_gateway_url)
ALB_URL=$(TF_OUT alb_url)
SQS_QUEUE=$(TF_OUT sqs_main_queue_url)

echo "=== API Gateway: $API_URL"
echo "=== ALB:         $ALB_URL"
echo "=== SQS Queue:   $SQS_QUEUE"
echo ""

# ── Scenario 1: ECS + ALB — hit ALB 5 times, expect 503 ─────────────────────
echo "--- Scenario 1: ECS/ALB (expect 503 — unhealthy targets)"
for i in $(seq 1 5); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$ALB_URL/" --max-time 10 || echo "ERR")
  echo "  [$i] HTTP $STATUS"
done
echo ""

# ── Scenario 2: Lambda VPC no NAT — expect 500/timeout ──────────────────────
echo "--- Scenario 2: Lambda VPC no NAT (expect 500 — no route to internet)"
for i in $(seq 1 3); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/vpc-no-nat" --max-time 15 || echo "ERR")
  echo "  [$i] HTTP $STATUS"
done
echo ""

# ── Scenario 3: SQS → DLQ — send 5 messages that will fail processing ───────
echo "--- Scenario 3: SQS DLQ (send 5 messages — all will land in DLQ)"
for i in $(seq 1 5); do
  MSG_ID=$($AWS sqs send-message \
    --queue-url "$SQS_QUEUE" \
    --message-body "{\"id\":$i,\"data\":\"test-$(date +%s)\"}" \
    --query 'MessageId' --output text)
  echo "  [$i] Sent: $MSG_ID"
done
echo "  Waiting 30s for processing + DLQ drain..."
sleep 30
DLQ_DEPTH=$($AWS sqs get-queue-attributes \
  --queue-url "$(TF_OUT sqs_dlq_url)" \
  --attribute-names ApproximateNumberOfMessages \
  --query 'Attributes.ApproximateNumberOfMessages' --output text)
echo "  DLQ depth: $DLQ_DEPTH (should be > 0)"
echo ""

# ── Scenario 4: Lambda throttle — fire 5 concurrent requests ────────────────
echo "--- Scenario 4: Lambda throttling (5 concurrent requests — expect 429/502)"
PIDS=()
for i in $(seq 1 5); do
  (
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/throttle" --max-time 15 || echo "ERR")
    echo "  [$i] HTTP $STATUS"
  ) &
  PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait "$pid" || true; done
echo ""

# ── Scenario 5: Lambda → RDS SG mismatch — expect 500/timeout ──────────────
echo "--- Scenario 5: Lambda→RDS SG mismatch (expect 500 — TCP timeout)"
for i in $(seq 1 3); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/rds-connect" --max-time 20 || echo "ERR")
  echo "  [$i] HTTP $STATUS"
done
echo ""

echo "=== Traffic generation complete."
echo "    Run 'cloudctl debug' against each resource to verify diagnosis."

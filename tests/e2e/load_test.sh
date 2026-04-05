#!/usr/bin/env bash
# Fires 200 requests at each endpoint to populate cloud monitoring data.
# Usage: ./load_test.sh <base-url>
# Example (AWS API GW): ./load_test.sh https://abc123.execute-api.us-east-1.amazonaws.com/

set -euo pipefail

BASE_URL="${1:?Usage: $0 <base-url>}"
BASE_URL="${BASE_URL%/}"   # strip trailing slash

ENDPOINTS=("healthy" "error-5xx" "error-4xx" "intermittent")
REQUESTS=50

echo "Firing ${REQUESTS} requests at each endpoint under ${BASE_URL}"
echo ""

for endpoint in "${ENDPOINTS[@]}"; do
  url="${BASE_URL}/${endpoint}"
  echo -n "  ${endpoint}: "
  ok=0; fail=0
  for _ in $(seq 1 $REQUESTS); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    if [[ "$code" == 2* ]]; then
      ok=$((ok + 1))
    else
      fail=$((fail + 1))
    fi
  done
  echo "${ok} ok  /  ${fail} errors (out of ${REQUESTS})"
done

echo ""
echo "Done. Wait ~2 minutes for metrics to appear in CloudWatch / Azure Monitor / GCP Monitoring."
echo ""
echo "Then run:"
echo "  cloudctl debug symptom \"error-5xx app returning 500s\"     --cloud aws"
echo "  cloudctl debug symptom \"error-4xx app returning 403s\"     --cloud aws"
echo "  cloudctl debug symptom \"intermittent app flapping 502s\"   --cloud aws"

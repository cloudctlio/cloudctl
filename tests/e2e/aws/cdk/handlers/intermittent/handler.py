"""
Intermittent Lambda — fails ~50 % of the time with a 502.
Simulates a flapping upstream dependency (external API, Redis, etc.).
ALB / API Gateway will show a mix of 200 and 502 in access logs.
"""
import json
import os
import random
import time


# Configurable via env var — default 50 % failure rate
FAILURE_RATE = float(os.environ.get("FAILURE_RATE", "0.5"))


def handler(event, context):
    if random.random() < FAILURE_RATE:
        # Slow then fail — mimics a timeout on an upstream service
        time.sleep(random.uniform(0.5, 2.5))
        raise ConnectionError(
            "Upstream service (payments-processor) failed to respond within 2s. "
            "Circuit breaker OPEN. Retries exhausted (3/3)."
        )

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "status":     "ok",
            "app":        "cloudctl-test-intermittent",
            "latency_ms": random.randint(50, 300),
        }),
    }

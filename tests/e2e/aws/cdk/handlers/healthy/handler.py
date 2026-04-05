"""Healthy Lambda — always returns 200."""
import json
import random


def handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "status":     "ok",
            "app":        "cloudctl-test-healthy",
            "latency_ms": random.randint(10, 80),
        }),
    }

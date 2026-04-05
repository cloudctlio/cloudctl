"""
5xx Lambda — raises an unhandled exception every time.
API Gateway converts an unhandled Lambda exception into a 502 Bad Gateway.
CloudWatch Logs will show the traceback; Lambda Errors metric will spike.
"""
import json
import time
import random


def handler(event, context):
    # Simulate a slow DB call before dying (makes it look like connection pool exhaustion)
    time.sleep(random.uniform(0.2, 0.8))
    raise RuntimeError(
        "Connection pool exhausted: all 20 connections in use. "
        "RDS max_connections=100, current=98. "
        "Check DB_POOL_SIZE configuration."
    )

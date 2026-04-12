"""
Scenario 4 — Lambda throttling via reserved concurrency = 1.
Sleeps long enough to hold the single concurrency slot; concurrent
requests are throttled (TooManyRequestsException → 429/502).
Lambda Throttles metric spikes; no log entries for throttled invocations.
"""
import json
import time


def handler(event, context):
    # Hold the concurrency slot for 3 s so concurrent callers get throttled
    time.sleep(3)
    return {
        "statusCode": 200,
        "body": json.dumps({"status": "ok", "remaining_ms": context.get_remaining_time_in_millis()}),
    }

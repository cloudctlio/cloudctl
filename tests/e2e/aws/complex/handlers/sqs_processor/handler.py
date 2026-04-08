"""
Scenario 3 — SQS → Lambda with DLQ filling up.
Lambda always fails processing; after maxReceiveCount retries the message
lands in the Dead Letter Queue. DLQ depth grows, CloudWatch alarm fires.
"""
import json


def handler(event, context):
    for record in event.get("Records", []):
        body        = record.get("body", "")
        message_id  = record.get("messageId", "?")
        receive_cnt = record.get("attributes", {}).get("ApproximateReceiveCount", "?")

        print(
            f"[ERROR] Processing failed for message {message_id} "
            f"(attempt #{receive_cnt}): "
            f"Cannot deserialise payload — unexpected schema version. "
            f"body_preview={body[:80]!r}"
        )

    # Raising causes SQS to retry; after maxReceiveCount the message → DLQ
    raise ValueError(
        f"Batch processing error: {len(event.get('Records', []))} message(s) failed. "
        "Schema version mismatch — expected v2, got v1. "
        "All messages will be moved to the Dead Letter Queue."
    )

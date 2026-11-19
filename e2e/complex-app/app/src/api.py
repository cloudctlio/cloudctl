"""Orders API: POST /orders queues a new order, GET /orders/{id} reads it back."""
import json
import logging
import os
import socket
import time
import uuid

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

TABLE = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
SQS = boto3.client("sqs")
QUEUE_URL = os.environ["QUEUE_URL"]
CACHE_ENDPOINT = os.environ.get("CACHE_ENDPOINT", "")


def _resp(code, body):
    return {"statusCode": code, "headers": {"content-type": "application/json"},
            "body": json.dumps(body, default=str)}


def _warm_cache():
    """Optional read-through cache. Failure is non-fatal: we fall back to DynamoDB."""
    if not CACHE_ENDPOINT:
        return
    host, _, port = CACHE_ENDPOINT.replace("redis://", "").partition(":")
    try:
        with socket.create_connection((host, int(port or 6379)), timeout=0.2):
            pass
    except OSError:
        log.exception("ERROR cache warmup failed for %s, falling back to DynamoDB", CACHE_ENDPOINT)


def create_order(body):
    order = {
        "order_id": str(uuid.uuid4()),
        "status": "PENDING",
        "items": int(body.get("items", 1)),
        "receipt": bool(body.get("receipt", False)),
        "customer": str(body.get("customer", "anon"))[:64],
        "created_at": int(time.time()),
    }
    TABLE.put_item(Item=order)
    SQS.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps(order))
    log.info("queued order %s items=%s receipt=%s", order["order_id"], order["items"], order["receipt"])
    return _resp(202, {"order_id": order["order_id"], "status": "PENDING"})


def get_order(order_id):
    _warm_cache()
    item = TABLE.get_item(Key={"order_id": order_id}).get("Item")
    if not item:
        return _resp(404, {"error": "not found"})
    return _resp(200, item)


def handler(event, _context):
    route = event.get("routeKey", "")
    if route == "POST /orders":
        return create_order(json.loads(event.get("body") or "{}"))
    if route == "GET /orders/{id}":
        return get_order(event["pathParameters"]["id"])
    return _resp(404, {"error": f"no route {route}"})

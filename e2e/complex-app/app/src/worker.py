"""Order worker: SQS -> charge (simulated) -> receipt to S3 -> PROCESSED -> OrderProcessed event."""
import json
import logging
import os
import time

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

TABLE = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
S3 = boto3.client("s3")
EVENTS = boto3.client("events")
BUCKET = os.environ["RECEIPT_BUCKET"]
BUS = os.environ["BUS_NAME"]
BASE_MS = int(os.environ.get("BASE_MS", "200"))
ITEM_MS = int(os.environ.get("ITEM_MS", "300"))


def process(order):
    oid = order["order_id"]
    # Simulated payment call: larger orders take longer.
    time.sleep((BASE_MS + ITEM_MS * int(order.get("items", 1))) / 1000.0)
    if order.get("receipt"):
        S3.put_object(Bucket=BUCKET, Key=f"receipts/{oid}.json",
                      Body=json.dumps(order).encode(), ContentType="application/json")
    TABLE.update_item(Key={"order_id": oid},
                      UpdateExpression="SET #s = :s, processed_at = :t",
                      ExpressionAttributeNames={"#s": "status"},
                      ExpressionAttributeValues={":s": "PROCESSED", ":t": int(time.time())})
    EVENTS.put_events(Entries=[{"Source": "cctl.orders", "DetailType": "OrderProcessed",
                                "Detail": json.dumps({"order_id": oid}), "EventBusName": BUS}])
    log.info("processed order %s items=%s receipt=%s", oid, order.get("items"), order.get("receipt"))


def handler(event, _context):
    for record in event["Records"]:
        process(json.loads(record["body"]))

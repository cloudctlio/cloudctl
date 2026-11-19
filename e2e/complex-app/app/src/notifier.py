"""Notifier: OrderProcessed event -> (simulated) customer email -> marks the order notified."""
import logging
import os
import time

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

TABLE = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])


def handler(event, _context):
    oid = event["detail"]["order_id"]
    TABLE.update_item(Key={"order_id": oid},
                      UpdateExpression="SET notified = :t",
                      ExpressionAttributeValues={":t": int(time.time())})
    log.info("notified customer for order %s", oid)

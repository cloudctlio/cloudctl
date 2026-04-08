"""
Scenario 5 — Lambda ↔ RDS security group mismatch.
Lambda's SG is not in the RDS SG's inbound allow-list, so the TCP
handshake never completes — connection times out at the network layer.
"""
import json
import os
import socket


DB_HOST    = os.environ.get("DB_HOST", "")
DB_PORT    = int(os.environ.get("DB_PORT", "5432"))
TIMEOUT_S  = 5


def handler(event, context):
    if not DB_HOST:
        return {"statusCode": 500, "body": json.dumps({"error": "DB_HOST not set"})}

    try:
        sock = socket.create_connection((DB_HOST, DB_PORT), timeout=TIMEOUT_S)
        sock.close()
        return {"statusCode": 200, "body": json.dumps({"status": "connected", "host": DB_HOST})}

    except socket.timeout:
        print(
            f"[ERROR] TCP timeout connecting to RDS {DB_HOST}:{DB_PORT} after {TIMEOUT_S}s. "
            "Security group on RDS does not allow inbound port 5432 from this Lambda's "
            "security group. Check RDS inbound rules — only rds-access-sg is whitelisted, "
            "but this Lambda uses lambda-sg."
        )
        raise TimeoutError(
            f"Cannot connect to RDS at {DB_HOST}:{DB_PORT} — "
            "TCP connection timed out. Security group mismatch: "
            "lambda-sg is not in the RDS inbound allow-list."
        )

    except OSError as exc:
        print(f"[ERROR] Network error connecting to RDS {DB_HOST}:{DB_PORT}: {exc}")
        raise

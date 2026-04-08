"""
Scenario 2 — Lambda in private VPC with no NAT Gateway.
Tries to reach an external HTTPS endpoint; connection times out because
the private subnet has no default route to the internet.
"""
import json
import urllib.request
import socket


EXTERNAL_URL = "https://checkip.amazonaws.com"
TIMEOUT_S    = 5


def handler(event, context):
    try:
        with urllib.request.urlopen(EXTERNAL_URL, timeout=TIMEOUT_S) as resp:
            body = resp.read().decode()
        return {"statusCode": 200, "body": json.dumps({"ip": body.strip()})}
    except socket.timeout:
        print(
            f"[ERROR] socket.timeout: Cannot reach {EXTERNAL_URL} after {TIMEOUT_S}s. "
            "Private subnet has no NAT Gateway — no default route to internet. "
            "Packets are dropped at the route table."
        )
        raise
    except OSError as exc:
        print(
            f"[ERROR] OSError({exc}): Network unreachable from private subnet. "
            f"Check route table — missing 0.0.0.0/0 → NAT Gateway entry."
        )
        raise

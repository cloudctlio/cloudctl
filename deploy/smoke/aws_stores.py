"""Live check of the control plane's AWS stores, for a person to run by hand.

Exercises the real code against the real DynamoDB table and S3 Object Lock
bucket that deploy/terraform/aws created:

    python deploy/smoke/aws_stores.py --table cctl-control-plane \
        --bucket <audit_bucket output> --kms-key <kms_key_arn output> \
        --region us-east-1 --profile <profile>

DynamoDB: readiness (key schema, TTL), create-only and versioned writes,
conflicts, a scan, leases between two owners, then deletes everything it wrote.

S3: Object Lock readiness, then writes TWO hash-chained audit records and
verifies the chain. Those two objects are locked in COMPLIANCE mode for
--retain-days (default 1) and cannot be deleted by anyone until then.
Pass --skip-audit to leave the bucket untouched. Once the lock has expired,
--delete-smoke-objects removes them so the bucket can be destroyed.

Nothing else is created. Exit code 0 means every check passed.
"""
from __future__ import annotations

import argparse
import sys
import uuid


def check(name: str, cond: bool) -> None:
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        raise SystemExit(1)


def dynamodb(table: str, region: str, profile: str | None) -> None:
    import boto3

    from cloudctl.controlplane import kv as K

    client = boto3.Session(profile_name=profile, region_name=region).client("dynamodb")
    db = K.DynamoDBKV(table, client=client)
    db.check_ready()
    check("dynamodb: table has ns/k keys and TTL on 'ttl'", True)
    ns, key = "smoke", "k-" + uuid.uuid4().hex[:12]
    lease = "smoke-" + uuid.uuid4().hex[:12]
    try:
        v1 = db.put(ns, key, {"n": 1}, expect=K.ABSENT)
        try:
            db.put(ns, key, {"n": 9}, expect=K.ABSENT)
            check("dynamodb: second create-only write is refused", False)
        except K.Conflict:
            check("dynamodb: second create-only write is refused", True)
        v2 = db.put(ns, key, {"n": 2}, expect=v1)
        try:
            db.put(ns, key, {"n": 3}, expect=v1)
            check("dynamodb: stale-version write is refused", False)
        except K.Conflict:
            check("dynamodb: stale-version write is refused", True)
        it = db.get(ns, key)
        check("dynamodb: read back the latest version", it is not None and it.doc == {"n": 2} and it.version == v2)
        check("dynamodb: scan finds the item", any(i.key == key for i in db.scan(ns)))
        check("dynamodb: lease taken by owner a", db.acquire(lease, "a", 60))
        check("dynamodb: lease refused to owner b", not db.acquire(lease, "b", 60))
        db.release(lease, "a")
        check("dynamodb: lease free after release", db.acquire(lease, "b", 60))
    finally:
        db.delete(ns, key)
        db.release(lease, "b")
        try:
            db.delete("lease", lease)
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass
    check("dynamodb: cleaned up", db.get(ns, key) is None)


def s3_audit(bucket: str, kms_key: str | None, region: str, profile: str | None, retain_days: int) -> None:
    from cloudctl.gate.audit import AuditLog, ObjectStoreSink, S3ObjectLockBackend

    backend = S3ObjectLockBackend(bucket, region=region, profile=profile, mode="COMPLIANCE", kms_key_id=kms_key)
    chain = "smoke-" + uuid.uuid4().hex[:8]
    sink = ObjectStoreSink(backend, prefix="cctl-smoke", chain=chain, retain_days=retain_days)
    log = AuditLog(sink, chain=chain, actor="smoke-test")
    log.check_ready()
    check("s3: bucket has Object Lock and versioning", True)
    log.append("smoke.first", {"note": "live check"})
    log.append("smoke.second", {"note": "live check"})
    res = log.verify()
    check(f"s3: two records written and the chain verifies ({res.records} records)", res.ok and res.records == 2)
    # Read the lock back from S3 itself rather than estimating it.
    from datetime import datetime, timedelta, timezone
    client = getattr(backend, "client", None)
    keys = list(backend.list_keys(sink.base))
    check("s3: two objects stored", len(keys) == 2)
    if client is not None:
        latest = None
        for k in keys:
            h = client.head_object(Bucket=bucket, Key=k)
            until = h.get("ObjectLockRetainUntilDate")
            check(f"s3: {k.rsplit('/', 1)[-1]} is locked in COMPLIANCE mode", h.get("ObjectLockMode") == "COMPLIANCE")
            expected = datetime.now(timezone.utc) + timedelta(days=retain_days)
            check(f"s3: {k.rsplit('/', 1)[-1]} retain-until is about {retain_days} day(s) out",
                  until is not None and abs((until - expected).total_seconds()) < 3600)
            latest = until if latest is None or until > latest else latest
        print(f"NOTE  s3://{bucket}/{sink.base} holds 2 objects locked until "
              f"{latest.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} (read from S3; now is "
              f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}); the bucket cannot be deleted before then")


def delete_smoke_objects(bucket: str, region: str, profile: str | None) -> None:
    """Delete every version under cctl-smoke/ (works only once the lock has expired)."""
    import boto3
    s3 = boto3.Session(profile_name=profile, region_name=region).client("s3")
    n = 0
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix="cctl-smoke/"):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
            n += 1
    print(f"deleted {n} object version(s) under s3://{bucket}/cctl-smoke/")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--table", required=True)
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--kms-key")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--profile")
    ap.add_argument("--retain-days", type=int, default=1)
    ap.add_argument("--skip-audit", action="store_true")
    ap.add_argument("--delete-smoke-objects", action="store_true",
                    help="Only delete the smoke audit objects (after their lock has expired), then stop.")
    a = ap.parse_args()
    if a.delete_smoke_objects:
        delete_smoke_objects(a.bucket, a.region, a.profile)
        return 0
    dynamodb(a.table, a.region, a.profile)
    if not a.skip_audit:
        s3_audit(a.bucket, a.kms_key, a.region, a.profile, a.retain_days)
    print("ALL PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

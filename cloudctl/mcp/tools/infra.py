"""MCP tool implementations for cloud infrastructure queries."""
from __future__ import annotations

import json
from typing import Any

from cloudctl.mcp.context import get_cfg
from cloudctl.ai.data_fetcher import DataFetcher


def _fetcher() -> DataFetcher:
    return DataFetcher(get_cfg())


def _direct_aws(profile: str | None = None, region: str | None = None) -> dict:
    """Fall back to boto3 directly — works even with no cloudctl config."""
    import boto3
    sess   = boto3.Session(profile_name=profile, region_name=region or "us-east-1")
    result: dict = {}

    try:
        ec2 = sess.client("ec2")
        reservations = ec2.describe_instances().get("Reservations", [])
        instances = [
            {
                "id":     i["InstanceId"],
                "type":   i["InstanceType"],
                "state":  i["State"]["Name"],
                "region": sess.region_name,
                "name":   next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), ""),
            }
            for r in reservations for i in r.get("Instances", [])
        ]
        if instances:
            result["compute"] = instances
    except Exception:
        pass

    try:
        s3 = sess.client("s3")
        buckets = [{"name": b["Name"], "region": "global"} for b in s3.list_buckets().get("Buckets", [])]
        if buckets:
            result["storage"] = buckets
    except Exception:
        pass

    try:
        rds = sess.client("rds")
        dbs = [
            {
                "id":     d["DBInstanceIdentifier"],
                "engine": d["Engine"],
                "state":  d["DBInstanceStatus"],
                "region": sess.region_name,
            }
            for d in rds.describe_db_instances().get("DBInstances", [])
        ]
        if dbs:
            result["databases"] = dbs
    except Exception:
        pass

    return result


def _ensure_aws_configured(cfg) -> None:
    """If no clouds configured, synthesise an 'aws' entry from the environment."""
    if not cfg.clouds:
        cfg._data["clouds"] = ["aws"]
        cfg._data["accounts"] = {"aws": [{"name": "default"}]}


def list_compute(cloud: str = "all", account: str = "", region: str = "") -> str:
    """List compute instances across clouds."""
    cfg = get_cfg()
    _ensure_aws_configured(cfg)
    try:
        ctx = DataFetcher(cfg).fetch_summary(
            cloud=cloud,
            account=account or None,
            region=region or None,
            include=["compute"],
        )
        if ctx:
            return json.dumps(ctx, default=str)
    except Exception:
        pass
    # Direct fallback
    return json.dumps(_direct_aws(account or None, region or None), default=str)


def list_storage(cloud: str = "all", account: str = "", region: str = "") -> str:
    """List storage buckets/accounts across clouds."""
    cfg = get_cfg()
    _ensure_aws_configured(cfg)
    try:
        ctx = DataFetcher(cfg).fetch_summary(
            cloud=cloud,
            account=account or None,
            region=region or None,
            include=["storage"],
        )
        if ctx:
            return json.dumps(ctx, default=str)
    except Exception:
        pass
    return json.dumps(_direct_aws(account or None, region or None), default=str)


def list_databases(cloud: str = "all", account: str = "", region: str = "") -> str:
    """List database instances across clouds."""
    cfg = get_cfg()
    _ensure_aws_configured(cfg)
    try:
        ctx = DataFetcher(cfg).fetch_summary(
            cloud=cloud,
            account=account or None,
            region=region or None,
            include=["database"],
        )
        if ctx:
            return json.dumps(ctx, default=str)
    except Exception:
        pass
    return json.dumps(_direct_aws(account or None, region or None), default=str)


def get_inventory(cloud: str = "all", account: str = "", region: str = "") -> str:
    """Get full infrastructure inventory for an account."""
    cfg = get_cfg()
    _ensure_aws_configured(cfg)
    try:
        ctx = DataFetcher(cfg).fetch_summary(
            cloud=cloud,
            account=account or None,
            region=region or None,
        )
        if ctx:
            return json.dumps(ctx, default=str)
    except Exception:
        pass
    return json.dumps(_direct_aws(account or None, region or None), default=str)


def check_security(cloud: str = "all", account: str = "") -> str:
    """Run security audit across cloud accounts."""
    cfg = get_cfg()
    _ensure_aws_configured(cfg)
    try:
        ctx = DataFetcher(cfg).fetch_summary(
            cloud=cloud,
            account=account or None,
            include=["security"],
        )
        if ctx:
            return json.dumps(ctx, default=str)
    except Exception:
        pass
    # Direct security check
    import boto3
    sess = boto3.Session(profile_name=account or None)
    findings: dict = {}
    try:
        s3 = sess.client("s3")
        public = []
        for b in s3.list_buckets().get("Buckets", []):
            try:
                acl = s3.get_bucket_acl(Bucket=b["Name"])
                for g in acl.get("Grants", []):
                    if g.get("Grantee", {}).get("URI", "").endswith("AllUsers"):
                        public.append(b["Name"])
            except Exception:
                pass
        findings["public_buckets"] = public
    except Exception:
        pass
    return json.dumps(findings, default=str)


def list_accounts() -> str:
    """List all configured cloud accounts."""
    cfg = get_cfg()
    _ensure_aws_configured(cfg)
    return json.dumps({
        "clouds":   cfg.clouds,
        "accounts": cfg.accounts,
    }, default=str)

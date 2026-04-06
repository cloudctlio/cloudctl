"""MCP tool implementations for cloud actions (write operations).

All actions default to dry_run=True. Pass dry_run=False to execute.
"""
from __future__ import annotations

import json
from typing import Any


def stop_compute(
    instance_id: str,
    cloud: str = "aws",
    account: str = "",
    region: str = "",
    dry_run: bool = True,
) -> str:
    """Stop a compute instance. Defaults to dry_run=True."""
    if dry_run:
        return json.dumps({
            "dry_run": True,
            "action": "stop_compute",
            "instance_id": instance_id,
            "cloud": cloud,
            "account": account or "default",
            "region": region or "default",
            "description": f"Would stop {cloud} instance {instance_id}. Pass dry_run=false to execute.",
        })

    if cloud == "aws":
        try:
            import boto3  # noqa: PLC0415
            sess = boto3.Session(profile_name=account or "default", region_name=region or None)
            ec2 = sess.client("ec2")
            ec2.stop_instances(InstanceIds=[instance_id])
            return json.dumps({"success": True, "action": "stop_compute", "instance_id": instance_id})
        except Exception as e:
            return json.dumps({"error": str(e), "instance_id": instance_id})
    return json.dumps({"error": f"stop_compute not supported for cloud '{cloud}' yet"})


def start_compute(
    instance_id: str,
    cloud: str = "aws",
    account: str = "",
    region: str = "",
    dry_run: bool = True,
) -> str:
    """Start a compute instance. Defaults to dry_run=True."""
    if dry_run:
        return json.dumps({
            "dry_run": True,
            "action": "start_compute",
            "instance_id": instance_id,
            "cloud": cloud,
            "account": account or "default",
            "region": region or "default",
            "description": f"Would start {cloud} instance {instance_id}. Pass dry_run=false to execute.",
        })

    if cloud == "aws":
        try:
            import boto3  # noqa: PLC0415
            sess = boto3.Session(profile_name=account or "default", region_name=region or None)
            ec2 = sess.client("ec2")
            ec2.start_instances(InstanceIds=[instance_id])
            return json.dumps({"success": True, "action": "start_compute", "instance_id": instance_id})
        except Exception as e:
            return json.dumps({"error": str(e), "instance_id": instance_id})
    return json.dumps({"error": f"start_compute not supported for cloud '{cloud}' yet"})

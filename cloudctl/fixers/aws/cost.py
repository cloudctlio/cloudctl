"""AWS cost fixers — stop idle instances, delete orphaned volumes, remove old snapshots.

Deleting a volume or snapshot destroys data. Under the policy gate that is a
MEDIUM finding outside production and a CRITICAL one (rejected) in
production: the gate does not let an automated cost fix delete prod data.
"""
from __future__ import annotations

import re
from typing import Any

from cloudctl.fixers.aws.security import _act, _rc, _region
from cloudctl.fixers.base import BaseFixer, aws_session
from cloudctl.fixers.registry import register


def _find(pattern: str, issue: dict, what: str) -> str:
    resource = issue.get("resource", "")
    match = re.search(pattern, resource)
    if not match:
        raise ValueError(f"Could not parse {what} from: {resource}")
    return match.group(1)


@register
class AWSStopIdleInstanceFixer(BaseFixer):
    """Stops EC2 instances identified as idle."""

    cloud = "aws"
    supported_issue_types = ["idle_instance", "stopped_unused"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("ec2" in resource or "i-" in resource) and (
            "idle" in issue_text or "unused" in issue_text or "low cpu" in issue_text
        )

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        iid = _find(r"(i-[a-z0-9]+)", issue, "instance ID")
        region = _region(issue, env)
        return [_rc(address=f"ec2/{iid}", type="aws_instance", action=_act("update"), name=iid,
                    location=region or "", before={"instance_state": "running", "region": region},
                    after={"instance_state": "stopped", "region": region}, operations=("ec2:StopInstances",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        instance_id = _find(r"(i-[a-z0-9]+)", issue, "instance ID")
        ec2 = aws_session(issue, creds, issue.get("region")).client("ec2")
        ec2.stop_instances(InstanceIds=[instance_id])


@register
class AWSDeleteOrphanedVolumeFixer(BaseFixer):
    """Deletes EBS volumes that are unattached and identified as orphaned."""

    cloud = "aws"
    supported_issue_types = ["orphaned_volume", "unattached_ebs"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("vol-" in resource or "ebs" in resource or "volume" in resource) and (
            "orphan" in issue_text or "unattached" in issue_text or "unused" in issue_text
        )

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        vid = _find(r"(vol-[a-z0-9]+)", issue, "volume ID")
        region = _region(issue, env)
        ec2 = aws_session(issue, creds, region).client("ec2")
        vols = ec2.describe_volumes(VolumeIds=[vid]).get("Volumes") or []
        if not vols:
            return []
        v = vols[0]
        if v.get("Attachments"):
            from cloudctl.gate.models import PlanError  # noqa: PLC0415
            raise PlanError(f"{vid} is attached to an instance; it is not orphaned")
        return [_rc(address=f"ebs/{vid}", type="aws_ebs_volume", action=_act("delete"), name=vid,
                    location=region or "",
                    before={"size": v.get("Size"), "state": v.get("State"), "encrypted": v.get("Encrypted"),
                            "region": region},
                    after=None, operations=("ec2:DeleteVolume",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        volume_id = _find(r"(vol-[a-z0-9]+)", issue, "volume ID")
        ec2 = aws_session(issue, creds, issue.get("region")).client("ec2")
        ec2.delete_volume(VolumeId=volume_id)


@register
class AWSDeleteOldSnapshotFixer(BaseFixer):
    """Deletes EBS snapshots older than the retention policy."""

    cloud = "aws"
    supported_issue_types = ["old_snapshot", "snapshot_cleanup"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("snap-" in resource or "snapshot" in resource) and (
            "old" in issue_text or "retention" in issue_text or "expired" in issue_text
        )

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        sid = _find(r"(snap-[a-z0-9]+)", issue, "snapshot ID")
        region = _region(issue, env)
        return [_rc(address=f"snapshot/{sid}", type="aws_ebs_snapshot", action=_act("delete"), name=sid,
                    location=region or "", before={"region": region}, after=None,
                    operations=("ec2:DeleteSnapshot",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        snapshot_id = _find(r"(snap-[a-z0-9]+)", issue, "snapshot ID")
        ec2 = aws_session(issue, creds, issue.get("region")).client("ec2")
        ec2.delete_snapshot(SnapshotId=snapshot_id)

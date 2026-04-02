"""AWS cost fixers — stop idle instances, delete orphaned volumes, remove old snapshots."""
from __future__ import annotations

from cloudctl.fixers.base import BaseFixer
from cloudctl.fixers.registry import register


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

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        import re  # noqa: PLC0415
        import boto3  # noqa: PLC0415

        resource = issue.get("resource", "")
        match    = re.search(r"(i-[a-z0-9]+)", resource)
        if not match:
            raise ValueError(f"Could not parse instance ID from: {resource}")

        instance_id = match.group(1)
        account     = issue.get("account", "default")
        region      = issue.get("region")

        session = boto3.Session(profile_name=account, region_name=region)
        ec2     = session.client("ec2")
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

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        import re  # noqa: PLC0415
        import boto3  # noqa: PLC0415

        resource = issue.get("resource", "")
        match    = re.search(r"(vol-[a-z0-9]+)", resource)
        if not match:
            raise ValueError(f"Could not parse volume ID from: {resource}")

        volume_id = match.group(1)
        account   = issue.get("account", "default")
        region    = issue.get("region")

        session = boto3.Session(profile_name=account, region_name=region)
        ec2     = session.client("ec2")
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

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        import re  # noqa: PLC0415
        import boto3  # noqa: PLC0415

        resource = issue.get("resource", "")
        match    = re.search(r"(snap-[a-z0-9]+)", resource)
        if not match:
            raise ValueError(f"Could not parse snapshot ID from: {resource}")

        snapshot_id = match.group(1)
        account     = issue.get("account", "default")
        region      = issue.get("region")

        session = boto3.Session(profile_name=account, region_name=region)
        ec2     = session.client("ec2")
        ec2.delete_snapshot(SnapshotId=snapshot_id)

"""GCP cost fixers — stop idle GCE instances, delete orphaned persistent disks."""
from __future__ import annotations

from cloudctl.fixers.base import BaseFixer
from cloudctl.fixers.registry import register


@register
class GCPStopIdleInstanceFixer(BaseFixer):
    """Stops GCE instances identified as idle."""

    cloud = "gcp"
    supported_issue_types = ["idle_gce", "gcp_idle_instance"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("gce" in resource or "instance" in resource or "compute" in resource) and (
            "idle" in issue_text or "unused" in issue_text or "low cpu" in issue_text
        )

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        from googleapiclient import discovery  # noqa: PLC0415
        import google.auth  # noqa: PLC0415
        import re  # noqa: PLC0415

        resource      = issue.get("resource", "")
        project       = issue.get("account", "")
        zone          = fix_proposal.get("zone") or issue.get("region", "us-central1-a")
        name_match    = re.search(r"instances/([^\s/]+)|instance:([^\s/]+)", resource, re.IGNORECASE)
        instance_name = (name_match.group(1) or name_match.group(2)) if name_match else resource.split("/")[-1]

        creds, _ = google.auth.default()
        svc      = discovery.build("compute", "v1", credentials=creds)
        svc.instances().stop(project=project, zone=zone, instance=instance_name).execute()


@register
class GCPDeleteOrphanedDiskFixer(BaseFixer):
    """Deletes GCP persistent disks that are not attached to any instance."""

    cloud = "gcp"
    supported_issue_types = ["orphaned_pd", "unattached_disk_gcp"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("disk" in resource or "persistent" in resource) and (
            "orphan" in issue_text or "unattached" in issue_text or "unused" in issue_text
        )

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        from googleapiclient import discovery  # noqa: PLC0415
        import google.auth  # noqa: PLC0415
        import re  # noqa: PLC0415

        resource   = issue.get("resource", "")
        project    = issue.get("account", "")
        zone       = fix_proposal.get("zone") or issue.get("region", "us-central1-a")
        disk_match = re.search(r"disks/([^\s/]+)|disk:([^\s/]+)", resource, re.IGNORECASE)
        disk_name  = (disk_match.group(1) or disk_match.group(2)) if disk_match else resource.split("/")[-1]

        creds, _ = google.auth.default()
        svc      = discovery.build("compute", "v1", credentials=creds)
        svc.disks().delete(project=project, zone=zone, disk=disk_name).execute()

"""GCP cost fixers — stop idle GCE instances, delete orphaned persistent disks.

Deleting a disk destroys data: the policy gate rejects it in production.
"""
from __future__ import annotations

import re
from typing import Any

from cloudctl.fixers.base import BaseFixer, gcp_project
from cloudctl.fixers.gcp.security import _act, _build, _project_for_apply, _rc
from cloudctl.fixers.registry import register


def _name(issue: dict, pattern: str) -> str:
    resource = issue.get("resource", "")
    m = re.search(pattern, resource, re.IGNORECASE)
    return (m.group(1) or m.group(2)) if m else resource.split("/")[-1]


def _zone(issue: dict, fix_proposal: dict) -> str:
    return fix_proposal.get("zone") or issue.get("region", "us-central1-a")


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

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        name = _name(issue, r"instances/([^\s/]+)|instance:([^\s/]+)")
        project, zone = gcp_project(issue, env), _zone(issue, fix_proposal)
        return [_rc(address=f"projects/{project}/zones/{zone}/instances/{name}", type="google_compute_instance",
                    action=_act("update"), name=name, location=zone,
                    before={"project": project, "status": "RUNNING"},
                    after={"project": project, "status": "TERMINATED"},
                    operations=("compute.instances.stop",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        instance_name = _name(issue, r"instances/([^\s/]+)|instance:([^\s/]+)")
        svc = _build("compute", creds)
        svc.instances().stop(project=_project_for_apply(issue, creds), zone=_zone(issue, fix_proposal),
                             instance=instance_name).execute()


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

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        name = _name(issue, r"disks/([^\s/]+)|disk:([^\s/]+)")
        project, zone = gcp_project(issue, env), _zone(issue, fix_proposal)
        return [_rc(address=f"projects/{project}/zones/{zone}/disks/{name}", type="google_compute_disk",
                    action=_act("delete"), name=name, location=zone, before={"project": project}, after=None,
                    operations=("compute.disks.delete",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        disk_name = _name(issue, r"disks/([^\s/]+)|disk:([^\s/]+)")
        svc = _build("compute", creds)
        svc.disks().delete(project=_project_for_apply(issue, creds), zone=_zone(issue, fix_proposal),
                           disk=disk_name).execute()

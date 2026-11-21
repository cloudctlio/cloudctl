"""GCP security fixers — remove public firewall rules, remove public GCS bindings."""
from __future__ import annotations

import re
from typing import Any

from cloudctl.fixers.base import BaseFixer, gcp_credentials, gcp_project
from cloudctl.fixers.registry import register


def _rc(**kw: Any) -> Any:
    from cloudctl.gate.models import ResourceChange  # noqa: PLC0415
    return ResourceChange(cloud="gcp", **kw)


def _act(name: str) -> Any:
    from cloudctl.gate.models import Action  # noqa: PLC0415
    return Action(name)


def _build(service: str, creds: Any) -> Any:
    from googleapiclient import discovery  # noqa: PLC0415
    if creds is not None:
        return discovery.build(service, "v1", credentials=gcp_credentials(creds), cache_discovery=False)
    return discovery.build(service, "v1", credentials=gcp_credentials(None))


def _project_for_apply(issue: dict, creds: Any) -> str:
    # Under the gate, act only in the scoped project; the plan's scope rule
    # has already rejected an issue from another project.
    if creds is not None:
        return creds.scope.get("project_id", "")
    return issue.get("account", "")


def _firewall(issue: dict) -> str:
    match = re.search(r"firewalls?/([^\s/]+)", issue.get("resource", ""), re.IGNORECASE)
    if not match:
        raise ValueError(f"Could not parse firewall rule name from: {issue.get('resource', '')}")
    return match.group(1)


def _bucket(issue: dict) -> str:
    resource = issue.get("resource", "")
    match = re.search(r"gs://([^\s/]+)|buckets/([^\s/]+)", resource, re.IGNORECASE)
    return (match.group(1) or match.group(2)) if match else resource.split("/")[-1]


_PUBLIC = ("allUsers", "allAuthenticatedUsers")


@register
class GCPOpenFirewallFixer(BaseFixer):
    """Removes GCP firewall rules that allow all inbound traffic from 0.0.0.0/0."""

    cloud = "gcp"
    supported_issue_types = ["open_firewall", "gcp_public_firewall"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("firewall" in resource or "fw" in resource) and (
            "0.0.0.0/0" in issue_text or "all" in issue_text or "internet" in issue_text
        )

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        rule = _firewall(issue)
        project = gcp_project(issue, env)
        return [_rc(address=f"projects/{project}/global/firewalls/{rule}", type="google_compute_firewall",
                    action=_act("delete"), name=rule, before={"project": project}, after=None,
                    operations=("compute.firewalls.delete",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        rule_name = _firewall(issue)
        svc = _build("compute", creds)
        svc.firewalls().delete(project=_project_for_apply(issue, creds), firewall=rule_name).execute()


@register
class GCPPublicBucketFixer(BaseFixer):
    """Removes allUsers / allAuthenticatedUsers IAM bindings from GCS buckets."""

    cloud = "gcp"
    supported_issue_types = ["public_gcs", "gcs_public_access"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("gcs" in resource or "bucket" in resource or "storage" in resource) and (
            "public" in issue_text or "allusers" in issue_text or "allAuthenticatedUsers" in issue.get("issue", "")
        )

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        bucket = _bucket(issue)
        svc = _build("storage", creds)
        meta = svc.buckets().get(bucket=bucket).execute()
        policy = svc.buckets().getIamPolicy(bucket=bucket).execute()
        public = [b for b in policy.get("bindings", []) if any(m in _PUBLIC for m in b.get("members", []))]
        if not public:
            return []
        project_number = str(meta.get("projectNumber", ""))
        return [_rc(address=f"gs://{bucket}", type="google_storage_bucket_iam_policy", action=_act("update"),
                    name=bucket, location=str(meta.get("location", "")).lower(),
                    before={"bindings": [{"role": b.get("role"), "members": list(b.get("members", []))}
                                         for b in public], "project_number": project_number},
                    after={"removed_members": list(_PUBLIC), "project_number": project_number},
                    operations=("storage.buckets.setIamPolicy",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        bucket_name = _bucket(issue)
        svc = _build("storage", creds)
        policy = svc.buckets().getIamPolicy(bucket=bucket_name).execute()
        policy["bindings"] = [
            b for b in policy.get("bindings", [])
            if "allUsers" not in b.get("members", []) and "allAuthenticatedUsers" not in b.get("members", [])
        ]
        svc.buckets().setIamPolicy(bucket=bucket_name, body=policy).execute()

"""GCP security fixers — remove public firewall rules, disable public GCS buckets."""
from __future__ import annotations

from cloudctl.fixers.base import BaseFixer
from cloudctl.fixers.registry import register


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

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        from googleapiclient import discovery  # noqa: PLC0415
        import google.auth  # noqa: PLC0415
        import re  # noqa: PLC0415

        resource = issue.get("resource", "")
        project  = issue.get("account", "")
        match    = re.search(r"firewalls?/([^\s/]+)", resource, re.IGNORECASE)
        if not match:
            raise ValueError(f"Could not parse firewall rule name from: {resource}")

        rule_name = match.group(1)
        creds, _  = google.auth.default()
        svc       = discovery.build("compute", "v1", credentials=creds)
        svc.firewalls().delete(project=project, firewall=rule_name).execute()


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

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        from googleapiclient import discovery  # noqa: PLC0415
        import google.auth  # noqa: PLC0415
        import re  # noqa: PLC0415

        resource    = issue.get("resource", "")
        match       = re.search(r"gs://([^\s/]+)|buckets/([^\s/]+)", resource, re.IGNORECASE)
        bucket_name = (match.group(1) or match.group(2)) if match else resource.split("/")[-1]

        creds, _ = google.auth.default()
        svc      = discovery.build("storage", "v1", credentials=creds)
        policy   = svc.buckets().getIamPolicy(bucket=bucket_name).execute()

        bindings = [
            b for b in policy.get("bindings", [])
            if "allUsers" not in b.get("members", [])
            and "allAuthenticatedUsers" not in b.get("members", [])
        ]
        policy["bindings"] = bindings
        svc.buckets().setIamPolicy(bucket=bucket_name, body=policy).execute()

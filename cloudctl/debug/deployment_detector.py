"""Deployment method detector — identifies CDK/Terraform/Pulumi/CF/Pipeline."""
from __future__ import annotations

from typing import Optional


# Detection priority (highest first)
_IaC_METHODS = ["cdk", "terraform", "pulumi", "cloudformation", "codepipeline", "github-actions", "unknown"]


def detect(
    session,
    resource_arn: Optional[str] = None,
    resource_tags: Optional[dict] = None,
) -> str:
    """
    Detect the deployment method for a resource.
    Returns one of: cdk | terraform | pulumi | cloudformation |
                    codepipeline | github-actions | unknown
    """
    tags = resource_tags or {}

    # 1. CloudFormation stack membership
    if resource_arn:
        method = _check_cfn_stack(session, resource_arn, tags)
        if method != "unknown":
            return method

    # 2. Resource tags
    method = _check_tags(tags)
    if method != "unknown":
        return method

    # 3. CloudTrail last modifier
    if resource_arn and session:
        method = _check_cloudtrail_modifier(session, resource_arn)
        if method != "unknown":
            return method

    return "unknown"


def _check_cfn_stack(session, resource_arn: str, tags: dict) -> str:
    """Check if resource is managed by CloudFormation (CDK or raw CF)."""
    if not session:
        return "unknown"
    try:
        cf = session.client("cloudformation")
        resp = cf.describe_stack_resources(PhysicalResourceId=resource_arn)
        stacks = resp.get("StackResources", [])
        if not stacks:
            return "unknown"
        stack_name = stacks[0].get("StackName", "")
        # Get stack tags to check for CDK marker
        stack_resp = cf.describe_stacks(StackName=stack_name)
        stack_tags = {
            t["Key"]: t["Value"]
            for t in stack_resp.get("Stacks", [{}])[0].get("Tags", [])
        }
        if "aws:cdk:path" in stack_tags or any(k.startswith("aws:cdk:") for k in stack_tags):
            return "cdk"
        return "cloudformation"
    except Exception:  # noqa: BLE001
        return "unknown"


def _check_tags(tags: dict) -> str:
    """Detect IaC tool from resource tags."""
    lower_keys   = {k.lower(): v.lower() if isinstance(v, str) else "" for k, v in tags.items()}
    lower_values = {v.lower() if isinstance(v, str) else "" for v in tags.values()}

    if "terraform" in lower_keys or any("terraform" in v for v in lower_values):
        return "terraform"
    if "pulumi:project" in lower_keys or any("pulumi" in v for v in lower_values):
        return "pulumi"
    if "managed-by" in lower_keys:
        mgd = lower_keys["managed-by"]
        if "terraform" in mgd:
            return "terraform"
        if "pulumi" in mgd:
            return "pulumi"
        if "cdk" in mgd:
            return "cdk"
    return "unknown"


def _check_cloudtrail_modifier(session, resource_arn: str) -> str:
    """Look at the last CloudTrail event that modified this resource."""
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415
    try:
        ct   = session.client("cloudtrail")
        end  = datetime.now(timezone.utc)
        start = end - timedelta(hours=24)
        resp = ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": resource_arn}],
            StartTime=start,
            EndTime=end,
            MaxResults=10,
        )
        for ev in resp.get("Events", []):
            username = (ev.get("Username") or "").lower()
            if "codepipeline" in username:
                return "codepipeline"
            if "github-actions" in username or "github.com" in username:
                return "github-actions"
            if "terraform-cloud" in username or "terraform" in username:
                return "terraform"
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


def iac_drift_warning(method: str) -> Optional[str]:
    """Return a calm, factual IaC drift warning or None."""
    warnings = {
        "cdk":            "Direct changes will be overwritten on the next cdk deploy.",
        "terraform":      "Direct changes will be overwritten on the next terraform apply.",
        "pulumi":         "Direct changes will be overwritten on the next pulumi up.",
        "cloudformation": "Direct changes will be overwritten on the next stack update.",
    }
    return warnings.get(method.lower())

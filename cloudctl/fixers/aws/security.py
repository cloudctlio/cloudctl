"""AWS security fixers — block public access, tighten security groups, rotate keys."""
from __future__ import annotations

import re
from typing import Any

from cloudctl.fixers.base import BaseFixer, aws_session
from cloudctl.fixers.registry import register


def _rc(**kw: Any) -> Any:
    from cloudctl.gate.models import ResourceChange  # noqa: PLC0415
    return ResourceChange(cloud="aws", **kw)


def _act(name: str) -> Any:
    from cloudctl.gate.models import Action  # noqa: PLC0415
    return Action(name)


def _region(issue: dict, env: Any = None) -> Any:
    return issue.get("region") or (env.scope.get("region") if env is not None else None)


def _open_rules(sg: dict) -> list[dict]:
    return [
        r for r in sg.get("IpPermissions", [])
        if any(ip.get("CidrIp") == "0.0.0.0/0" for ip in r.get("IpRanges", []))
    ]


def _sg_id(issue: dict) -> str:
    match = re.search(r"sg/(sg-[a-z0-9]+)", issue.get("resource", ""))
    if not match:
        raise ValueError(f"Could not parse security group ID from: {issue.get('resource', '')}")
    return match.group(1)


def _rule_view(r: dict) -> dict:
    return {"from_port": r.get("FromPort", 0), "to_port": r.get("ToPort", 65535),
            "protocol": r.get("IpProtocol", "-1"),
            "cidr_blocks": [ip.get("CidrIp") for ip in r.get("IpRanges", []) if ip.get("CidrIp")]}


@register
class AWSOpenSecurityGroupFixer(BaseFixer):
    """Restricts security groups that allow all inbound traffic (0.0.0.0/0)."""

    cloud = "aws"
    supported_issue_types = ["open_security_group", "open_sg"]

    def can_fix(self, issue: dict) -> bool:
        resource = issue.get("resource", "")
        issue_text = issue.get("issue", "").lower()
        return (
            "sg/" in resource or "security group" in resource.lower()
        ) and (
            "0.0.0.0/0" in issue_text or "all inbound" in issue_text or "open" in issue_text
        )

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        sg_id = _sg_id(issue)
        region = _region(issue, env)
        ec2 = aws_session(issue, creds, region).client("ec2")
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        open_rules = _open_rules(sg)
        if not open_rules:
            return []
        keep = [r for r in sg.get("IpPermissions", []) if r not in open_rules]
        return [_rc(address=f"sg/{sg_id}", type="aws_security_group", action=_act("update"),
                    name=sg.get("GroupName", ""), location=region or "",
                    before={"ingress": [_rule_view(r) for r in sg.get("IpPermissions", [])], "region": region},
                    after={"ingress": [_rule_view(r) for r in keep], "region": region},
                    operations=("ec2:RevokeSecurityGroupIngress",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        """
        Revoke inbound rules that allow all traffic on the security group.
        Reads sg_id from issue['resource'] (format: sg/<id> (<name>)).
        """
        sg_id = _sg_id(issue)
        session = aws_session(issue, creds, issue.get("region"))
        ec2 = session.client("ec2")
        sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
        open_rules = _open_rules(sg)
        if open_rules:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=open_rules)


def _bucket(issue: dict) -> str:
    resource = issue.get("resource", "")
    match = re.search(r"s3/([^\s(]+)", resource)
    return match.group(1) if match else resource.split("/")[-1]


_PAB = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True}


@register
class AWSS3PublicAccessFixer(BaseFixer):
    """Blocks public access on S3 buckets."""

    cloud = "aws"
    supported_issue_types = ["public_s3", "s3_public_access"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return "s3" in resource or ("bucket" in resource and "public" in issue_text)

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        bucket = _bucket(issue)
        return [_rc(address=f"s3/{bucket}", type="aws_s3_bucket_public_access_block", action=_act("update"),
                    name=bucket,
                    after={"bucket": bucket, "block_public_acls": True, "block_public_policy": True,
                           "ignore_public_acls": True, "restrict_public_buckets": True},
                    operations=("s3:PutBucketPublicAccessBlock",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        bucket = _bucket(issue)
        session = aws_session(issue, creds)
        s3 = session.client("s3")
        owner_id = session.client("sts").get_caller_identity()["Account"]
        s3.put_public_access_block(
            Bucket=bucket,
            ExpectedBucketOwner=owner_id,
            PublicAccessBlockConfiguration=dict(_PAB),
        )


def _key_id(issue: dict) -> str:
    resource = issue.get("resource", "")
    key_id = issue.get("key_id") or (
        m.group(0) if (m := re.search(r"AKIA[A-Z0-9]{16}", resource)) else None
    )
    if not key_id:
        raise ValueError(f"Could not parse access key ID from: {resource}")
    return key_id


@register
class AWSIAMOldKeyFixer(BaseFixer):
    """Deactivates old IAM access keys (does not rotate — a human creates the new key)."""

    cloud = "aws"
    supported_issue_types = ["old_access_key", "iam_key_rotation"]

    def can_fix(self, issue: dict) -> bool:
        issue_text = issue.get("issue", "").lower()
        return "access key" in issue_text and ("old" in issue_text or "rotation" in issue_text or "days" in issue_text)

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        key_id = _key_id(issue)
        return [_rc(address=f"iam-access-key/{key_id}", type="aws_iam_access_key", action=_act("update"),
                    name=key_id, before={"status": "Active"}, after={"status": "Inactive"},
                    operations=("iam:UpdateAccessKey",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        """Deactivate the old key. User must create a new one manually."""
        key_id = _key_id(issue)
        iam = aws_session(issue, creds).client("iam")
        iam.update_access_key(AccessKeyId=key_id, Status="Inactive")

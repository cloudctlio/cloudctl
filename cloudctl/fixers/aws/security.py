"""AWS security fixers — block public access, tighten security groups, rotate keys."""
from __future__ import annotations

from cloudctl.fixers.base import BaseFixer
from cloudctl.fixers.registry import register


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

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        """
        Revoke inbound rules that allow all traffic on the security group.
        Reads sg_id from issue['resource'] (format: sg/<id> (<name>)).
        """
        import re  # noqa: PLC0415
        import boto3  # noqa: PLC0415

        resource = issue.get("resource", "")
        match = re.search(r"sg/(sg-[a-z0-9]+)", resource)
        if not match:
            raise ValueError(f"Could not parse security group ID from: {resource}")

        sg_id   = match.group(1)
        account = issue.get("account", "default")
        region  = issue.get("region")

        session = boto3.Session(profile_name=account, region_name=region)
        ec2     = session.client("ec2")
        sg      = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]

        open_rules = [
            r for r in sg.get("IpPermissions", [])
            if any(ip.get("CidrIp") == "0.0.0.0/0" for ip in r.get("IpRanges", []))
        ]
        if open_rules:
            ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=open_rules)


@register
class AWSS3PublicAccessFixer(BaseFixer):
    """Blocks public access on S3 buckets."""

    cloud = "aws"
    supported_issue_types = ["public_s3", "s3_public_access"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return "s3" in resource or ("bucket" in resource and "public" in issue_text)

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        import boto3  # noqa: PLC0415
        import re  # noqa: PLC0415

        resource = issue.get("resource", "")
        match    = re.search(r"s3/([^\s(]+)", resource)
        bucket   = match.group(1) if match else resource.split("/")[-1]
        account  = issue.get("account", "default")

        session  = boto3.Session(profile_name=account)
        s3       = session.client("s3")
        owner_id = session.client("sts").get_caller_identity()["Account"]
        s3.put_public_access_block(
            Bucket=bucket,
            ExpectedBucketOwner=owner_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls":       True,
                "IgnorePublicAcls":      True,
                "BlockPublicPolicy":     True,
                "RestrictPublicBuckets": True,
            },
        )


@register
class AWSIAMOldKeyFixer(BaseFixer):
    """Flags old IAM access keys (does not auto-rotate — requires human action)."""

    cloud = "aws"
    supported_issue_types = ["old_access_key", "iam_key_rotation"]

    def can_fix(self, issue: dict) -> bool:
        issue_text = issue.get("issue", "").lower()
        return "access key" in issue_text and ("old" in issue_text or "rotation" in issue_text or "days" in issue_text)

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        """Deactivate the old key. User must create a new one manually."""
        import boto3  # noqa: PLC0415
        import re  # noqa: PLC0415

        resource = issue.get("resource", "")
        # Accept key_id directly from the issue dict (preferred) or parse from resource
        key_id = issue.get("key_id") or (
            m.group(0) if (m := re.search(r"AKIA[A-Z0-9]{16}", resource)) else None
        )
        if not key_id:
            raise ValueError(f"Could not parse access key ID from: {resource}")

        account = issue.get("account", "default")

        session = boto3.Session(profile_name=account)
        iam     = session.client("iam")
        iam.update_access_key(AccessKeyId=key_id, Status="Inactive")

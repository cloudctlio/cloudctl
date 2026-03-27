"""AWS provider — EC2, S3, RDS implementation."""
from __future__ import annotations

from typing import Optional

import boto3
from botocore.exceptions import ClientError, ProfileNotFound

from cloudctl.providers.base import (
    CloudProvider,
    ComputeResource,
    DatabaseResource,
    StorageResource,
)


class AWSProvider(CloudProvider):
    def __init__(self, profile: str, region: Optional[str] = None) -> None:
        self._profile = profile
        self._region = region
        try:
            self._session = boto3.Session(profile_name=profile, region_name=region)
        except ProfileNotFound as e:
            raise ValueError(f"AWS profile '{profile}' not found: {e}") from e

    def _ec2(self, region: Optional[str] = None):
        return self._session.client("ec2", region_name=region or self._region)

    def _account_id(self) -> str:
        try:
            sts = self._session.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception:
            return self._profile

    # ── Compute ──────────────────────────────────────────────────────────────

    def list_compute(
        self,
        account: str,
        region: Optional[str] = None,
        state: Optional[str] = None,
        tags: Optional[dict] = None,
    ) -> list[ComputeResource]:
        ec2 = self._ec2(region)
        filters: list[dict] = []

        if state:
            filters.append({"Name": "instance-state-name", "Values": [state]})
        if tags:
            for k, v in tags.items():
                filters.append({"Name": f"tag:{k}", "Values": [v]})

        paginator = ec2.get_paginator("describe_instances")
        resources: list[ComputeResource] = []

        for page in paginator.paginate(Filters=filters):
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    resources.append(self._to_compute(inst, account, region or self._region or ""))

        return resources

    def describe_compute(self, account: str, instance_id: str) -> ComputeResource:
        ec2 = self._ec2()
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            raise ValueError(f"Instance {instance_id} not found")
        inst = reservations[0]["Instances"][0]
        return self._to_compute(inst, account, self._region or "")

    def stop_compute(self, account: str, instance_id: str) -> None:
        ec2 = self._ec2()
        try:
            ec2.stop_instances(InstanceIds=[instance_id])
        except ClientError as e:
            raise RuntimeError(f"Failed to stop {instance_id}: {e}") from e

    def start_compute(self, account: str, instance_id: str) -> None:
        ec2 = self._ec2()
        try:
            ec2.start_instances(InstanceIds=[instance_id])
        except ClientError as e:
            raise RuntimeError(f"Failed to start {instance_id}: {e}") from e

    # ── Storage (S3) ─────────────────────────────────────────────────────────

    def list_storage(
        self,
        account: str,
        public_only: bool = False,
    ) -> list[StorageResource]:
        s3 = self._session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        resources: list[StorageResource] = []

        for bucket in buckets:
            name = bucket["Name"]
            created = bucket.get("CreationDate")

            # Get bucket region
            try:
                loc = s3.get_bucket_location(Bucket=name)
                region = loc.get("LocationConstraint") or "us-east-1"
            except ClientError:
                region = "—"

            # Check public access
            is_public = False
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI", "").endswith("AllUsers"):
                        is_public = True
                        break
            except ClientError:
                pass

            if public_only and not is_public:
                continue

            # Get size (best-effort via CloudWatch — skip if unavailable)
            resources.append(StorageResource(
                id=name,
                name=name,
                region=region,
                cloud="aws",
                account=account,
                public=is_public,
                created_at=created.isoformat() if created else None,
            ))

        return resources

    def describe_storage(self, account: str, bucket_name: str) -> StorageResource:
        s3 = self._session.client("s3")
        try:
            loc = s3.get_bucket_location(Bucket=bucket_name)
            region = loc.get("LocationConstraint") or "us-east-1"
        except ClientError as e:
            raise ValueError(f"Bucket '{bucket_name}' not found: {e}") from e

        is_public = False
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                if grant.get("Grantee", {}).get("URI", "").endswith("AllUsers"):
                    is_public = True
                    break
        except ClientError:
            pass

        return StorageResource(
            id=bucket_name,
            name=bucket_name,
            region=region,
            cloud="aws",
            account=account,
            public=is_public,
        )

    # ── Database (RDS) ────────────────────────────────────────────────────────

    def list_databases(
        self,
        account: str,
        region: Optional[str] = None,
    ) -> list[DatabaseResource]:
        rds = self._session.client("rds", region_name=region or self._region)
        paginator = rds.get_paginator("describe_db_instances")
        resources: list[DatabaseResource] = []

        for page in paginator.paginate():
            for db in page["DBInstances"]:
                resources.append(self._to_database(db, account, region or self._region or ""))

        return resources

    def describe_database(self, account: str, db_id: str, region: Optional[str] = None) -> DatabaseResource:
        rds = self._session.client("rds", region_name=region or self._region)
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        instances = resp.get("DBInstances", [])
        if not instances:
            raise ValueError(f"Database '{db_id}' not found")
        return self._to_database(instances[0], account, region or self._region or "")

    def list_snapshots(self, account: str, db_id: Optional[str] = None, region: Optional[str] = None) -> list[dict]:
        rds = self._session.client("rds", region_name=region or self._region)
        kwargs = {}
        if db_id:
            kwargs["DBInstanceIdentifier"] = db_id
        paginator = rds.get_paginator("describe_db_snapshots")
        snapshots: list[dict] = []

        for page in paginator.paginate(**kwargs):
            for snap in page["DBSnapshots"]:
                created = snap.get("SnapshotCreateTime")
                snapshots.append({
                    "id": snap["DBSnapshotIdentifier"],
                    "db": snap.get("DBInstanceIdentifier", "—"),
                    "status": snap.get("Status", "—"),
                    "engine": snap.get("Engine", "—"),
                    "size_gb": snap.get("AllocatedStorage"),
                    "created_at": created.isoformat() if created else "—",
                })

        return snapshots

    # ── Helpers ───────────────────────────────────────────────────────────────

    # ── Network ───────────────────────────────────────────────────────────────

    def list_vpcs(self, account: str, region: Optional[str] = None) -> list[dict]:
        ec2 = self._ec2(region)
        resp = ec2.describe_vpcs()
        results = []
        for vpc in resp.get("Vpcs", []):
            tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
            results.append({
                "id": vpc["VpcId"],
                "name": tags.get("Name", "—"),
                "cidr": vpc.get("CidrBlock", "—"),
                "state": vpc.get("State", "—"),
                "default": vpc.get("IsDefault", False),
                "region": region or self._region or "—",
                "account": account,
            })
        return results

    def list_security_groups(self, account: str, region: Optional[str] = None, vpc_id: Optional[str] = None) -> list[dict]:
        ec2 = self._ec2(region)
        kwargs = {}
        if vpc_id:
            kwargs["Filters"] = [{"Name": "vpc-id", "Values": [vpc_id]}]
        resp = ec2.describe_security_groups(**kwargs)
        results = []
        for sg in resp.get("SecurityGroups", []):
            results.append({
                "id": sg["GroupId"],
                "name": sg.get("GroupName", "—"),
                "description": sg.get("Description", "—"),
                "vpc_id": sg.get("VpcId", "—"),
                "inbound_rules": len(sg.get("IpPermissions", [])),
                "outbound_rules": len(sg.get("IpPermissionsEgress", [])),
                "region": region or self._region or "—",
                "account": account,
            })
        return results

    # ── IAM ───────────────────────────────────────────────────────────────────

    def list_iam_roles(self, account: str) -> list[dict]:
        iam = self._session.client("iam")
        paginator = iam.get_paginator("list_roles")
        results = []
        for page in paginator.paginate():
            for role in page["Roles"]:
                created = role.get("CreateDate")
                results.append({
                    "name": role["RoleName"],
                    "id": role["RoleId"],
                    "path": role.get("Path", "/"),
                    "created": created.isoformat()[:10] if created else "—",
                    "account": account,
                })
        return results

    def list_iam_users(self, account: str) -> list[dict]:
        iam = self._session.client("iam")
        paginator = iam.get_paginator("list_users")
        results = []
        for page in paginator.paginate():
            for user in page["Users"]:
                created = user.get("CreateDate")
                last_used = user.get("PasswordLastUsed")
                results.append({
                    "username": user["UserName"],
                    "id": user["UserId"],
                    "path": user.get("Path", "/"),
                    "created": created.isoformat()[:10] if created else "—",
                    "last_login": last_used.isoformat()[:10] if last_used else "never",
                    "account": account,
                })
        return results

    def check_iam_permission(self, account: str, action: str, resource: str = "*") -> dict:
        iam = self._session.client("iam")
        sts = self._session.client("sts")
        identity = sts.get_caller_identity()
        arn = identity["Arn"]
        resp = iam.simulate_principal_policy(
            PolicySourceArn=arn,
            ActionNames=[action],
            ResourceArns=[resource],
        )
        result = resp["EvaluationResults"][0] if resp.get("EvaluationResults") else {}
        return {
            "action": action,
            "resource": resource,
            "decision": result.get("EvalDecision", "unknown"),
            "principal": arn,
        }

    # ── Cost ──────────────────────────────────────────────────────────────────

    def cost_summary(self, account: str, days: int = 30) -> list[dict]:
        from datetime import date, timedelta
        ce = self._session.client("ce", region_name="us-east-1")
        end = date.today()
        start = end - timedelta(days=days)
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
        )
        results = []
        for period in resp.get("ResultsByTime", []):
            total = period["Total"].get("UnblendedCost", {})
            results.append({
                "period": period["TimePeriod"]["Start"][:7],
                "cost": f"${float(total.get('Amount', 0)):.2f}",
                "currency": total.get("Unit", "USD"),
                "account": account,
            })
        return results

    def cost_by_service(self, account: str, days: int = 30) -> list[dict]:
        from datetime import date, timedelta
        ce = self._session.client("ce", region_name="us-east-1")
        end = date.today()
        start = end - timedelta(days=days)
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
        )
        results = []
        for period in resp.get("ResultsByTime", []):
            for group in period.get("Groups", []):
                amount = float(group["Metrics"]["UnblendedCost"].get("Amount", 0))
                if amount < 0.01:
                    continue
                results.append({
                    "service": group["Keys"][0],
                    "period": period["TimePeriod"]["Start"][:7],
                    "cost": f"${amount:.2f}",
                    "account": account,
                })
        results.sort(key=lambda x: float(x["cost"].replace("$", "")), reverse=True)
        return results

    # ── Security ──────────────────────────────────────────────────────────────

    def security_audit(self, account: str) -> list[dict]:
        """Basic security checks across the account."""
        findings = []

        # Check for public S3 buckets
        try:
            buckets = self.list_storage(account=account)
            for b in buckets:
                if b.public:
                    findings.append({
                        "severity": "HIGH",
                        "resource": f"s3://{b.name}",
                        "issue": "Bucket is publicly accessible",
                        "account": account,
                    })
        except Exception:
            pass

        # Check for security groups with open inbound (0.0.0.0/0 on all ports)
        try:
            ec2 = self._ec2()
            resp = ec2.describe_security_groups()
            for sg in resp.get("SecurityGroups", []):
                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", -1)
                    to_port = rule.get("ToPort", -1)
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0" and from_port == -1:
                            findings.append({
                                "severity": "HIGH",
                                "resource": f"sg/{sg['GroupId']} ({sg.get('GroupName','')})",
                                "issue": "Security group allows all inbound traffic (0.0.0.0/0)",
                                "account": account,
                            })
        except Exception:
            pass

        # Check for IAM users with no MFA (best-effort)
        try:
            iam = self._session.client("iam")
            users = iam.list_users().get("Users", [])
            for user in users:
                mfa = iam.list_mfa_devices(UserName=user["UserName"]).get("MFADevices", [])
                if not mfa:
                    findings.append({
                        "severity": "MEDIUM",
                        "resource": f"iam/user/{user['UserName']}",
                        "issue": "IAM user has no MFA device",
                        "account": account,
                    })
        except Exception:
            pass

        return findings

    def list_public_resources(self, account: str) -> list[dict]:
        """List all publicly accessible resources."""
        results = []
        try:
            buckets = self.list_storage(account=account, public_only=True)
            for b in buckets:
                results.append({"type": "S3 Bucket", "id": b.name, "region": b.region, "account": account})
        except Exception:
            pass
        return results

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _to_database(self, db: dict, account: str, region: str) -> DatabaseResource:
        tags = {t["Key"]: t["Value"] for t in db.get("TagList", [])}
        return DatabaseResource(
            id=db["DBInstanceIdentifier"],
            name=db.get("DBName") or db["DBInstanceIdentifier"],
            engine=f"{db.get('Engine', '—')} {db.get('EngineVersion', '')}".strip(),
            state=db.get("DBInstanceStatus", "—"),
            region=region,
            cloud="aws",
            account=account,
            instance_class=db.get("DBInstanceClass"),
            storage_gb=db.get("AllocatedStorage"),
            multi_az=db.get("MultiAZ", False),
            tags=tags,
        )

    def _to_compute(self, inst: dict, account: str, region: str) -> ComputeResource:
        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        name = tags.get("Name", inst["InstanceId"])
        launched = inst.get("LaunchTime")
        return ComputeResource(
            id=inst["InstanceId"],
            name=name,
            state=inst["State"]["Name"],
            type=inst.get("InstanceType", "—"),
            region=region,
            cloud="aws",
            account=account,
            public_ip=inst.get("PublicIpAddress"),
            private_ip=inst.get("PrivateIpAddress"),
            tags=tags,
            launched_at=launched.isoformat() if launched else None,
        )

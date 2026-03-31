"""AWS provider — full service coverage."""
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
        try:
            self._session = boto3.Session(profile_name=profile, region_name=region)
        except ProfileNotFound as e:
            raise ValueError(f"AWS profile '{profile}' not found: {e}") from e
        # Use the explicitly passed region, or fall back to what the profile defines
        self._region = region or self._session.region_name or "us-east-1"

    def _client(self, service: str, region: Optional[str] = None):
        return self._session.client(service, region_name=region or self._region)

    def _ec2(self, region: Optional[str] = None):
        return self._client("ec2", region)

    def _account_id(self) -> str:
        try:
            return self._client("sts").get_caller_identity()["Account"]
        except Exception:
            return self._profile

    # ── EC2 ──────────────────────────────────────────────────────────────────

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
        results: list[ComputeResource] = []
        for page in paginator.paginate(Filters=filters):
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    results.append(self._to_compute(inst, account, region or self._region or ""))
        return results

    def describe_compute(self, account: str, instance_id: str) -> ComputeResource:
        resp = self._ec2().describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            raise ValueError(f"Instance {instance_id} not found")
        return self._to_compute(reservations[0]["Instances"][0], account, self._region or "")

    def stop_compute(self, account: str, instance_id: str) -> None:
        try:
            self._ec2().stop_instances(InstanceIds=[instance_id])
        except ClientError as e:
            raise RuntimeError(f"Failed to stop {instance_id}: {e}") from e

    def start_compute(self, account: str, instance_id: str) -> None:
        try:
            self._ec2().start_instances(InstanceIds=[instance_id])
        except ClientError as e:
            raise RuntimeError(f"Failed to start {instance_id}: {e}") from e

    # ── Lambda ───────────────────────────────────────────────────────────────

    def list_lambda_functions(self, account: str, region: Optional[str] = None) -> list[dict]:
        lmb = self._client("lambda", region)
        paginator = lmb.get_paginator("list_functions")
        results = []
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                modified = fn.get("LastModified", "—")
                results.append({
                    "name": fn["FunctionName"],
                    "runtime": fn.get("Runtime", "—"),
                    "memory_mb": fn.get("MemorySize"),
                    "timeout_s": fn.get("Timeout"),
                    "state": fn.get("State", "Active"),
                    "last_modified": modified[:10] if modified and modified != "—" else "—",
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    # ── ECS ──────────────────────────────────────────────────────────────────

    def list_ecs_clusters(self, account: str, region: Optional[str] = None) -> list[dict]:
        ecs = self._client("ecs", region)
        arns = []
        paginator = ecs.get_paginator("list_clusters")
        for page in paginator.paginate():
            arns.extend(page.get("clusterArns", []))
        if not arns:
            return []
        clusters = ecs.describe_clusters(clusters=arns).get("clusters", [])
        results = []
        for c in clusters:
            results.append({
                "name": c["clusterName"],
                "arn": c["clusterArn"],
                "status": c.get("status", "—"),
                "running_tasks": c.get("runningTasksCount", 0),
                "pending_tasks": c.get("pendingTasksCount", 0),
                "services": c.get("activeServicesCount", 0),
                "region": region or self._region or "—",
                "account": account,
            })
        return results

    # ── EKS ──────────────────────────────────────────────────────────────────

    def _describe_eks_cluster(self, eks, name: str, account: str, region: Optional[str]) -> Optional[dict]:
        try:
            c = eks.describe_cluster(name=name)["cluster"]
            return {
                "name": c["name"],
                "version": c.get("version", "—"),
                "status": c.get("status", "—"),
                "endpoint": c.get("endpoint", "—"),
                "region": region or self._region or "—",
                "account": account,
            }
        except Exception:
            return None

    def list_eks_clusters(self, account: str, region: Optional[str] = None) -> list[dict]:
        eks = self._client("eks", region)
        paginator = eks.get_paginator("list_clusters")
        names = []
        for page in paginator.paginate():
            names.extend(page.get("clusters", []))
        results = []
        for name in names:
            entry = self._describe_eks_cluster(eks, name, account, region)
            if entry is not None:
                results.append(entry)
        return results

    # ── Auto Scaling ─────────────────────────────────────────────────────────

    def list_auto_scaling_groups(self, account: str, region: Optional[str] = None) -> list[dict]:
        asg = self._client("autoscaling", region)
        paginator = asg.get_paginator("describe_auto_scaling_groups")
        results = []
        for page in paginator.paginate():
            for g in page.get("AutoScalingGroups", []):
                results.append({
                    "name": g["AutoScalingGroupName"],
                    "min": g.get("MinSize", 0),
                    "max": g.get("MaxSize", 0),
                    "desired": g.get("DesiredCapacity", 0),
                    "instances": len(g.get("Instances", [])),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    # ── App Runner ───────────────────────────────────────────────────────────

    def list_app_runner_services(self, account: str, region: Optional[str] = None) -> list[dict]:
        try:
            ar = self._client("apprunner", region)
            paginator = ar.get_paginator("list_services")
            results = []
            for page in paginator.paginate():
                for svc in page.get("ServiceSummaryList", []):
                    results.append({
                        "name": svc["ServiceName"],
                        "arn": svc["ServiceArn"],
                        "status": svc.get("Status", "—"),
                        "url": svc.get("ServiceUrl", "—"),
                        "region": region or self._region or "—",
                        "account": account,
                    })
            return results
        except Exception:
            return []

    # ── EBS ──────────────────────────────────────────────────────────────────

    def _ebs_volume_to_dict(self, vol: dict, account: str, region: Optional[str]) -> dict:
        tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
        attachments = vol.get("Attachments", [])
        attached_to = attachments[0]["InstanceId"] if attachments else "—"
        return {
            "id": vol["VolumeId"],
            "name": tags.get("Name", "—"),
            "type": vol.get("VolumeType", "—"),
            "size_gb": vol.get("Size"),
            "state": vol.get("State", "—"),
            "iops": vol.get("Iops"),
            "encrypted": vol.get("Encrypted", False),
            "attached_to": attached_to,
            "region": region or self._region or "—",
            "account": account,
        }

    def list_ebs_volumes(self, account: str, region: Optional[str] = None) -> list[dict]:
        ec2 = self._ec2(region)
        paginator = ec2.get_paginator("describe_volumes")
        results = []
        for page in paginator.paginate():
            for vol in page.get("Volumes", []):
                results.append(self._ebs_volume_to_dict(vol, account, region))
        return results

    # ── EFS ──────────────────────────────────────────────────────────────────

    def list_efs_filesystems(self, account: str, region: Optional[str] = None) -> list[dict]:
        efs = self._client("efs", region)
        results = []
        paginator = efs.get_paginator("describe_file_systems")
        for page in paginator.paginate():
            for fs in page.get("FileSystems", []):
                tags = {t["Key"]: t["Value"] for t in fs.get("Tags", [])}
                results.append({
                    "id": fs["FileSystemId"],
                    "name": tags.get("Name", fs["FileSystemId"]),
                    "state": fs.get("LifeCycleState", "—"),
                    "size_gb": round(fs.get("SizeInBytes", {}).get("Value", 0) / (1024 ** 3), 1),
                    "encrypted": fs.get("Encrypted", False),
                    "throughput_mode": fs.get("ThroughputMode", "—"),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    # ── FSx ──────────────────────────────────────────────────────────────────

    def list_fsx_filesystems(self, account: str, region: Optional[str] = None) -> list[dict]:
        try:
            fsx = self._client("fsx", region)
            paginator = fsx.get_paginator("describe_file_systems")
            results = []
            for page in paginator.paginate():
                for fs in page.get("FileSystems", []):
                    tags = {t["Key"]: t["Value"] for t in fs.get("Tags", [])}
                    results.append({
                        "id": fs["FileSystemId"],
                        "name": tags.get("Name", "—"),
                        "type": fs.get("FileSystemType", "—"),
                        "state": fs.get("Lifecycle", "—"),
                        "size_gb": fs.get("StorageCapacity"),
                        "region": region or self._region or "—",
                        "account": account,
                    })
            return results
        except Exception:
            return []

    # ── S3 ───────────────────────────────────────────────────────────────────

    def list_storage(
        self,
        account: str,
        public_only: bool = False,
    ) -> list[StorageResource]:
        s3 = self._client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        results: list[StorageResource] = []
        for bucket in buckets:
            name = bucket["Name"]
            created = bucket.get("CreationDate")
            try:
                loc = s3.get_bucket_location(Bucket=name)
                region = loc.get("LocationConstraint") or "us-east-1"
            except ClientError:
                region = "—"
            is_public = False
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    if grant.get("Grantee", {}).get("URI", "").endswith("AllUsers"):
                        is_public = True
                        break
            except ClientError:
                pass
            if public_only and not is_public:
                continue
            results.append(StorageResource(
                id=name,
                name=name,
                region=region,
                cloud="aws",
                account=account,
                public=is_public,
                created_at=created.isoformat() if created else None,
            ))
        return results

    def describe_storage(self, account: str, bucket_name: str) -> StorageResource:
        s3 = self._client("s3")
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
            id=bucket_name, name=bucket_name, region=region,
            cloud="aws", account=account, public=is_public,
        )

    # ── RDS ──────────────────────────────────────────────────────────────────

    def list_databases(
        self,
        account: str,
        region: Optional[str] = None,
    ) -> list[DatabaseResource]:
        rds = self._client("rds", region)
        paginator = rds.get_paginator("describe_db_instances")
        results: list[DatabaseResource] = []
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                results.append(self._to_database(db, account, region or self._region or ""))
        return results

    def describe_database(self, account: str, db_id: str, region: Optional[str] = None) -> DatabaseResource:
        rds = self._client("rds", region)
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        instances = resp.get("DBInstances", [])
        if not instances:
            raise ValueError(f"Database '{db_id}' not found")
        return self._to_database(instances[0], account, region or self._region or "")

    def list_snapshots(self, _account: str, db_id: Optional[str] = None, region: Optional[str] = None) -> list[dict]:
        rds = self._client("rds", region)
        kwargs = {}
        if db_id:
            kwargs["DBInstanceIdentifier"] = db_id
        paginator = rds.get_paginator("describe_db_snapshots")
        results = []
        for page in paginator.paginate(**kwargs):
            for snap in page["DBSnapshots"]:
                created = snap.get("SnapshotCreateTime")
                results.append({
                    "id": snap["DBSnapshotIdentifier"],
                    "db": snap.get("DBInstanceIdentifier", "—"),
                    "status": snap.get("Status", "—"),
                    "engine": snap.get("Engine", "—"),
                    "size_gb": snap.get("AllocatedStorage"),
                    "created_at": created.isoformat() if created else "—",
                })
        return results

    # ── DynamoDB ─────────────────────────────────────────────────────────────

    def list_dynamodb_tables(self, account: str, region: Optional[str] = None) -> list[dict]:
        ddb = self._client("dynamodb", region)
        paginator = ddb.get_paginator("list_tables")
        names = []
        for page in paginator.paginate():
            names.extend(page.get("TableNames", []))
        results = []
        for name in names:
            try:
                t = ddb.describe_table(TableName=name)["Table"]
                results.append({
                    "name": t["TableName"],
                    "status": t.get("TableStatus", "—"),
                    "items": t.get("ItemCount", 0),
                    "size_bytes": t.get("TableSizeBytes", 0),
                    "billing_mode": t.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED"),
                    "region": region or self._region or "—",
                    "account": account,
                })
            except Exception:
                continue
        return results

    # ── ElastiCache ──────────────────────────────────────────────────────────

    def list_elasticache_clusters(self, account: str, region: Optional[str] = None) -> list[dict]:
        ec = self._client("elasticache", region)
        paginator = ec.get_paginator("describe_cache_clusters")
        results = []
        for page in paginator.paginate(ShowCacheNodeInfo=False):
            for c in page.get("CacheClusters", []):
                results.append({
                    "id": c["CacheClusterId"],
                    "engine": f"{c.get('Engine', '—')} {c.get('EngineVersion', '')}".strip(),
                    "node_type": c.get("CacheNodeType", "—"),
                    "nodes": c.get("NumCacheNodes", 0),
                    "status": c.get("CacheClusterStatus", "—"),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    # ── Redshift ─────────────────────────────────────────────────────────────

    def list_redshift_clusters(self, account: str, region: Optional[str] = None) -> list[dict]:
        rs = self._client("redshift", region)
        paginator = rs.get_paginator("describe_clusters")
        results = []
        for page in paginator.paginate():
            for c in page.get("Clusters", []):
                results.append({
                    "id": c["ClusterIdentifier"],
                    "node_type": c.get("NodeType", "—"),
                    "nodes": c.get("NumberOfNodes", 1),
                    "status": c.get("ClusterStatus", "—"),
                    "db_name": c.get("DBName", "—"),
                    "encrypted": c.get("Encrypted", False),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    # ── DocumentDB ───────────────────────────────────────────────────────────

    def list_documentdb_clusters(self, account: str, region: Optional[str] = None) -> list[dict]:
        rds = self._client("rds", region)
        paginator = rds.get_paginator("describe_db_clusters")
        results = []
        for page in paginator.paginate():
            for c in page.get("DBClusters", []):
                if c.get("Engine", "") not in ("docdb",):
                    continue
                results.append({
                    "id": c["DBClusterIdentifier"],
                    "engine": f"{c.get('Engine', '—')} {c.get('EngineVersion', '')}".strip(),
                    "status": c.get("Status", "—"),
                    "instances": len(c.get("DBClusterMembers", [])),
                    "multi_az": c.get("MultiAZ", False),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    # ── Neptune ──────────────────────────────────────────────────────────────

    def list_neptune_clusters(self, account: str, region: Optional[str] = None) -> list[dict]:
        rds = self._client("rds", region)
        paginator = rds.get_paginator("describe_db_clusters")
        results = []
        for page in paginator.paginate():
            for c in page.get("DBClusters", []):
                if c.get("Engine", "") != "neptune":
                    continue
                results.append({
                    "id": c["DBClusterIdentifier"],
                    "engine": f"neptune {c.get('EngineVersion', '')}".strip(),
                    "status": c.get("Status", "—"),
                    "instances": len(c.get("DBClusterMembers", [])),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    # ── Keyspaces ────────────────────────────────────────────────────────────

    def list_keyspaces(self, account: str, region: Optional[str] = None) -> list[dict]:
        try:
            ks = self._client("keyspaces", region)
            paginator = ks.get_paginator("list_keyspaces")
            results = []
            for page in paginator.paginate():
                for k in page.get("keyspaces", []):
                    results.append({
                        "name": k["keyspaceName"],
                        "arn": k.get("resourceArn", "—"),
                        "region": region or self._region or "—",
                        "account": account,
                    })
            return results
        except Exception:
            return []

    # ── Network ───────────────────────────────────────────────────────────────

    def list_vpcs(self, account: str, region: Optional[str] = None) -> list[dict]:
        ec2 = self._ec2(region)
        results = []
        for vpc in ec2.describe_vpcs().get("Vpcs", []):
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
        results = []
        for sg in ec2.describe_security_groups(**kwargs).get("SecurityGroups", []):
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

    def list_load_balancers(self, account: str, region: Optional[str] = None) -> list[dict]:
        elb = self._client("elbv2", region)
        paginator = elb.get_paginator("describe_load_balancers")
        results = []
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                results.append({
                    "name": lb["LoadBalancerName"],
                    "type": lb.get("Type", "—"),
                    "scheme": lb.get("Scheme", "—"),
                    "state": lb.get("State", {}).get("Code", "—"),
                    "dns": lb.get("DNSName", "—"),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    def list_route53_zones(self, account: str) -> list[dict]:
        r53 = self._client("route53", "us-east-1")
        paginator = r53.get_paginator("list_hosted_zones")
        results = []
        for page in paginator.paginate():
            for zone in page.get("HostedZones", []):
                results.append({
                    "id": zone["Id"].split("/")[-1],
                    "name": zone["Name"].rstrip("."),
                    "records": zone.get("ResourceRecordSetCount", 0),
                    "private": zone.get("Config", {}).get("PrivateZone", False),
                    "account": account,
                })
        return results

    def list_cloudfront_distributions(self, account: str) -> list[dict]:
        cf = self._client("cloudfront", "us-east-1")
        paginator = cf.get_paginator("list_distributions")
        results = []
        for page in paginator.paginate():
            items = page.get("DistributionList", {}).get("Items", [])
            for d in items:
                origins = [o["DomainName"] for o in d.get("Origins", {}).get("Items", [])]
                results.append({
                    "id": d["Id"],
                    "domain": d.get("DomainName", "—"),
                    "status": d.get("Status", "—"),
                    "enabled": d.get("Enabled", False),
                    "origins": ", ".join(origins),
                    "price_class": d.get("PriceClass", "—"),
                    "account": account,
                })
        return results

    def list_api_gateways(self, account: str, region: Optional[str] = None) -> list[dict]:
        apigw = self._client("apigateway", region)
        results = []
        try:
            for api in apigw.get_rest_apis().get("items", []):
                results.append({
                    "id": api["id"],
                    "name": api["name"],
                    "type": "REST",
                    "created": api.get("createdDate", "—"),
                    "region": region or self._region or "—",
                    "account": account,
                })
        except Exception:
            pass
        try:
            apigwv2 = self._client("apigatewayv2", region)
            paginator = apigwv2.get_paginator("get_apis")
            for page in paginator.paginate():
                for api in page.get("Items", []):
                    results.append({
                        "id": api["ApiId"],
                        "name": api["Name"],
                        "type": api.get("ProtocolType", "HTTP"),
                        "created": str(api.get("CreatedDate", "—"))[:10],
                        "region": region or self._region or "—",
                        "account": account,
                    })
        except Exception:
            pass
        return results

    def list_transit_gateways(self, account: str, region: Optional[str] = None) -> list[dict]:
        ec2 = self._ec2(region)
        paginator = ec2.get_paginator("describe_transit_gateways")
        results = []
        for page in paginator.paginate():
            for tgw in page.get("TransitGateways", []):
                tags = {t["Key"]: t["Value"] for t in tgw.get("Tags", [])}
                results.append({
                    "id": tgw["TransitGatewayId"],
                    "name": tags.get("Name", "—"),
                    "state": tgw.get("State", "—"),
                    "owner": tgw.get("OwnerId", "—"),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    def list_nat_gateways(self, account: str, region: Optional[str] = None) -> list[dict]:
        ec2 = self._ec2(region)
        paginator = ec2.get_paginator("describe_nat_gateways")
        results = []
        for page in paginator.paginate():
            for ng in page.get("NatGateways", []):
                tags = {t["Key"]: t["Value"] for t in ng.get("Tags", [])}
                results.append({
                    "id": ng["NatGatewayId"],
                    "name": tags.get("Name", "—"),
                    "state": ng.get("State", "—"),
                    "vpc_id": ng.get("VpcId", "—"),
                    "subnet_id": ng.get("SubnetId", "—"),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    def list_vpn_connections(self, account: str, region: Optional[str] = None) -> list[dict]:
        ec2 = self._ec2(region)
        results = []
        for vpn in ec2.describe_vpn_connections().get("VpnConnections", []):
            tags = {t["Key"]: t["Value"] for t in vpn.get("Tags", [])}
            results.append({
                "id": vpn["VpnConnectionId"],
                "name": tags.get("Name", "—"),
                "state": vpn.get("State", "—"),
                "type": vpn.get("Type", "—"),
                "region": region or self._region or "—",
                "account": account,
            })
        return results

    # ── IAM ───────────────────────────────────────────────────────────────────

    def list_iam_roles(self, account: str) -> list[dict]:
        iam = self._client("iam")
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
        iam = self._client("iam")
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

    def check_iam_permission(self, _account: str, action: str, resource: str = "*") -> dict:
        iam = self._client("iam")
        arn = self._client("sts").get_caller_identity()["Arn"]
        resp = iam.simulate_principal_policy(
            PolicySourceArn=arn, ActionNames=[action], ResourceArns=[resource],
        )
        result = resp["EvaluationResults"][0] if resp.get("EvaluationResults") else {}
        return {"action": action, "resource": resource, "decision": result.get("EvalDecision", "unknown"), "principal": arn}

    # ── KMS ───────────────────────────────────────────────────────────────────

    def list_kms_keys(self, account: str, region: Optional[str] = None) -> list[dict]:
        kms = self._client("kms", region)
        paginator = kms.get_paginator("list_keys")
        results = []
        for page in paginator.paginate():
            for k in page.get("Keys", []):
                try:
                    meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                    if meta.get("KeyManager") == "AWS":
                        continue  # skip AWS-managed keys
                    results.append({
                        "id": meta["KeyId"],
                        "alias": "—",
                        "state": meta.get("KeyState", "—"),
                        "usage": meta.get("KeyUsage", "—"),
                        "spec": meta.get("KeySpec", "—"),
                        "region": region or self._region or "—",
                        "account": account,
                    })
                except Exception:
                    continue
        # Enrich with aliases
        try:
            for alias in kms.list_aliases().get("Aliases", []):
                kid = alias.get("TargetKeyId")
                for r in results:
                    if r["id"] == kid:
                        r["alias"] = alias.get("AliasName", "—")
        except Exception:
            pass
        return results

    # ── Secrets Manager ──────────────────────────────────────────────────────

    def list_secrets(self, account: str, region: Optional[str] = None) -> list[dict]:
        sm = self._client("secretsmanager", region)
        paginator = sm.get_paginator("list_secrets")
        results = []
        for page in paginator.paginate():
            for s in page.get("SecretList", []):
                last_rotated = s.get("LastRotatedDate")
                results.append({
                    "name": s["Name"],
                    "arn": s["ARN"],
                    "rotation_enabled": s.get("RotationEnabled", False),
                    "last_rotated": last_rotated.isoformat()[:10] if last_rotated else "never",
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    # ── ACM Certificates ─────────────────────────────────────────────────────

    def list_acm_certificates(self, account: str, region: Optional[str] = None) -> list[dict]:
        acm = self._client("acm", region)
        paginator = acm.get_paginator("list_certificates")
        results = []
        for page in paginator.paginate():
            for cert in page.get("CertificateSummaryList", []):
                expiry = cert.get("NotAfter")
                results.append({
                    "arn": cert["CertificateArn"],
                    "domain": cert.get("DomainName", "—"),
                    "status": cert.get("Status", "—"),
                    "type": cert.get("Type", "—"),
                    "expires": expiry.isoformat()[:10] if expiry else "—",
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    # ── GuardDuty ────────────────────────────────────────────────────────────

    def list_guardduty_findings(self, account: str, region: Optional[str] = None, severity_min: float = 4.0) -> list[dict]:
        try:
            gd = self._client("guardduty", region)
            detectors = gd.list_detectors().get("DetectorIds", [])
            if not detectors:
                return []
            detector_id = detectors[0]
            finding_ids = gd.list_findings(
                DetectorId=detector_id,
                FindingCriteria={"Criterion": {"severity": {"Gte": int(severity_min)}}},
            ).get("FindingIds", [])
            if not finding_ids:
                return []
            findings = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids[:50]).get("Findings", [])
            results = []
            for f in findings:
                results.append({
                    "id": f["Id"],
                    "title": f.get("Title", "—"),
                    "severity": f.get("Severity", 0),
                    "type": f.get("Type", "—"),
                    "region": f.get("Region", region or self._region or "—"),
                    "account": account,
                })
            return results
        except Exception:
            return []

    # ── Config Rules ─────────────────────────────────────────────────────────

    def list_config_rules(self, account: str, region: Optional[str] = None) -> list[dict]:
        try:
            cfg = self._client("config", region)
            paginator = cfg.get_paginator("describe_config_rules")
            results = []
            for page in paginator.paginate():
                for rule in page.get("ConfigRules", []):
                    results.append({
                        "name": rule["ConfigRuleName"],
                        "source": rule.get("Source", {}).get("Owner", "—"),
                        "state": rule.get("ConfigRuleState", "—"),
                        "region": region or self._region or "—",
                        "account": account,
                    })
            return results
        except Exception:
            return []

    # ── WAF ──────────────────────────────────────────────────────────────────

    def list_waf_web_acls(self, account: str, region: Optional[str] = None) -> list[dict]:
        try:
            results = []
            for scope in ("REGIONAL", "CLOUDFRONT"):
                if scope == "CLOUDFRONT" and (region or self._region) not in (None, "us-east-1"):
                    continue
                r = "us-east-1" if scope == "CLOUDFRONT" else region
                try:
                    for acl in self._client("wafv2", r).list_web_acls(Scope=scope).get("WebACLs", []):
                        results.append({
                            "name": acl["Name"],
                            "id": acl["Id"],
                            "scope": scope,
                            "rules": acl.get("RulesCount", "—"),
                            "region": r or self._region or "—",
                            "account": account,
                        })
                except Exception:
                    continue
            return results
        except Exception:
            return []

    # ── CloudTrail ───────────────────────────────────────────────────────────

    def list_cloudtrail_trails(self, account: str, region: Optional[str] = None) -> list[dict]:
        ct = self._client("cloudtrail", region)
        results = []
        for trail in ct.describe_trails().get("trailList", []):
            results.append({
                "name": trail["Name"],
                "s3_bucket": trail.get("S3BucketName", "—"),
                "multi_region": trail.get("IsMultiRegionTrail", False),
                "logging": trail.get("HasCustomEventSelectors", False),
                "region": trail.get("HomeRegion", region or self._region or "—"),
                "account": account,
            })
        return results

    # ── DevOps ───────────────────────────────────────────────────────────────

    def list_pipelines(self, account: str, region: Optional[str] = None) -> list[dict]:
        cp = self._client("codepipeline", region)
        paginator = cp.get_paginator("list_pipelines")
        results = []
        for page in paginator.paginate():
            for p in page.get("pipelines", []):
                updated = p.get("updated")
                results.append({
                    "name": p["name"],
                    "version": p.get("version", "—"),
                    "updated": updated.isoformat()[:10] if updated else "—",
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    def list_codebuild_projects(self, account: str, region: Optional[str] = None) -> list[dict]:
        cb = self._client("codebuild", region)
        paginator = cb.get_paginator("list_projects")
        names = []
        for page in paginator.paginate():
            names.extend(page.get("projects", []))
        if not names:
            return []
        projects = cb.batch_get_projects(names=names[:100]).get("projects", [])
        results = []
        for p in projects:
            results.append({
                "name": p["name"],
                "source": p.get("source", {}).get("type", "—"),
                "environment": p.get("environment", {}).get("type", "—"),
                "runtime": p.get("environment", {}).get("image", "—").split(":")[-1],
                "region": region or self._region or "—",
                "account": account,
            })
        return results

    def list_cloudformation_stacks(self, account: str, region: Optional[str] = None) -> list[dict]:
        cf = self._client("cloudformation", region)
        paginator = cf.get_paginator("describe_stacks")
        results = []
        for page in paginator.paginate():
            for stack in page.get("Stacks", []):
                if stack.get("ParentId"):  # skip nested stacks
                    continue
                updated = stack.get("LastUpdatedTime") or stack.get("CreationTime")
                results.append({
                    "name": stack["StackName"],
                    "status": stack.get("StackStatus", "—"),
                    "resources": len(stack.get("Outputs", [])),
                    "updated": updated.isoformat()[:10] if updated else "—",
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    def list_ssm_parameters(self, account: str, region: Optional[str] = None, _path: str = "/") -> list[dict]:
        ssm = self._client("ssm", region)
        paginator = ssm.get_paginator("describe_parameters")
        results = []
        for page in paginator.paginate():
            for p in page.get("Parameters", []):
                modified = p.get("LastModifiedDate")
                results.append({
                    "name": p["Name"],
                    "type": p.get("Type", "—"),
                    "tier": p.get("Tier", "Standard"),
                    "modified": modified.isoformat()[:10] if modified else "—",
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    # ── Monitoring ───────────────────────────────────────────────────────────

    def list_cloudwatch_alarms(self, account: str, region: Optional[str] = None, state: Optional[str] = None) -> list[dict]:
        cw = self._client("cloudwatch", region)
        kwargs = {}
        if state:
            kwargs["StateValue"] = state.upper()
        paginator = cw.get_paginator("describe_alarms")
        results = []
        for page in paginator.paginate(**kwargs):
            for alarm in page.get("MetricAlarms", []):
                results.append({
                    "name": alarm["AlarmName"],
                    "state": alarm.get("StateValue", "—"),
                    "metric": alarm.get("MetricName", "—"),
                    "namespace": alarm.get("Namespace", "—"),
                    "threshold": alarm.get("Threshold"),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    def list_cloudwatch_dashboards(self, account: str) -> list[dict]:
        cw = self._client("cloudwatch")
        paginator = cw.get_paginator("list_dashboards")
        results = []
        for page in paginator.paginate():
            for d in page.get("DashboardEntries", []):
                modified = d.get("LastModified")
                results.append({
                    "name": d["DashboardName"],
                    "size_bytes": d.get("Size", 0),
                    "modified": modified.isoformat()[:10] if modified else "—",
                    "account": account,
                })
        return results

    def list_service_quotas(self, account: str, service_code: str, region: Optional[str] = None) -> list[dict]:
        try:
            sq = self._client("service-quotas", region)
            paginator = sq.get_paginator("list_service_quotas")
            results = []
            for page in paginator.paginate(ServiceCode=service_code):
                for q in page.get("Quotas", []):
                    results.append({
                        "name": q["QuotaName"],
                        "value": q.get("Value"),
                        "adjustable": q.get("Adjustable", False),
                        "global": q.get("GlobalQuota", False),
                        "region": region or self._region or "—",
                        "account": account,
                    })
            return results
        except Exception:
            return []

    # ── Messaging ─────────────────────────────────────────────────────────────

    def list_sqs_queues(self, account: str, region: Optional[str] = None) -> list[dict]:
        sqs = self._client("sqs", region)
        urls = sqs.list_queues().get("QueueUrls", [])
        results = []
        for url in urls:
            name = url.split("/")[-1]
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=url,
                    AttributeNames=["ApproximateNumberOfMessages", "CreatedTimestamp", "QueueArn"],
                ).get("Attributes", {})
                results.append({
                    "name": name,
                    "url": url,
                    "messages": attrs.get("ApproximateNumberOfMessages", 0),
                    "fifo": name.endswith(".fifo"),
                    "region": region or self._region or "—",
                    "account": account,
                })
            except Exception:
                results.append({"name": name, "url": url, "messages": "—", "fifo": name.endswith(".fifo"),
                                 "region": region or self._region or "—", "account": account})
        return results

    def list_sns_topics(self, account: str, region: Optional[str] = None) -> list[dict]:
        sns = self._client("sns", region)
        paginator = sns.get_paginator("list_topics")
        results = []
        for page in paginator.paginate():
            for t in page.get("Topics", []):
                arn = t["TopicArn"]
                results.append({
                    "name": arn.split(":")[-1],
                    "arn": arn,
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    def list_eventbridge_buses(self, account: str, region: Optional[str] = None) -> list[dict]:
        eb = self._client("events", region)
        paginator = eb.get_paginator("list_event_buses")
        results = []
        for page in paginator.paginate():
            for bus in page.get("EventBuses", []):
                results.append({
                    "name": bus["Name"],
                    "arn": bus.get("Arn", "—"),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    def list_kinesis_streams(self, account: str, region: Optional[str] = None) -> list[dict]:
        kinesis = self._client("kinesis", region)
        paginator = kinesis.get_paginator("list_streams")
        names = []
        for page in paginator.paginate():
            names.extend(page.get("StreamNames", []))
        results = []
        for name in names:
            try:
                s = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
                results.append({
                    "name": name,
                    "status": s.get("StreamStatus", "—"),
                    "shards": s.get("OpenShardCount", 0),
                    "retention_hours": s.get("RetentionPeriodHours", 24),
                    "region": region or self._region or "—",
                    "account": account,
                })
            except Exception:
                results.append({"name": name, "status": "—", "shards": "—",
                                 "region": region or self._region or "—", "account": account})
        return results

    def list_msk_clusters(self, account: str, region: Optional[str] = None) -> list[dict]:
        try:
            msk = self._client("kafka", region)
            paginator = msk.get_paginator("list_clusters_v2")
            results = []
            for page in paginator.paginate():
                for c in page.get("ClusterInfoList", []):
                    results.append({
                        "name": c["ClusterName"],
                        "arn": c["ClusterArn"],
                        "state": c.get("State", "—"),
                        "type": c.get("ClusterType", "—"),
                        "region": region or self._region or "—",
                        "account": account,
                    })
            return results
        except Exception:
            return []

    def list_mq_brokers(self, account: str, region: Optional[str] = None) -> list[dict]:
        try:
            mq = self._client("mq", region)
            results = []
            for broker in mq.list_brokers().get("BrokerSummaries", []):
                results.append({
                    "name": broker["BrokerName"],
                    "id": broker["BrokerId"],
                    "state": broker.get("BrokerState", "—"),
                    "engine": broker.get("EngineType", "—"),
                    "deployment": broker.get("DeploymentMode", "—"),
                    "region": region or self._region or "—",
                    "account": account,
                })
            return results
        except Exception:
            return []

    # ── Containers ───────────────────────────────────────────────────────────

    def list_ecr_repositories(self, account: str, region: Optional[str] = None) -> list[dict]:
        ecr = self._client("ecr", region)
        paginator = ecr.get_paginator("describe_repositories")
        results = []
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                created = repo.get("createdAt")
                results.append({
                    "name": repo["repositoryName"],
                    "uri": repo["repositoryUri"],
                    "scan_on_push": repo.get("imageScanningConfiguration", {}).get("scanOnPush", False),
                    "mutable": repo.get("imageTagMutability", "MUTABLE") == "MUTABLE",
                    "created": created.isoformat()[:10] if created else "—",
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    # ── AI / ML ──────────────────────────────────────────────────────────────

    def list_bedrock_models(self, account: str, region: Optional[str] = None) -> list[dict]:
        try:
            bedrock = self._client("bedrock", region or "us-east-1")
            results = []
            for model in bedrock.list_foundation_models().get("modelSummaries", []):
                results.append({
                    "id": model["modelId"],
                    "name": model.get("modelName", "—"),
                    "provider": model.get("providerName", "—"),
                    "input_modalities": ", ".join(model.get("inputModalities", [])),
                    "output_modalities": ", ".join(model.get("outputModalities", [])),
                    "region": region or self._region or "us-east-1",
                    "account": account,
                })
            return results
        except Exception:
            return []

    def list_sagemaker_endpoints(self, account: str, region: Optional[str] = None) -> list[dict]:
        try:
            sm = self._client("sagemaker", region)
            paginator = sm.get_paginator("list_endpoints")
            results = []
            for page in paginator.paginate():
                for ep in page.get("Endpoints", []):
                    modified = ep.get("LastModifiedTime")
                    results.append({
                        "name": ep["EndpointName"],
                        "status": ep.get("EndpointStatus", "—"),
                        "modified": modified.isoformat()[:10] if modified else "—",
                        "region": region or self._region or "—",
                        "account": account,
                    })
            return results
        except Exception:
            return []

    # ── Analytics ────────────────────────────────────────────────────────────

    def list_athena_workgroups(self, account: str, region: Optional[str] = None) -> list[dict]:
        athena = self._client("athena", region)
        paginator = athena.get_paginator("list_work_groups")
        results = []
        for page in paginator.paginate():
            for wg in page.get("WorkGroups", []):
                results.append({
                    "name": wg["Name"],
                    "state": wg.get("State", "—"),
                    "description": wg.get("Description", "—"),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    def list_glue_jobs(self, account: str, region: Optional[str] = None) -> list[dict]:
        glue = self._client("glue", region)
        paginator = glue.get_paginator("get_jobs")
        results = []
        for page in paginator.paginate():
            for job in page.get("Jobs", []):
                modified = job.get("LastModifiedOn")
                results.append({
                    "name": job["Name"],
                    "type": job.get("GlueVersion", "—"),
                    "worker_type": job.get("WorkerType", "—"),
                    "workers": job.get("NumberOfWorkers"),
                    "modified": modified.isoformat()[:10] if modified else "—",
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    def list_emr_clusters(self, account: str, region: Optional[str] = None) -> list[dict]:
        emr = self._client("emr", region)
        paginator = emr.get_paginator("list_clusters")
        results = []
        for page in paginator.paginate():
            for c in page.get("Clusters", []):
                results.append({
                    "id": c["Id"],
                    "name": c["Name"],
                    "state": c.get("Status", {}).get("State", "—"),
                    "region": region or self._region or "—",
                    "account": account,
                })
        return results

    def list_opensearch_domains(self, account: str, region: Optional[str] = None) -> list[dict]:
        try:
            es = self._client("es", region)
            names = [d["DomainName"] for d in es.list_domain_names().get("DomainNames", [])]
            if not names:
                return []
            domains = es.describe_elasticsearch_domains(DomainNames=names).get("DomainStatusList", [])
            results = []
            for d in domains:
                results.append({
                    "name": d["DomainName"],
                    "arn": d.get("ARN", "—"),
                    "version": d.get("ElasticsearchVersion", "—"),
                    "endpoint": d.get("Endpoint", "—"),
                    "region": region or self._region or "—",
                    "account": account,
                })
            return results
        except Exception:
            return []

    # ── Cost ──────────────────────────────────────────────────────────────────

    def cost_summary(self, account: str, days: int = 30) -> list[dict]:
        from datetime import date, timedelta
        ce = self._client("ce", "us-east-1")
        end = date.today()
        start = end - timedelta(days=days)
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
            Granularity="MONTHLY", Metrics=["UnblendedCost"],
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
        ce = self._client("ce", "us-east-1")
        end = date.today()
        start = end - timedelta(days=days)
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
            Granularity="MONTHLY", Metrics=["UnblendedCost"],
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

    def list_budgets(self, account: str) -> list[dict]:
        try:
            budgets = self._client("budgets", "us-east-1")
            account_id = self._account_id()
            paginator = budgets.get_paginator("describe_budgets")
            results = []
            for page in paginator.paginate(AccountId=account_id):
                for b in page.get("Budgets", []):
                    limit = b.get("BudgetLimit", {})
                    actual = b.get("CalculatedSpend", {}).get("ActualSpend", {})
                    results.append({
                        "name": b["BudgetName"],
                        "type": b.get("BudgetType", "—"),
                        "limit": f"${float(limit.get('Amount', 0)):.2f} {limit.get('Unit', 'USD')}",
                        "actual": f"${float(actual.get('Amount', 0)):.2f}",
                        "account": account,
                    })
            return results
        except Exception:
            return []

    def list_cost_anomalies(self, account: str) -> list[dict]:
        try:
            ce = self._client("ce", "us-east-1")
            results = []
            for anomaly in ce.get_anomalies(DateInterval={"StartDate": "2024-01-01"}).get("Anomalies", []):
                impact = anomaly.get("Impact", {})
                results.append({
                    "id": anomaly["AnomalyId"],
                    "service": anomaly.get("DimensionValue", "—"),
                    "total_impact": f"${float(impact.get('TotalImpact', 0)):.2f}",
                    "start": anomaly.get("AnomalyStartDate", "—"),
                    "end": anomaly.get("AnomalyEndDate", "open"),
                    "account": account,
                })
            return results
        except Exception:
            return []

    def list_savings_plans(self, account: str) -> list[dict]:
        try:
            sp = self._client("savingsplans", "us-east-1")
            results = []
            for plan in sp.describe_savings_plans().get("savingsPlans", []):
                end = plan.get("end")
                results.append({
                    "id": plan["savingsPlanId"],
                    "type": plan.get("savingsPlanType", "—"),
                    "commitment": f"${float(plan.get('commitment', 0)):.2f}/hr",
                    "state": plan.get("state", "—"),
                    "expires": end[:10] if end else "—",
                    "account": account,
                })
            return results
        except Exception:
            return []

    def list_reserved_instances(self, account: str, region: Optional[str] = None) -> list[dict]:
        ec2 = self._ec2(region)
        results = []
        for ri in ec2.describe_reserved_instances().get("ReservedInstances", []):
            end = ri.get("End")
            results.append({
                "id": ri["ReservedInstancesId"],
                "type": ri.get("InstanceType", "—"),
                "count": ri.get("InstanceCount", 0),
                "state": ri.get("State", "—"),
                "scope": ri.get("Scope", "—"),
                "expires": end.isoformat()[:10] if end else "—",
                "region": region or self._region or "—",
                "account": account,
            })
        return results

    # ── Backup ────────────────────────────────────────────────────────────────

    def list_backup_vaults(self, account: str, region: Optional[str] = None) -> list[dict]:
        try:
            backup = self._client("backup", region)
            paginator = backup.get_paginator("list_backup_vaults")
            results = []
            for page in paginator.paginate():
                for vault in page.get("BackupVaultList", []):
                    results.append({
                        "name": vault["BackupVaultName"],
                        "arn": vault["BackupVaultArn"],
                        "recovery_points": vault.get("NumberOfRecoveryPoints", 0),
                        "locked": vault.get("Locked", False),
                        "region": region or self._region or "—",
                        "account": account,
                    })
            return results
        except Exception:
            return []

    def list_backup_jobs(self, account: str, region: Optional[str] = None, state: Optional[str] = None) -> list[dict]:
        try:
            backup = self._client("backup", region)
            kwargs = {}
            if state:
                kwargs["ByState"] = state.upper()
            paginator = backup.get_paginator("list_backup_jobs")
            results = []
            for page in paginator.paginate(**kwargs):
                for job in page.get("BackupJobs", []):
                    created = job.get("CreationDate")
                    results.append({
                        "id": job["BackupJobId"],
                        "resource_type": job.get("ResourceType", "—"),
                        "resource_arn": job.get("ResourceArn", "—").split(":")[-1],
                        "state": job.get("State", "—"),
                        "vault": job.get("BackupVaultName", "—"),
                        "created": created.isoformat()[:10] if created else "—",
                        "region": region or self._region or "—",
                        "account": account,
                    })
            return results
        except Exception:
            return []

    # ── Security ──────────────────────────────────────────────────────────────

    def security_audit(self, account: str) -> list[dict]:
        findings = []
        try:
            for b in self.list_storage(account=account):
                if b.public:
                    findings.append({
                        "severity": "HIGH", "resource": f"s3://{b.name}",
                        "issue": "Bucket is publicly accessible", "account": account,
                    })
        except Exception:
            pass
        try:
            ec2 = self._ec2()
            for sg in ec2.describe_security_groups().get("SecurityGroups", []):
                for rule in sg.get("IpPermissions", []):
                    if rule.get("FromPort", -1) == -1:
                        for ip in rule.get("IpRanges", []):
                            if ip.get("CidrIp") == "0.0.0.0/0":
                                findings.append({
                                    "severity": "HIGH",
                                    "resource": f"sg/{sg['GroupId']} ({sg.get('GroupName', '')})",
                                    "issue": "Security group allows all inbound traffic (0.0.0.0/0)",
                                    "account": account,
                                })
        except Exception:
            pass
        try:
            iam = self._client("iam")
            for user in iam.list_users().get("Users", []):
                mfa = iam.list_mfa_devices(UserName=user["UserName"]).get("MFADevices", [])
                if not mfa:
                    findings.append({
                        "severity": "MEDIUM", "resource": f"iam/user/{user['UserName']}",
                        "issue": "IAM user has no MFA device", "account": account,
                    })
        except Exception:
            pass
        return findings

    def list_public_resources(self, account: str) -> list[dict]:
        results = []
        try:
            for b in self.list_storage(account=account, public_only=True):
                results.append({"type": "S3 Bucket", "id": b.name, "region": b.region, "account": account})
        except Exception:
            pass
        return results

    # ── Private helpers ───────────────────────────────────────────────────────

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

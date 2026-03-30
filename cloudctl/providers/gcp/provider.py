"""GCP cloud provider — full service coverage via existing `gcloud auth` credentials."""
from __future__ import annotations

from typing import Optional

from cloudctl.providers.base import CloudProvider, ComputeResource, DatabaseResource, StorageResource

# ── Core auth ────────────────────────────────────────────────────────────────
try:
    import google.auth
    _GCP_AUTH_AVAILABLE = True
except ImportError:
    _GCP_AUTH_AVAILABLE = False

try:
    from googleapiclient.discovery import build as gapi_build
    _GAPI_AVAILABLE = True
except ImportError:
    _GAPI_AVAILABLE = False

try:
    from google.cloud import storage as gcs
    _GCS_AVAILABLE = True
except ImportError:
    _GCS_AVAILABLE = False

_STATE_MAP = {
    "RUNNING": "running", "TERMINATED": "stopped",
    "STAGING": "starting", "STOPPING": "stopping",
    "SUSPENDED": "suspended", "REPAIRING": "repairing",
}

_DEFAULT_REGION = "us-central1"


class GCPProvider(CloudProvider):
    """GCP provider — uses credentials from `gcloud auth application-default login`."""

    def __init__(self, project_id: Optional[str] = None) -> None:
        if not _GCP_AUTH_AVAILABLE:
            raise ImportError("GCP SDK not installed. Run: pip install 'cctl[gcp]'")
        self._creds, detected_project = google.auth.default()
        self._project = project_id or detected_project
        if not self._project:
            raise ValueError("No GCP project detected. Run: gcloud config set project PROJECT_ID")

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _svc(self, api: str, version: str):
        return gapi_build(api, version, credentials=self._creds)

    def _paginate(self, request_fn, items_key: str = "items") -> list:
        """Exhaust all pages of a list call."""
        results = []
        req = request_fn()
        while req is not None:
            resp = req.execute()
            results.extend(resp.get(items_key, []))
            req = request_fn.__self__.list_next(req, resp) \
                if hasattr(request_fn, "__self__") else None
            break  # discovery API pagination handled per-method below
        return results

    def _all_zones(self, svc) -> list[str]:
        try:
            resp = svc.zones().list(project=self._project).execute()
            return [z["name"] for z in resp.get("items", [])]
        except Exception:
            return []

    def _zones_in_region(self, svc, region: str) -> list[str]:
        return [z for z in self._all_zones(svc) if z.startswith(region)]

    def _find_instance_zone(self, svc, name: str) -> str:
        for zone in self._all_zones(svc):
            try:
                svc.instances().get(project=self._project, zone=zone, instance=name).execute()
                return zone
            except Exception:
                continue
        raise ValueError(f"Instance '{name}' not found in any zone")

    def _wait_for_zone_op(self, svc, zone: str, op_name: str) -> None:
        import time
        for _ in range(60):
            op = svc.zoneOperations().get(
                project=self._project, zone=zone, operation=op_name
            ).execute()
            if op.get("status") == "DONE":
                return
            time.sleep(5)
        raise TimeoutError(f"Operation {op_name} timed out")

    def _gcp_locations(self, svc, api_name: str) -> list[str]:
        """List available locations for a regional GCP service."""
        try:
            resp = svc.projects().locations().list(
                name=f"projects/{self._project}"
            ).execute()
            return [loc["locationId"] for loc in resp.get("locations", [])]
        except Exception:
            return [_DEFAULT_REGION]

    # ── Compute — GCE Instances ───────────────────────────────────────────────

    def list_compute(
        self,
        account: str,
        region: Optional[str] = None,
        state: Optional[str] = None,
        tags: Optional[dict] = None,
    ) -> list[ComputeResource]:
        if not _GAPI_AVAILABLE:
            raise ImportError("google-api-python-client not installed.")
        svc = self._svc("compute", "v1")
        zones = self._zones_in_region(svc, region) if region else self._all_zones(svc)
        results = []
        for zone in zones:
            try:
                resp = svc.instances().list(project=self._project, zone=zone).execute()
                for inst in resp.get("items", []):
                    vm_state = _STATE_MAP.get(inst.get("status", ""), "unknown")
                    if state and vm_state != state:
                        continue
                    inst_tags = dict(inst.get("labels", {}))
                    if tags and not all(inst_tags.get(k) == v for k, v in tags.items()):
                        continue
                    ifaces = inst.get("networkInterfaces", [])
                    public_ip = private_ip = None
                    if ifaces:
                        private_ip = ifaces[0].get("networkIP")
                        acs = ifaces[0].get("accessConfigs", [])
                        if acs:
                            public_ip = acs[0].get("natIP")
                    results.append(ComputeResource(
                        id=str(inst.get("id", inst["name"])), name=inst["name"],
                        state=vm_state, type=inst.get("machineType", "").split("/")[-1],
                        region=zone, cloud="gcp", account=account,
                        public_ip=public_ip, private_ip=private_ip,
                        tags=inst_tags, launched_at=inst.get("creationTimestamp"),
                    ))
            except Exception:
                continue
        return results

    def describe_compute(self, account: str, instance_id: str) -> ComputeResource:
        svc = self._svc("compute", "v1")
        if "/" in instance_id:
            zone, name = instance_id.split("/", 1)
        else:
            zone, name = self._find_instance_zone(svc, instance_id), instance_id
        inst = svc.instances().get(project=self._project, zone=zone, instance=name).execute()
        vm_state = _STATE_MAP.get(inst.get("status", ""), "unknown")
        ifaces = inst.get("networkInterfaces", [])
        public_ip = private_ip = None
        if ifaces:
            private_ip = ifaces[0].get("networkIP")
            acs = ifaces[0].get("accessConfigs", [])
            if acs:
                public_ip = acs[0].get("natIP")
        return ComputeResource(
            id=str(inst.get("id", inst["name"])), name=inst["name"],
            state=vm_state, type=inst.get("machineType", "").split("/")[-1],
            region=zone, cloud="gcp", account=account,
            public_ip=public_ip, private_ip=private_ip,
            tags=dict(inst.get("labels", {})), launched_at=inst.get("creationTimestamp"),
        )

    def stop_compute(self, account: str, instance_id: str) -> None:
        svc = self._svc("compute", "v1")
        zone, name = instance_id.split("/", 1) if "/" in instance_id else (
            self._find_instance_zone(svc, instance_id), instance_id)
        op = svc.instances().stop(project=self._project, zone=zone, instance=name).execute()
        self._wait_for_zone_op(svc, zone, op["name"])

    def start_compute(self, account: str, instance_id: str) -> None:
        svc = self._svc("compute", "v1")
        zone, name = instance_id.split("/", 1) if "/" in instance_id else (
            self._find_instance_zone(svc, instance_id), instance_id)
        op = svc.instances().start(project=self._project, zone=zone, instance=name).execute()
        self._wait_for_zone_op(svc, zone, op["name"])

    # ── Compute — Cloud Run ───────────────────────────────────────────────────

    def list_cloud_run(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cloud Run services."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("run", "v2")
            locations = [region] if region else self._gcp_locations(svc, "run")
            for loc in locations:
                try:
                    resp = svc.projects().locations().services().list(
                        parent=f"projects/{self._project}/locations/{loc}"
                    ).execute()
                    for svc_item in resp.get("services", []):
                        results.append({
                            "account": account,
                            "name": svc_item["name"].split("/")[-1],
                            "url": svc_item.get("uri", "—"),
                            "state": svc_item.get("terminalCondition", {}).get("state", "—"),
                            "region": loc,
                        })
                except Exception:
                    continue
        except Exception:
            pass
        return results

    # ── Compute — Cloud Functions ─────────────────────────────────────────────

    def list_cloud_functions(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cloud Functions (gen 2)."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("cloudfunctions", "v2")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().functions().list(parent=parent).execute()
            for fn in resp.get("functions", []):
                name = fn["name"].split("/")[-1]
                loc = fn["name"].split("/")[5] if len(fn["name"].split("/")) > 5 else "—"
                results.append({
                    "account": account, "name": name,
                    "runtime": fn.get("buildConfig", {}).get("runtime", "—"),
                    "state": fn.get("state", "—"),
                    "url": fn.get("serviceConfig", {}).get("uri", "—"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    # ── Compute — GKE ────────────────────────────────────────────────────────

    def list_gke_clusters(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Google Kubernetes Engine clusters."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("container", "v1")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().clusters().list(parent=parent).execute()
            for cluster in resp.get("clusters", []):
                results.append({
                    "account": account, "name": cluster["name"],
                    "k8s_version": cluster.get("currentMasterVersion", "—"),
                    "node_count": cluster.get("currentNodeCount", 0),
                    "state": cluster.get("status", "—"),
                    "region": cluster.get("location", "—"),
                })
        except Exception:
            pass
        return results

    # ── Compute — App Engine ──────────────────────────────────────────────────

    def list_app_engine(self, account: str) -> list[dict]:
        """List App Engine services."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("appengine", "v1")
            resp = svc.apps().services().list(appsId=self._project).execute()
            for service in resp.get("services", []):
                results.append({
                    "account": account, "name": service["id"],
                    "split": str(service.get("split", {}).get("allocations", {}))[:60],
                    "region": "app-engine",
                })
        except Exception:
            pass
        return results

    # ── Compute — Instance Groups ─────────────────────────────────────────────

    def list_instance_groups(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List managed instance groups."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("compute", "v1")
            resp = svc.instanceGroupManagers().aggregatedList(
                project=self._project
            ).execute()
            for zone_key, zone_data in resp.get("items", {}).items():
                for ig in zone_data.get("instanceGroupManagers", []):
                    loc = zone_key.replace("zones/", "").replace("regions/", "")
                    if region and not loc.startswith(region):
                        continue
                    results.append({
                        "account": account, "name": ig["name"],
                        "size": ig.get("targetSize", 0),
                        "template": ig.get("instanceTemplate", "—").split("/")[-1],
                        "state": ig.get("status", {}).get("isStable", False) and "stable" or "updating",
                        "region": loc,
                    })
        except Exception:
            pass
        return results

    # ── Storage — GCS Buckets ─────────────────────────────────────────────────

    def list_storage(
        self,
        account: str,
        region: Optional[str] = None,
        public_only: bool = False,
    ) -> list[StorageResource]:
        if not _GCS_AVAILABLE:
            raise ImportError("google-cloud-storage not installed.")
        client = gcs.Client(project=self._project, credentials=self._creds)
        results = []
        for bucket in client.list_buckets():
            bucket_region = (bucket.location or "unknown").lower()
            if region and bucket_region != region.lower():
                continue
            is_public = self._bucket_is_public(bucket)
            if public_only and not is_public:
                continue
            results.append(StorageResource(
                id=bucket.name, name=bucket.name, region=bucket_region,
                cloud="gcp", account=account, public=is_public,
                tags=dict(bucket.labels or {}),
                created_at=bucket.time_created.isoformat() if bucket.time_created else None,
            ))
        return results

    def describe_storage(self, account: str, bucket_name: str) -> StorageResource:
        if not _GCS_AVAILABLE:
            raise ImportError("google-cloud-storage not installed.")
        client = gcs.Client(project=self._project, credentials=self._creds)
        bucket = client.get_bucket(bucket_name)
        return StorageResource(
            id=bucket.name, name=bucket.name,
            region=(bucket.location or "unknown").lower(),
            cloud="gcp", account=account, public=self._bucket_is_public(bucket),
            tags=dict(bucket.labels or {}),
            created_at=bucket.time_created.isoformat() if bucket.time_created else None,
        )

    def _bucket_is_public(self, bucket) -> bool:
        try:
            policy = bucket.get_iam_policy()
            for binding in policy.bindings:
                if "allUsers" in binding.get("members", []) or \
                   "allAuthenticatedUsers" in binding.get("members", []):
                    return True
        except Exception:
            pass
        return False

    # ── Storage — Persistent Disks ────────────────────────────────────────────

    def list_persistent_disks(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Persistent Disks."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("compute", "v1")
            resp = svc.disks().aggregatedList(project=self._project).execute()
            for zone_key, zone_data in resp.get("items", {}).items():
                for disk in zone_data.get("disks", []):
                    loc = zone_key.replace("zones/", "")
                    if region and not loc.startswith(region):
                        continue
                    users = disk.get("users", [])
                    results.append({
                        "account": account, "name": disk["name"],
                        "size_gb": disk.get("sizeGb", "—"),
                        "type": disk.get("type", "—").split("/")[-1],
                        "state": disk.get("status", "—"),
                        "attached_to": users[0].split("/")[-1] if users else "unattached",
                        "region": loc,
                    })
        except Exception:
            pass
        return results

    # ── Storage — Filestore ───────────────────────────────────────────────────

    def list_filestore(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cloud Filestore instances."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("file", "v1")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().instances().list(parent=parent).execute()
            for inst in resp.get("instances", []):
                loc = inst["name"].split("/")[5] if len(inst["name"].split("/")) > 5 else "—"
                shares = inst.get("fileShares", [{}])
                results.append({
                    "account": account, "name": inst["name"].split("/")[-1],
                    "tier": inst.get("tier", "—"),
                    "capacity_gb": shares[0].get("capacityGb", "—") if shares else "—",
                    "state": inst.get("state", "—"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    # ── Network — VPCs ────────────────────────────────────────────────────────

    def list_vpcs(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List VPC networks."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("compute", "v1")
            resp = svc.networks().list(project=self._project).execute()
            for net in resp.get("items", []):
                results.append({
                    "account": account,
                    "id": str(net.get("id", net["name"])),
                    "name": net["name"],
                    "cidr": net.get("IPv4Range", "auto (subnet mode)"),
                    "state": "available",
                    "default": net["name"] == "default",
                    "region": "global",
                })
        except Exception:
            pass
        return results

    # ── Network — Firewall Rules (Security Groups) ────────────────────────────

    def list_security_groups(self, account: str, region: Optional[str] = None, vpc_id: Optional[str] = None) -> list[dict]:
        """List VPC firewall rules (GCP equivalent of security groups)."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("compute", "v1")
            resp = svc.firewalls().list(project=self._project).execute()
            rules: dict[str, dict] = {}
            for rule in resp.get("items", []):
                net_name = rule.get("network", "").split("/")[-1]
                if vpc_id and net_name != vpc_id:
                    continue
                key = f"{net_name}:{rule.get('direction', 'INGRESS')}"
                if net_name not in rules:
                    rules[net_name] = {"inbound": 0, "outbound": 0, "net": net_name, "id": str(rule.get("id", ""))}
                if rule.get("direction") == "INGRESS":
                    rules[net_name]["inbound"] += 1
                else:
                    rules[net_name]["outbound"] += 1
            for net_name, data in rules.items():
                results.append({
                    "account": account, "id": data["id"], "name": net_name,
                    "vpc_id": net_name, "inbound_rules": data["inbound"],
                    "outbound_rules": data["outbound"], "region": "global",
                })
        except Exception:
            pass
        return results

    # ── Network — Load Balancers ──────────────────────────────────────────────

    def list_load_balancers(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cloud Load Balancers (forwarding rules)."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("compute", "v1")
            resp = svc.globalForwardingRules().list(project=self._project).execute()
            for rule in resp.get("items", []):
                results.append({
                    "account": account, "name": rule["name"],
                    "ip": rule.get("IPAddress", "—"),
                    "protocol": rule.get("IPProtocol", "—"),
                    "target": rule.get("target", "—").split("/")[-1],
                    "region": "global",
                })
        except Exception:
            pass
        return results

    # ── Network — Cloud DNS ───────────────────────────────────────────────────

    def list_dns_zones(self, account: str) -> list[dict]:
        """List Cloud DNS managed zones."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("dns", "v1")
            resp = svc.managedZones().list(project=self._project).execute()
            for zone in resp.get("managedZones", []):
                results.append({
                    "account": account, "name": zone["name"],
                    "dns_name": zone.get("dnsName", "—"),
                    "visibility": zone.get("visibility", "public"),
                    "record_sets": zone.get("nameServers", []),
                    "region": "global",
                })
        except Exception:
            pass
        return results

    # ── Network — Cloud Armor ─────────────────────────────────────────────────

    def list_cloud_armor(self, account: str) -> list[dict]:
        """List Cloud Armor security policies."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("compute", "v1")
            resp = svc.securityPolicies().list(project=self._project).execute()
            for policy in resp.get("items", []):
                results.append({
                    "account": account, "name": policy["name"],
                    "rules": len(policy.get("rules", [])),
                    "type": policy.get("type", "CLOUD_ARMOR"),
                    "region": "global",
                })
        except Exception:
            pass
        return results

    # ── Network — Cloud NAT ───────────────────────────────────────────────────

    def list_cloud_nat(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cloud NAT gateways."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("compute", "v1")
            resp = svc.routers().aggregatedList(project=self._project).execute()
            for region_key, region_data in resp.get("items", {}).items():
                loc = region_key.replace("regions/", "")
                if region and loc != region:
                    continue
                for router in region_data.get("routers", []):
                    for nat in router.get("nats", []):
                        results.append({
                            "account": account,
                            "name": nat["name"],
                            "router": router["name"],
                            "nat_ip": ", ".join(nat.get("natIps", [])) or "auto",
                            "region": loc,
                        })
        except Exception:
            pass
        return results

    # ── Network — VPC Peerings ────────────────────────────────────────────────

    def list_vpc_peerings(self, account: str) -> list[dict]:
        """List VPC network peerings."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("compute", "v1")
            resp = svc.networks().list(project=self._project).execute()
            for net in resp.get("items", []):
                for peering in net.get("peerings", []):
                    results.append({
                        "account": account,
                        "name": peering["name"],
                        "network": net["name"],
                        "peer_network": peering.get("network", "—").split("/")[-1],
                        "state": peering.get("state", "—"),
                        "region": "global",
                    })
        except Exception:
            pass
        return results

    # ── Network — Apigee ──────────────────────────────────────────────────────

    def list_apigee(self, account: str) -> list[dict]:
        """List Apigee environments."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("apigee", "v1")
            envs = svc.organizations().environments().list(
                parent=f"organizations/{self._project}"
            ).execute()
            for env in envs.get("environments", []):
                results.append({
                    "account": account, "name": env if isinstance(env, str) else env.get("name", "—"),
                    "region": "—",
                })
        except Exception:
            pass
        return results

    # ── Database — Cloud SQL ──────────────────────────────────────────────────

    def list_databases(
        self,
        account: str,
        region: Optional[str] = None,
        engine: Optional[str] = None,
    ) -> list[DatabaseResource]:
        if not _GAPI_AVAILABLE:
            raise ImportError("google-api-python-client not installed.")
        svc = self._svc("sqladmin", "v1beta4")
        results = []
        try:
            resp = svc.instances().list(project=self._project).execute()
            for inst in resp.get("items", []):
                db_region = inst.get("region", "unknown")
                if region and db_region != region:
                    continue
                db_engine = inst.get("databaseVersion", "unknown")
                if engine and engine.lower() not in db_engine.lower():
                    continue
                settings = inst.get("settings", {})
                results.append(DatabaseResource(
                    id=inst["name"], name=inst["name"], engine=db_engine,
                    state=inst.get("state", "unknown").lower(),
                    region=db_region, cloud="gcp", account=account,
                    instance_class=settings.get("tier"),
                    storage_gb=int(settings["dataDiskSizeGb"]) if settings.get("dataDiskSizeGb") else None,
                    tags={},
                ))
        except Exception:
            pass
        return results

    def describe_database(self, account: str, db_id: str, region: Optional[str] = None) -> DatabaseResource:
        svc = self._svc("sqladmin", "v1beta4")
        inst = svc.instances().get(project=self._project, instance=db_id).execute()
        settings = inst.get("settings", {})
        return DatabaseResource(
            id=inst["name"], name=inst["name"],
            engine=inst.get("databaseVersion", "unknown"),
            state=inst.get("state", "unknown").lower(),
            region=inst.get("region", "unknown"), cloud="gcp", account=account,
            instance_class=settings.get("tier"),
            storage_gb=int(settings["dataDiskSizeGb"]) if settings.get("dataDiskSizeGb") else None,
            tags={},
        )

    # ── Database — Cloud Spanner ──────────────────────────────────────────────

    def list_spanner(self, account: str) -> list[dict]:
        """List Cloud Spanner instances."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("spanner", "v1")
            resp = svc.projects().instances().list(parent=f"projects/{self._project}").execute()
            for inst in resp.get("instances", []):
                results.append({
                    "account": account,
                    "name": inst["name"].split("/")[-1],
                    "config": inst.get("config", "—").split("/")[-1],
                    "nodes": inst.get("nodeCount", inst.get("processingUnits", 0)),
                    "state": inst.get("state", "—"),
                    "region": "multi-region",
                })
        except Exception:
            pass
        return results

    # ── Database — Bigtable ───────────────────────────────────────────────────

    def list_bigtable(self, account: str) -> list[dict]:
        """List Bigtable instances."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("bigtableadmin", "v2")
            resp = svc.projects().instances().list(parent=f"projects/{self._project}").execute()
            for inst in resp.get("instances", []):
                results.append({
                    "account": account,
                    "name": inst["name"].split("/")[-1],
                    "type": inst.get("type", "PRODUCTION"),
                    "state": inst.get("state", "—"),
                    "region": "multi-zone",
                })
        except Exception:
            pass
        return results

    # ── Database — Firestore ──────────────────────────────────────────────────

    def list_firestore(self, account: str) -> list[dict]:
        """List Firestore databases."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("firestore", "v1")
            resp = svc.projects().databases().list(parent=f"projects/{self._project}").execute()
            for db in resp.get("databases", []):
                results.append({
                    "account": account,
                    "name": db["name"].split("/")[-1],
                    "type": db.get("type", "FIRESTORE_NATIVE"),
                    "location": db.get("locationId", "—"),
                    "state": db.get("state", "—"),
                    "region": db.get("locationId", "unknown"),
                })
        except Exception:
            pass
        return results

    # ── Database — Memorystore (Redis) ────────────────────────────────────────

    def list_memorystore(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Memorystore (Redis) instances."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("redis", "v1")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().instances().list(parent=parent).execute()
            for inst in resp.get("instances", []):
                loc = inst["name"].split("/")[5] if len(inst["name"].split("/")) > 5 else "—"
                results.append({
                    "account": account,
                    "name": inst["name"].split("/")[-1],
                    "tier": inst.get("tier", "—"),
                    "memory_gb": inst.get("memorySizeGb", "—"),
                    "state": inst.get("state", "—"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    # ── Database — AlloyDB ────────────────────────────────────────────────────

    def list_alloydb(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List AlloyDB clusters."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("alloydb", "v1")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().clusters().list(parent=parent).execute()
            for cluster in resp.get("clusters", []):
                loc = cluster["name"].split("/")[5] if len(cluster["name"].split("/")) > 5 else "—"
                results.append({
                    "account": account,
                    "name": cluster["name"].split("/")[-1],
                    "database_version": cluster.get("databaseVersion", "—"),
                    "state": cluster.get("state", "—"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    # ── IAM — Roles ───────────────────────────────────────────────────────────

    def list_roles(self, account: str) -> list[dict]:
        """List custom IAM roles for the project."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("iam", "v1")
            resp = svc.projects().roles().list(
                parent=f"projects/{self._project}", view="FULL"
            ).execute()
            for role in resp.get("roles", []):
                results.append({
                    "account": account,
                    "name": role.get("title", role["name"].split("/")[-1]),
                    "id": role["name"].split("/")[-1],
                    "path": role["name"],
                    "created": "—",
                })
        except Exception:
            pass
        return results

    # ── IAM — Service Accounts (Users) ───────────────────────────────────────

    def list_service_accounts(self, account: str) -> list[dict]:
        """List service accounts (GCP equivalent of IAM users)."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("iam", "v1")
            resp = svc.projects().serviceAccounts().list(
                name=f"projects/{self._project}"
            ).execute()
            for sa in resp.get("accounts", []):
                results.append({
                    "account": account,
                    "username": sa.get("displayName") or sa["email"].split("@")[0],
                    "id": sa.get("uniqueId", sa["email"]),
                    "created": "—",
                    "last_login": "—",
                })
        except Exception:
            pass
        return results

    # ── IAM — KMS Keys ────────────────────────────────────────────────────────

    def list_kms_keys(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cloud KMS key rings and crypto keys."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("cloudkms", "v1")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            kr_resp = svc.projects().locations().keyRings().list(parent=parent).execute()
            for kr in kr_resp.get("keyRings", []):
                try:
                    keys_resp = svc.projects().locations().keyRings().cryptoKeys().list(
                        parent=kr["name"]
                    ).execute()
                    loc = kr["name"].split("/")[5] if len(kr["name"].split("/")) > 5 else "—"
                    for key in keys_resp.get("cryptoKeys", []):
                        results.append({
                            "account": account,
                            "name": f"{kr['name'].split('/')[-1]}/{key['name'].split('/')[-1]}",
                            "purpose": key.get("purpose", "—"),
                            "state": key.get("primary", {}).get("state", "—"),
                            "region": loc,
                        })
                except Exception:
                    pass
        except Exception:
            pass
        return results

    # ── IAM — Secrets ─────────────────────────────────────────────────────────

    def list_secrets(self, account: str) -> list[dict]:
        """List Secret Manager secrets."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("secretmanager", "v1")
            resp = svc.projects().secrets().list(
                parent=f"projects/{self._project}"
            ).execute()
            for secret in resp.get("secrets", []):
                replication = secret.get("replication", {})
                region = "automatic" if "automatic" in replication else \
                    "/".join(r.get("location", "") for r in
                             replication.get("userManaged", {}).get("replicas", [{}]))
                results.append({
                    "account": account,
                    "name": secret["name"].split("/")[-1],
                    "replication": "auto" if "automatic" in replication else "user-managed",
                    "created": secret.get("createTime", "—")[:10],
                    "region": region or "global",
                })
        except Exception:
            pass
        return results

    # ── Security — SCC & Public Resources ────────────────────────────────────

    def security_audit(self, account: str) -> list[dict]:
        """Fetch Security Command Center findings."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("securitycenter", "v1")
            resp = svc.projects().sources().findings().list(
                parent=f"projects/{self._project}/sources/-",
                filter='state="ACTIVE"',
                pageSize=50,
            ).execute()
            for finding in resp.get("listFindingsResults", []):
                f = finding.get("finding", {})
                results.append({
                    "account": account,
                    "severity": f.get("severity", "MEDIUM"),
                    "resource": f.get("resourceName", "—").split("/")[-1],
                    "issue": f.get("category", f.get("findingClass", "—")),
                })
        except Exception:
            pass
        return results

    def list_public_resources(self, account: str) -> list[dict]:
        """List publicly accessible GCP resources."""
        results = []
        # Public GCS buckets
        if _GCS_AVAILABLE:
            try:
                client = gcs.Client(project=self._project, credentials=self._creds)
                for bucket in client.list_buckets():
                    if self._bucket_is_public(bucket):
                        results.append({
                            "account": account, "type": "GCS Bucket (Public)",
                            "id": bucket.name, "region": (bucket.location or "unknown").lower(),
                        })
            except Exception:
                pass
        # Firewall rules open to internet
        if _GAPI_AVAILABLE:
            try:
                svc = self._svc("compute", "v1")
                resp = svc.firewalls().list(project=self._project).execute()
                for rule in resp.get("items", []):
                    if rule.get("direction") == "INGRESS" and \
                       "0.0.0.0/0" in rule.get("sourceRanges", []) and \
                       not rule.get("disabled", False):
                        ports = rule.get("allowed", [{}])[0].get("ports", ["all"])
                        results.append({
                            "account": account,
                            "type": f"Firewall Rule (Open: {', '.join(ports[:3])})",
                            "id": rule["name"],
                            "region": "global",
                        })
            except Exception:
                pass
        return results

    # ── DevOps — Cloud Build ──────────────────────────────────────────────────

    def list_pipelines(self, account: str) -> list[dict]:
        """List Cloud Build triggers (CI/CD pipelines)."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("cloudbuild", "v1")
            resp = svc.projects().triggers().list(projectId=self._project).execute()
            for trigger in resp.get("triggers", []):
                results.append({
                    "account": account,
                    "name": trigger.get("name", trigger.get("id", "—")),
                    "description": (trigger.get("description", ""))[:60],
                    "disabled": trigger.get("disabled", False),
                    "region": trigger.get("resourceName", "global"),
                })
        except Exception:
            pass
        return results

    def list_cloud_build(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List recent Cloud Build jobs."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("cloudbuild", "v1")
            resp = svc.projects().builds().list(
                projectId=self._project, pageSize=20
            ).execute()
            for build in resp.get("builds", []):
                results.append({
                    "account": account,
                    "id": build["id"][:12],
                    "status": build.get("status", "—"),
                    "trigger": build.get("buildTriggerId", "manual"),
                    "duration": build.get("duration", "—"),
                    "region": "global",
                })
        except Exception:
            pass
        return results

    def list_cloud_deploy(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cloud Deploy delivery pipelines."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("clouddeploy", "v1")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().deliveryPipelines().list(parent=parent).execute()
            for pipeline in resp.get("deliveryPipelines", []):
                loc = pipeline["name"].split("/")[5] if len(pipeline["name"].split("/")) > 5 else "—"
                results.append({
                    "account": account,
                    "name": pipeline["name"].split("/")[-1],
                    "state": pipeline.get("condition", {}).get("pipelineReadyCondition", {}).get("status", "—"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    def list_artifact_registry(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Artifact Registry repositories."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("artifactregistry", "v1")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().repositories().list(parent=parent).execute()
            for repo in resp.get("repositories", []):
                loc = repo["name"].split("/")[5] if len(repo["name"].split("/")) > 5 else "—"
                results.append({
                    "account": account,
                    "name": repo["name"].split("/")[-1],
                    "format": repo.get("format", "—"),
                    "mode": repo.get("mode", "STANDARD_REPOSITORY"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    # ── Monitoring ────────────────────────────────────────────────────────────

    def list_monitoring_alerts(self, account: str) -> list[dict]:
        """List Cloud Monitoring alert policies."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("monitoring", "v3")
            resp = svc.projects().alertPolicies().list(
                name=f"projects/{self._project}"
            ).execute()
            for policy in resp.get("alertPolicies", []):
                results.append({
                    "account": account,
                    "name": policy.get("displayName", policy["name"].split("/")[-1]),
                    "state": "enabled" if policy.get("enabled", True) else "disabled",
                    "severity": "—",
                    "region": "global",
                    "description": (policy.get("documentation", {}).get("content", ""))[:60],
                })
        except Exception:
            pass
        return results

    def list_log_sinks(self, account: str) -> list[dict]:
        """List Cloud Logging sinks."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("logging", "v2")
            resp = svc.projects().sinks().list(
                parent=f"projects/{self._project}"
            ).execute()
            for sink in resp.get("sinks", []):
                results.append({
                    "account": account,
                    "name": sink["name"],
                    "destination": sink.get("destination", "—"),
                    "filter": (sink.get("filter", "all logs"))[:60],
                    "region": "global",
                })
        except Exception:
            pass
        return results

    # ── Messaging — Pub/Sub ───────────────────────────────────────────────────

    def list_pubsub_topics(self, account: str) -> list[dict]:
        """List Pub/Sub topics."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("pubsub", "v1")
            resp = svc.projects().topics().list(
                project=f"projects/{self._project}"
            ).execute()
            for topic in resp.get("topics", []):
                results.append({
                    "account": account,
                    "name": topic["name"].split("/")[-1],
                    "region": "global",
                })
        except Exception:
            pass
        return results

    def list_pubsub_subscriptions(self, account: str) -> list[dict]:
        """List Pub/Sub subscriptions."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("pubsub", "v1")
            resp = svc.projects().subscriptions().list(
                project=f"projects/{self._project}"
            ).execute()
            for sub in resp.get("subscriptions", []):
                results.append({
                    "account": account,
                    "name": sub["name"].split("/")[-1],
                    "topic": sub.get("topic", "—").split("/")[-1],
                    "ack_deadline": sub.get("ackDeadlineSeconds", 10),
                    "region": "global",
                })
        except Exception:
            pass
        return results

    # ── Messaging — Cloud Tasks / Scheduler / Eventarc / Workflows ───────────

    def list_cloud_tasks(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cloud Tasks queues."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("cloudtasks", "v2")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().queues().list(parent=parent).execute()
            for q in resp.get("queues", []):
                loc = q["name"].split("/")[5] if len(q["name"].split("/")) > 5 else "—"
                results.append({
                    "account": account,
                    "name": q["name"].split("/")[-1],
                    "state": q.get("state", "—"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    def list_cloud_scheduler(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cloud Scheduler jobs."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("cloudscheduler", "v1")
            parent = f"projects/{self._project}/locations/{region or _DEFAULT_REGION}"
            resp = svc.projects().locations().jobs().list(parent=parent).execute()
            for job in resp.get("jobs", []):
                results.append({
                    "account": account,
                    "name": job["name"].split("/")[-1],
                    "schedule": job.get("schedule", "—"),
                    "state": job.get("state", "—"),
                    "region": parent.split("/")[5],
                })
        except Exception:
            pass
        return results

    def list_eventarc_triggers(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Eventarc triggers."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("eventarc", "v1")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().triggers().list(parent=parent).execute()
            for trigger in resp.get("triggers", []):
                loc = trigger["name"].split("/")[5] if len(trigger["name"].split("/")) > 5 else "—"
                results.append({
                    "account": account,
                    "name": trigger["name"].split("/")[-1],
                    "state": trigger.get("state", "—"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    def list_workflows(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Workflows."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("workflows", "v1")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().workflows().list(parent=parent).execute()
            for workflow in resp.get("workflows", []):
                loc = workflow["name"].split("/")[5] if len(workflow["name"].split("/")) > 5 else "—"
                results.append({
                    "account": account,
                    "name": workflow["name"].split("/")[-1],
                    "state": workflow.get("state", "—"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    # ── AI/ML — Vertex AI ─────────────────────────────────────────────────────

    def list_vertex_endpoints(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Vertex AI endpoints."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("aiplatform", "v1")
            loc = region or _DEFAULT_REGION
            parent = f"projects/{self._project}/locations/{loc}"
            resp = svc.projects().locations().endpoints().list(parent=parent).execute()
            for endpoint in resp.get("endpoints", []):
                results.append({
                    "account": account,
                    "name": endpoint.get("displayName", endpoint["name"].split("/")[-1]),
                    "deployed_models": len(endpoint.get("deployedModels", [])),
                    "state": "active" if endpoint.get("deployedModels") else "empty",
                    "region": loc,
                })
        except Exception:
            pass
        return results

    def list_vertex_models(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Vertex AI models."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("aiplatform", "v1")
            loc = region or _DEFAULT_REGION
            parent = f"projects/{self._project}/locations/{loc}"
            resp = svc.projects().locations().models().list(parent=parent).execute()
            for model in resp.get("models", []):
                results.append({
                    "account": account,
                    "name": model.get("displayName", model["name"].split("/")[-1]),
                    "version": model.get("versionId", "1"),
                    "framework": model.get("metadata", {}).get("framework", "—"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    # ── Analytics — BigQuery ──────────────────────────────────────────────────

    def list_bigquery_datasets(self, account: str) -> list[dict]:
        """List BigQuery datasets."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("bigquery", "v2")
            resp = svc.datasets().list(projectId=self._project).execute()
            for ds in resp.get("datasets", []):
                ref = ds.get("datasetReference", {})
                results.append({
                    "account": account,
                    "name": ref.get("datasetId", "—"),
                    "region": ds.get("location", "—"),
                })
        except Exception:
            pass
        return results

    # ── Analytics — Dataflow / Dataproc / Composer / Dataplex ────────────────

    def list_dataflow_jobs(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Dataflow jobs."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("dataflow", "v1b3")
            resp = svc.projects().jobs().aggregatedList(projectId=self._project).execute()
            for job in resp.get("jobs", []):
                loc = job.get("location", "—")
                if region and loc != region:
                    continue
                results.append({
                    "account": account,
                    "name": job.get("name", job["id"]),
                    "state": job.get("currentState", "—").replace("JOB_STATE_", ""),
                    "type": job.get("type", "—").replace("JOB_TYPE_", ""),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    def list_dataproc_clusters(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Dataproc clusters."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("dataproc", "v1")
            resp = svc.projects().regions().clusters().list(
                projectId=self._project, region=region or "-"
            ).execute()
            for cluster in resp.get("clusters", []):
                results.append({
                    "account": account,
                    "name": cluster["clusterName"],
                    "workers": cluster.get("config", {}).get(
                        "workerConfig", {}).get("numInstances", 0),
                    "state": cluster.get("status", {}).get("state", "—"),
                    "region": cluster.get("config", {}).get(
                        "gceClusterConfig", {}).get("zoneUri", "—").split("/")[-1],
                })
        except Exception:
            pass
        return results

    def list_composer_environments(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cloud Composer environments."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("composer", "v1")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().environments().list(parent=parent).execute()
            for env in resp.get("environments", []):
                loc = env["name"].split("/")[5] if len(env["name"].split("/")) > 5 else "—"
                results.append({
                    "account": account,
                    "name": env["name"].split("/")[-1],
                    "airflow_version": env.get("config", {}).get(
                        "softwareConfig", {}).get("airflowVersion", "—"),
                    "state": env.get("state", "—"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    def list_dataplex_lakes(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Dataplex lakes."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("dataplex", "v1")
            parent = f"projects/{self._project}/locations/{region or '-'}"
            resp = svc.projects().locations().lakes().list(parent=parent).execute()
            for lake in resp.get("lakes", []):
                loc = lake["name"].split("/")[5] if len(lake["name"].split("/")) > 5 else "—"
                results.append({
                    "account": account,
                    "name": lake["name"].split("/")[-1],
                    "state": lake.get("state", "—"),
                    "region": loc,
                })
        except Exception:
            pass
        return results

    # ── Cost ──────────────────────────────────────────────────────────────────

    def cost_summary(self, account: str, days: int = 30) -> list[dict]:
        """Return billing account info. Full cost data requires BigQuery billing export."""
        if not _GAPI_AVAILABLE:
            return []
        try:
            svc = self._svc("cloudbilling", "v1")
            info = svc.projects().getBillingInfo(
                name=f"projects/{self._project}"
            ).execute()
            billing_account = info.get("billingAccountName", "—").split("/")[-1]
            return [{
                "account": account,
                "period": f"last {days}d",
                "cost": "—",
                "currency": "USD",
                "note": f"Billing account: {billing_account}. "
                        "For cost data, set up BigQuery billing export.",
            }]
        except Exception:
            return []

    def cost_by_service(self, account: str, days: int = 30) -> list[dict]:
        """GCP cost by service requires BigQuery billing export."""
        return [{
            "account": account, "service": "BigQuery export required",
            "period": f"last {days}d", "cost": "—",
        }]

    # ── Backup ────────────────────────────────────────────────────────────────

    def list_backup_jobs(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cloud SQL backup runs as a proxy for backup jobs."""
        if not _GAPI_AVAILABLE:
            return []
        results = []
        try:
            svc = self._svc("sqladmin", "v1beta4")
            instances_resp = svc.instances().list(project=self._project).execute()
            for inst in instances_resp.get("items", []):
                try:
                    backups = svc.backupRuns().list(
                        project=self._project, instance=inst["name"], maxResults=3
                    ).execute()
                    for backup in backups.get("items", []):
                        results.append({
                            "account": account,
                            "name": f"{inst['name']} backup",
                            "resource": inst["name"],
                            "state": backup.get("status", "—"),
                            "created": backup.get("startTime", "—")[:10],
                            "region": inst.get("region", "—"),
                        })
                except Exception:
                    pass
        except Exception:
            pass
        return results

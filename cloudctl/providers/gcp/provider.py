"""GCP cloud provider — reads existing `gcloud auth` credentials."""
from __future__ import annotations

from typing import Optional

from cloudctl.providers.base import CloudProvider, ComputeResource, DatabaseResource, StorageResource

try:
    import google.auth
    from google.auth.transport.requests import Request
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
    "RUNNING": "running",
    "TERMINATED": "stopped",
    "STAGING": "starting",
    "STOPPING": "stopping",
    "SUSPENDED": "suspended",
    "REPAIRING": "repairing",
}


class GCPProvider(CloudProvider):
    """GCP provider — uses credentials from `gcloud auth application-default login`."""

    def __init__(self, project_id: Optional[str] = None) -> None:
        if not _GCP_AUTH_AVAILABLE:
            raise ImportError("GCP SDK not installed. Run: pip install 'cctl[gcp]'")

        self._creds, detected_project = google.auth.default()
        self._project = project_id or detected_project

        if not self._project:
            raise ValueError(
                "No GCP project detected. Run: gcloud config set project PROJECT_ID"
            )

    # ── Compute ─────────────────────────────────────────────────────────────

    def list_compute(
        self,
        account: str,
        region: Optional[str] = None,
        state: Optional[str] = None,
        tags: Optional[dict] = None,
    ) -> list[ComputeResource]:
        if not _GAPI_AVAILABLE:
            raise ImportError("google-api-python-client not installed. Run: pip install 'cctl[gcp]'")

        svc = gapi_build("compute", "v1", credentials=self._creds)
        results = []

        if region:
            zones = self._zones_in_region(svc, region)
        else:
            zones = self._all_zones(svc)

        for zone in zones:
            try:
                resp = svc.instances().list(project=self._project, zone=zone).execute()
                for inst in resp.get("items", []):
                    vm_state = _STATE_MAP.get(inst.get("status", ""), "unknown")
                    if state and vm_state != state:
                        continue

                    inst_tags = {k: v for k, v in inst.get("labels", {}).items()}
                    if tags and not all(inst_tags.get(k) == v for k, v in tags.items()):
                        continue

                    network_ifaces = inst.get("networkInterfaces", [])
                    public_ip = None
                    private_ip = None
                    if network_ifaces:
                        private_ip = network_ifaces[0].get("networkIP")
                        access_configs = network_ifaces[0].get("accessConfigs", [])
                        if access_configs:
                            public_ip = access_configs[0].get("natIP")

                    results.append(ComputeResource(
                        id=str(inst.get("id", inst["name"])),
                        name=inst["name"],
                        state=vm_state,
                        type=inst.get("machineType", "").split("/")[-1],
                        region=zone,
                        cloud="gcp",
                        account=account,
                        public_ip=public_ip,
                        private_ip=private_ip,
                        tags=inst_tags,
                        launched_at=inst.get("creationTimestamp"),
                    ))
            except Exception:
                continue

        return results

    def describe_compute(self, account: str, instance_id: str) -> ComputeResource:
        if not _GAPI_AVAILABLE:
            raise ImportError("google-api-python-client not installed. Run: pip install 'cctl[gcp]'")

        # instance_id format: zone/name  or just name (searches all zones)
        svc = gapi_build("compute", "v1", credentials=self._creds)
        if "/" in instance_id:
            zone, name = instance_id.split("/", 1)
        else:
            zone, name = self._find_instance_zone(svc, instance_id), instance_id

        inst = svc.instances().get(project=self._project, zone=zone, instance=name).execute()
        vm_state = _STATE_MAP.get(inst.get("status", ""), "unknown")
        network_ifaces = inst.get("networkInterfaces", [])
        public_ip = private_ip = None
        if network_ifaces:
            private_ip = network_ifaces[0].get("networkIP")
            acs = network_ifaces[0].get("accessConfigs", [])
            if acs:
                public_ip = acs[0].get("natIP")

        return ComputeResource(
            id=str(inst.get("id", inst["name"])),
            name=inst["name"],
            state=vm_state,
            type=inst.get("machineType", "").split("/")[-1],
            region=zone,
            cloud="gcp",
            account=account,
            public_ip=public_ip,
            private_ip=private_ip,
            tags={k: v for k, v in inst.get("labels", {}).items()},
            launched_at=inst.get("creationTimestamp"),
        )

    def stop_compute(self, account: str, instance_id: str) -> None:
        svc = gapi_build("compute", "v1", credentials=self._creds)
        zone, name = instance_id.split("/", 1) if "/" in instance_id else (
            self._find_instance_zone(svc, instance_id), instance_id
        )
        op = svc.instances().stop(project=self._project, zone=zone, instance=name).execute()
        self._wait_for_zone_op(svc, zone, op["name"])

    def start_compute(self, account: str, instance_id: str) -> None:
        svc = gapi_build("compute", "v1", credentials=self._creds)
        zone, name = instance_id.split("/", 1) if "/" in instance_id else (
            self._find_instance_zone(svc, instance_id), instance_id
        )
        op = svc.instances().start(project=self._project, zone=zone, instance=name).execute()
        self._wait_for_zone_op(svc, zone, op["name"])

    # ── Storage ─────────────────────────────────────────────────────────────

    def list_storage(
        self,
        account: str,
        region: Optional[str] = None,
        public_only: bool = False,
    ) -> list[StorageResource]:
        if not _GCS_AVAILABLE:
            raise ImportError("google-cloud-storage not installed. Run: pip install 'cctl[gcp]'")

        client = gcs.Client(project=self._project, credentials=self._creds)
        results = []
        for bucket in client.list_buckets():
            bucket_region = bucket.location.lower() if bucket.location else "unknown"
            if region and bucket_region != region.lower():
                continue

            is_public = self._bucket_is_public(bucket)
            if public_only and not is_public:
                continue

            results.append(StorageResource(
                id=bucket.name,
                name=bucket.name,
                region=bucket_region,
                cloud="gcp",
                account=account,
                public=is_public,
                tags=dict(bucket.labels or {}),
                created_at=bucket.time_created.isoformat() if bucket.time_created else None,
            ))
        return results

    def describe_storage(self, account: str, bucket_name: str) -> StorageResource:
        if not _GCS_AVAILABLE:
            raise ImportError("google-cloud-storage not installed. Run: pip install 'cctl[gcp]'")

        client = gcs.Client(project=self._project, credentials=self._creds)
        bucket = client.get_bucket(bucket_name)
        return StorageResource(
            id=bucket.name,
            name=bucket.name,
            region=bucket.location.lower() if bucket.location else "unknown",
            cloud="gcp",
            account=account,
            public=self._bucket_is_public(bucket),
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

    # ── Database ─────────────────────────────────────────────────────────────

    def list_databases(
        self,
        account: str,
        region: Optional[str] = None,
        engine: Optional[str] = None,
    ) -> list[DatabaseResource]:
        if not _GAPI_AVAILABLE:
            raise ImportError("google-api-python-client not installed. Run: pip install 'cctl[gcp]'")

        svc = gapi_build("sqladmin", "v1beta4", credentials=self._creds)
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
                tier = settings.get("tier")
                storage_gb = settings.get("dataDiskSizeGb")

                results.append(DatabaseResource(
                    id=inst["name"],
                    name=inst["name"],
                    engine=db_engine,
                    state=inst.get("state", "unknown").lower(),
                    region=db_region,
                    cloud="gcp",
                    account=account,
                    instance_class=tier,
                    storage_gb=int(storage_gb) if storage_gb else None,
                    tags={},
                ))
        except Exception:
            pass
        return results

    def describe_database(self, account: str, db_id: str, region: Optional[str] = None) -> DatabaseResource:
        svc = gapi_build("sqladmin", "v1beta4", credentials=self._creds)
        inst = svc.instances().get(project=self._project, instance=db_id).execute()
        settings = inst.get("settings", {})
        storage_gb = settings.get("dataDiskSizeGb")
        return DatabaseResource(
            id=inst["name"],
            name=inst["name"],
            engine=inst.get("databaseVersion", "unknown"),
            state=inst.get("state", "unknown").lower(),
            region=inst.get("region", "unknown"),
            cloud="gcp",
            account=account,
            instance_class=settings.get("tier"),
            storage_gb=int(storage_gb) if storage_gb else None,
            tags={},
        )

    # ── Zone helpers ─────────────────────────────────────────────────────────

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

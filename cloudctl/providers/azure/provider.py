"""Azure cloud provider — reads existing `az login` credentials."""
from __future__ import annotations

from typing import Optional

from cloudctl.providers.base import CloudProvider, ComputeResource, DatabaseResource, StorageResource

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.subscription import SubscriptionClient
    _AZURE_AVAILABLE = True
except ImportError:
    _AZURE_AVAILABLE = False

try:
    from azure.mgmt.sql import SqlManagementClient
    _SQL_AVAILABLE = True
except ImportError:
    _SQL_AVAILABLE = False

try:
    from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient as PgFlexClient
    _PG_AVAILABLE = True
except ImportError:
    _PG_AVAILABLE = False

try:
    from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient as MySQLFlexClient
    _MYSQL_AVAILABLE = True
except ImportError:
    _MYSQL_AVAILABLE = False

try:
    from azure.mgmt.monitor import MonitorManagementClient
    _MONITOR_AVAILABLE = True
except ImportError:
    _MONITOR_AVAILABLE = False

try:
    from azure.mgmt.servicebus import ServiceBusManagementClient
    _SERVICEBUS_AVAILABLE = True
except ImportError:
    _SERVICEBUS_AVAILABLE = False

try:
    from azure.mgmt.eventhub import EventHubManagementClient
    _EVENTHUB_AVAILABLE = True
except ImportError:
    _EVENTHUB_AVAILABLE = False

try:
    import datetime
    from azure.mgmt.costmanagement import CostManagementClient
    from azure.mgmt.costmanagement.models import (
        QueryDefinition, QueryTimePeriod, QueryDataset,
        QueryAggregation, QueryGrouping,
    )
    _COST_AVAILABLE = True
except ImportError:
    _COST_AVAILABLE = False


class AzureProvider(CloudProvider):
    """Azure provider — uses credentials from `az login`."""

    def __init__(self, subscription_id: Optional[str] = None) -> None:
        if not _AZURE_AVAILABLE:
            raise ImportError("Azure SDK not installed. Run: pip install 'cctl[azure]'")

        self._cred = DefaultAzureCredential()

        if subscription_id:
            self._subscriptions = [subscription_id]
        else:
            self._subscriptions = self._list_subscriptions()

        if not self._subscriptions:
            raise ValueError("No Azure subscriptions found. Run: az login")

    # ── Internal helpers ────────────────────────────────────────────────────

    def _list_subscriptions(self) -> list[str]:
        client = SubscriptionClient(self._cred)
        return [s.subscription_id for s in client.subscriptions.list()]

    def _parse_arm_id(self, arm_id: str) -> tuple[str, str, str]:
        """Parse full ARM resource ID → (subscription_id, resource_group, name)."""
        parts = arm_id.strip("/").split("/")
        # /subscriptions/{sub}/resourceGroups/{rg}/providers/.../name
        if len(parts) >= 8:
            return parts[1], parts[3], parts[-1]
        # short format: sub/rg/name
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
        return self._subscriptions[0], parts[0], parts[-1]

    # ── Compute ─────────────────────────────────────────────────────────────

    def list_compute(
        self,
        account: str,
        region: Optional[str] = None,
        state: Optional[str] = None,
        tags: Optional[dict] = None,
    ) -> list[ComputeResource]:
        results = []
        for sub_id in self._subscriptions:
            client = ComputeManagementClient(self._cred, sub_id)
            for vm in client.virtual_machines.list_all():
                vm_region = vm.location or "unknown"
                if region and vm_region != region:
                    continue

                if tags:
                    vm_tags = vm.tags or {}
                    if not all(vm_tags.get(k) == v for k, v in tags.items()):
                        continue

                vm_state = self._vm_power_state(client, vm)
                if state and vm_state != state:
                    continue

                results.append(ComputeResource(
                    id=vm.id or vm.name,
                    name=vm.name,
                    state=vm_state,
                    type=vm.hardware_profile.vm_size if vm.hardware_profile else "unknown",
                    region=vm_region,
                    cloud="azure",
                    account=account,
                    tags=dict(vm.tags or {}),
                ))
        return results

    def _vm_power_state(self, client, vm) -> str:
        try:
            _, rg, name = self._parse_arm_id(vm.id)
            iv = client.virtual_machines.instance_view(rg, name)
            for s in iv.statuses or []:
                if s.code and s.code.startswith("PowerState/"):
                    return s.code.split("/")[1]  # running | deallocated | stopped
        except Exception:
            pass
        return "unknown"

    def describe_compute(self, account: str, instance_id: str) -> ComputeResource:
        sub_id, rg, name = self._parse_arm_id(instance_id)
        client = ComputeManagementClient(self._cred, sub_id)
        vm = client.virtual_machines.get(rg, name, expand="instanceView")
        vm_state = "unknown"
        if vm.instance_view and vm.instance_view.statuses:
            for s in vm.instance_view.statuses:
                if s.code and s.code.startswith("PowerState/"):
                    vm_state = s.code.split("/")[1]
                    break
        return ComputeResource(
            id=vm.id or vm.name,
            name=vm.name,
            state=vm_state,
            type=vm.hardware_profile.vm_size if vm.hardware_profile else "unknown",
            region=vm.location or "unknown",
            cloud="azure",
            account=account,
            tags=dict(vm.tags or {}),
        )

    def stop_compute(self, account: str, instance_id: str) -> None:
        sub_id, rg, name = self._parse_arm_id(instance_id)
        ComputeManagementClient(self._cred, sub_id).virtual_machines.begin_deallocate(rg, name).wait()

    def start_compute(self, account: str, instance_id: str) -> None:
        sub_id, rg, name = self._parse_arm_id(instance_id)
        ComputeManagementClient(self._cred, sub_id).virtual_machines.begin_start(rg, name).wait()

    # ── Storage ─────────────────────────────────────────────────────────────

    def list_storage(
        self,
        account: str,
        region: Optional[str] = None,
        public_only: bool = False,
    ) -> list[StorageResource]:
        results = []
        for sub_id in self._subscriptions:
            client = StorageManagementClient(self._cred, sub_id)
            for sa in client.storage_accounts.list():
                if region and sa.location != region:
                    continue
                is_public = bool(sa.allow_blob_public_access)
                if public_only and not is_public:
                    continue
                results.append(StorageResource(
                    id=sa.id or sa.name,
                    name=sa.name,
                    region=sa.location or "unknown",
                    cloud="azure",
                    account=account,
                    public=is_public,
                    tags=dict(sa.tags or {}),
                    created_at=sa.creation_time.isoformat() if sa.creation_time else None,
                ))
        return results

    def describe_storage(self, account: str, storage_name: str) -> StorageResource:
        for sub_id in self._subscriptions:
            for sa in StorageManagementClient(self._cred, sub_id).storage_accounts.list():
                if sa.name == storage_name:
                    return StorageResource(
                        id=sa.id or sa.name,
                        name=sa.name,
                        region=sa.location or "unknown",
                        cloud="azure",
                        account=account,
                        public=bool(sa.allow_blob_public_access),
                        tags=dict(sa.tags or {}),
                        created_at=sa.creation_time.isoformat() if sa.creation_time else None,
                    )
        raise ValueError(f"Storage account '{storage_name}' not found")

    # ── Database ─────────────────────────────────────────────────────────────

    def list_databases(
        self,
        account: str,
        region: Optional[str] = None,
        engine: Optional[str] = None,
    ) -> list[DatabaseResource]:
        results: list[DatabaseResource] = []
        for sub_id in self._subscriptions:
            if _SQL_AVAILABLE:
                results.extend(self._list_azure_sql(sub_id, account, region))
            if _PG_AVAILABLE:
                results.extend(self._list_postgres_flex(sub_id, account, region))
            if _MYSQL_AVAILABLE:
                results.extend(self._list_mysql_flex(sub_id, account, region))
        if engine:
            results = [r for r in results if engine.lower() in r.engine.lower()]
        return results

    def _list_azure_sql(self, sub_id: str, account: str, region: Optional[str]) -> list[DatabaseResource]:
        try:
            client = SqlManagementClient(self._cred, sub_id)
            results = []
            for server in client.servers.list():
                if region and server.location != region:
                    continue
                _, rg, _ = self._parse_arm_id(server.id)
                for db in client.databases.list_by_server(rg, server.name):
                    if db.name == "master":
                        continue
                    size_gb = int(db.max_size_bytes / (1024 ** 3)) if db.max_size_bytes else None
                    results.append(DatabaseResource(
                        id=db.id or db.name,
                        name=f"{server.name}/{db.name}",
                        engine="Azure SQL",
                        state=db.status or "unknown",
                        region=server.location or "unknown",
                        cloud="azure",
                        account=account,
                        instance_class=db.sku.name if db.sku else None,
                        storage_gb=size_gb,
                        tags=dict(db.tags or {}),
                    ))
            return results
        except Exception:
            return []

    def _list_postgres_flex(self, sub_id: str, account: str, region: Optional[str]) -> list[DatabaseResource]:
        try:
            client = PgFlexClient(self._cred, sub_id)
            results = []
            for server in client.servers.list():
                if region and server.location != region:
                    continue
                results.append(DatabaseResource(
                    id=server.id or server.name,
                    name=server.name,
                    engine="PostgreSQL Flexible",
                    state=server.state.value if server.state else "unknown",
                    region=server.location or "unknown",
                    cloud="azure",
                    account=account,
                    instance_class=server.sku.name if server.sku else None,
                    storage_gb=server.storage.storage_size_gb if server.storage else None,
                    tags=dict(server.tags or {}),
                ))
            return results
        except Exception:
            return []

    def _list_mysql_flex(self, sub_id: str, account: str, region: Optional[str]) -> list[DatabaseResource]:
        try:
            client = MySQLFlexClient(self._cred, sub_id)
            results = []
            for server in client.servers.list():
                if region and server.location != region:
                    continue
                results.append(DatabaseResource(
                    id=server.id or server.name,
                    name=server.name,
                    engine="MySQL Flexible",
                    state=server.state.value if server.state else "unknown",
                    region=server.location or "unknown",
                    cloud="azure",
                    account=account,
                    instance_class=server.sku.name if server.sku else None,
                    storage_gb=server.storage.storage_size_gb if server.storage else None,
                    tags=dict(server.tags or {}),
                ))
            return results
        except Exception:
            return []

    def describe_database(self, account: str, db_id: str, region: Optional[str] = None) -> DatabaseResource:
        raise NotImplementedError("Use list_databases() to find the database first")

    # ── Cost ─────────────────────────────────────────────────────────────────

    def cost_summary(self, account: str, days: int = 30) -> list[dict]:
        """Return monthly cost totals for the last N days via Cost Management API."""
        if not _COST_AVAILABLE:
            return [{"account": account, "period": "—", "cost": "—", "currency": "—",
                     "note": "Install azure-mgmt-costmanagement"}]
        import datetime as _dt
        results = []
        end = _dt.datetime.utcnow()
        start = end - _dt.timedelta(days=days)
        for sub_id in self._subscriptions:
            try:
                client = CostManagementClient(self._cred)
                scope = f"/subscriptions/{sub_id}"
                query = QueryDefinition(
                    type="ActualCost",
                    timeframe="Custom",
                    time_period=QueryTimePeriod(from_property=start, to=end),
                    dataset=QueryDataset(
                        granularity="Monthly",
                        aggregation={"TotalCost": QueryAggregation(name="Cost", function="Sum")},
                    ),
                )
                result = client.query.usage(scope, query)
                col_names = [c["name"] for c in (result.columns or [])]
                cost_idx = col_names.index("Cost") if "Cost" in col_names else 0
                curr_idx = col_names.index("Currency") if "Currency" in col_names else 1
                period_idx = next((i for i, n in enumerate(col_names)
                                   if "Month" in n or "Date" in n), 2)
                for row in (result.rows or []):
                    results.append({
                        "account": account,
                        "period": str(row[period_idx])[:7],
                        "cost": f"{float(row[cost_idx]):.2f}",
                        "currency": str(row[curr_idx]),
                    })
            except Exception:
                pass
        return results

    def cost_by_service(self, account: str, days: int = 30) -> list[dict]:
        """Return cost breakdown by Azure service for the last N days."""
        if not _COST_AVAILABLE:
            return [{"account": account, "service": "—", "period": "—", "cost": "—",
                     "note": "Install azure-mgmt-costmanagement"}]
        import datetime as _dt
        results = []
        end = _dt.datetime.utcnow()
        start = end - _dt.timedelta(days=days)
        for sub_id in self._subscriptions:
            try:
                client = CostManagementClient(self._cred)
                scope = f"/subscriptions/{sub_id}"
                query = QueryDefinition(
                    type="ActualCost",
                    timeframe="Custom",
                    time_period=QueryTimePeriod(from_property=start, to=end),
                    dataset=QueryDataset(
                        granularity="None",
                        aggregation={"TotalCost": QueryAggregation(name="Cost", function="Sum")},
                        grouping=[QueryGrouping(type="Dimension", name="ServiceName")],
                    ),
                )
                result = client.query.usage(scope, query)
                col_names = [c["name"] for c in (result.columns or [])]
                cost_idx = col_names.index("Cost") if "Cost" in col_names else 0
                svc_idx = col_names.index("ServiceName") if "ServiceName" in col_names else 1
                for row in (result.rows or []):
                    results.append({
                        "account": account,
                        "service": str(row[svc_idx]),
                        "period": f"last {days}d",
                        "cost": f"{float(row[cost_idx]):.2f}",
                    })
            except Exception:
                pass
        return results

    # ── Monitoring ───────────────────────────────────────────────────────────

    def list_monitor_alerts(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Monitor metric alert rules across all subscriptions."""
        if not _MONITOR_AVAILABLE:
            return [{"account": account, "name": "azure-mgmt-monitor not installed",
                     "state": "—", "severity": "—", "region": "—"}]
        results = []
        for sub_id in self._subscriptions:
            try:
                client = MonitorManagementClient(self._cred, sub_id)
                for alert in client.metric_alerts.list_by_subscription():
                    if region and alert.location != region:
                        continue
                    results.append({
                        "account": account,
                        "name": alert.name,
                        "state": "enabled" if alert.enabled else "disabled",
                        "severity": str(alert.severity) if alert.severity is not None else "—",
                        "region": alert.location or "global",
                        "description": (alert.description or "")[:60],
                    })
            except Exception:
                pass
        return results

    # ── Messaging ────────────────────────────────────────────────────────────

    def list_service_bus_namespaces(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Service Bus namespaces."""
        if not _SERVICEBUS_AVAILABLE:
            return [{"account": account, "name": "azure-mgmt-servicebus not installed",
                     "sku": "—", "state": "—", "region": "—"}]
        results = []
        for sub_id in self._subscriptions:
            try:
                client = ServiceBusManagementClient(self._cred, sub_id)
                for ns in client.namespaces.list():
                    if region and ns.location != region:
                        continue
                    results.append({
                        "account": account,
                        "name": ns.name,
                        "sku": ns.sku.name if ns.sku else "—",
                        "state": ns.status or "—",
                        "region": ns.location or "unknown",
                    })
            except Exception:
                pass
        return results

    def list_event_hub_namespaces(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Event Hub namespaces."""
        if not _EVENTHUB_AVAILABLE:
            return [{"account": account, "name": "azure-mgmt-eventhub not installed",
                     "sku": "—", "state": "—", "region": "—"}]
        results = []
        for sub_id in self._subscriptions:
            try:
                client = EventHubManagementClient(self._cred, sub_id)
                for ns in client.namespaces.list():
                    if region and ns.location != region:
                        continue
                    results.append({
                        "account": account,
                        "name": ns.name,
                        "sku": ns.sku.name if ns.sku else "—",
                        "state": ns.status or "—",
                        "region": ns.location or "unknown",
                    })
            except Exception:
                pass
        return results

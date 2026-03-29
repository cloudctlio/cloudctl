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
    from azure.mgmt.network import NetworkManagementClient
    _NETWORK_AVAILABLE = True
except ImportError:
    _NETWORK_AVAILABLE = False

try:
    from azure.mgmt.authorization import AuthorizationManagementClient
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

try:
    from azure.mgmt.keyvault import KeyVaultManagementClient
    _KEYVAULT_AVAILABLE = True
except ImportError:
    _KEYVAULT_AVAILABLE = False

try:
    from azure.mgmt.msi import ManagedServiceIdentityClient
    _MSI_AVAILABLE = True
except ImportError:
    _MSI_AVAILABLE = False

try:
    from azure.mgmt.security import SecurityCenter
    _SECURITY_AVAILABLE = True
except ImportError:
    _SECURITY_AVAILABLE = False


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

    # ── Network ──────────────────────────────────────────────────────────────

    def list_vnets(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Virtual Networks across all subscriptions."""
        if not _NETWORK_AVAILABLE:
            return [{"account": account, "id": "—", "name": "azure-mgmt-network not installed",
                     "cidr": "—", "state": "—", "default": False, "region": "—"}]
        results = []
        for sub_id in self._subscriptions:
            try:
                client = NetworkManagementClient(self._cred, sub_id)
                for vnet in client.virtual_networks.list_all():
                    if region and vnet.location != region:
                        continue
                    prefixes = vnet.address_space.address_prefixes if vnet.address_space else []
                    results.append({
                        "account": account,
                        "id": vnet.id or vnet.name,
                        "name": vnet.name,
                        "cidr": ", ".join(prefixes) if prefixes else "—",
                        "state": "available",
                        "default": False,
                        "region": vnet.location or "unknown",
                    })
            except Exception:
                pass
        return results

    def list_nsgs(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Network Security Groups across all subscriptions."""
        if not _NETWORK_AVAILABLE:
            return [{"account": account, "id": "—", "name": "azure-mgmt-network not installed",
                     "vpc_id": "—", "inbound_rules": 0, "outbound_rules": 0, "region": "—"}]
        results = []
        for sub_id in self._subscriptions:
            try:
                client = NetworkManagementClient(self._cred, sub_id)
                for nsg in client.network_security_groups.list_all():
                    if region and nsg.location != region:
                        continue
                    inbound = sum(
                        1 for r in (nsg.security_rules or []) if r.direction == "Inbound"
                    )
                    outbound = sum(
                        1 for r in (nsg.security_rules or []) if r.direction == "Outbound"
                    )
                    results.append({
                        "account": account,
                        "id": nsg.id or nsg.name,
                        "name": nsg.name,
                        "vpc_id": "—",
                        "inbound_rules": inbound,
                        "outbound_rules": outbound,
                        "region": nsg.location or "unknown",
                    })
            except Exception:
                pass
        return results

    # ── IAM ──────────────────────────────────────────────────────────────────

    def list_rbac_assignments(self, account: str) -> list[dict]:
        """List RBAC role assignments across all subscriptions."""
        if not _AUTH_AVAILABLE:
            return [{"account": account, "name": "azure-mgmt-authorization not installed",
                     "id": "—", "path": "—", "created": "—"}]
        results = []
        for sub_id in self._subscriptions:
            try:
                client = AuthorizationManagementClient(self._cred, sub_id)
                # Build role definition name map to avoid per-assignment API calls
                role_map: dict[str, str] = {}
                try:
                    for rd in client.role_definitions.list(scope=f"/subscriptions/{sub_id}"):
                        if rd.name and rd.role_name:
                            role_map[rd.name] = rd.role_name
                except Exception:
                    pass
                for assignment in client.role_assignments.list_for_subscription():
                    role_def_uuid = (assignment.role_definition_id or "").split("/")[-1]
                    role_name = role_map.get(role_def_uuid, role_def_uuid or "—")
                    results.append({
                        "account": account,
                        "name": role_name,
                        "id": assignment.principal_id or "—",
                        "path": assignment.scope or "—",
                        "created": str(assignment.created_on)[:10] if assignment.created_on else "—",
                    })
            except Exception:
                pass
        return results

    def list_key_vaults(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Key Vaults across all subscriptions."""
        if not _KEYVAULT_AVAILABLE:
            return [{"account": account, "name": "azure-mgmt-keyvault not installed",
                     "id": "—", "sku": "—", "uri": "—", "region": "—"}]
        results = []
        for sub_id in self._subscriptions:
            try:
                client = KeyVaultManagementClient(self._cred, sub_id)
                for vault_ref in client.vaults.list():
                    _, rg, name = self._parse_arm_id(vault_ref.id)
                    if region:
                        # vault_ref only has id/name/type/location — check location
                        if hasattr(vault_ref, "location") and vault_ref.location != region:
                            continue
                    try:
                        vault = client.vaults.get(rg, name)
                        sku = vault.properties.sku.name if vault.properties and vault.properties.sku else "—"
                        uri = vault.properties.vault_uri if vault.properties else "—"
                        loc = vault.location or "unknown"
                    except Exception:
                        sku, uri, loc = "—", "—", "unknown"
                    results.append({
                        "account": account,
                        "name": name,
                        "id": vault_ref.id or name,
                        "sku": sku,
                        "uri": uri,
                        "region": loc,
                    })
            except Exception:
                pass
        return results

    def list_managed_identities(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List user-assigned managed identities across all subscriptions."""
        if not _MSI_AVAILABLE:
            return [{"account": account, "username": "azure-mgmt-msi not installed",
                     "id": "—", "created": "—", "last_login": "—"}]
        results = []
        for sub_id in self._subscriptions:
            try:
                client = ManagedServiceIdentityClient(self._cred, sub_id)
                for identity in client.user_assigned_identities.list_by_subscription():
                    if region and identity.location != region:
                        continue
                    results.append({
                        "account": account,
                        "username": identity.name,
                        "id": identity.client_id or identity.principal_id or "—",
                        "created": "—",
                        "last_login": "—",
                    })
            except Exception:
                pass
        return results

    # ── Security ─────────────────────────────────────────────────────────────

    def security_audit(self, account: str) -> list[dict]:
        """Run Defender for Cloud assessments and return unhealthy findings."""
        if not _SECURITY_AVAILABLE:
            return [{"account": account, "severity": "INFO",
                     "resource": "azure-mgmt-security",
                     "issue": "Install azure-mgmt-security for Defender for Cloud checks"}]
        results = []
        for sub_id in self._subscriptions:
            try:
                client = SecurityCenter(self._cred, sub_id)
                for assessment in client.assessments.list(scope=f"/subscriptions/{sub_id}"):
                    if not assessment.status or assessment.status.code != "Unhealthy":
                        continue
                    severity = "MEDIUM"
                    try:
                        meta = client.assessments_metadata.get(assessment_name=assessment.name)
                        if meta and meta.severity:
                            severity = str(meta.severity).upper()
                    except Exception:
                        pass
                    resource_id = ""
                    if hasattr(assessment, "resource_details") and assessment.resource_details:
                        resource_id = getattr(assessment.resource_details, "id", "") or ""
                    results.append({
                        "account": account,
                        "severity": severity,
                        "resource": resource_id or assessment.name,
                        "issue": assessment.display_name or assessment.name,
                    })
            except Exception:
                pass
        return results

    def list_public_resources(self, account: str) -> list[dict]:
        """List publicly accessible Azure resources (public blobs, open NSGs)."""
        results = []
        for sub_id in self._subscriptions:
            # Public storage accounts (blob public access enabled)
            try:
                storage_client = StorageManagementClient(self._cred, sub_id)
                for sa in storage_client.storage_accounts.list():
                    if sa.allow_blob_public_access:
                        results.append({
                            "account": account,
                            "type": "Storage Account (Public Blob)",
                            "id": sa.name,
                            "region": sa.location or "unknown",
                        })
            except Exception:
                pass
            # NSGs with open inbound rules (any port from internet)
            if _NETWORK_AVAILABLE:
                try:
                    net_client = NetworkManagementClient(self._cred, sub_id)
                    for nsg in net_client.network_security_groups.list_all():
                        for rule in (nsg.security_rules or []):
                            if (
                                rule.access == "Allow"
                                and rule.direction == "Inbound"
                                and rule.source_address_prefix in ("*", "Internet", "0.0.0.0/0")
                                and rule.destination_port_range in ("*", "0-65535")
                            ):
                                results.append({
                                    "account": account,
                                    "type": f"NSG (Open Rule: {rule.name})",
                                    "id": nsg.name,
                                    "region": nsg.location or "unknown",
                                })
                                break
                except Exception:
                    pass
        return results

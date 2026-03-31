"""Azure cloud provider — full service coverage via existing `az login` credentials."""
from __future__ import annotations

from typing import Optional

from cloudctl.providers.base import CloudProvider, ComputeResource, DatabaseResource, StorageResource

# ── Core (required) ──────────────────────────────────────────────────────────
try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.subscription import SubscriptionClient
    _AZURE_AVAILABLE = True
except ImportError:
    _AZURE_AVAILABLE = False

# ── Database ─────────────────────────────────────────────────────────────────
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
    from azure.mgmt.cosmosdb import CosmosDBManagementClient
    _COSMOSDB_AVAILABLE = True
except ImportError:
    _COSMOSDB_AVAILABLE = False

try:
    from azure.mgmt.redis import RedisManagementClient
    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False

# ── Compute extras ────────────────────────────────────────────────────────────
try:
    from azure.mgmt.containerservice import ContainerServiceClient
    _AKS_AVAILABLE = True
except ImportError:
    _AKS_AVAILABLE = False

try:
    from azure.mgmt.containerinstance import ContainerInstanceManagementClient
    _ACI_AVAILABLE = True
except ImportError:
    _ACI_AVAILABLE = False

try:
    from azure.mgmt.web import WebSiteManagementClient
    _WEB_AVAILABLE = True
except ImportError:
    _WEB_AVAILABLE = False

# ── Network ───────────────────────────────────────────────────────────────────
try:
    from azure.mgmt.network import NetworkManagementClient
    _NETWORK_AVAILABLE = True
except ImportError:
    _NETWORK_AVAILABLE = False

try:
    from azure.mgmt.dns import DnsManagementClient
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

try:
    from azure.mgmt.apimanagement import ApiManagementClient
    _APIM_AVAILABLE = True
except ImportError:
    _APIM_AVAILABLE = False

# ── IAM / Security ────────────────────────────────────────────────────────────
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

# ── Containers / DevOps ───────────────────────────────────────────────────────
try:
    from azure.mgmt.containerregistry import ContainerRegistryManagementClient
    _ACR_AVAILABLE = True
except ImportError:
    _ACR_AVAILABLE = False

# ── Monitoring ────────────────────────────────────────────────────────────────
try:
    from azure.mgmt.monitor import MonitorManagementClient
    _MONITOR_AVAILABLE = True
except ImportError:
    _MONITOR_AVAILABLE = False

# ── Messaging / Integration ───────────────────────────────────────────────────
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
    from azure.mgmt.logic import LogicManagementClient
    _LOGIC_AVAILABLE = True
except ImportError:
    _LOGIC_AVAILABLE = False

# ── AI / Analytics ────────────────────────────────────────────────────────────
try:
    from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
    _COGSVCS_AVAILABLE = True
except ImportError:
    _COGSVCS_AVAILABLE = False

try:
    from azure.mgmt.synapse import SynapseManagementClient
    _SYNAPSE_AVAILABLE = True
except ImportError:
    _SYNAPSE_AVAILABLE = False

try:
    from azure.mgmt.datafactory import DataFactoryManagementClient
    _ADF_AVAILABLE = True
except ImportError:
    _ADF_AVAILABLE = False

# ── Cost ──────────────────────────────────────────────────────────────────────
try:
    from azure.mgmt.costmanagement import CostManagementClient
    from azure.mgmt.costmanagement.models import (
        QueryDefinition, QueryTimePeriod, QueryDataset,
        QueryAggregation, QueryGrouping,
    )
    _COST_AVAILABLE = True
except ImportError:
    _COST_AVAILABLE = False

# ── Backup ────────────────────────────────────────────────────────────────────
try:
    from azure.mgmt.recoveryservices import RecoveryServicesClient
    _BACKUP_AVAILABLE = True
except ImportError:
    _BACKUP_AVAILABLE = False


class AzureProvider(CloudProvider):
    """Azure provider — uses credentials from `az login` / environment / managed identity."""

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

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _list_subscriptions(self) -> list[str]:
        client = SubscriptionClient(self._cred)
        return [s.subscription_id for s in client.subscriptions.list()]

    def _parse_arm_id(self, arm_id: str) -> tuple[str, str, str]:
        """Parse ARM resource ID → (subscription_id, resource_group, name)."""
        parts = (arm_id or "").strip("/").split("/")
        if len(parts) >= 8:
            return parts[1], parts[3], parts[-1]
        if len(parts) == 3:
            return parts[0], parts[1], parts[2]
        return self._subscriptions[0], parts[0] if parts else "", parts[-1] if parts else ""

    def _stub(self, account: str, service: str, pkg: str) -> list[dict]:
        return [{"account": account, "name": f"{pkg} not installed — run: pip install 'cctl[azure]'",
                 "service": service, "region": "—", "state": "—"}]

    # ── Compute — Virtual Machines ───────────────────────────────────────────

    def _compute_from_sub(
        self, sub_id: str, account: str,
        region: Optional[str], state: Optional[str], tags: Optional[dict],
    ) -> list[ComputeResource]:
        results = []
        client = ComputeManagementClient(self._cred, sub_id)
        for vm in client.virtual_machines.list_all():
            if region and vm.location != region:
                continue
            if tags and not all((vm.tags or {}).get(k) == v for k, v in tags.items()):
                continue
            vm_state = self._vm_power_state(client, vm)
            if state and vm_state != state:
                continue
            results.append(ComputeResource(
                id=vm.id or vm.name, name=vm.name, state=vm_state,
                type=vm.hardware_profile.vm_size if vm.hardware_profile else "unknown",
                region=vm.location or "unknown", cloud="azure", account=account,
                tags=dict(vm.tags or {}),
            ))
        return results

    def list_compute(
        self,
        account: str,
        region: Optional[str] = None,
        state: Optional[str] = None,
        tags: Optional[dict] = None,
    ) -> list[ComputeResource]:
        results = []
        for sub_id in self._subscriptions:
            results.extend(self._compute_from_sub(sub_id, account, region, state, tags))
        return results

    def _vm_power_state(self, client, vm) -> str:
        try:
            _, rg, name = self._parse_arm_id(vm.id)
            iv = client.virtual_machines.instance_view(rg, name)
            for s in iv.statuses or []:
                if s.code and s.code.startswith("PowerState/"):
                    return s.code.split("/")[1]
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
            id=vm.id or vm.name, name=vm.name, state=vm_state,
            type=vm.hardware_profile.vm_size if vm.hardware_profile else "unknown",
            region=vm.location or "unknown", cloud="azure", account=account,
            tags=dict(vm.tags or {}),
        )

    def stop_compute(self, account: str, instance_id: str) -> None:
        sub_id, rg, name = self._parse_arm_id(instance_id)
        ComputeManagementClient(self._cred, sub_id).virtual_machines.begin_deallocate(rg, name).wait()

    def start_compute(self, account: str, instance_id: str) -> None:
        sub_id, rg, name = self._parse_arm_id(instance_id)
        ComputeManagementClient(self._cred, sub_id).virtual_machines.begin_start(rg, name).wait()

    # ── Compute — VM Scale Sets ───────────────────────────────────────────────

    def _vmss_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = ComputeManagementClient(self._cred, sub_id)
        for vmss in client.virtual_machine_scale_sets.list_all():
            if region and vmss.location != region:
                continue
            results.append({
                "account": account, "name": vmss.name,
                "sku": vmss.sku.name if vmss.sku else "—",
                "capacity": vmss.sku.capacity if vmss.sku else "—",
                "state": vmss.provisioning_state or "—",
                "region": vmss.location or "unknown",
            })
        return results

    def list_vmss(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Virtual Machine Scale Sets."""
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._vmss_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Compute — AKS ─────────────────────────────────────────────────────────

    def _aks_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = ContainerServiceClient(self._cred, sub_id)
        for cluster in client.managed_clusters.list():
            if region and cluster.location != region:
                continue
            results.append({
                "account": account, "name": cluster.name,
                "k8s_version": cluster.kubernetes_version or "—",
                "node_count": sum(
                    (p.count or 0) for p in (cluster.agent_pool_profiles or [])
                ),
                "state": cluster.provisioning_state or "—",
                "region": cluster.location or "unknown",
            })
        return results

    def list_aks_clusters(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Kubernetes Service clusters."""
        if not _AKS_AVAILABLE:
            return self._stub(account, "AKS", "azure-mgmt-containerservice")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._aks_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Compute — ACI ─────────────────────────────────────────────────────────

    def _aci_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = ContainerInstanceManagementClient(self._cred, sub_id)
        for cg in client.container_groups.list():
            if region and cg.location != region:
                continue
            results.append({
                "account": account, "name": cg.name,
                "containers": len(cg.containers or []),
                "os_type": str(cg.os_type) if cg.os_type else "—",
                "state": cg.provisioning_state or "—",
                "region": cg.location or "unknown",
            })
        return results

    def list_container_instances(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Container Instances (container groups)."""
        if not _ACI_AVAILABLE:
            return self._stub(account, "ACI", "azure-mgmt-containerinstance")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._aci_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Compute — App Service & Functions ────────────────────────────────────

    def _app_services_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = WebSiteManagementClient(self._cred, sub_id)
        for app in client.web_apps.list():
            if region and app.location != region:
                continue
            if app.kind and "functionapp" in (app.kind or ""):
                continue  # skip function apps here
            results.append({
                "account": account, "name": app.name,
                "sku": app.sku if hasattr(app, "sku") else "—",
                "state": app.state or "—",
                "url": f"https://{app.default_host_name}" if app.default_host_name else "—",
                "region": app.location or "unknown",
            })
        return results

    def list_app_services(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List App Service web apps."""
        if not _WEB_AVAILABLE:
            return self._stub(account, "App Service", "azure-mgmt-web")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._app_services_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    def _functions_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = WebSiteManagementClient(self._cred, sub_id)
        for app in client.web_apps.list():
            if region and app.location != region:
                continue
            if "functionapp" not in (app.kind or ""):
                continue
            results.append({
                "account": account, "name": app.name,
                "runtime": (app.site_config.linux_fx_version or "—")
                           if app.site_config else "—",
                "state": app.state or "—",
                "url": f"https://{app.default_host_name}" if app.default_host_name else "—",
                "region": app.location or "unknown",
            })
        return results

    def list_functions(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Function Apps."""
        if not _WEB_AVAILABLE:
            return self._stub(account, "Functions", "azure-mgmt-web")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._functions_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Storage — Storage Accounts ───────────────────────────────────────────

    def _storage_from_sub(
        self, sub_id: str, account: str, region: Optional[str], public_only: bool
    ) -> list[StorageResource]:
        results = []
        client = StorageManagementClient(self._cred, sub_id)
        for sa in client.storage_accounts.list():
            if region and sa.location != region:
                continue
            is_public = bool(sa.allow_blob_public_access)
            if public_only and not is_public:
                continue
            results.append(StorageResource(
                id=sa.id or sa.name, name=sa.name,
                region=sa.location or "unknown", cloud="azure", account=account,
                public=is_public, tags=dict(sa.tags or {}),
                created_at=sa.creation_time.isoformat() if sa.creation_time else None,
            ))
        return results

    def list_storage(
        self,
        account: str,
        region: Optional[str] = None,
        public_only: bool = False,
    ) -> list[StorageResource]:
        results = []
        for sub_id in self._subscriptions:
            results.extend(self._storage_from_sub(sub_id, account, region, public_only))
        return results

    def describe_storage(self, account: str, storage_name: str) -> StorageResource:
        for sub_id in self._subscriptions:
            for sa in StorageManagementClient(self._cred, sub_id).storage_accounts.list():
                if sa.name == storage_name:
                    return StorageResource(
                        id=sa.id or sa.name, name=sa.name,
                        region=sa.location or "unknown", cloud="azure", account=account,
                        public=bool(sa.allow_blob_public_access), tags=dict(sa.tags or {}),
                        created_at=sa.creation_time.isoformat() if sa.creation_time else None,
                    )
        raise ValueError(f"Storage account '{storage_name}' not found")

    # ── Storage — Managed Disks ───────────────────────────────────────────────

    def _managed_disks_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = ComputeManagementClient(self._cred, sub_id)
        for disk in client.disks.list():
            if region and disk.location != region:
                continue
            results.append({
                "account": account, "name": disk.name,
                "size_gb": disk.disk_size_gb or "—",
                "sku": disk.sku.name if disk.sku else "—",
                "state": str(disk.disk_state) if disk.disk_state else "—",
                "attached_to": disk.managed_by.split("/")[-1] if disk.managed_by else "unattached",
                "region": disk.location or "unknown",
            })
        return results

    def list_managed_disks(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Managed Disks."""
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._managed_disks_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Storage — File Shares ─────────────────────────────────────────────────

    def _file_shares_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        storage_client = StorageManagementClient(self._cred, sub_id)
        for sa in storage_client.storage_accounts.list():
            if region and sa.location != region:
                continue
            _, rg, _ = self._parse_arm_id(sa.id)
            try:
                for share in storage_client.file_shares.list(rg, sa.name):
                    results.append({
                        "account": account,
                        "name": f"{sa.name}/{share.name}",
                        "quota_gb": share.share_quota or "—",
                        "state": share.lease_status or "—",
                        "region": sa.location or "unknown",
                    })
            except Exception:
                pass
        return results

    def list_file_shares(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure File Shares across all storage accounts."""
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._file_shares_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Network — VNets & NSGs ────────────────────────────────────────────────

    def _vnets_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = NetworkManagementClient(self._cred, sub_id)
        for vnet in client.virtual_networks.list_all():
            if region and vnet.location != region:
                continue
            prefixes = vnet.address_space.address_prefixes if vnet.address_space else []
            results.append({
                "account": account, "id": vnet.id or vnet.name, "name": vnet.name,
                "cidr": ", ".join(prefixes) if prefixes else "—",
                "state": "available", "default": False,
                "region": vnet.location or "unknown",
            })
        return results

    def list_vnets(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Virtual Networks."""
        if not _NETWORK_AVAILABLE:
            return self._stub(account, "VNet", "azure-mgmt-network")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._vnets_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    def _nsgs_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = NetworkManagementClient(self._cred, sub_id)
        for nsg in client.network_security_groups.list_all():
            if region and nsg.location != region:
                continue
            inbound = sum(1 for r in (nsg.security_rules or []) if r.direction == "Inbound")
            outbound = sum(1 for r in (nsg.security_rules or []) if r.direction == "Outbound")
            results.append({
                "account": account, "id": nsg.id or nsg.name, "name": nsg.name,
                "vpc_id": "—", "inbound_rules": inbound, "outbound_rules": outbound,
                "region": nsg.location or "unknown",
            })
        return results

    def list_nsgs(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Network Security Groups."""
        if not _NETWORK_AVAILABLE:
            return self._stub(account, "NSG", "azure-mgmt-network")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._nsgs_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Network — Load Balancers ──────────────────────────────────────────────

    def _load_balancers_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = NetworkManagementClient(self._cred, sub_id)
        for lb in client.load_balancers.list_all():
            if region and lb.location != region:
                continue
            results.append({
                "account": account, "name": lb.name,
                "sku": lb.sku.name if lb.sku else "—",
                "state": lb.provisioning_state or "—",
                "region": lb.location or "unknown",
            })
        return results

    def list_load_balancers(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Load Balancers."""
        if not _NETWORK_AVAILABLE:
            return self._stub(account, "Load Balancer", "azure-mgmt-network")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._load_balancers_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Network — Application Gateways ───────────────────────────────────────

    def list_application_gateways(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Application Gateways."""
        if not _NETWORK_AVAILABLE:
            return self._stub(account, "App Gateway", "azure-mgmt-network")
        results = []
        for sub_id in self._subscriptions:
            try:
                client = NetworkManagementClient(self._cred, sub_id)
                for ag in client.application_gateways.list_all():
                    if region and ag.location != region:
                        continue
                    results.append({
                        "account": account, "name": ag.name,
                        "sku": ag.sku.name if ag.sku else "—",
                        "state": ag.provisioning_state or "—",
                        "region": ag.location or "unknown",
                    })
            except Exception:
                pass
        return results

    # ── Network — DNS ─────────────────────────────────────────────────────────

    def list_dns_zones(self, account: str) -> list[dict]:
        """List Azure DNS Zones."""
        if not _DNS_AVAILABLE:
            return self._stub(account, "DNS", "azure-mgmt-dns")
        results = []
        for sub_id in self._subscriptions:
            try:
                client = DnsManagementClient(self._cred, sub_id)
                for zone in client.zones.list():
                    results.append({
                        "account": account, "name": zone.name,
                        "record_sets": zone.number_of_record_sets or 0,
                        "region": zone.location or "global",
                    })
            except Exception:
                pass
        return results

    # ── Network — Firewall ────────────────────────────────────────────────────

    def list_firewalls(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Firewalls."""
        if not _NETWORK_AVAILABLE:
            return self._stub(account, "Firewall", "azure-mgmt-network")
        results = []
        for sub_id in self._subscriptions:
            try:
                client = NetworkManagementClient(self._cred, sub_id)
                for fw in client.azure_firewalls.list_all():
                    if region and fw.location != region:
                        continue
                    results.append({
                        "account": account, "name": fw.name,
                        "sku": fw.sku.name if fw.sku else "—",
                        "state": fw.provisioning_state or "—",
                        "region": fw.location or "unknown",
                    })
            except Exception:
                pass
        return results

    # ── Network — Private Endpoints ───────────────────────────────────────────

    def list_private_endpoints(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Private Endpoints."""
        if not _NETWORK_AVAILABLE:
            return self._stub(account, "Private Endpoint", "azure-mgmt-network")
        results = []
        for sub_id in self._subscriptions:
            try:
                client = NetworkManagementClient(self._cred, sub_id)
                for pe in client.private_endpoints.list_by_subscription():
                    if region and pe.location != region:
                        continue
                    results.append({
                        "account": account, "name": pe.name,
                        "state": pe.provisioning_state or "—",
                        "region": pe.location or "unknown",
                    })
            except Exception:
                pass
        return results

    # ── Network — VPN Gateways ────────────────────────────────────────────────

    def list_vpn_gateways(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Virtual Network (VPN) Gateways."""
        if not _NETWORK_AVAILABLE:
            return self._stub(account, "VPN Gateway", "azure-mgmt-network")
        results = []
        for sub_id in self._subscriptions:
            try:
                client = NetworkManagementClient(self._cred, sub_id)
                for rg_obj in ComputeManagementClient(self._cred, sub_id).resource_groups.list() \
                        if False else []:
                    pass
                # list all VPN gateways requires iterating by resource group;
                # use a broader list approach
                for vgw in client.virtual_network_gateways.list_all() \
                        if hasattr(client.virtual_network_gateways, "list_all") else []:
                    if region and vgw.location != region:
                        continue
                    results.append({
                        "account": account, "name": vgw.name,
                        "type": str(vgw.gateway_type) if vgw.gateway_type else "—",
                        "state": vgw.provisioning_state or "—",
                        "region": vgw.location or "unknown",
                    })
            except Exception:
                pass
        return results

    # ── Network — API Management ──────────────────────────────────────────────

    def list_api_management(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List API Management services."""
        if not _APIM_AVAILABLE:
            return self._stub(account, "APIM", "azure-mgmt-apimanagement")
        results = []
        for sub_id in self._subscriptions:
            try:
                client = ApiManagementClient(self._cred, sub_id)
                for svc in client.api_management_service.list():
                    if region and svc.location != region:
                        continue
                    results.append({
                        "account": account, "name": svc.name,
                        "sku": svc.sku.name if svc.sku else "—",
                        "gateway_url": svc.gateway_url or "—",
                        "state": svc.provisioning_state or "—",
                        "region": svc.location or "unknown",
                    })
            except Exception:
                pass
        return results

    # ── Database — SQL / PostgreSQL / MySQL ───────────────────────────────────

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

    def _list_azure_sql(self, sub_id, account, region):
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
                    results.append(DatabaseResource(
                        id=db.id or db.name, name=f"{server.name}/{db.name}",
                        engine="Azure SQL", state=db.status or "unknown",
                        region=server.location or "unknown", cloud="azure", account=account,
                        instance_class=db.sku.name if db.sku else None,
                        storage_gb=int(db.max_size_bytes / (1024 ** 3)) if db.max_size_bytes else None,
                        tags=dict(db.tags or {}),
                    ))
            return results
        except Exception:
            return []

    def _list_postgres_flex(self, sub_id, account, region):
        try:
            client = PgFlexClient(self._cred, sub_id)
            return [
                DatabaseResource(
                    id=s.id or s.name, name=s.name, engine="PostgreSQL Flexible",
                    state=s.state.value if s.state else "unknown",
                    region=s.location or "unknown", cloud="azure", account=account,
                    instance_class=s.sku.name if s.sku else None,
                    storage_gb=s.storage.storage_size_gb if s.storage else None,
                    tags=dict(s.tags or {}),
                )
                for s in client.servers.list()
                if not region or s.location == region
            ]
        except Exception:
            return []

    def _list_mysql_flex(self, sub_id, account, region):
        try:
            client = MySQLFlexClient(self._cred, sub_id)
            return [
                DatabaseResource(
                    id=s.id or s.name, name=s.name, engine="MySQL Flexible",
                    state=s.state.value if s.state else "unknown",
                    region=s.location or "unknown", cloud="azure", account=account,
                    instance_class=s.sku.name if s.sku else None,
                    storage_gb=s.storage.storage_size_gb if s.storage else None,
                    tags=dict(s.tags or {}),
                )
                for s in client.servers.list()
                if not region or s.location == region
            ]
        except Exception:
            return []

    def describe_database(self, account: str, db_id: str, region: Optional[str] = None) -> DatabaseResource:
        raise NotImplementedError("Use list_databases() to find the database first")

    # ── Database — CosmosDB ───────────────────────────────────────────────────

    def _cosmos_db_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = CosmosDBManagementClient(self._cred, sub_id)
        for db_account in client.database_accounts.list():
            if region and db_account.location != region:
                continue
            results.append({
                "account": account, "name": db_account.name,
                "kind": str(db_account.kind) if db_account.kind else "—",
                "endpoint": db_account.document_endpoint or "—",
                "state": db_account.provisioning_state or "—",
                "region": db_account.location or "unknown",
            })
        return results

    def list_cosmos_db(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cosmos DB accounts."""
        if not _COSMOSDB_AVAILABLE:
            return self._stub(account, "CosmosDB", "azure-mgmt-cosmosdb")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._cosmos_db_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Database — Redis Cache ─────────────────────────────────────────────────

    def _redis_caches_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = RedisManagementClient(self._cred, sub_id)
        for cache in client.redis.list():
            if region and cache.location != region:
                continue
            results.append({
                "account": account, "name": cache.name,
                "sku": f"{cache.sku.name} C{cache.sku.capacity}" if cache.sku else "—",
                "host": cache.host_name or "—",
                "state": cache.provisioning_state or "—",
                "region": cache.location or "unknown",
            })
        return results

    def list_redis_caches(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Cache for Redis."""
        if not _REDIS_AVAILABLE:
            return self._stub(account, "Redis Cache", "azure-mgmt-redis")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._redis_caches_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── IAM — RBAC / Key Vault / Managed Identities ───────────────────────────

    def _build_role_map(self, client, sub_id: str) -> dict[str, str]:
        role_map: dict[str, str] = {}
        try:
            for rd in client.role_definitions.list(scope=f"/subscriptions/{sub_id}"):
                if rd.name and rd.role_name:
                    role_map[rd.name] = rd.role_name
        except Exception:
            pass
        return role_map

    def _rbac_from_sub(self, sub_id: str, account: str) -> list[dict]:
        results = []
        client = AuthorizationManagementClient(self._cred, sub_id)
        role_map = self._build_role_map(client, sub_id)
        for assignment in client.role_assignments.list_for_subscription():
            role_def_uuid = (assignment.role_definition_id or "").split("/")[-1]
            results.append({
                "account": account,
                "name": role_map.get(role_def_uuid, role_def_uuid or "—"),
                "id": assignment.principal_id or "—",
                "path": assignment.scope or "—",
                "created": str(assignment.created_on)[:10] if assignment.created_on else "—",
            })
        return results

    def list_rbac_assignments(self, account: str) -> list[dict]:
        """List RBAC role assignments."""
        if not _AUTH_AVAILABLE:
            return self._stub(account, "RBAC", "azure-mgmt-authorization")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._rbac_from_sub(sub_id, account))
            except Exception:
                pass
        return results

    def _vault_details(self, client, rg: str, name: str) -> tuple[str, str, str]:
        try:
            vault = client.vaults.get(rg, name)
            sku = vault.properties.sku.name if vault.properties and vault.properties.sku else "—"
            uri = vault.properties.vault_uri if vault.properties else "—"
            loc = vault.location or "unknown"
            return sku, uri, loc
        except Exception:
            return "—", "—", "unknown"

    def _key_vaults_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = KeyVaultManagementClient(self._cred, sub_id)
        for vault_ref in client.vaults.list():
            _, rg, name = self._parse_arm_id(vault_ref.id)
            sku, uri, loc = self._vault_details(client, rg, name)
            if region and loc != region:
                continue
            results.append({
                "account": account, "name": name,
                "id": vault_ref.id or name, "sku": sku,
                "uri": uri, "region": loc,
            })
        return results

    def list_key_vaults(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Key Vaults."""
        if not _KEYVAULT_AVAILABLE:
            return self._stub(account, "Key Vault", "azure-mgmt-keyvault")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._key_vaults_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    def _managed_identities_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = ManagedServiceIdentityClient(self._cred, sub_id)
        for identity in client.user_assigned_identities.list_by_subscription():
            if region and identity.location != region:
                continue
            results.append({
                "account": account,
                "name": identity.name,
                "id": identity.client_id or identity.principal_id or "—",
                "created": "—", "last_login": "—",
            })
        return results

    def list_managed_identities(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List user-assigned managed identities."""
        if not _MSI_AVAILABLE:
            return self._stub(account, "Managed Identity", "azure-mgmt-msi")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._managed_identities_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Containers — ACR ──────────────────────────────────────────────────────

    def _container_registries_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = ContainerRegistryManagementClient(self._cred, sub_id)
        for registry in client.registries.list():
            if region and registry.location != region:
                continue
            results.append({
                "account": account, "name": registry.name,
                "sku": registry.sku.name if registry.sku else "—",
                "login_server": registry.login_server or "—",
                "state": registry.provisioning_state or "—",
                "region": registry.location or "unknown",
            })
        return results

    def list_container_registries(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Container Registries."""
        if not _ACR_AVAILABLE:
            return self._stub(account, "ACR", "azure-mgmt-containerregistry")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._container_registries_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Security — Defender for Cloud ─────────────────────────────────────────

    def _assessment_severity(self, client, assessment) -> str:
        try:
            meta = client.assessments_metadata.get(assessment_name=assessment.name)
            if meta and meta.severity:
                return str(meta.severity).upper()
        except Exception:
            pass
        return "MEDIUM"

    def _security_audit_from_sub(self, sub_id: str, account: str) -> list[dict]:
        results = []
        client = SecurityCenter(self._cred, sub_id)
        for assessment in client.assessments.list(scope=f"/subscriptions/{sub_id}"):
            if not assessment.status or assessment.status.code != "Unhealthy":
                continue
            severity = self._assessment_severity(client, assessment)
            resource_id = ""
            if hasattr(assessment, "resource_details") and assessment.resource_details:
                resource_id = getattr(assessment.resource_details, "id", "") or ""
            results.append({
                "account": account, "severity": severity,
                "resource": resource_id or assessment.name,
                "issue": assessment.display_name or assessment.name,
            })
        return results

    def security_audit(self, account: str) -> list[dict]:
        """Run Defender for Cloud assessments."""
        if not _SECURITY_AVAILABLE:
            return [{"account": account, "severity": "INFO",
                     "resource": "azure-mgmt-security",
                     "issue": "Install azure-mgmt-security for Defender for Cloud checks"}]
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._security_audit_from_sub(sub_id, account))
            except Exception:
                pass
        return results

    def _public_storage_from_sub(self, sub_id: str, account: str) -> list[dict]:
        results = []
        storage_client = StorageManagementClient(self._cred, sub_id)
        for sa in storage_client.storage_accounts.list():
            if sa.allow_blob_public_access:
                results.append({
                    "account": account, "type": "Storage Account (Public Blob)",
                    "id": sa.name, "region": sa.location or "unknown",
                })
        return results

    def _public_nsgs_from_sub(self, sub_id: str, account: str) -> list[dict]:
        results = []
        net_client = NetworkManagementClient(self._cred, sub_id)
        for nsg in net_client.network_security_groups.list_all():
            for rule in (nsg.security_rules or []):
                if (rule.access == "Allow" and rule.direction == "Inbound"
                        and rule.source_address_prefix in ("*", "Internet", "0.0.0.0/0")
                        and rule.destination_port_range in ("*", "0-65535")):
                    results.append({
                        "account": account,
                        "type": f"NSG (Open Rule: {rule.name})",
                        "id": nsg.name, "region": nsg.location or "unknown",
                    })
                    break
        return results

    def list_public_resources(self, account: str) -> list[dict]:
        """List publicly accessible Azure resources."""
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._public_storage_from_sub(sub_id, account))
            except Exception:
                pass
            if _NETWORK_AVAILABLE:
                try:
                    results.extend(self._public_nsgs_from_sub(sub_id, account))
                except Exception:
                    pass
        return results

    # ── Monitoring — Azure Monitor ─────────────────────────────────────────────

    def _monitor_alerts_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = MonitorManagementClient(self._cred, sub_id)
        for alert in client.metric_alerts.list_by_subscription():
            if region and alert.location != region:
                continue
            results.append({
                "account": account, "name": alert.name,
                "state": "enabled" if alert.enabled else "disabled",
                "severity": str(alert.severity) if alert.severity is not None else "—",
                "description": (alert.description or "")[:60],
                "region": alert.location or "global",
            })
        return results

    def list_monitor_alerts(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Monitor metric alert rules."""
        if not _MONITOR_AVAILABLE:
            return self._stub(account, "Monitor Alerts", "azure-mgmt-monitor")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._monitor_alerts_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Messaging — Service Bus / Event Hubs / Logic Apps ─────────────────────

    def _service_bus_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = ServiceBusManagementClient(self._cred, sub_id)
        for ns in client.namespaces.list():
            if region and ns.location != region:
                continue
            results.append({
                "account": account, "name": ns.name,
                "sku": ns.sku.name if ns.sku else "—",
                "state": ns.status or "—",
                "region": ns.location or "unknown",
            })
        return results

    def list_service_bus_namespaces(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Service Bus namespaces."""
        if not _SERVICEBUS_AVAILABLE:
            return self._stub(account, "Service Bus", "azure-mgmt-servicebus")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._service_bus_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    def _event_hub_namespaces_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = EventHubManagementClient(self._cred, sub_id)
        for ns in client.namespaces.list():
            if region and ns.location != region:
                continue
            results.append({
                "account": account, "name": ns.name,
                "sku": ns.sku.name if ns.sku else "—",
                "state": ns.status or "—",
                "region": ns.location or "unknown",
            })
        return results

    def list_event_hub_namespaces(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Event Hub namespaces."""
        if not _EVENTHUB_AVAILABLE:
            return self._stub(account, "Event Hubs", "azure-mgmt-eventhub")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._event_hub_namespaces_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    def _logic_apps_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = LogicManagementClient(self._cred, sub_id)
        for workflow in client.workflows.list_by_subscription():
            if region and workflow.location != region:
                continue
            results.append({
                "account": account, "name": workflow.name,
                "state": str(workflow.state) if workflow.state else "—",
                "region": workflow.location or "unknown",
            })
        return results

    def list_logic_apps(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Logic App workflows."""
        if not _LOGIC_AVAILABLE:
            return self._stub(account, "Logic Apps", "azure-mgmt-logic")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._logic_apps_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── AI / Analytics ────────────────────────────────────────────────────────

    def _cognitive_services_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = CognitiveServicesManagementClient(self._cred, sub_id)
        for acct in client.accounts.list():
            if region and acct.location != region:
                continue
            results.append({
                "account": account, "name": acct.name,
                "kind": acct.kind or "—",
                "sku": acct.sku.name if acct.sku else "—",
                "endpoint": (acct.properties.endpoint if acct.properties else None) or "—",
                "state": (acct.properties.provisioning_state
                          if acct.properties else None) or "—",
                "region": acct.location or "unknown",
            })
        return results

    def list_cognitive_services(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Cognitive Services accounts (includes Azure OpenAI)."""
        if not _COGSVCS_AVAILABLE:
            return self._stub(account, "Cognitive Services", "azure-mgmt-cognitiveservices")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._cognitive_services_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    def _synapse_workspaces_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = SynapseManagementClient(self._cred, sub_id)
        for ws in client.workspaces.list():
            if region and ws.location != region:
                continue
            results.append({
                "account": account, "name": ws.name,
                "state": ws.provisioning_state or "—",
                "region": ws.location or "unknown",
            })
        return results

    def list_synapse_workspaces(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Synapse Analytics workspaces."""
        if not _SYNAPSE_AVAILABLE:
            return self._stub(account, "Synapse", "azure-mgmt-synapse")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._synapse_workspaces_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    def _data_factories_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = DataFactoryManagementClient(self._cred, sub_id)
        for factory in client.factories.list():
            if region and factory.location != region:
                continue
            results.append({
                "account": account, "name": factory.name,
                "state": factory.provisioning_state or "—",
                "region": factory.location or "unknown",
            })
        return results

    def list_data_factories(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Data Factory instances."""
        if not _ADF_AVAILABLE:
            return self._stub(account, "Data Factory", "azure-mgmt-datafactory")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._data_factories_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

    # ── Cost ──────────────────────────────────────────────────────────────────

    def cost_summary(self, account: str, days: int = 30) -> list[dict]:
        """Monthly cost totals via Cost Management API."""
        if not _COST_AVAILABLE:
            return [{"account": account, "period": "—", "cost": "—", "currency": "—"}]
        import datetime as _dt
        results = []
        end = _dt.datetime.now(_dt.timezone.utc)
        start = end - _dt.timedelta(days=days)
        for sub_id in self._subscriptions:
            try:
                client = CostManagementClient(self._cred)
                query = QueryDefinition(
                    type="ActualCost", timeframe="Custom",
                    time_period=QueryTimePeriod(from_property=start, to=end),
                    dataset=QueryDataset(
                        granularity="Monthly",
                        aggregation={"TotalCost": QueryAggregation(name="Cost", function="Sum")},
                    ),
                )
                result = client.query.usage(f"/subscriptions/{sub_id}", query)
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
        """Cost breakdown by Azure service."""
        if not _COST_AVAILABLE:
            return [{"account": account, "service": "—", "period": "—", "cost": "—"}]
        import datetime as _dt
        results = []
        end = _dt.datetime.now(_dt.timezone.utc)
        start = end - _dt.timedelta(days=days)
        for sub_id in self._subscriptions:
            try:
                client = CostManagementClient(self._cred)
                query = QueryDefinition(
                    type="ActualCost", timeframe="Custom",
                    time_period=QueryTimePeriod(from_property=start, to=end),
                    dataset=QueryDataset(
                        granularity="None",
                        aggregation={"TotalCost": QueryAggregation(name="Cost", function="Sum")},
                        grouping=[QueryGrouping(type="Dimension", name="ServiceName")],
                    ),
                )
                result = client.query.usage(f"/subscriptions/{sub_id}", query)
                col_names = [c["name"] for c in (result.columns or [])]
                cost_idx = col_names.index("Cost") if "Cost" in col_names else 0
                svc_idx = col_names.index("ServiceName") if "ServiceName" in col_names else 1
                for row in (result.rows or []):
                    results.append({
                        "account": account, "service": str(row[svc_idx]),
                        "period": f"last {days}d",
                        "cost": f"{float(row[cost_idx]):.2f}",
                    })
            except Exception:
                pass
        return results

    # ── Backup ────────────────────────────────────────────────────────────────

    def _backup_vaults_from_sub(self, sub_id: str, account: str, region: Optional[str]) -> list[dict]:
        results = []
        client = RecoveryServicesClient(self._cred, sub_id)
        for vault in client.vaults.list_by_subscription_id():
            if region and vault.location != region:
                continue
            results.append({
                "account": account, "name": vault.name,
                "sku": vault.sku.name if vault.sku else "—",
                "state": vault.properties.provisioning_state if vault.properties else "—",
                "region": vault.location or "unknown",
            })
        return results

    def list_backup_vaults(self, account: str, region: Optional[str] = None) -> list[dict]:
        """List Azure Recovery Services (Backup) Vaults."""
        if not _BACKUP_AVAILABLE:
            return self._stub(account, "Backup Vault", "azure-mgmt-recoveryservices")
        results = []
        for sub_id in self._subscriptions:
            try:
                results.extend(self._backup_vaults_from_sub(sub_id, account, region))
            except Exception:
                pass
        return results

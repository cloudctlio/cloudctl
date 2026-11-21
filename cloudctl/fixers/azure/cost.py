"""Azure cost fixers — deallocate idle VMs, delete orphaned disks.

Deleting a disk destroys data: the policy gate rejects it in production.
"""
from __future__ import annotations

from typing import Any

from cloudctl.fixers.azure.security import _act, _parts, _rc, arm_id
from cloudctl.fixers.base import BaseFixer, azure_credential, azure_subscription
from cloudctl.fixers.registry import register


def _sub(issue: dict, creds: Any) -> str:
    return creds.scope.get("subscription_id") if creds is not None else issue.get("account", "")


@register
class AzureDeallocateIdleVMFixer(BaseFixer):
    """Deallocates Azure VMs identified as idle."""

    cloud = "azure"
    supported_issue_types = ["idle_vm", "azure_idle_instance"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("virtualMachines" in issue.get("resource", "") or "vm" in resource) and (
            "idle" in issue_text or "unused" in issue_text or "low cpu" in issue_text
        )

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        rg, vm = _parts(issue, "virtualMachines", "VM resource")
        sub = azure_subscription(issue, env)
        return [_rc(address=arm_id(sub, rg, f"Microsoft.Compute/virtualMachines/{vm}"),
                    type="Microsoft.Compute/virtualMachines", action=_act("update"), name=vm,
                    before={"power_state": "running", "resource_group_name": rg},
                    after={"power_state": "deallocated", "resource_group_name": rg},
                    operations=("Microsoft.Compute/virtualMachines/deallocate/action",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        from azure.mgmt.compute import ComputeManagementClient  # noqa: PLC0415

        rg, vm = _parts(issue, "virtualMachines", "VM resource")
        client = ComputeManagementClient(azure_credential(creds), _sub(issue, creds))
        client.virtual_machines.begin_deallocate(rg, vm).result()


@register
class AzureDeleteOrphanedDiskFixer(BaseFixer):
    """Deletes Azure Managed Disks that are unattached."""

    cloud = "azure"
    supported_issue_types = ["orphaned_disk", "unattached_disk"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("disk" in resource or "managed disk" in resource) and (
            "orphan" in issue_text or "unattached" in issue_text or "unused" in issue_text
        )

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        rg, disk = _parts(issue, "disks", "disk resource")
        sub = azure_subscription(issue, env)
        return [_rc(address=arm_id(sub, rg, f"Microsoft.Compute/disks/{disk}"), type="Microsoft.Compute/disks",
                    action=_act("delete"), name=disk, before={"resource_group_name": rg}, after=None,
                    operations=("Microsoft.Compute/disks/delete",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        from azure.mgmt.compute import ComputeManagementClient  # noqa: PLC0415

        rg, disk = _parts(issue, "disks", "disk resource")
        client = ComputeManagementClient(azure_credential(creds), _sub(issue, creds))
        client.disks.begin_delete(rg, disk).result()

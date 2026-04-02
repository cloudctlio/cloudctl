"""Azure cost fixers — deallocate idle VMs, delete orphaned disks."""
from __future__ import annotations

from cloudctl.fixers.base import BaseFixer
from cloudctl.fixers.registry import register


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

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        from azure.identity import DefaultAzureCredential  # noqa: PLC0415
        from azure.mgmt.compute import ComputeManagementClient  # noqa: PLC0415
        import re  # noqa: PLC0415

        resource     = issue.get("resource", "")
        subscription = issue.get("account", "")
        cred         = DefaultAzureCredential()
        client       = ComputeManagementClient(cred, subscription)

        rg_match = re.search(r"resourceGroups/([^/]+)", resource, re.IGNORECASE)
        vm_match = re.search(r"virtualMachines/([^/\s]+)", resource, re.IGNORECASE)
        if not rg_match or not vm_match:
            raise ValueError(f"Could not parse VM resource: {resource}")

        client.virtual_machines.begin_deallocate(rg_match.group(1), vm_match.group(1)).result()


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

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        from azure.identity import DefaultAzureCredential  # noqa: PLC0415
        from azure.mgmt.compute import ComputeManagementClient  # noqa: PLC0415
        import re  # noqa: PLC0415

        resource     = issue.get("resource", "")
        subscription = issue.get("account", "")
        cred         = DefaultAzureCredential()
        client       = ComputeManagementClient(cred, subscription)

        rg_match   = re.search(r"resourceGroups/([^/]+)", resource, re.IGNORECASE)
        disk_match = re.search(r"disks/([^/\s]+)", resource, re.IGNORECASE)
        if not rg_match or not disk_match:
            raise ValueError(f"Could not parse disk resource: {resource}")

        client.disks.begin_delete(rg_match.group(1), disk_match.group(1)).result()

"""Azure security fixers — tighten NSG rules, enable storage encryption, lock public blobs."""
from __future__ import annotations

from cloudctl.fixers.base import BaseFixer
from cloudctl.fixers.registry import register


@register
class AzureNSGOpenRuleFixer(BaseFixer):
    """Removes NSG rules that allow all inbound traffic from the internet."""

    cloud = "azure"
    supported_issue_types = ["open_nsg", "nsg_any_inbound"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("nsg" in resource or "security group" in resource) and (
            "any" in issue_text or "unrestricted" in issue_text or "internet" in issue_text
        )

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        from azure.identity import DefaultAzureCredential  # noqa: PLC0415
        from azure.mgmt.network import NetworkManagementClient  # noqa: PLC0415
        import re  # noqa: PLC0415

        resource     = issue.get("resource", "")
        subscription = issue.get("account", "")
        cred         = DefaultAzureCredential()
        client       = NetworkManagementClient(cred, subscription)

        # Parse resource group and NSG name from resource string
        rg_match  = re.search(r"resourceGroups/([^/]+)", resource, re.IGNORECASE)
        nsg_match = re.search(r"networkSecurityGroups/([^/\s]+)", resource, re.IGNORECASE)
        if not rg_match or not nsg_match:
            raise ValueError(f"Could not parse NSG resource: {resource}")

        rg_name   = rg_match.group(1)
        nsg_name  = nsg_match.group(1)
        rule_name = fix_proposal.get("rule_name", "")
        if rule_name:
            client.security_rules.begin_delete(rg_name, nsg_name, rule_name).result()


@register
class AzurePublicBlobFixer(BaseFixer):
    """Disables anonymous public access on Azure Storage containers."""

    cloud = "azure"
    supported_issue_types = ["public_blob", "public_storage_container"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("storage" in resource or "blob" in resource or "container" in resource) and (
            "public" in issue_text or "anonymous" in issue_text
        )

    def apply(self, issue: dict, fix_proposal: dict) -> None:
        from azure.identity import DefaultAzureCredential  # noqa: PLC0415
        from azure.mgmt.storage import StorageManagementClient  # noqa: PLC0415
        from azure.mgmt.storage.models import StorageAccountUpdateParameters  # noqa: PLC0415
        import re  # noqa: PLC0415

        resource     = issue.get("resource", "")
        subscription = issue.get("account", "")
        cred         = DefaultAzureCredential()
        client       = StorageManagementClient(cred, subscription)

        rg_match   = re.search(r"resourceGroups/([^/]+)", resource, re.IGNORECASE)
        acct_match = re.search(r"storageAccounts/([^/\s]+)", resource, re.IGNORECASE)
        if not rg_match or not acct_match:
            raise ValueError(f"Could not parse storage account: {resource}")

        client.storage_accounts.update(
            rg_match.group(1),
            acct_match.group(1),
            StorageAccountUpdateParameters(allow_blob_public_access=False),
        )

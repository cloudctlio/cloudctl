"""Azure security fixers — tighten NSG rules, lock public blobs."""
from __future__ import annotations

import re
from typing import Any

from cloudctl.fixers.base import BaseFixer, azure_credential, azure_subscription
from cloudctl.fixers.registry import register


def _rc(**kw: Any) -> Any:
    from cloudctl.gate.models import ResourceChange  # noqa: PLC0415
    return ResourceChange(cloud="azure", **kw)


def _act(name: str) -> Any:
    from cloudctl.gate.models import Action  # noqa: PLC0415
    return Action(name)


def _parts(issue: dict, kind: str, what: str) -> tuple[str, str]:
    resource = issue.get("resource", "")
    rg = re.search(r"resourceGroups/([^/]+)", resource, re.IGNORECASE)
    name = re.search(rf"{kind}/([^/\s]+)", resource, re.IGNORECASE)
    if not rg or not name:
        raise ValueError(f"Could not parse {what}: {resource}")
    return rg.group(1), name.group(1)


def arm_id(sub: str, rg: str, provider_path: str) -> str:
    return f"/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider_path}"


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

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        rg, nsg = _parts(issue, "networkSecurityGroups", "NSG resource")
        rule = fix_proposal.get("rule_name", "")
        if not rule:
            return []
        sub = azure_subscription(issue, env)
        rid = arm_id(sub, rg, f"Microsoft.Network/networkSecurityGroups/{nsg}/securityRules/{rule}")
        return [_rc(address=rid, type="Microsoft.Network/networkSecurityGroups/securityRules",
                    action=_act("delete"), name=rule, before={"resource_group_name": rg}, after=None,
                    operations=("Microsoft.Network/networkSecurityGroups/securityRules/delete",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        from azure.mgmt.network import NetworkManagementClient  # noqa: PLC0415

        rg_name, nsg_name = _parts(issue, "networkSecurityGroups", "NSG resource")
        sub = creds.scope.get("subscription_id") if creds is not None else issue.get("account", "")
        client = NetworkManagementClient(azure_credential(creds), sub)
        rule_name = fix_proposal.get("rule_name", "")
        if rule_name:
            client.security_rules.begin_delete(rg_name, nsg_name, rule_name).result()


@register
class AzurePublicBlobFixer(BaseFixer):
    """Disables anonymous public access on Azure Storage accounts."""

    cloud = "azure"
    supported_issue_types = ["public_blob", "public_storage_container"]

    def can_fix(self, issue: dict) -> bool:
        resource   = issue.get("resource", "").lower()
        issue_text = issue.get("issue", "").lower()
        return ("storage" in resource or "blob" in resource or "container" in resource) and (
            "public" in issue_text or "anonymous" in issue_text
        )

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        rg, acct = _parts(issue, "storageAccounts", "storage account")
        sub = azure_subscription(issue, env)
        return [_rc(address=arm_id(sub, rg, f"Microsoft.Storage/storageAccounts/{acct}"),
                    type="Microsoft.Storage/storageAccounts", action=_act("update"), name=acct,
                    after={"properties": {"allowBlobPublicAccess": False}, "resource_group_name": rg},
                    operations=("Microsoft.Storage/storageAccounts/write",))]

    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        from azure.mgmt.storage import StorageManagementClient  # noqa: PLC0415
        from azure.mgmt.storage.models import StorageAccountUpdateParameters  # noqa: PLC0415

        rg, acct = _parts(issue, "storageAccounts", "storage account")
        sub = creds.scope.get("subscription_id") if creds is not None else issue.get("account", "")
        client = StorageManagementClient(azure_credential(creds), sub)
        client.storage_accounts.update(rg, acct, StorageAccountUpdateParameters(allow_blob_public_access=False))

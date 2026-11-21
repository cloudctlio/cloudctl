"""Base fixer — interface all cloud fixers must implement."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseFixer(ABC):
    """
    Base class for all cloud resource fixers.

    Fixers are never auto-executed. From the CLI every fix goes through the
    policy gate (``cloudctl.gate``): the fixer declares the exact change with
    :meth:`plan`, the gate checks it (policy, approval), and only then calls
    :meth:`apply` with the gate's short-lived, scoped credentials.

    ``apply(..., creds=None)`` keeps the old ambient-credential behaviour for
    library callers and tests; the CLI never calls it that way.
    """

    # Override in subclasses to declare which issue types this fixer handles.
    supported_issue_types: list[str] = []
    cloud: str = ""

    @abstractmethod
    def can_fix(self, issue: dict) -> bool:
        """Return True if this fixer can handle the given issue dict."""

    @abstractmethod
    def apply(self, issue: dict, fix_proposal: dict, creds: Any = None) -> None:
        """
        Apply the fix. Called only after the gate authorized it.

        Args:
            issue:        The original issue dict from the security/cost audit.
            fix_proposal: The AI-generated fix proposal dict.
            creds:        The gate's ScopedCredentials (None = ambient, library use only).
        """

    def plan(self, issue: dict, fix_proposal: dict, *, creds: Any, env: Any) -> list:
        """Declare the change apply() would make, as a list of
        :class:`cloudctl.gate.models.ResourceChange`. Read live state with
        *creds* only. A fixer that cannot declare its change cannot pass the gate."""
        raise NotImplementedError(f"{type(self).__name__} does not declare a plan")

    def dry_run(self, issue: dict, fix_proposal: dict) -> str:
        """
        Return a human-readable description of what apply() would do.
        Default implementation formats the fix_proposal dict.
        Override for more specific descriptions.
        """
        lines = [f"Would fix: {issue.get('resource', issue)}"]
        for k, v in fix_proposal.items():
            if k != "error":
                lines.append(f"  {k}: {v}")
        return "\n".join(lines)

    @classmethod
    def for_cloud(cls, cloud: str) -> bool:
        return cls.cloud == cloud or cls.cloud == ""


# ── credential helpers shared by the cloud fixers ────────────────────────────

def aws_session(issue: dict, creds: Any = None, region: Optional[str] = None) -> Any:
    """Scoped session from the gate, or (library use) the issue's profile."""
    if creds is not None:
        return creds.client("session", region_name=region) if region else creds.client("session")
    import boto3  # noqa: PLC0415
    kw: dict[str, Any] = {"profile_name": issue.get("account", "default")}
    if region is not None:
        kw["region_name"] = region
    return boto3.Session(**kw)


def azure_credential(creds: Any = None) -> Any:
    if creds is not None:
        return creds.client("credential")
    from azure.identity import DefaultAzureCredential  # noqa: PLC0415
    return DefaultAzureCredential()


def gcp_credentials(creds: Any = None) -> Any:
    if creds is not None:
        return creds.client("credentials")
    import google.auth  # noqa: PLC0415
    c, _ = google.auth.default()
    return c


def azure_subscription(issue: dict, env: Any = None) -> str:
    """The subscription to act in. Under the gate it must be the environment's."""
    sub = str(issue.get("account", "") or "")
    if env is not None:
        want = env.scope.get("subscription_id", "")
        if sub and sub.lower() != want.lower():
            from cloudctl.gate.models import PlanError  # noqa: PLC0415
            raise PlanError(f"issue is in subscription {sub}, but environment {env.name} is {want}")
        return want
    return sub


def gcp_project(issue: dict, env: Any = None) -> str:
    """The project the issue names (the gate's scope rule rejects a mismatch)."""
    proj = str(issue.get("account", "") or "")
    if env is not None and not proj:
        return env.scope.get("project_id", "")
    return proj

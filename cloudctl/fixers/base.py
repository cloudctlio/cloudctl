"""Base fixer — interface all cloud fixers must implement."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class BaseFixer(ABC):
    """
    Base class for all cloud resource fixers.

    Fixers are never auto-executed. The AIFixer always presents proposals
    to the user for approval before calling apply().
    """

    # Override in subclasses to declare which issue types this fixer handles.
    supported_issue_types: list[str] = []
    cloud: str = ""

    @abstractmethod
    def can_fix(self, issue: dict) -> bool:
        """Return True if this fixer can handle the given issue dict."""

    @abstractmethod
    def apply(self, issue: dict, fix_proposal: dict) -> None:
        """
        Apply the fix. Called only after human approval.

        Args:
            issue:        The original issue dict from the security/cost audit.
            fix_proposal: The AI-generated fix proposal dict.
        """

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

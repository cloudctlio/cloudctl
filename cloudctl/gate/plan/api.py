"""Planner for direct API fixes (``cloudctl security audit --fix`` and
``cloudctl cost --fix``).

There is no external plan tool for a single API call, so each fixer declares
the exact change it will make via ``BaseFixer.plan()``, reading live state
with the scoped credentials. A fixer without ``plan()`` cannot pass the gate.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from cloudctl.gate.models import Plan, PlanError


class ApiActionPlanner:
    platform = "api"

    def __init__(self, fixer: Any, issue: Mapping[str, Any], proposal: Mapping[str, Any]) -> None:
        self.fixer = fixer
        self.issue = dict(issue)
        self.proposal = dict(proposal)

    def plan(self, *, env: Any, creds: Any, workdir: Path) -> Plan:
        if not hasattr(self.fixer, "plan"):
            raise PlanError(f"{type(self.fixer).__name__} cannot declare a plan; it cannot pass the gate")
        try:
            changes = tuple(self.fixer.plan(self.issue, self.proposal, creds=creds, env=env))
        except PlanError:
            raise
        except Exception as e:  # noqa: BLE001
            raise PlanError(f"{type(self.fixer).__name__}.plan failed: {e}") from e
        if not changes:
            raise PlanError(f"{type(self.fixer).__name__} declared no change for {self.issue.get('resource')!r}")
        return Plan(platform="api", environment=env.name, changes=changes,
                    source=type(self.fixer).__name__,
                    metadata={"issue": str(self.issue.get("issue", ""))[:300],
                              "resource": str(self.issue.get("resource", ""))[:300]})

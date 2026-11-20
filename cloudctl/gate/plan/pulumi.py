"""Pulumi planner: ``pulumi preview --json --diff``.

Pulumi programs can target AWS, Azure, GCP and Kubernetes; the cloud of each
step comes from its resource type token (``aws:s3/bucket:Bucket``,
``azure-native:storage:StorageAccount``, ``gcp:storage/bucket:Bucket``).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Optional

from cloudctl.gate.models import Action, Plan, PlanError, ResourceChange
from cloudctl.gate.plan.base import find_binary, run_tool, tool_version_matches

_OPS = {
    "create": Action.CREATE,
    "update": Action.UPDATE,
    "delete": Action.DELETE,
    "replace": Action.REPLACE,
    "create-replacement": Action.REPLACE,
    "delete-replaced": Action.REPLACE,
    "create-before-replace": Action.REPLACE,
    "delete-before-replace": Action.REPLACE,
    "same": Action.NOOP,
    "read": Action.READ,
    "refresh": Action.READ,
    "read-replacement": Action.READ,
    "import": Action.UPDATE,
    "import-replacement": Action.REPLACE,
    "discard": Action.UPDATE,
    "discard-replaced": Action.REPLACE,
    "remove-pending-replace": Action.UPDATE,
}

_PKG_CLOUD = {"aws": "aws", "aws-native": "aws", "awsx": "aws",
              "azure": "azure", "azure-native": "azure", "azuread": "azure",
              "gcp": "gcp", "google-native": "gcp",
              "kubernetes": "kubernetes"}


def pulumi_cloud(type_token: str) -> str:
    return _PKG_CLOUD.get((type_token or "").split(":", 1)[0], "other")


def parse_preview(doc: Mapping[str, Any], *, environment: str, source: str = "") -> Plan:
    if not isinstance(doc.get("steps"), list):
        raise PlanError("pulumi preview JSON has no `steps`")
    merged: dict[str, ResourceChange] = {}
    for st in doc["steps"]:
        op = st.get("op")
        if op not in _OPS:
            raise PlanError(f"unknown pulumi step op {op!r}")
        urn = st.get("urn", "")
        new = st.get("newState") or {}
        old = st.get("oldState") or {}
        typ = new.get("type") or old.get("type") or (urn.split("::")[2] if urn.count("::") >= 3 else "")
        if typ.startswith("pulumi:pulumi:Stack") or typ.startswith("pulumi:providers:"):
            continue
        action = _OPS[op]
        prev = merged.get(urn)
        if prev and prev.action == Action.REPLACE:
            continue  # replace steps come in pairs; keep one
        merged[urn] = ResourceChange(
            address=urn, type=typ, action=action, cloud=pulumi_cloud(typ),
            name=urn.rsplit("::", 1)[-1],
            location=str((new.get("inputs") or {}).get("region") or (new.get("inputs") or {}).get("location") or ""),
            before=old.get("outputs") or old.get("inputs"),
            after=new.get("inputs"),
        )
    return Plan(platform="pulumi", environment=environment, changes=tuple(merged.values()), source=source)


class PulumiPlanner:
    platform = "pulumi"

    def __init__(self, root: Path | str, stack: str, *, binary_path: Optional[str] = None,
                 pinned_version: Optional[str] = None, timeout: int = 900) -> None:
        self.root = Path(root).expanduser().resolve()
        self.stack = stack
        self.binary_path = binary_path
        self.pinned_version = pinned_version
        self.timeout = timeout

    def plan(self, *, env: Any, creds: Any, workdir: Path) -> Plan:
        exe = find_binary("pulumi", self.binary_path)
        senv = creds.subprocess_env()
        senv.update({"PULUMI_SKIP_UPDATE_CHECK": "true", "PULUMI_SKIP_CONFIRMATIONS": "true"})
        ver = run_tool([exe, "version"], cwd=self.root, env=senv, timeout=60, what="pulumi version")
        if not tool_version_matches(ver.stdout, self.pinned_version):
            raise PlanError(f"pulumi version mismatch: pinned {self.pinned_version}, found {ver.stdout.strip()}")
        res = run_tool([exe, "preview", "--json", "--diff", "--non-interactive", "--stack", self.stack],
                       cwd=self.root, env=senv, timeout=self.timeout, what="pulumi preview")
        try:
            doc = json.loads(res.stdout)
        except ValueError as e:
            raise PlanError(f"pulumi preview output is not JSON: {e}") from e
        (workdir / "pulumi-preview.json").write_text(res.stdout, encoding="utf-8")
        plan = parse_preview(doc, environment=env.name, source=f"{self.root}:{self.stack}")
        return Plan(platform=plan.platform, environment=plan.environment, changes=plan.changes,
                    source=plan.source, artifacts={"pulumi_preview_json": str(workdir / "pulumi-preview.json"),
                                                   "iac_root": str(self.root)})

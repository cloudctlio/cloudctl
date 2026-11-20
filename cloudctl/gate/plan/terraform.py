"""Terraform / OpenTofu planner: ``plan -out`` then ``show -json``.

Works for AWS, Azure and GCP (and anything else Terraform manages): the
cloud of each change comes from its provider. The binary plan file is kept
in the private workdir so the executor can later apply *exactly* that plan,
and its SHA-256 is recorded so a swapped file is detected.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Optional

from cloudctl.gate.canonical import sha256_hex
from cloudctl.gate.models import Action, Plan, PlanError, ResourceChange
from cloudctl.gate.plan.base import find_binary, run_tool, tool_version_matches

_PROVIDER_CLOUD = {
    "aws": "aws", "awscc": "aws",
    "azurerm": "azure", "azapi": "azure", "azuread": "azure", "azuredevops": "azure",
    "google": "gcp", "google-beta": "gcp",
    "kubernetes": "kubernetes", "helm": "kubernetes", "kubectl": "kubernetes",
}

# Attributes that carry a resource's location, per provider family.
_LOCATION_KEYS = ("region", "location", "zone", "availability_zone")


def provider_cloud(provider_name: str) -> str:
    short = (provider_name or "").rstrip("/").split("/")[-1]
    return _PROVIDER_CLOUD.get(short, "other")


def map_actions(actions: list[str]) -> Action:
    a = list(actions or [])
    if a in (["delete", "create"], ["create", "delete"]):
        return Action.REPLACE
    if a == ["create"]:
        return Action.CREATE
    if a == ["delete"]:
        return Action.DELETE
    if a == ["update"]:
        return Action.UPDATE
    if a == ["read"]:
        return Action.READ
    if a in (["no-op"], []):
        return Action.NOOP
    if a == ["forget"]:  # Terraform 1.7+: removed from state, not destroyed
        return Action.UPDATE
    raise PlanError(f"unknown Terraform action list {a!r}")


def _merge_unknown(after: Any, unknown: Any) -> Any:
    """Mark values known only after apply as the string "(known after apply)"
    so policies can tell 'unset' from 'not yet known'."""
    if unknown is True:
        return "(known after apply)"
    if isinstance(after, dict) and isinstance(unknown, dict):
        out = dict(after)
        for k, u in unknown.items():
            out[k] = _merge_unknown(after.get(k), u)
        return out
    if isinstance(after, list) and isinstance(unknown, list):
        return [_merge_unknown(after[i] if i < len(after) else None, u) for i, u in enumerate(unknown)] \
            + after[len(unknown):]
    return after


def parse_show_json(doc: Mapping[str, Any], *, environment: str, source: str = "",
                    platform: str = "terraform") -> Plan:
    """Normalise ``terraform show -json <planfile>`` output (format 1.x)."""
    fmt = str(doc.get("format_version", ""))
    if not fmt.startswith("1."):
        raise PlanError(f"unsupported Terraform plan format_version {fmt!r}")
    if doc.get("errored"):
        raise PlanError("Terraform reports the plan errored; nothing can be authorized from it")
    changes: list[ResourceChange] = []
    for rc in doc.get("resource_changes") or []:
        ch = rc.get("change") or {}
        action = map_actions(ch.get("actions") or [])
        if rc.get("mode") == "data":
            action = Action.READ
        after = _merge_unknown(ch.get("after"), ch.get("after_unknown"))
        attrs = after if isinstance(after, dict) else (ch.get("before") or {})
        location = ""
        if isinstance(attrs, dict):
            for k in _LOCATION_KEYS:
                if isinstance(attrs.get(k), str):
                    location = attrs[k]
                    break
        changes.append(ResourceChange(
            address=rc["address"], type=rc.get("type", ""), action=action,
            cloud=provider_cloud(rc.get("provider_name", "")), name=rc.get("name", ""),
            location=location, before=ch.get("before"), after=after,
        ))
    return Plan(platform=platform, environment=environment, changes=tuple(changes), source=source,
                metadata={"terraform_version": doc.get("terraform_version", ""),
                          "format_version": fmt})


class TerraformPlanner:
    """Runs ``init``/``plan``/``show`` in an IaC root with scoped credentials."""

    def __init__(self, root: Path | str, *, binary: str = "terraform",
                 binary_path: Optional[str] = None, pinned_version: Optional[str] = None,
                 var_files: tuple[str, ...] = (), timeout: int = 900) -> None:
        self.root = Path(root).expanduser().resolve()
        self.binary = binary
        self.platform = "opentofu" if binary == "tofu" else "terraform"
        self.binary_path = binary_path
        self.pinned_version = pinned_version
        self.var_files = var_files
        self.timeout = timeout

    def plan(self, *, env: Any, creds: Any, workdir: Path) -> Plan:
        if not self.root.is_dir():
            raise PlanError(f"IaC root {self.root} does not exist")
        exe = find_binary(self.binary, self.binary_path)
        senv = creds.subprocess_env()
        senv.update({"TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "CHECKPOINT_DISABLE": "1"})
        ver = run_tool([exe, "version"], cwd=self.root, env=senv, timeout=60, what=f"{self.binary} version")
        if not tool_version_matches(ver.stdout, self.pinned_version):
            raise PlanError(f"{self.binary} version mismatch: pinned {self.pinned_version}, "
                            f"found {ver.stdout.splitlines()[0] if ver.stdout else '?'}")
        run_tool([exe, "init", "-input=false", "-no-color"], cwd=self.root, env=senv,
                 timeout=self.timeout, what=f"{self.binary} init")
        planfile = workdir / "plan.tfplan"
        argv = [exe, "plan", "-input=false", "-no-color", "-lock-timeout=120s",
                "-detailed-exitcode", f"-out={planfile}"]
        argv += [f"-var-file={v}" for v in self.var_files]
        # -detailed-exitcode: 0 = no changes, 2 = changes, 1 = error
        run_tool(argv, cwd=self.root, env=senv, timeout=self.timeout, ok_codes=(0, 2),
                 what=f"{self.binary} plan")
        shown = run_tool([exe, "show", "-json", str(planfile)], cwd=self.root, env=senv,
                         timeout=self.timeout, what=f"{self.binary} show -json")
        try:
            doc = json.loads(shown.stdout)
        except ValueError as e:
            raise PlanError(f"{self.binary} show -json returned invalid JSON: {e}") from e
        plan_json = workdir / "plan.json"
        plan_json.write_text(shown.stdout, encoding="utf-8")
        base = parse_show_json(doc, environment=env.name, source=str(self.root), platform=self.platform)
        return Plan(
            platform=base.platform, environment=base.environment, changes=base.changes, source=base.source,
            artifacts={"terraform_plan_json": str(plan_json), "terraform_plan_binary": str(planfile),
                       "iac_root": str(self.root)},
            metadata={**dict(base.metadata), "plan_binary_sha256": sha256_hex(planfile.read_bytes())},
        )

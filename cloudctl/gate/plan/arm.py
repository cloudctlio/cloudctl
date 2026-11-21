"""Azure ARM / Bicep planner: deployment what-if.

Bicep is compiled to ARM JSON with ``bicep build --stdout`` (or
``az bicep build --stdout`` when only the Azure CLI is installed); the ARM
template then goes to the resource group's what-if API with the scoped
credentials. ``Unsupported`` what-if results are reported as findings by the
policy stage (rule CCTL-PLAN-001): the gate never treats "cannot predict" as
"no change".
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from cloudctl.gate.models import Action, Plan, PlanError, ResourceChange
from cloudctl.gate.plan.base import find_binary, run_tool

_WHATIF_ACTION = {
    "Create": Action.CREATE,
    "Delete": Action.DELETE,
    "Modify": Action.UPDATE,
    "Deploy": Action.UPDATE,      # redeploy; properties may change
    "NoChange": Action.NOOP,
    "Ignore": Action.NOOP,        # resource exists but is not in the template (incremental mode)
    "Unsupported": Action.UPDATE,  # cannot predict: treated as a change, flagged by policy
}



def arm_type(resource_id: str) -> str:
    """Resource type from an ARM ID, e.g. Microsoft.Storage/storageAccounts."""
    parts = resource_id.split("/providers/")
    if len(parts) < 2:
        return ""
    segs = parts[-1].split("/")
    if len(segs) < 2:
        return ""
    ns, typ = segs[0], [segs[1]]
    # nested types: ns/type/name/subtype/subname
    rest = segs[3:]
    while len(rest) >= 2:
        typ.append(rest[0])
        rest = rest[2:]
    return ns + "/" + "/".join(typ)


def parse_what_if(changes: Iterable[Any], *, location: str = "") -> list[ResourceChange]:
    out: list[ResourceChange] = []
    for ch in changes:
        get = (lambda k: ch.get(k)) if isinstance(ch, Mapping) else (lambda k: getattr(ch, k, None))
        rid = get("resource_id") or get("resourceId") or ""
        ctype = get("change_type") or get("changeType")
        ctype = getattr(ctype, "value", ctype)
        if ctype not in _WHATIF_ACTION:
            raise PlanError(f"unknown what-if change type {ctype!r} for {rid}")
        after = get("after")
        before = get("before")
        after_d = after if isinstance(after, Mapping) else (after.as_dict() if hasattr(after, "as_dict") else after)
        before_d = before if isinstance(before, Mapping) else (before.as_dict() if hasattr(before, "as_dict") else before)
        loc = (after_d or {}).get("location") if isinstance(after_d, Mapping) else None
        out.append(ResourceChange(
            address=rid, type=arm_type(rid), action=_WHATIF_ACTION[ctype], cloud="azure",
            name=rid.rstrip("/").split("/")[-1], location=loc or location,
            before=before_d if isinstance(before_d, Mapping) else None,
            after={**(after_d if isinstance(after_d, Mapping) else {}),
                   "_whatif_change_type": ctype,
                   "_unsupported_reason": get("unsupported_reason") or get("unsupportedReason") or ""},
        ))
    return out


class ArmWhatIfPlanner:
    def __init__(self, template: Path | str, *, parameters: Optional[Path | str] = None,
                 mode: str = "Incremental", bicep_binary: Optional[str] = None,
                 rm_client_factory: Any = None, timeout: int = 900) -> None:
        self.template = Path(template).expanduser().resolve()
        self.parameters = Path(parameters).expanduser().resolve() if parameters else None
        if mode not in ("Incremental", "Complete"):
            raise ValueError("mode must be Incremental or Complete")
        self.mode = mode
        self.platform = "bicep" if self.template.suffix == ".bicep" else "arm"
        self.bicep_binary = bicep_binary
        self._rm_factory = rm_client_factory
        self.timeout = timeout

    def _template_json(self, creds: Any) -> dict:
        if self.platform == "arm":
            return json.loads(self.template.read_text(encoding="utf-8"))
        senv = creds.subprocess_env()
        try:
            exe = find_binary("bicep", self.bicep_binary)
            argv = [exe, "build", str(self.template), "--stdout"]
        except PlanError:
            exe = find_binary("az")
            argv = [exe, "bicep", "build", "--file", str(self.template), "--stdout"]
        res = run_tool(argv, cwd=self.template.parent, env=senv, timeout=300, what="bicep build")
        try:
            return json.loads(res.stdout)
        except ValueError as e:
            raise PlanError(f"bicep build output is not JSON: {e}") from e

    def _params(self) -> dict:
        if not self.parameters:
            return {}
        doc = json.loads(self.parameters.read_text(encoding="utf-8"))
        return doc.get("parameters", doc)

    def plan(self, *, env: Any, creds: Any, workdir: Path) -> Plan:
        template = self._template_json(creds)
        (workdir / "template.json").write_text(json.dumps(template), encoding="utf-8")
        sub = env.scope["subscription_id"]
        rg = env.scope["resource_group"]
        if self._rm_factory is not None:
            client = self._rm_factory(creds.client("credential"), sub)
        else:
            try:
                from azure.mgmt.resource import ResourceManagementClient  # noqa: PLC0415
            except ImportError as e:
                raise PlanError("ARM what-if needs azure-mgmt-resource (pip install 'cctl[azure]')") from e
            client = ResourceManagementClient(creds.client("credential"), sub)
        body = {"properties": {"mode": self.mode, "template": template, "parameters": self._params()}}
        try:
            poller = client.deployments.begin_what_if(rg, "cctl-whatif", body)
            result = poller.result(timeout=self.timeout)
        except Exception as e:  # noqa: BLE001
            raise PlanError(f"what-if on resource group {rg} failed: {e}") from e
        status = getattr(result, "status", None) or (result.get("status") if isinstance(result, Mapping) else None)
        if status and str(status).lower() not in ("succeeded",):
            err = getattr(result, "error", None)
            raise PlanError(f"what-if finished with status {status}: {err}")
        changes = getattr(result, "changes", None)
        if changes is None and isinstance(result, Mapping):
            changes = (result.get("properties") or {}).get("changes", result.get("changes"))
        rcs = parse_what_if(changes or [], location=env.scope.get("location", ""))
        return Plan(platform=self.platform, environment=env.name, changes=tuple(rcs),
                    source=str(self.template),
                    artifacts={"arm_template_json": str(workdir / "template.json"),
                               "iac_root": str(self.template.parent)},
                    metadata={"resource_group": rg, "mode": self.mode})

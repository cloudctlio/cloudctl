"""Remediation as a verified IaC diff (design step 5). Mostly STUBBED.

Whether ``terraform plan -lock=false`` and ``cdk diff`` count as read-only
under cctl's rules is an open question for the owner. Until it is answered,
nothing here runs terraform or cdk: :func:`plan_check` returns ``not_run``
unless ``CLOUDCTL_VERIFY_PLAN_CHECK=1``, and even then it only reports that
the runner is not built.

What is built is the part that needs no tool run: :func:`blast_radius`, a pure
check over an already-produced plan JSON (``terraform show -json``) that the
planned changes stay on the verified node and resources with a direct edge to
it, with no delete or replace unless the draft says why.

Not built: re-running the failing predictions against planned values
("would it fix it"), and cdk diff parsing.
"""
from __future__ import annotations

import os

from cloudctl.verify.model import SystemModel

PLAN_FLAG = "CLOUDCTL_VERIFY_PLAN_CHECK"


def plan_check(iac_dir: str, kind: str = "terraform") -> dict:
    if os.environ.get(PLAN_FLAG, "") != "1":
        return {"status": "not_run",
                "reason": "plan/diff check is off: running terraform plan -lock=false or cdk diff "
                          "has not been approved as read-only yet",
                "flag": PLAN_FLAG}
    return {"status": "not_implemented",
            "reason": f"{kind} plan runner is not built in this pass; nothing was executed",
            "iac_dir": iac_dir}


def blast_radius(plan: dict, model: SystemModel, verified_node: str,
                 allow_replace_reason: str = "") -> dict:
    """Check a plan's ``resource_changes`` against the graph.

    Allowed: the verified node itself, and resources with a direct edge to or
    from it in any layer. Any delete or replace fails the check unless
    ``allow_replace_reason`` (the draft's stated reason) is given."""
    vn = model.resolve(verified_node)
    if not vn:
        return {"ok": False, "reason": f"{verified_node!r} is not in the graph", "violations": []}
    neighbours = set(model.dependencies(vn)) | set(model.dependents(vn)) | {vn}
    violations, touched = [], []
    for rc in plan.get("resource_changes") or []:
        actions = list((rc.get("change") or {}).get("actions") or [])
        if actions in (["no-op"], ["read"]):
            continue
        addr = rc.get("address", "")
        nid = model.resolve(addr)
        touched.append({"address": addr, "actions": actions, "node": nid})
        if not nid or nid not in neighbours:
            violations.append(f"{addr}: {'/'.join(actions)} outside the verified node and its direct edges")
        if "delete" in actions and not allow_replace_reason:
            violations.append(f"{addr}: {'replace' if 'create' in actions else 'delete'} without a stated reason")
    return {"ok": not violations, "violations": violations, "touched": touched,
            "allowed_nodes": sorted(neighbours)}

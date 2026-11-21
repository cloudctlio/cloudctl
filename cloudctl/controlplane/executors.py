"""Executors: apply exactly what the gate approved, with the gate's credentials.

Each node gets an executor with two parts:

* ``planner``: what the gate runs in its plan stage;
* ``apply(creds, plan, env)``: called inside ``Authorization.execute``, so it
  runs once, with the scoped short-lived credentials, and is audited.

Every executor refuses to apply anything other than the approved plan:

========================  ===================================================
Terraform / OpenTofu      applies the saved plan file from the gate's plan
                          stage after checking its SHA-256 against the
                          digest recorded in the plan. Terraform itself
                          refuses a stale saved plan.
CloudFormation / CDK      plans again with change sets kept, refuses if the
                          new plan's digest differs from the approved one
                          (and deletes those change sets), otherwise executes
                          exactly those change sets and waits for each stack.
ARM / Bicep               what-if again, refuses on a digest mismatch, then
                          deploys the same compiled template.
Pulumi                    preview again, refuses on a digest mismatch, then
                          ``pulumi up --skip-preview``.
Kubernetes (EKS/AKS/GKE)  ``kubectl diff`` again, refuses on a digest
                          mismatch, then ``kubectl apply --server-side``.
API fixes                 the fixer's own ``apply`` with the scoped
                          credentials (its plan declared the exact change).
========================  ===================================================

For ARM, Pulumi and Kubernetes the re-check happens seconds before the
deploy, but those tools have no saved-plan apply, so a change made by
someone else in that window is not caught by cctl. That is stated in the
docs rather than hidden.
"""
from __future__ import annotations

import logging
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Protocol

from cloudctl.controlplane.graph import Node
from cloudctl.gate.canonical import sha256_hex
from cloudctl.gate.models import GateError, Plan, PlanError
from cloudctl.gate.plan.base import find_binary, private_workdir, run_tool


log = logging.getLogger(__name__)


def _delete_change_set(cfn: Any, cs: str) -> None:
    """Best-effort cleanup of an unexecuted change set (it changes nothing
    if left behind; its name starts with ``cctl-``)."""
    try:
        cfn.delete_change_set(ChangeSetName=cs)
    except Exception as e:  # noqa: BLE001
        log.warning("could not delete change set %s: %s", cs, e)


class ExecutionError(GateError):
    """The apply did not happen, or did not finish. The node is failed."""


class Executor(Protocol):
    planner: Any
    kind: str

    def apply(self, creds: Any, plan: Plan, env: Any) -> Any: ...


def _tool(f: Callable[[], Any], what: str) -> Any:
    try:
        return f()
    except PlanError as e:
        raise ExecutionError(f"{what}: {e}") from e


def _check_same(approved: Plan, fresh: Plan) -> None:
    if fresh.environment != approved.environment:
        raise ExecutionError(f"re-plan is for {fresh.environment!r}, not {approved.environment!r}")
    if fresh.digest() != approved.digest():
        raise ExecutionError("the live state changed after approval (plan digest mismatch); nothing was "
                             "applied. Run the node again to plan and approve the new change.")


# ── API fixes ───────────────────────────────────────────────────────────────

class ApiFixExecutor:
    kind = "api_action"

    def __init__(self, fixer: Any, issue: Mapping[str, Any], fix: Mapping[str, Any]) -> None:
        from cloudctl.gate.plan.api import ApiActionPlanner  # noqa: PLC0415
        self.fixer = fixer
        self.issue = dict(issue)
        self.fix = dict(fix)
        self.planner = ApiActionPlanner(fixer, self.issue, self.fix)

    def apply(self, creds: Any, plan: Plan, env: Any) -> Any:
        self.fixer.apply(self.issue, self.fix, creds=creds)
        return {"applied": type(self.fixer).__name__, "resource": str(self.issue.get("resource", ""))[:300]}


# ── Terraform / OpenTofu ────────────────────────────────────────────────────

class TerraformExecutor:
    kind = "iac_apply"

    def __init__(self, planner: Any) -> None:
        self.planner = planner

    def apply(self, creds: Any, plan: Plan, env: Any) -> Any:
        planfile = Path(str(plan.artifacts.get("terraform_plan_binary", "")))
        expected = str(plan.metadata.get("plan_binary_sha256", ""))
        if not planfile.is_file() or not expected:
            raise ExecutionError("the approved Terraform plan file is missing; nothing was applied")
        if sha256_hex(planfile.read_bytes()) != expected:
            raise ExecutionError("the saved Terraform plan file changed after approval; nothing was applied")
        p = self.planner
        exe = _tool(lambda: find_binary(p.binary, p.binary_path), "terraform apply")
        senv = creds.subprocess_env()
        senv.update({"TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "CHECKPOINT_DISABLE": "1"})
        res = _tool(lambda: run_tool([exe, "apply", "-input=false", "-no-color", "-lock-timeout=120s",
                                      str(planfile)], cwd=p.root, env=senv, timeout=p.timeout,
                                     what=f"{p.binary} apply"), f"{p.binary} apply")
        return {"tool": p.binary, "applied_plan_sha256": expected, "output_tail": res.stdout[-500:]}


# ── re-plan then deploy (CloudFormation/CDK, ARM/Bicep, Pulumi, Kubernetes) ─

class _ReplanExecutor:
    kind = "iac_apply"

    def __init__(self, planner: Any) -> None:
        self.planner = planner

    def _fresh_planner(self) -> Any:
        return self.planner

    def apply(self, creds: Any, plan: Plan, env: Any) -> Any:
        workdir = private_workdir("cctl-exec-")
        try:
            try:
                fresh = self._fresh_planner().plan(env=env, creds=creds, workdir=workdir)
            except PlanError as e:
                raise ExecutionError(f"re-plan before apply failed: {e}") from e
            try:
                _check_same(plan, fresh)
            except ExecutionError:
                self._discard(fresh, creds, env)
                raise
            return self._deploy(fresh, creds, env, workdir)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def _discard(self, fresh: Plan, creds: Any, env: Any) -> None:
        return None

    def _deploy(self, fresh: Plan, creds: Any, env: Any, workdir: Path) -> Any:  # pragma: no cover
        raise NotImplementedError


class CloudFormationExecutor(_ReplanExecutor):
    _OK = ("CREATE_COMPLETE", "UPDATE_COMPLETE", "IMPORT_COMPLETE")

    def __init__(self, planner: Any, *, poll_seconds: float = 5.0, timeout: int = 3600) -> None:
        super().__init__(planner)
        self.poll_seconds = poll_seconds
        self.timeout = timeout

    def _fresh_planner(self) -> Any:
        from cloudctl.gate.plan.cloudformation import CdkPlanner, CloudFormationPlanner  # noqa: PLC0415
        p = self.planner
        if isinstance(p, CdkPlanner):
            return CdkPlanner(p.root, binary_path=p.binary_path, pinned_version=p.pinned_version, stacks=p.only,
                              template_bucket=p.template_bucket, timeout=p.timeout, keep_change_sets=True)
        if isinstance(p, CloudFormationPlanner):
            return CloudFormationPlanner(p.stacks, keep_change_sets=True, template_bucket=p.template_bucket,
                                         capabilities=p.capabilities, poll_seconds=p.poll_seconds,
                                         timeout=p.timeout)
        raise ExecutionError(f"not a CloudFormation planner: {type(p).__name__}")

    def _cfn(self, creds: Any, env: Any) -> Any:
        return creds.client("session").client("cloudformation", region_name=env.scope["region"])

    def _discard(self, fresh: Plan, creds: Any, env: Any) -> None:
        cfn = self._cfn(creds, env)
        for cs in (fresh.metadata.get("change_sets") or {}).values():
            _delete_change_set(cfn, cs)

    def _deploy(self, fresh: Plan, creds: Any, env: Any, workdir: Path) -> Any:
        cfn = self._cfn(creds, env)
        change_sets: Mapping[str, str] = fresh.metadata.get("change_sets") or {}
        if not change_sets:
            raise ExecutionError("the re-plan kept no change sets; nothing was applied")
        done: dict[str, str] = {}
        pending = dict(change_sets)
        try:
            for stack, cs in change_sets.items():
                d = cfn.describe_change_set(ChangeSetName=cs)
                pending.pop(stack, None)
                if d.get("Status") != "CREATE_COMPLETE" or d.get("ExecutionStatus") != "AVAILABLE":
                    # a change set with no changes FAILs at creation; nothing to run for that stack
                    _delete_change_set(cfn, cs)
                    done[stack] = "no changes"
                    continue
                cfn.execute_change_set(ChangeSetName=cs)
                done[stack] = self._wait(cfn, stack)
        except ExecutionError:
            raise
        except Exception as e:  # noqa: BLE001
            raise ExecutionError(f"CloudFormation execution failed: {e}") from e
        finally:
            for cs in pending.values():
                _delete_change_set(cfn, cs)
        return {"stacks": done}

    def _wait(self, cfn: Any, stack: str) -> str:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            st = (cfn.describe_stacks(StackName=stack)["Stacks"] or [{}])[0].get("StackStatus", "")
            if st in self._OK:
                return st
            if st.endswith("_FAILED") or "ROLLBACK" in st:
                raise ExecutionError(f"stack {stack} ended in {st}")
            time.sleep(self.poll_seconds)
        raise ExecutionError(f"stack {stack} did not finish within {self.timeout}s")


class ArmExecutor(_ReplanExecutor):
    def __init__(self, planner: Any, *, timeout: int = 3600) -> None:
        super().__init__(planner)
        self.timeout = timeout

    def _deploy(self, fresh: Plan, creds: Any, env: Any, workdir: Path) -> Any:
        import json  # noqa: PLC0415
        tpath = Path(str(fresh.artifacts.get("arm_template_json", "")))
        if not tpath.is_file():
            raise ExecutionError("the re-planned ARM template is missing; nothing was applied")
        template = json.loads(tpath.read_text(encoding="utf-8"))
        rg = env.scope["resource_group"]
        name = f"cctl-{int(time.time())}"
        try:
            client = self.planner.client(env, creds)
            poller = client.deployments.begin_create_or_update(rg, name, self.planner.deployment_body(template))
            result = poller.result(timeout=self.timeout)
        except Exception as e:  # noqa: BLE001
            raise ExecutionError(f"ARM deployment {name} to {rg} failed: {e}") from e
        props = getattr(result, "properties", None)
        state = getattr(props, "provisioning_state", None) if props is not None else None
        if state is None and isinstance(result, Mapping):
            state = (result.get("properties") or {}).get("provisioningState")
        if state and str(state).lower() != "succeeded":
            raise ExecutionError(f"ARM deployment {name} ended in {state}")
        return {"deployment": name, "resource_group": rg, "state": str(state or "")}


class PulumiExecutor(_ReplanExecutor):
    def _deploy(self, fresh: Plan, creds: Any, env: Any, workdir: Path) -> Any:
        p = self.planner
        exe = _tool(lambda: find_binary("pulumi", p.binary_path), "pulumi up")
        senv = creds.subprocess_env()
        senv.update({"PULUMI_SKIP_UPDATE_CHECK": "true", "PULUMI_SKIP_CONFIRMATIONS": "true"})
        res = _tool(lambda: run_tool([exe, "up", "--yes", "--skip-preview", "--non-interactive",
                                      "--stack", p.stack], cwd=p.root, env=senv, timeout=p.timeout,
                                     what="pulumi up"), "pulumi up")
        return {"tool": "pulumi", "stack": p.stack, "output_tail": res.stdout[-500:]}


class KubernetesExecutor(_ReplanExecutor):
    def _deploy(self, fresh: Plan, creds: Any, env: Any, workdir: Path) -> Any:
        p = self.planner
        kubeconfig = workdir / "kubeconfig"
        if not kubeconfig.is_file():
            raise ExecutionError("no kubeconfig from the re-plan; nothing was applied")
        exe = _tool(lambda: find_binary("kubectl", p.binary_path), "kubectl apply")
        senv = creds.subprocess_env()
        senv["KUBECONFIG"] = str(kubeconfig)
        argv = [exe, "apply", "-f", str(p.manifests), "-R", "--field-manager=cctl"]
        if p.server_side:
            argv.append("--server-side")
        if env.kubernetes.namespace:
            argv += ["-n", env.kubernetes.namespace]
        if p.prune_selector:
            argv += ["--prune", "-l", p.prune_selector]
        res = _tool(lambda: run_tool(argv, cwd=workdir, env=senv, timeout=p.timeout, what="kubectl apply"),
                    "kubectl apply")
        return {"tool": "kubectl", "cluster": env.kubernetes.cluster, "output_tail": res.stdout[-500:]}


# ── factory ─────────────────────────────────────────────────────────────────

def executor_for_planner(planner: Any) -> Executor:
    from cloudctl.gate.plan.arm import ArmWhatIfPlanner  # noqa: PLC0415
    from cloudctl.gate.plan.cloudformation import CdkPlanner, CloudFormationPlanner  # noqa: PLC0415
    from cloudctl.gate.plan.kubernetes import KubernetesPlanner  # noqa: PLC0415
    from cloudctl.gate.plan.pulumi import PulumiPlanner  # noqa: PLC0415
    from cloudctl.gate.plan.terraform import TerraformPlanner  # noqa: PLC0415

    if isinstance(planner, TerraformPlanner):
        return TerraformExecutor(planner)
    if isinstance(planner, (CdkPlanner, CloudFormationPlanner)):
        return CloudFormationExecutor(planner)
    if isinstance(planner, ArmWhatIfPlanner):
        return ArmExecutor(planner)
    if isinstance(planner, PulumiPlanner):
        return PulumiExecutor(planner)
    if isinstance(planner, KubernetesPlanner):
        return KubernetesExecutor(planner)
    raise ExecutionError(f"no executor for {type(planner).__name__}")


def default_executor_factory(node: Node, env: Any, *, tool_pins: Optional[dict] = None) -> Executor:
    """Build the executor for one graph node. Raises ExecutionError when the
    node cannot be carried out (no fixer, unknown IaC tool)."""
    if node.kind == "api_action":
        from cloudctl.fixers.registry import get_fixer  # noqa: PLC0415
        fixer = get_fixer(dict(node.issue), cloud=env.cloud)
        if fixer is None:
            raise ExecutionError(f"no fixer handles {node.issue.get('issue', '')!r}")
        if fixer.cloud and fixer.cloud != env.cloud:
            raise ExecutionError(f"the fixer is for {fixer.cloud}, the environment is {env.cloud}")
        return ApiFixExecutor(fixer, node.issue, node.fix)
    from cloudctl.gate.plan import detect_iac_planner  # noqa: PLC0415
    try:
        planner = detect_iac_planner(node.iac_root, env=env, tool_pins=tool_pins)
    except PlanError as e:
        raise ExecutionError(str(e)) from e
    return executor_for_planner(planner)

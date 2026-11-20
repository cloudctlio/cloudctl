"""Plan stage: the platform's own plan tool, normalised to one Plan."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from cloudctl.gate.models import PlanError
from cloudctl.gate.plan.base import Planner, private_workdir  # noqa: F401


def detect_iac_planner(root: Path | str, *, env: Any, tool_pins: Optional[dict] = None) -> Planner:
    """Pick the planner for an IaC root by what is in it. Ambiguous roots are
    an error rather than a guess."""
    from cloudctl.gate.plan.arm import ArmWhatIfPlanner  # noqa: PLC0415
    from cloudctl.gate.plan.cloudformation import CdkPlanner  # noqa: PLC0415
    from cloudctl.gate.plan.kubernetes import KubernetesPlanner  # noqa: PLC0415
    from cloudctl.gate.plan.pulumi import PulumiPlanner  # noqa: PLC0415
    from cloudctl.gate.plan.terraform import TerraformPlanner  # noqa: PLC0415

    pins = tool_pins or {}
    r = Path(root).expanduser().resolve()
    if not r.is_dir():
        raise PlanError(f"IaC root {r} is not a directory")
    found = []
    if (r / "cdk.json").is_file():
        found.append(("cdk", lambda: CdkPlanner(r, pinned_version=pins.get("cdk"))))
    if list(r.glob("*.tf")) or list(r.glob("*.tofu")):
        binary = "tofu" if list(r.glob("*.tofu")) or (r / ".opentofu").exists() else "terraform"
        found.append((binary, lambda: TerraformPlanner(r, binary=binary, pinned_version=pins.get(binary))))
    if (r / "Pulumi.yaml").is_file():
        stack = pins.get("pulumi_stack") or env.name
        found.append(("pulumi", lambda: PulumiPlanner(r, stack, pinned_version=pins.get("pulumi"))))
    biceps = sorted(r.glob("main.bicep")) or sorted(r.glob("*.bicep"))
    if biceps:
        found.append(("bicep", lambda: ArmWhatIfPlanner(biceps[0])))
    if not found and env.kubernetes is not None and (list(r.glob("*.yaml")) or list(r.glob("*.yml"))):
        found.append(("kubernetes", lambda: KubernetesPlanner(r, pinned_version=pins.get("kubectl"))))
    if not found:
        raise PlanError(f"cannot tell which IaC tool manages {r} (no *.tf, cdk.json, Pulumi.yaml, "
                        "*.bicep, or Kubernetes manifests for a cluster environment)")
    if len(found) > 1:
        raise PlanError(f"{r} matches several IaC tools ({[n for n, _ in found]}); point --iac-root at one")
    return found[0][1]()

"""Policy stage: industry-standard engines behind one finding contract.

``build_policy(config)`` turns the ``policy:`` block of the control-plane
config into enrichers and engines:

* ``rego`` (on by default): the gate's YAML rules compiled to Rego plus any
  Conftest-style Rego packs, evaluated by OPA semantics (regopy in-process, or
  the ``opa`` binary).
* ``trivy``, ``checkov``: baseline IaC scanners (AWS, Azure, GCP, Kubernetes).
* ``cfn_guard``: AWS CloudFormation Guard (AWS only).
* ``kyverno``: Kubernetes policies for EKS, AKS and GKE manifests.
* ``infracost``: cost enricher (Terraform/OpenTofu plans).
* ``aws_native``, ``azure_native``, ``gcp_native`` (on by default): the
  organization's own guardrails (SCPs, Azure Policy, GCP Org Policy).

Every engine maps its output to :class:`~cloudctl.gate.models.Finding`, and
any engine failure fails the gate closed.
"""
from __future__ import annotations

from typing import Any

from cloudctl.gate.config import GateConfig, engine_enabled
from cloudctl.gate.models import EngineError
from cloudctl.gate.policy.engine import (  # noqa: F401
    EngineRun, PolicyContext, PolicyResult, evaluate_policy,
)

ENGINE_LICENCES = {
    "rego": "OPA semantics: regopy/rego-cpp (MIT) or opa (Apache-2.0)",
    "trivy": "Apache-2.0",
    "checkov": "Apache-2.0",
    "cfn_guard": "Apache-2.0",
    "kyverno": "Apache-2.0",
    "infracost": "Apache-2.0 (CLI); pricing API needs a key",
    "aws_native": "AWS IAM Access Analyzer + IAM policy simulator (cloud API)",
    "azure_native": "Azure Policy checkPolicyRestrictions (cloud API)",
    "gcp_native": "GCP Organization Policy v2 (cloud API)",
    "approval": "Cedar authorization via cedarpy (Apache-2.0)",
}


def build_policy(config: GateConfig) -> tuple[list[Any], list[Any]]:
    """Return (enrichers, engines) for the configured, enabled engines."""
    from cloudctl.gate.policy import cost, native, rego, scanners  # noqa: PLC0415

    pc = config.policy

    def params(name: str) -> dict[str, Any]:
        e = pc.engines.get(name)
        return dict(e.params) if e else {}

    engines: list[Any] = []
    enrichers: list[Any] = []
    try:
        if engine_enabled(pc, "rego"):
            engines.append(rego.RegoEngine.from_config(builtin=pc.builtin_rules, rule_paths=pc.rule_paths,
                                                       rego_paths=pc.rego_paths, params=params("rego")))
        factories = {
            "trivy": scanners.TrivyEngine.from_params,
            "checkov": scanners.CheckovEngine.from_params,
            "cfn_guard": scanners.CfnGuardEngine.from_params,
            "kyverno": scanners.KyvernoEngine.from_params,
            "aws_native": native.AwsNativeEngine.from_params,
            "azure_native": native.AzureNativeEngine.from_params,
            "gcp_native": native.GcpNativeEngine.from_params,
        }
        for name, make in factories.items():
            if engine_enabled(pc, name):
                engines.append(make(params(name)))
        if engine_enabled(pc, "infracost"):
            enrichers.append(cost.InfracostEnricher.from_params(params("infracost")))
    except EngineError:
        raise
    except (TypeError, ValueError) as e:
        raise EngineError(f"policy engine configuration: {e}") from e
    return enrichers, engines

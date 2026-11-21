"""cloudctl policy gate — the only path through which cctl changes cloud state.

The model proposes; deterministic code checks and acts. Every change, whether
a direct API fix (``cloudctl security audit --fix``), an IaC fix pushed as a
pull request (``cloudctl debug --agent --resolve``) or, later, an orchestrated
change graph, passes the same five stages:

1. **Credentials** — short-lived, per-operation credentials for the target
   environment (AWS STS AssumeRole for 900 s, Azure workload identity /
   managed identity scoped to one subscription and resource group, GCP service
   account impersonation for 900 s). Kept in process memory only.
2. **Plan** — the platform's own plan tool (Terraform/OpenTofu, CloudFormation
   change sets for CDK, ARM/Bicep what-if, Pulumi preview, ``kubectl diff``) or,
   for direct API fixes, the fixer's own declared change set. Normalised to one
   :class:`~cloudctl.gate.models.Plan` with add / modify / destroy counts.
3. **Policy** — the structured plan is evaluated by pluggable engines (OPA/Rego
   rules written as YAML, Trivy, Checkov, cfn-guard, Kyverno, Infracost, and
   the clouds' own guardrails). Every finding is mapped to one contract: rule
   ID, severity LOW..CRITICAL, message, fix hint.
4. **Approval** — any HIGH or CRITICAL finding rejects outright. Plans above
   the environment's change threshold wait for an Ed25519-signed approval from
   a named approver, whose authority is decided by Cedar policy.
5. **Authorization** — only then are the scoped credentials and the exact plan
   handed to the executor, once.

Every stage, decision and execution event is written to a hash-chained audit
log (local file, or S3 Object Lock / Azure immutable Blob / GCS bucket lock).

Anything unexpected — a missing engine, an engine error, a config error, an
audit write failure — rejects the change. The gate fails closed.
"""
from __future__ import annotations

from cloudctl.gate.models import (  # noqa: F401
    Action,
    ChangeRequest,
    Finding,
    GateDecision,
    Outcome,
    Plan,
    ResourceChange,
    Severity,
)

__all__ = [
    "Action",
    "ChangeRequest",
    "Finding",
    "GateDecision",
    "Outcome",
    "Plan",
    "ResourceChange",
    "Severity",
]

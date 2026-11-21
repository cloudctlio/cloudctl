"""Data model shared by every gate stage.

All types are immutable where they cross a stage boundary, so a later stage can
never alter what an earlier stage evaluated.
"""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from cloudctl.gate.canonical import digest


class GateError(Exception):
    """Base class for gate errors. Any GateError rejects the change."""


class ConfigError(GateError):
    """The control-plane configuration is missing or invalid."""


class EngineError(GateError):
    """A policy engine is missing, mis-versioned or failed to evaluate."""


class CredentialError(GateError):
    """Scoped credentials could not be acquired or are no longer valid."""


class PlanError(GateError):
    """The platform's plan tool failed or produced output the gate cannot read."""


class AuditError(GateError):
    """An audit record could not be written durably."""


class ApprovalError(GateError):
    """A signed approval is missing, invalid, expired, reused or unauthorized."""


class Severity(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        """Parse a severity name (case-insensitive). Unknown values raise
        ``ValueError`` — callers decide the fail-closed fallback explicitly."""
        if isinstance(value, Severity):
            return value
        if not isinstance(value, str):
            raise ValueError(f"severity must be a string, got {type(value).__name__}")
        key = value.strip().upper()
        aliases = {"INFO": "LOW", "INFORMATIONAL": "LOW", "WARNING": "MEDIUM",
                   "MODERATE": "MEDIUM", "ERROR": "HIGH", "SEVERE": "CRITICAL"}
        key = aliases.get(key, key)
        try:
            return cls[key]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}; expected LOW, MEDIUM, HIGH or CRITICAL") from None

    @property
    def blocking(self) -> bool:
        """HIGH and CRITICAL findings reject a change outright."""
        return self >= Severity.HIGH


class Action(str, enum.Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"   # delete + create (in either order)
    READ = "read"         # data sources; never a mutation
    NOOP = "no-op"

    @property
    def mutates(self) -> bool:
        return self not in (Action.READ, Action.NOOP)


#: Platforms the plan stage understands.
PLATFORMS = frozenset({
    "terraform", "opentofu", "cloudformation", "cdk", "arm", "bicep",
    "pulumi", "kubernetes", "api",
})

#: Clouds a resource change can belong to.
CLOUDS = frozenset({"aws", "azure", "gcp", "kubernetes", "other"})


@dataclass(frozen=True)
class ResourceChange:
    """One resource-level change, normalised across every plan tool."""

    address: str                  # e.g. aws_s3_bucket.logs, /subscriptions/../storageAccounts/x
    type: str                     # e.g. aws_s3_bucket, Microsoft.Storage/storageAccounts
    action: Action
    cloud: str = "other"
    name: str = ""
    location: str = ""            # region / location / zone when known
    before: Optional[Mapping[str, Any]] = None
    after: Optional[Mapping[str, Any]] = None
    #: The concrete API operations this change performs, when known
    #: (e.g. ["ec2:RevokeSecurityGroupIngress"]). Used by native guardrail
    #: checks; empty for plan tools that do not expose them.
    operations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.action, Action):
            object.__setattr__(self, "action", Action(self.action))
        if self.cloud not in CLOUDS:
            raise ValueError(f"unknown cloud {self.cloud!r}")
        if not self.address:
            raise ValueError("resource change needs an address")

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "type": self.type,
            "action": self.action.value,
            "cloud": self.cloud,
            "name": self.name,
            "location": self.location,
            "before": _plain(self.before),
            "after": _plain(self.after),
            "operations": list(self.operations),
        }


@dataclass(frozen=True)
class Plan:
    """A normalised plan: what the platform's own plan tool says will change.

    ``artifacts`` names files produced by the plan tool (e.g. the Terraform
    plan JSON) that scanners read. They are *not* part of the digest: the
    digest covers what will change, so an approval binds to the change itself.
    """

    platform: str
    environment: str
    changes: tuple[ResourceChange, ...]
    source: str = ""                         # IaC root, stack name, or fixer name
    artifacts: Mapping[str, str] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.platform not in PLATFORMS:
            raise ValueError(f"unknown platform {self.platform!r}")
        object.__setattr__(self, "changes", tuple(self.changes))

    @property
    def mutations(self) -> tuple[ResourceChange, ...]:
        return tuple(c for c in self.changes if c.action.mutates)

    @property
    def add_count(self) -> int:
        return sum(1 for c in self.changes if c.action in (Action.CREATE, Action.REPLACE))

    @property
    def modify_count(self) -> int:
        return sum(1 for c in self.changes if c.action == Action.UPDATE)

    @property
    def destroy_count(self) -> int:
        return sum(1 for c in self.changes if c.action in (Action.DELETE, Action.REPLACE))

    @property
    def changed_resource_count(self) -> int:
        """Number of distinct resources the plan mutates."""
        return len({c.address for c in self.mutations})

    @property
    def clouds(self) -> tuple[str, ...]:
        return tuple(sorted({c.cloud for c in self.changes}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "environment": self.environment,
            "source": self.source,
            "counts": {
                "add": self.add_count,
                "modify": self.modify_count,
                "destroy": self.destroy_count,
                "changed_resources": self.changed_resource_count,
            },
            "clouds": list(self.clouds),
            "changes": [c.to_dict() for c in self.changes],
        }

    def digest(self) -> str:
        """Digest of what the plan changes (stable across re-plans of the same
        live state; excludes timestamps and local file paths)."""
        d = self.to_dict()
        d["changes"] = sorted(d["changes"], key=lambda c: (c["address"], c["action"]))
        return digest(d)


@dataclass(frozen=True)
class Finding:
    """One policy finding, in the gate's single contract."""

    rule_id: str
    severity: Severity
    message: str
    engine: str
    fix_hint: str = ""
    resource: str = ""
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.name,
            "message": self.message,
            "engine": self.engine,
            "fix_hint": self.fix_hint,
            "resource": self.resource,
            "references": list(self.references),
        }


class Outcome(str, enum.Enum):
    AUTHORIZED = "authorized"
    REJECTED = "rejected"
    PENDING_APPROVAL = "pending_approval"


#: Change kinds the gate accepts.
REQUEST_KINDS = frozenset({"api_action", "iac_pr", "iac_apply"})


@dataclass(frozen=True)
class ChangeRequest:
    """What an operator (or the orchestrator) asks the gate to authorize."""

    kind: str
    environment: str
    summary: str
    requester: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    #: Extra facts the policy engines may use, e.g. the model spend so far.
    context: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in REQUEST_KINDS:
            raise ValueError(f"unknown change kind {self.kind!r}")
        if not self.environment:
            raise ValueError("change request needs an environment")
        if not self.requester:
            raise ValueError("change request needs a requester identity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "kind": self.kind,
            "environment": self.environment,
            "summary": self.summary,
            "requester": self.requester,
            "context": _plain(self.context),
        }


@dataclass(frozen=True)
class GateDecision:
    request_id: str
    outcome: Outcome
    stage: str                     # the last stage reached
    reasons: tuple[str, ...]
    findings: tuple[Finding, ...] = ()
    plan_digest: str = ""
    plan_counts: Mapping[str, int] = field(default_factory=dict)
    approval_request_path: str = ""
    approver: str = ""
    decided_at: str = field(default_factory=lambda: utcnow_iso())

    @property
    def authorized(self) -> bool:
        return self.outcome == Outcome.AUTHORIZED

    @property
    def max_severity(self) -> Optional[Severity]:
        return max((f.severity for f in self.findings), default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "outcome": self.outcome.value,
            "stage": self.stage,
            "reasons": list(self.reasons),
            "findings": [f.to_dict() for f in self.findings],
            "plan_digest": self.plan_digest,
            "plan_counts": dict(self.plan_counts),
            "approval_request_path": self.approval_request_path,
            "approver": self.approver,
            "decided_at": self.decided_at,
        }


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _plain(value: Any) -> Any:
    """Convert mappings/sequences to plain JSON-compatible containers."""
    if value is None:
        return None
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)

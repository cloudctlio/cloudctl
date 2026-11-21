"""Data types shared by the diff-first checks. Plain dataclasses, JSON-friendly."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def to_dt(value: Any) -> datetime | None:
    """Parse an ISO-8601 string / epoch number / datetime into an aware UTC datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # epoch seconds or milliseconds
        v = float(value)
        if v > 1e12:
            v /= 1000.0
        return datetime.fromtimestamp(v, tz=timezone.utc)
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


@dataclass
class Resource:
    """One resource as the expected-state source declares it.

    ``key`` is the IaC address (``aws_lambda_function.worker``, a CloudFormation
    logical id, a Pulumi URN). ``type`` is the canonical CloudFormation type name
    (``AWS::Lambda::Function``), so every adapter speaks the same vocabulary.
    """

    key: str
    type: str
    name: str = ""
    physical_id: str = ""
    arn: str = ""
    config: dict = field(default_factory=dict)
    source: str = ""          # terraform | cloudformation | cdk | pulumi | baseline | live
    source_type: str = ""     # the IaC's own type name (aws_lambda_function, ...)

    def tokens(self) -> set[str]:
        """Identifiers by which this resource can be recognised in other data
        (CloudTrail resource lists, env vars, ARNs). Lower-cased, exact match."""
        out: set[str] = set()
        for v in (self.name, self.physical_id, self.arn):
            if v and isinstance(v, str) and len(v) >= 3:
                out.add(v.lower())
                # last ARN / URL segment ("...:function:foo", ".../queue-name")
                tail = v.replace(":", "/").rstrip("/").split("/")[-1]
                if len(tail) >= 3:
                    out.add(tail.lower())
        return out

    def label(self) -> str:
        return self.name or self.physical_id or self.key


@dataclass
class DriftItem:
    resource_key: str
    resource_type: str
    resource_name: str
    fields: list[dict]                 # [{"field": "Enabled", "expected": True, "live": False}]
    kind: str = "modified"             # modified | deleted | unmanaged
    source: str = ""                   # which comparison found it
    changed_at: str | None = None      # matched CloudTrail time, when known
    changed_by: str = ""
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Change:
    """One write call (CloudTrail) or IaC commit that touched a resource."""

    time: str
    event_name: str
    event_source: str = ""
    actor: str = ""
    resource_key: str = ""             # matched expected-state resource, if any
    resource_name: str = ""
    params: dict = field(default_factory=dict)
    error_code: str = ""
    origin: str = "cloudtrail"         # cloudtrail | iac_commit
    status: str = ""                   # candidate | after_metrics | before_window | after_onset | superseded | reverted | failed_call | unmatched
    reason: str = ""
    superseded_by: str = ""
    # Set for an in-window change that puts back the values in force before an
    # earlier change while live now matches what is declared: likely a revert.
    restores: bool = False
    # Set for a call that sets no settings (a purge, a restart) on a resource
    # whose live config matches what is declared: it left nothing behind.
    one_off: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IncidentWindow:
    onset: str | None = None           # first abnormal bucket of the current symptom
    last_healthy: str | None = None    # last bucket with positive evidence of health
    start: str | None = None           # earliest time a cause may have happened
    end: str | None = None             # latest time a cause may have happened (onset + skew)
    method: str = ""                   # metrics | observation | override | unknown
    signals: list[dict] = field(default_factory=list)   # the series that defined it
    note: str = ""
    # Last bucket the metrics cover (CloudWatch lags a few minutes). A change
    # after it is too recent for the metrics to show, so timing can't rule it out.
    metrics_end: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Symptom:
    id: str
    kind: str                          # errors_up | backlog_up | throughput_down | flow_stopped | log_errors
    node: str                          # resource key where it is observed
    onset: str | None
    detail: str
    scope: list[str] = field(default_factory=list)   # resource keys a cause may sit on
    # Flow stopped right after an "actor" (a function writing to what its config
    # names): the actor's config explains it only if the change touched the link.
    link_scope: list[str] = field(default_factory=list)
    link_targets: list[str] = field(default_factory=list)
    # Nothing known feeds this node (topology incomplete): a change that
    # re-pointed a reference of this service may explain it.
    open_service: str = ""
    # Set when a change inside this symptom's scope landed after it began and
    # live config now matches what's declared: the metrics end before that
    # change, so the symptom may already be over. Not required to be explained.
    may_be_over: str = ""
    # Set when the node was failing in every minute it had work, back to its
    # first work: a standing condition, not this incident's onset. Reported,
    # not required to be explained by a change in the window.
    standing: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Candidate:
    id: str
    kind: str                          # drift | change
    resource_key: str
    resource_name: str
    time: str | None
    summary: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

"""Drift repair loop.

Each pass, for every IaC root an environment owns:

1. **Detect** with the IaC tool's own view of live state, using short-lived
   credentials from the gate's broker (read only):

   - Terraform / OpenTofu: ``plan`` (which refreshes). ``resource_drift`` in
     the plan JSON tells drift apart from code that was merged but never
     applied.
   - ARM / Bicep: what-if (compares against live resources).
   - Pulumi: ``preview --refresh``.
   - Kubernetes: ``kubectl diff`` (compares against the live cluster).
   - CloudFormation / CDK: the drift detection API (``DetectStackDrift``).

2. **Classify** the drift: class (security incident, config drift, failed
   change), severity, and the live-state policy findings from the gate's own
   Rego rules run against what is actually deployed.
3. **Score confidence** that re-applying the declared state is a safe repair.
4. **Decide** with the autonomy table (:mod:`.autonomy`): class first, then
   tier × severity, then the platform cap, then θ.
5. **Repair** (``auto`` only, or when a person runs ``drift repair``): one
   ``iac_apply`` node through the orchestrator and so through every gate
   stage, pinned to the plan that was classified. If live state moved since,
   the gate rejects at the plan stage and nothing is applied.

Failed change runs queue rollback requests (stage 2); the loop turns each into
a ``failed_change`` event, which is never repaired without a person.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Optional

from cloudctl.controlplane import autonomy as A
from cloudctl.controlplane.graph import ChangeGraph, Node
from cloudctl.gate.models import (
    Action, ChangeRequest, CredentialError, EngineError, Plan, PlanError, ResourceChange, Severity, utcnow_iso,
)
from cloudctl.gate.plan.base import private_workdir

# ── classification ──────────────────────────────────────────────────────────

_CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("identity", ("iam", "role_assignment", "roleassignment", "microsoft.authorization", "service_account",
                  "serviceaccount", "rolebinding", "role_binding", "clusterrole", "cluster_role", "/role", "access_key", "workload_identity",
                  "managed_identity", "userassignedidentit", "sso", "identity_pool")),
    ("audit_logging", ("cloudtrail", "flow_log", "flowlog", "config_rule", "configuration_recorder", "guardduty",
                       "securityhub", "logging_", "diagnostic_setting", "diagnosticsettings", "microsoft.insights",
                       "log_analytics", "operationalinsights", "audit", "logging.sink", "logsink", "log_sink")),
    ("keys", ("kms", "key_vault", "keyvault", "secretsmanager", "secret_manager", "secretmanager",
              "certificate", "/secret")),
    ("network", ("security_group", "securitygroup", "network_security", "networksecuritygroups", "firewall",
                 "networkpolicy", "network_acl", "nacl", "ingress", "load_balancer", "public_ip", "publicip")),
    ("storage", ("s3_bucket", "s3::bucket", "storage_account", "storageaccounts", "storage_bucket", "blob",
                 "container_registry", "ecr_repository")),
)
_INCIDENT_CATEGORIES = {"identity", "audit_logging", "keys"}
_EXPOSURE = re.compile(r'0\.0\.0\.0/0|::/0|"allusers"|"allauthenticatedusers"|"principal":\s*"\*"|'
                       r'"principal":\s*\{\s*"aws":\s*"\*"|"(source_?address_?prefix|sourceaddressprefix)":\s*'
                       r'"(\*|internet|any)"|"public_?access(_?level)?":\s*"(blob|container|enabled)"|'
                       r'"allow_?blob_?public_?access":\s*true|"block_public_(acls|policy)":\s*false',
                       re.IGNORECASE)
_STATEFUL = ("db_instance", "rds", "dynamodb", "s3_bucket", "s3::bucket", "ebs", "volume", "snapshot", "efs",
             "file_system", "filesystem", "elasticache", "redshift", "docdb", "neptune", "opensearch", "kafka",
             "msk", "kinesis", "sqs", "sql", "cosmos", "storage_account", "storageaccounts", "storage_bucket",
             "disk", "bigtable", "spanner", "redis", "memorystore", "persistentvolume", "statefulset",
             "namespace", "kms", "key_vault", "keyvault")
_TAG_KEYS = {"tags", "tags_all", "labels", "Tags", "metadata.labels"}


def category(resource_type: str) -> str:
    t = resource_type.lower()
    for name, needles in _CATEGORIES:
        if any(n in t for n in needles):
            return name
    return "other"


def exposed(state: Any) -> bool:
    if not state:
        return False
    return bool(_EXPOSURE.search(json.dumps(state, default=str)))


def stateful(resource_type: str) -> bool:
    t = resource_type.lower()
    return any(n in t for n in _STATEFUL)


def tags_only(rc: ResourceChange) -> bool:
    if rc.action != Action.UPDATE or not isinstance(rc.before, Mapping) or not isinstance(rc.after, Mapping):
        return False
    keys = set(rc.before) | set(rc.after)
    diff = {k for k in keys if rc.before.get(k) != rc.after.get(k)}
    return bool(diff) and diff <= _TAG_KEYS


@dataclass(frozen=True)
class DriftItem:
    address: str
    type: str
    action: str
    category: str
    exposed: bool
    attributed: Optional[bool]      # True: the tool says this is drift; False: undeployed code; None: unknown

    def to_dict(self) -> dict[str, Any]:
        return {"address": self.address, "type": self.type, "action": self.action, "category": self.category,
                "exposed": self.exposed, "attributed": self.attributed}


@dataclass(frozen=True)
class Classification:
    drift_class: str
    severity: str
    reasons: tuple[str, ...]


def classify(changes: Iterable[ResourceChange], *, attributed: Optional[set[str]] = None,
             live_findings: Iterable[Any] = (), live_policy_ok: bool = True,
             failed_change: bool = False) -> tuple[Classification, list[DriftItem]]:
    items: list[DriftItem] = []
    reasons: list[str] = []
    incident = False
    sev = Severity.LOW
    muts = [c for c in changes if c.action.mutates]
    for c in muts:
        cat = category(c.type)
        exp = exposed(c.before)
        attr = None if attributed is None else (c.address in attributed)
        items.append(DriftItem(c.address, c.type, c.action.value, cat, exp, attr))
        if cat in _INCIDENT_CATEGORIES:
            incident = True
            reasons.append(f"{c.address}: {cat.replace('_', ' ')} changed outside IaC")
        elif cat in ("network", "storage") and exp:
            incident = True
            reasons.append(f"{c.address}: live state is open to the internet")
        if c.action in (Action.DELETE, Action.REPLACE) or (c.action == Action.CREATE and stateful(c.type)):
            sev = max(sev, Severity.HIGH)
            reasons.append(f"{c.address}: repair would {c.action.value} it")
        elif not tags_only(c):
            sev = max(sev, Severity.MEDIUM)
    for f in live_findings:
        fs = f.severity if isinstance(f.severity, Severity) else Severity.parse(f.severity)
        sev = max(sev, fs)
        reasons.append(f"live state: {f.rule_id} {fs.name} on {f.resource}")
        if fs >= Severity.HIGH and f.rule_id.split("-")[1:2] in (["IAM"], ["NET"], ["STG"], ["ENC"]):  # drift-introduced
            incident = True
    if not live_policy_ok:
        sev = max(sev, Severity.MEDIUM)
        reasons.append("the live-state policy check could not run")
    if incident:
        return Classification(A.SECURITY_INCIDENT, "CRITICAL", tuple(reasons)), items
    cls = A.FAILED_CHANGE if failed_change else A.CONFIG_DRIFT
    if failed_change:
        sev = max(sev, Severity.HIGH)
        reasons.append("left behind by a change run that failed")
    return Classification(cls, sev.name, tuple(reasons)), items


def confidence(items: list[DriftItem], *, sightings: int, active_run: bool, live_policy_ok: bool,
               platform: str) -> tuple[float, list[str]]:
    """How sure cctl is that re-applying the declared state is the right,
    safe repair. Deterministic; every factor is recorded."""
    if active_run:
        return 0.0, ["a change run is in progress on this root: never fight a deploy"]
    if not live_policy_ok:
        return 0.0, ["the live-state policy check could not run"]
    score, why = 1.0, []
    if sightings < 2:
        score *= 0.5
        why.append("seen once (×0.5): no default θ is met until a second scan finds the same drift")
    attrs = {i.attributed for i in items}
    if False in attrs:
        score *= 0.5
        why.append("the repair would also apply code that was never deployed (×0.5)")
    elif None in attrs:
        score *= 0.75
        why.append(f"{platform} cannot tell drift from undeployed code (×0.75)")
    if any(i.action in ("delete", "replace") for i in items):
        score *= 0.5
        why.append("the repair deletes or replaces something (×0.5)")
    if len(items) > 10:
        score *= 0.8
        why.append(f"{len(items)} resources (×0.8)")
    return round(score, 4), why or ["drift attributed, stable, small"]


# ── events and their store ──────────────────────────────────────────────────

OPEN = "open"                 # decided approve: waits for a person
REPORTED = "reported"         # decided report: a person must look (incident, or the tool cannot repair)
REPAIRING = "repairing"
REPAIRED = "repaired"         # applied; the next scan confirms
AWAITING_APPROVAL = "awaiting_approval"   # the gate wants a signed approval for the repair
REPAIR_FAILED = "repair_failed"
REPAIR_REJECTED = "repair_rejected"
RESOLVED = "resolved"         # a later scan found no drift
EVENT_STATES = (OPEN, REPORTED, REPAIRING, REPAIRED, AWAITING_APPROVAL, REPAIR_FAILED, REPAIR_REJECTED, RESOLVED)
_LIVE = {OPEN, REPORTED, REPAIRED, AWAITING_APPROVAL, REPAIR_REJECTED, REPAIRING}
_EVENT_ID = re.compile(r"^[0-9a-f]{32}$")


@dataclass
class DriftEvent:
    environment: str
    tier: str
    cloud: str
    root: str
    platform: str
    plan_digest: str
    drift_class: str
    severity: str
    confidence: float
    factors: list[str]
    decision: dict[str, Any]
    items: list[dict[str, Any]]
    reasons: list[str]
    status: str = OPEN
    sightings: int = 1
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    first_seen: str = field(default_factory=utcnow_iso)
    last_seen: str = field(default_factory=utcnow_iso)
    run_id: str = ""
    rollback_request_id: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)

    def note(self, what: str, **data: Any) -> None:
        self.history.append({"at": utcnow_iso(), "what": what, **data})
        del self.history[:-50]

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "DriftEvent":
        ev = cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})
        if ev.status not in EVENT_STATES or not _EVENT_ID.match(ev.id):
            raise ValueError(f"malformed drift event {d.get('id')!r}")
        return ev


def default_drift_dir() -> Path:
    return Path(os.environ.get("CLOUDCTL_DRIFT_DIR") or Path.home() / ".cloudctl" / "drift")


class DriftStore:
    def __init__(self, directory: Optional[Path | str] = None) -> None:
        self.dir = Path(directory).expanduser() if directory else default_drift_dir()

    def _ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    def save(self, ev: DriftEvent) -> None:
        self._ensure()
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".ev-", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(ev.to_dict(), fh, indent=1, sort_keys=True, default=str)
            os.replace(tmp, self.dir / f"{ev.id}.json")
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def load(self, event_id: str) -> DriftEvent:
        if not _EVENT_ID.match(event_id or ""):
            raise KeyError(f"not a drift event id: {event_id!r}")
        p = self.dir / f"{event_id}.json"
        if not p.is_file():
            raise KeyError(f"no drift event {event_id}")
        return DriftEvent.from_dict(json.loads(p.read_text(encoding="utf-8")))

    def list(self) -> list[DriftEvent]:
        if not self.dir.is_dir():
            return []
        out = []
        for p in self.dir.glob("*.json"):
            try:
                out.append(DriftEvent.from_dict(json.loads(p.read_text(encoding="utf-8"))))
            except (ValueError, TypeError):
                continue
        return sorted(out, key=lambda e: e.last_seen, reverse=True)

    def live_for(self, environment: str, root: str) -> Optional[DriftEvent]:
        for ev in self.list():
            if ev.environment == environment and ev.root == root and ev.status in _LIVE:
                return ev
        return None

    @contextmanager
    def lock(self) -> Iterator[None]:
        self._ensure()
        lp = self.dir / "loop.lock"
        try:
            fd = os.open(lp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise RuntimeError(f"another drift pass holds {lp}; if none is running, delete that file") from None
        try:
            os.write(fd, f"{os.getpid()} {utcnow_iso()}\n".encode())
            os.close(fd)
            yield
        finally:
            try:
                os.unlink(lp)
            except OSError:
                pass


# ── detection ───────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    platform: str
    plan: Plan
    attributed: Optional[set[str]] = None     # addresses the tool itself reports as drift


def _norm(p: str) -> str:
    return str(Path(p).expanduser().resolve())


def drift_planner(root: str, env: Any, *, tool_pins: Optional[dict] = None) -> Any:
    """The planner whose output reflects live state for *root*."""
    from cloudctl.gate.plan import detect_iac_planner  # noqa: PLC0415
    from cloudctl.gate.plan.pulumi import PulumiPlanner  # noqa: PLC0415
    planner = detect_iac_planner(root, env=env, tool_pins=tool_pins)
    if isinstance(planner, PulumiPlanner):
        planner.refresh = True
    return planner


def terraform_drift_addresses(plan_json: Path) -> Optional[set[str]]:
    try:
        doc = json.loads(plan_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if "resource_drift" not in doc and "resource_changes" not in doc:
        return None
    return {str(d.get("address")) for d in doc.get("resource_drift") or [] if d.get("address")}


class CfnDriftDetector:
    """CloudFormation drift via the DetectStackDrift API, for the stacks a CDK
    app synthesises (or explicit stack names)."""

    def __init__(self, *, poll_seconds: float = 5.0, timeout: int = 600) -> None:
        self.poll_seconds = poll_seconds
        self.timeout = timeout

    def detect(self, env: Any, creds: Any, stacks: Iterable[str], *, platform: str, source: str) -> Plan:
        region = env.scope["region"]
        cfn = creds.client("session").client("cloudformation", region_name=region)
        changes: list[ResourceChange] = []
        for stack in stacks:
            try:
                det = cfn.detect_stack_drift(StackName=stack)["StackDriftDetectionId"]
                deadline = time.monotonic() + self.timeout
                while True:
                    st = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=det)
                    if st.get("DetectionStatus") in ("DETECTION_COMPLETE", "DETECTION_FAILED"):
                        break
                    if time.monotonic() > deadline:
                        raise PlanError(f"drift detection on {stack} did not finish within {self.timeout}s")
                    time.sleep(self.poll_seconds)
                if st.get("DetectionStatus") == "DETECTION_FAILED" and st.get("StackDriftStatus") != "DRIFTED":
                    raise PlanError(f"drift detection on {stack} failed: {st.get('DetectionStatusReason', '')}")
                pages = cfn.get_paginator("describe_stack_resource_drifts").paginate(
                    StackName=stack, StackResourceDriftStatusFilters=["MODIFIED", "DELETED"])
                for page in pages:
                    for d in page.get("StackResourceDrifts") or []:
                        deleted = d.get("StackResourceDriftStatus") == "DELETED"
                        changes.append(ResourceChange(
                            address=f"{stack}/{d.get('LogicalResourceId', '?')}", type=d.get("ResourceType", ""),
                            action=Action.CREATE if deleted else Action.UPDATE, cloud="aws",
                            name=d.get("PhysicalResourceId", ""), location=region,
                            before=None if deleted else _props(d.get("ActualProperties")),
                            after=_props(d.get("ExpectedProperties"))))
            except PlanError:
                raise
            except Exception as e:  # noqa: BLE001
                raise PlanError(f"CloudFormation drift detection on {stack} failed: {e}") from e
        return Plan(platform=platform, environment=env.name, changes=tuple(changes), source=source)


def _props(text: Any) -> Optional[dict]:
    if not text:
        return None
    try:
        v = json.loads(text) if isinstance(text, str) else dict(text)
    except (ValueError, TypeError):
        return {"raw": str(text)[:2000]}
    return v if isinstance(v, dict) else {"value": v}


class DriftScanner:
    def __init__(self, config: Any, *, brokers: Optional[Mapping[str, Any]] = None,
                 planner_factory: Optional[Callable[[str, Any], Any]] = None,
                 cfn: Optional[CfnDriftDetector] = None, requester: str = "cctl-drift-loop",
                 policy: Optional[Callable[[], tuple[list[Any], list[Any]]]] = None) -> None:
        from cloudctl.gate.credentials import default_brokers  # noqa: PLC0415
        from cloudctl.gate.policy import build_policy  # noqa: PLC0415
        self.config = config
        self.policy = policy or (lambda: build_policy(config))
        self.brokers = dict(brokers) if brokers is not None else default_brokers()
        self.planner_factory = planner_factory or drift_planner
        self.cfn = cfn or CfnDriftDetector()
        self.requester = requester

    def scan(self, env: Any, root: str) -> ScanResult:
        from cloudctl.gate.credentials import broker_for  # noqa: PLC0415
        from cloudctl.gate.plan.cloudformation import CdkPlanner  # noqa: PLC0415
        planner = self.planner_factory(root, env)
        creds = broker_for(self.brokers, env.cloud).acquire(env, request_id=f"drift-{uuid.uuid4().hex[:12]}",
                                                            requester=self.requester)
        workdir = private_workdir("cctl-drift-")
        try:
            if isinstance(planner, CdkPlanner):
                stacks = planner.synth(env=env, creds=creds, workdir=workdir)
                plan = self.cfn.detect(env, creds, list(stacks), platform="cdk", source=str(planner.root))
                return ScanResult("cdk", plan, attributed={c.address for c in plan.changes})
            plan = planner.plan(env=env, creds=creds, workdir=workdir)
            attributed = None
            if plan.platform in ("terraform", "opentofu"):
                attributed = terraform_drift_addresses(Path(str(plan.artifacts.get("terraform_plan_json", ""))))
            return ScanResult(plan.platform, plan, attributed)
        finally:
            creds.destroy()
            shutil.rmtree(workdir, ignore_errors=True)

    def live_policy(self, env: Any, plan: Plan) -> list[Any]:
        """The gate's Rego rules on what is deployed now (each change's
        ``before``) and on what the code declares (``after``). Returns only the
        findings the drift introduced: on live state, not on the declared
        state. A finding both share was there before the drift and is the
        gate's business at the next change, not evidence about this drift.
        Raises EngineError if the engine cannot run."""
        live, declared = [], []
        for c in plan.changes:
            if not c.action.mutates:
                continue
            if isinstance(c.before, Mapping):
                live.append(_as_state(c, c.before))
            if isinstance(c.after, Mapping):
                declared.append(_as_state(c, c.after))
        if not live:
            return []
        live_f = self._rego(env, plan, live)
        declared_keys = {(f.rule_id, f.resource) for f in self._rego(env, plan, declared)} if declared else set()
        return [f for f in live_f if (f.rule_id, f.resource) not in declared_keys]

    def _rego(self, env: Any, plan: Plan, changes: list[ResourceChange]) -> list[Any]:
        from cloudctl.gate.policy.engine import PolicyContext, evaluate_policy  # noqa: PLC0415
        lp = Plan(platform=plan.platform, environment=plan.environment, changes=tuple(changes), source="live-state")
        _, engines = self.policy()
        engines = [e for e in engines if getattr(e, "name", "") == "rego"]
        if not engines:
            raise EngineError("the Rego engine is not enabled, so live state cannot be checked")
        req = ChangeRequest(kind="iac_apply", environment=env.name, summary="drift live-state check",
                            requester=self.requester)
        res = evaluate_policy(PolicyContext(plan=lp, env=env, request=req), enrichers=[], engines=engines,
                              severity_overrides=self.config.policy.severity_overrides,
                              disabled_rules=env.disabled_rules)
        # cost, scope, delete and plan rules judge a proposed change, not a state
        return [f for f in res.findings if not f.rule_id.startswith(_NOT_STATE_RULES)]


_NOT_STATE_RULES = ("CCTL-COST", "CCTL-SCOPE", "CCTL-PLAN", "CCTL-DEL")


def _as_state(c: ResourceChange, state: Mapping[str, Any]) -> ResourceChange:
    return ResourceChange(address=c.address, type=c.type, action=Action.UPDATE, cloud=c.cloud, name=c.name,
                          location=c.location, before=None, after=dict(state))


# ── the loop ────────────────────────────────────────────────────────────────

class _PinnedPlanner:
    """Wraps a planner so the gate rejects at the plan stage if live state has
    moved since the drift was classified."""

    def __init__(self, inner: Any, digest: str) -> None:
        self._inner = inner
        self._digest = digest

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def plan(self, *, env: Any, creds: Any, workdir: Path) -> Plan:
        p = self._inner.plan(env=env, creds=creds, workdir=workdir)
        if p.digest() != self._digest:
            raise PlanError("live state changed since the drift was classified; scan again")
        return p


def default_requester_for_loop() -> str:
    return f"cctl-drift-loop@{socket.gethostname()}"


class DriftLoop:
    def __init__(self, gate: Any, *, scanner: Optional[DriftScanner] = None, store: Optional[DriftStore] = None,
                 orchestrator_factory: Optional[Callable[..., Any]] = None, runs: Any = None,
                 requester: Optional[str] = None, executor_for: Optional[Callable[[Any], Any]] = None) -> None:
        from cloudctl.controlplane.state import LocalRunStore  # noqa: PLC0415
        self.gate = gate
        self.config = gate.config
        self.table: A.AutonomyTable = self.config.drift or A.AutonomyTable()
        self.requester = requester or default_requester_for_loop()
        self.scanner = scanner or DriftScanner(self.config, brokers=getattr(gate, "brokers", None),
                                               requester=self.requester, policy=gate.policy)
        self.store = store or DriftStore()
        self.runs = runs or LocalRunStore()
        self.orchestrator_factory = orchestrator_factory or self._default_orchestrator
        self.executor_for = executor_for

    def _default_orchestrator(self, *, requester: str, executor_factory: Any) -> Any:
        from cloudctl.controlplane.orchestrator import Orchestrator  # noqa: PLC0415
        return Orchestrator(self.gate, self.runs, executor_factory=executor_factory, requester=requester)

    # ── targets ─────────────────────────────────────────────────────────────
    def targets(self, environments: Optional[Iterable[str]] = None) -> list[tuple[Any, str]]:
        names = list(environments) if environments else sorted(self.config.environments)
        out = []
        for n in names:
            env = self.config.environment(n)
            out += [(env, _norm(r)) for r in env.match_iac_roots]
        return out

    def _active_run_on(self, root: str) -> bool:
        from cloudctl.controlplane import state as S  # noqa: PLC0415
        busy = {S.RUNNING, S.AWAITING_APPROVAL, S.BLOCKED, S.PENDING}
        for run in self.runs.list():
            for n in (run.graph.get("nodes") or []):
                r = (n.get("target") or {}).get("iac_root")
                if r and _norm(r) == root and run.nodes.get(n.get("id")) and run.nodes[n["id"]].status in busy:
                    return True
        return False

    # ── one pass ────────────────────────────────────────────────────────────
    def scan_once(self, environments: Optional[Iterable[str]] = None, *, repair: bool = True) -> list[DriftEvent]:
        with self.store.lock():
            return self._scan_all(environments, repair=repair)

    def pass_once(self, environments: Optional[Iterable[str]] = None, *, repair: bool = True,
                  rollbacks: Any = None) -> list[DriftEvent]:
        """One locked pass: take rollback requests, then scan."""
        with self.store.lock():
            taken = self._take_rollbacks(rollbacks) if rollbacks is not None else []
            return taken + self._scan_all(environments, repair=repair)

    def _scan_all(self, environments: Optional[Iterable[str]], *, repair: bool) -> list[DriftEvent]:
        targets = self.targets(environments)
        self.gate.record("drift.scan.start", {"targets": [[e.name, r] for e, r in targets], "repair": repair})
        out = []
        for env, root in targets:
            ev = self._scan_target(env, root, repair=repair)
            if ev is not None:
                out.append(ev)
        return out

    def _scan_target(self, env: Any, root: str, *, repair: bool, failed_change: bool = False,
                     rollback_id: str = "") -> Optional[DriftEvent]:
        prior = self.store.live_for(env.name, root)
        # left behind by a failed change: stays a failed change until a scan finds the root clean
        failed_change = failed_change or (prior is not None and prior.drift_class == A.FAILED_CHANGE)
        try:
            res = self.scanner.scan(env, root)
        except (PlanError, CredentialError) as e:
            self.gate.record("drift.scan.error", {"environment": env.name, "root": root, "error": str(e)[:1000]})
            return None
        if res.plan.changed_resource_count == 0:
            if prior is not None and not rollback_id:
                prior.status = RESOLVED
                prior.note("no drift on rescan")
                self.store.save(prior)
                self.gate.record("drift.resolved", {"event_id": prior.id, "environment": env.name, "root": root})
                return prior
            return None
        live_ok = True
        try:
            findings = self.scanner.live_policy(env, res.plan)
        except EngineError as e:
            live_ok, findings = False, []
            self.gate.record("drift.live_policy.error", {"environment": env.name, "root": root, "error": str(e)})
        cls, items = classify(res.plan.changes, attributed=res.attributed, live_findings=findings,
                              live_policy_ok=live_ok, failed_change=failed_change)
        digest = res.plan.digest()
        recurred = prior is not None and prior.status == REPAIRED
        if prior is not None and prior.plan_digest == digest and prior.status != REPAIR_REJECTED:
            ev = prior
            ev.sightings += 1
        else:
            ev = DriftEvent(environment=env.name, tier=env.tier, cloud=env.cloud, root=root, platform=res.platform,
                            plan_digest=digest, drift_class=cls.drift_class, severity=cls.severity, confidence=0.0,
                            factors=[], decision={}, items=[], reasons=[])
            if prior is not None and prior.id != ev.id:
                prior.status = RESOLVED
                prior.note("superseded by a new drift event", by=ev.id)
                self.store.save(prior)
        ev.last_seen = utcnow_iso()
        ev.drift_class, ev.severity, ev.reasons = cls.drift_class, cls.severity, list(cls.reasons)[:50]
        ev.items = [i.to_dict() for i in items][:200]
        ev.rollback_request_id = rollback_id or ev.rollback_request_id
        ev.confidence, ev.factors = confidence(items, sightings=ev.sightings, active_run=self._active_run_on(root),
                                               live_policy_ok=live_ok, platform=res.platform)
        d = self.table.decide(tier=env.tier, severity=ev.severity, drift_class=ev.drift_class,
                              confidence=ev.confidence, platform=res.platform)
        if recurred and d.mode == A.AUTO:
            d = A.Decision(A.APPROVE, d.reasons + ("the drift is still there after a repair: a person must look",))
        ev.decision = d.to_dict()
        if ev.status not in (AWAITING_APPROVAL, REPAIRING):
            ev.status = {A.REPORT: REPORTED, A.APPROVE: OPEN, A.AUTO: OPEN}[d.mode]
        ev.note("scanned", digest=digest, decision=d.mode, confidence=ev.confidence)
        self.store.save(ev)
        self.gate.record("drift.detected", {"event_id": ev.id, "environment": env.name, "root": root,
                                            "platform": res.platform, "class": ev.drift_class,
                                            "severity": ev.severity, "confidence": ev.confidence,
                                            "factors": ev.factors, "decision": ev.decision,
                                            "sightings": ev.sightings, "digest": digest,
                                            "items": ev.items[:50]})
        if repair and d.mode == A.AUTO and ev.status == OPEN:
            self._repair(ev, requester=self.requester, why="autonomy table: auto")
        return ev

    # ── repair ──────────────────────────────────────────────────────────────
    def repair(self, event_id: str, *, requester: str, override: str = "") -> DriftEvent:
        """A person's go-ahead to repair one event. ``report`` events (security
        incidents, tools that cannot repair) need an explicit, audited
        override reason."""
        ev = self.store.load(event_id)
        if ev.status not in (OPEN, REPORTED, REPAIR_REJECTED):
            raise RuntimeError(f"drift event {event_id} is {ev.status}; nothing to repair")
        if ev.decision.get("mode") == A.REPORT or ev.status == REPORTED:
            if not override.strip():
                raise RuntimeError(f"drift event {event_id} is report-only ({'; '.join(ev.decision.get('reasons', []))}); "
                                   "pass an override reason to repair it anyway")
            if ev.platform in A.REPORT_ONLY_PLATFORMS:
                raise RuntimeError(A.REPORT_ONLY_PLATFORMS[ev.platform])
            self.gate.record("drift.override", {"event_id": ev.id, "requester": requester, "reason": override[:500],
                                                "class": ev.drift_class})
        return self._repair(ev, requester=requester, why=override or "operator go-ahead")

    def _repair(self, ev: DriftEvent, *, requester: str, why: str) -> DriftEvent:
        from cloudctl.controlplane import state as S  # noqa: PLC0415
        from cloudctl.controlplane.executors import executor_for_planner  # noqa: PLC0415

        env = self.config.environment(ev.environment)
        digest = ev.plan_digest
        scanner = self.scanner
        build = self.executor_for or executor_for_planner

        def factory(node: Node, env_: Any) -> Any:
            ex = build(scanner.planner_factory(node.iac_root, env_))
            ex.planner = _PinnedPlanner(ex.planner, digest)
            return ex

        graph = ChangeGraph(request=f"repair drift {ev.id} in {env.name}: {why}"[:2000], nodes=(
            Node(id="repair", kind="iac_apply", environment=env.name,
                 summary=f"re-apply declared state of {ev.root} ({ev.severity} {ev.drift_class})"[:500],
                 iac_root=ev.root),))
        ev.status = REPAIRING
        ev.note("repair started", requester=requester, why=why[:300])
        self.store.save(ev)
        self.gate.record("drift.repair.start", {"event_id": ev.id, "requester": requester, "why": why[:500]})
        try:
            run = self.orchestrator_factory(requester=requester, executor_factory=factory).start(graph)
        except Exception as e:  # noqa: BLE001 — the event records it; nothing was applied by this code path
            ev.status = REPAIR_REJECTED
            ev.note("repair could not start", error=str(e)[:500])
            self.store.save(ev)
            self.gate.record("drift.repair.end", {"event_id": ev.id, "status": ev.status, "error": str(e)[:500]})
            return ev
        node = run.nodes["repair"]
        ev.run_id = run.run_id
        ev.status = {S.SUCCEEDED: REPAIRED, S.AWAITING_APPROVAL: AWAITING_APPROVAL,
                     S.FAILED: REPAIR_FAILED}.get(node.status, REPAIR_REJECTED)
        ev.note("repair finished", run_id=run.run_id, node_status=node.status, reasons=node.reasons[:5])
        self.store.save(ev)
        self.gate.record("drift.repair.end", {"event_id": ev.id, "run_id": run.run_id, "status": ev.status})
        return ev

    # ── rollback requests from failed change runs ───────────────────────────
    def take_rollbacks(self, queue: Any) -> list[DriftEvent]:
        """Turn queued rollback requests into ``failed_change`` events (never
        auto-repaired). Each request is marked done once handled."""
        with self.store.lock():
            return self._take_rollbacks(queue)

    def _take_rollbacks(self, queue: Any) -> list[DriftEvent]:
        out = []
        for req in queue.pending():
            target = req.get("target") or {}
            env = self.config.environment(req["environment"])
            ev: Optional[DriftEvent] = None
            if req.get("kind") == "iac_apply" and target.get("iac_root"):
                ev = self._scan_target(env, _norm(target["iac_root"]), repair=False, failed_change=True,
                                       rollback_id=req["id"])
            if ev is None:
                ev = DriftEvent(environment=env.name, tier=env.tier, cloud=env.cloud,
                                root=str(target.get("iac_root") or json.dumps(target.get("issue", {}))[:300]),
                                platform="api" if req.get("kind") == "api_action" else "unknown", plan_digest="",
                                drift_class=A.FAILED_CHANGE, severity="HIGH", confidence=0.0,
                                factors=["no plan to classify"],
                                decision={"mode": A.REPORT, "reasons": ["a failed change with nothing to re-apply: "
                                                                        "a person must check it"]},
                                items=[], reasons=[req.get("error", "")[:500]], status=REPORTED,
                                rollback_request_id=req["id"])
                self.store.save(ev)
            self.gate.record("drift.rollback.taken", {"rollback_id": req["id"], "event_id": ev.id,
                                                      "run_id": req.get("run_id"), "node_id": req.get("node_id")})
            queue.done(req["id"])
            out.append(ev)
        return out

    def run_forever(self, *, interval: int = 900, environments: Optional[Iterable[str]] = None,
                    repair: bool = True, rollbacks: Any = None, max_passes: Optional[int] = None,
                    sleep: Callable[[float], None] = time.sleep) -> int:
        if interval < 60:
            raise ValueError("interval must be at least 60 seconds")
        passes = 0
        while max_passes is None or passes < max_passes:
            self.pass_once(environments, repair=repair, rollbacks=rollbacks)
            passes += 1
            if max_passes is None or passes < max_passes:
                sleep(interval)
        return passes


__all__ = ["DriftLoop", "DriftScanner", "DriftStore", "DriftEvent", "classify", "confidence", "category",
           "exposed"]

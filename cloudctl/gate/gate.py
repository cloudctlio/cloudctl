"""The five-stage policy gate.

    1. credentials   short-lived, scoped credentials for the environment
                     (AWS STS AssumeRole 900 s, Azure workload identity /
                     managed identity, GCP service-account impersonation)
    2. plan          the platform's own plan tool → one normalised Plan with
                     add / modify / destroy counts and a digest
    3. policy        every enabled engine (Rego rules and packs, baseline
                     scanners, cost, native cloud guardrails) → findings
    4. approval      any HIGH/CRITICAL finding rejects outright; plans over
                     the environment's threshold need a signed approval by a
                     named approver, bound to this exact plan
    5. authorization only now are the credentials and the plan handed to the
                     executor, once, through :class:`Authorization`

Every stage, and every execution event, is appended to the hash-chained
audit log before the next stage runs. If the audit write fails the gate
fails closed. Nothing here applies a change itself: callers receive an
:class:`Authorization` and run their apply through ``Authorization.execute``.
"""
from __future__ import annotations

import getpass
import os
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, TypeVar

from cloudctl.gate.approval import (
    ApprovalRequest, LocalApprovalStore, authorize_approval, verify_signature,
)
from cloudctl.gate.audit import AuditLog, LocalFileSink, ObjectStoreSink
from cloudctl.gate.config import BASELINE_SCANNERS, GateConfig, engine_enabled
from cloudctl.gate.credentials import broker_for, default_brokers
from cloudctl.gate.models import (
    ApprovalError, AuditError, ChangeRequest, ConfigError, CredentialError, EngineError, Finding,
    GateDecision, GateError, Outcome, Plan, PlanError,
)
from cloudctl.gate.plan.base import private_workdir
from cloudctl.gate.policy import build_policy
from cloudctl.gate.policy.engine import PolicyContext, evaluate_policy

T = TypeVar("T")

#: Platforms with no baseline scanner available (rules + native engines still run).
NO_BASELINE_PLATFORMS = {"api", "pulumi"}


def default_requester() -> str:
    """Who is asking: CLOUDCTL_REQUESTER, else the OS user."""
    v = os.environ.get("CLOUDCTL_REQUESTER")
    if v:
        return v.strip()
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"


def build_audit_log(config: GateConfig, *, actor: str = "") -> AuditLog:
    """Immutable remote sink when configured, else the local hash-chained file."""
    a = config.audit
    if a.sink is None:
        return AuditLog(LocalFileSink(a.local_path), chain=a.chain, actor=actor)
    s = dict(a.sink)
    t = s["type"]
    if t == "s3":
        from cloudctl.gate.audit import S3ObjectLockBackend  # noqa: PLC0415
        backend = S3ObjectLockBackend(s["bucket"], region=s.get("region"), profile=s.get("profile"),
                                      mode=s.get("mode", "COMPLIANCE"), kms_key_id=s.get("kms_key_id"))
    elif t == "azure_blob":
        from cloudctl.gate.audit import AzureImmutableBlobBackend  # noqa: PLC0415
        backend = AzureImmutableBlobBackend(s["account_url"], s["container"])
    elif t == "gcs":
        from cloudctl.gate.audit import GcsBucketLockBackend  # noqa: PLC0415
        backend = GcsBucketLockBackend(s["bucket"], project=s.get("project"))
    else:  # pragma: no cover — config validation rejects it
        raise ConfigError(f"unknown audit sink {t!r}")
    sink = ObjectStoreSink(backend, prefix=s.get("prefix", "cctl-audit"), chain=a.chain,
                           retain_days=int(s["retain_days"]))
    return AuditLog(sink, chain=a.chain, actor=actor)


@dataclass
class GateResult:
    decision: GateDecision
    authorization: Optional["Authorization"] = None

    @property
    def authorized(self) -> bool:
        return self.authorization is not None and self.decision.authorized


class Authorization:
    """Stage 5's hand-off: scoped credentials + the approved plan, usable once."""

    def __init__(self, *, decision: GateDecision, request: ChangeRequest, plan: Plan, creds: Any,
                 audit: AuditLog, workdir: Optional[Path]) -> None:
        self.decision = decision
        self.request = request
        self.plan = plan
        self._creds = creds
        self._audit = audit
        self._workdir = workdir
        self._used = False
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"Authorization(request_id={self.request.request_id!r}, used={self._used})"

    def __enter__(self) -> "Authorization":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def execute(self, fn: Callable[[Any, Plan], T], *, what: str = "apply") -> T:
        """Run *fn(creds, plan)* once. Audits start and end; destroys creds after."""
        with self._lock:
            if self._used:
                raise GateError("this authorization was already used")
            self._used = True
        try:
            if self._creds is not None:
                self._creds.ensure_valid()
            self._audit.append("execution.start", {"request_id": self.request.request_id, "what": what,
                                                   "plan_digest": self.decision.plan_digest})
            try:
                result = fn(self._creds, self.plan)
            except Exception as e:
                self._audit_safely("execution.end", {"request_id": self.request.request_id, "ok": False,
                                                     "error": f"{type(e).__name__}: {e}"[:2000]})
                raise
            self._audit.append("execution.end", {"request_id": self.request.request_id, "ok": True,
                                                 "result": _summary(result)})
            return result
        finally:
            self.close()

    def _audit_safely(self, event: str, data: Mapping[str, Any]) -> None:
        try:
            self._audit.append(event, data)
        except AuditError:
            pass

    def close(self) -> None:
        if self._creds is not None:
            self._creds.destroy()
            self._creds = None
        if self._workdir is not None:
            shutil.rmtree(self._workdir, ignore_errors=True)
            self._workdir = None


def _summary(result: Any) -> Any:
    if result is None or isinstance(result, (bool, int, float)):
        return result
    if isinstance(result, str):
        return result[:500]
    if isinstance(result, Mapping):
        return {str(k): _summary(v) for k, v in list(result.items())[:20]}
    if hasattr(result, "to_dict"):
        try:
            return _summary(result.to_dict())
        except Exception:  # noqa: BLE001
            pass
    return str(result)[:500]


class PolicyGate:
    def __init__(self, config: GateConfig, *, audit: AuditLog, brokers: Optional[Mapping[str, Any]] = None,
                 approvals: Any = None, policy: Optional[tuple[list[Any], list[Any]]] = None) -> None:
        self.config = config
        self.audit = audit
        self.brokers = dict(brokers) if brokers is not None else default_brokers()
        self.approvals = approvals or LocalApprovalStore(config.approvals_dir)
        self._policy = policy

    @classmethod
    def from_config(cls, config: GateConfig, *, actor: str = "") -> "PolicyGate":
        return cls(config, audit=build_audit_log(config, actor=actor or default_requester()))

    # ── public ──────────────────────────────────────────────────────────────
    def record(self, event: str, data: Mapping[str, Any]) -> None:
        """Audit an operator action, model call or tool call (fails closed)."""
        self.audit.append(event, data)

    def evaluate(self, request: ChangeRequest, planner: Any, *, approval_id: Optional[str] = None,
                 keep_workdir: bool = False) -> GateResult:
        env_name = request.environment
        workdir: Optional[Path] = None
        creds: Any = None
        handed_off = False
        try:
            env = self.config.environment(env_name)
            self._log("gate.request", {**request.to_dict(), "approval_id": approval_id or "",
                                       "tier": env.tier, "cloud": env.cloud})

            # 1. credentials
            try:
                creds = broker_for(self.brokers, env.cloud).acquire(env, request_id=request.request_id,
                                                                    requester=request.requester)
            except CredentialError as e:
                return self._reject(request, "credentials", [str(e)])
            self._log("gate.credentials", {"request_id": request.request_id, "identity": creds.identity,
                                           "scope": dict(creds.scope),
                                           "expires_at": creds.expires_at.isoformat()})

            # 2. plan
            workdir = private_workdir()
            try:
                plan = planner.plan(env=env, creds=creds, workdir=workdir)
            except (PlanError, CredentialError) as e:
                return self._reject(request, "plan", [str(e)])
            if not isinstance(plan, Plan):
                return self._reject(request, "plan", ["planner returned no plan"])
            if plan.environment != env.name:
                return self._reject(request, "plan", [f"plan is for {plan.environment!r}, not {env.name!r}"])
            digest = plan.digest()
            counts = {"add": plan.add_count, "modify": plan.modify_count, "destroy": plan.destroy_count}
            self._log("gate.plan", {"request_id": request.request_id, "platform": plan.platform,
                                    "source": plan.source, "digest": digest, "counts": counts,
                                    "changes": [c.address for c in plan.changes if c.action.mutates][:200]})
            if plan.changed_resource_count == 0:
                return self._reject(request, "plan", ["the plan changes nothing"], digest=digest, counts=counts)

            # 3. policy
            ctx = PolicyContext(plan=plan, env=env, request=request, creds=creds)
            try:
                enrichers, engines = self._policy if self._policy is not None else build_policy(self.config)
                result = evaluate_policy(ctx, enrichers=enrichers, engines=engines,
                                         severity_overrides=self.config.policy.severity_overrides,
                                         disabled_rules=env.disabled_rules)
            except EngineError as e:
                return self._reject(request, "policy", [f"policy engine failed (fail closed): {e}"],
                                    digest=digest, counts=counts)
            self._log("gate.policy", {"request_id": request.request_id,
                                      "findings": [f.to_dict() for f in result.findings][:200],
                                      "engines": [{"engine": r.engine, "ran": r.ran, "findings": r.findings,
                                                   "detail": r.detail} for r in result.runs],
                                      "cost": ctx.facts.get("cost")})
            findings = list(result.findings)
            ran = {r.engine for r in result.runs if r.ran}
            if env.is_prod and plan.platform not in NO_BASELINE_PLATFORMS and \
                    not any(n in ran for n in BASELINE_SCANNERS if engine_enabled(self.config.policy, n)):
                return self._reject(request, "policy", ["prod requires a baseline scanner (trivy or checkov) to "
                                                        f"scan this {plan.platform} plan; none ran"],
                                    findings=findings, digest=digest, counts=counts)

            # 4. approval
            blocking = [f for f in findings if f.severity.blocking]
            if blocking:
                return self._reject(request, "approval",
                                    [f"{len(blocking)} HIGH/CRITICAL finding(s) reject the change"],
                                    findings=findings, digest=digest, counts=counts)
            approver = ""
            if self._needs_approval(env, plan):
                if not approval_id:
                    path = self._request_approval(request, env, digest, counts, findings)
                    return GateResult(self._decide(request, Outcome.PENDING_APPROVAL, "approval",
                                                   [f"plan changes {plan.changed_resource_count} resource(s) in "
                                                    f"{env.name}; a signed approval is required"],
                                                   findings, digest, counts, approval_request_path=path))
                try:
                    approver = self._check_approval(approval_id, request, env, digest)
                except ApprovalError as e:
                    return self._reject(request, "approval", [str(e)], findings=findings, digest=digest,
                                        counts=counts)

            # 5. authorization
            decision = self._decide(request, Outcome.AUTHORIZED, "authorization",
                                    ["all stages passed"], findings, digest, counts, approver=approver)
            auth = Authorization(decision=decision, request=request, plan=plan, creds=creds, audit=self.audit,
                                 workdir=None if keep_workdir else workdir)
            handed_off = True
            return GateResult(decision, auth)
        except AuditError as e:
            return GateResult(GateDecision(request_id=request.request_id, outcome=Outcome.REJECTED,
                                           stage="audit", reasons=(f"audit log unavailable (fail closed): {e}",)))
        except ConfigError as e:
            return self._reject(request, "config", [str(e)])
        finally:
            if not handed_off:
                if creds is not None:
                    creds.destroy()
                if workdir is not None and not keep_workdir:
                    shutil.rmtree(workdir, ignore_errors=True)

    # ── stages helpers ──────────────────────────────────────────────────────
    def _log(self, event: str, data: Mapping[str, Any]) -> None:
        self.audit.append(event, data)

    def _decide(self, request: ChangeRequest, outcome: Outcome, stage: str, reasons: list[str],
                findings: list[Finding], digest: str, counts: Mapping[str, int], *,
                approval_request_path: str = "", approver: str = "") -> GateDecision:
        d = GateDecision(request_id=request.request_id, outcome=outcome, stage=stage, reasons=tuple(reasons),
                         findings=tuple(findings), plan_digest=digest, plan_counts=dict(counts),
                         approval_request_path=approval_request_path, approver=approver)
        self._log("gate.decision", d.to_dict())
        return d

    def _reject(self, request: ChangeRequest, stage: str, reasons: list[str], *, findings: list[Finding] = (),
                digest: str = "", counts: Optional[Mapping[str, int]] = None) -> GateResult:
        try:
            d = self._decide(request, Outcome.REJECTED, stage, reasons, list(findings), digest, counts or {})
        except AuditError as e:
            d = GateDecision(request_id=request.request_id, outcome=Outcome.REJECTED, stage=stage,
                             reasons=tuple(reasons) + (f"audit log unavailable: {e}",), findings=tuple(findings),
                             plan_digest=digest, plan_counts=dict(counts or {}))
        return GateResult(d)

    @staticmethod
    def _needs_approval(env: Any, plan: Plan) -> bool:
        if env.approval.always:
            return True
        return bool(env.approval.approvers) and plan.changed_resource_count > env.approval.threshold

    def _request_approval(self, request: ChangeRequest, env: Any, digest: str, counts: Mapping[str, int],
                          findings: list[Finding]) -> str:
        top = max((f.severity for f in findings), default=None)
        req = ApprovalRequest.new(request_id=request.request_id, environment=env.name, tier=env.tier,
                                  plan_digest=digest, summary=request.summary, requester=request.requester,
                                  counts=counts, max_severity=top.name if top else "NONE",
                                  ttl_seconds=env.approval.ttl_seconds,
                                  reasons=tuple(f"{f.rule_id} {f.severity.name}: {f.message}"[:300]
                                                for f in findings[:20]))
        path = self.approvals.put_request(req)
        self._log("gate.approval.requested", {"request_id": request.request_id, "environment": env.name,
                                              "approvers": list(env.approval.approvers),
                                              "expires_at": req.expires_at, "plan_digest": digest})
        return path

    def _check_approval(self, approval_id: str, request: ChangeRequest, env: Any, digest: str) -> str:
        req = self.approvals.get_request(approval_id)
        signed = self.approvals.get_approval(approval_id)
        if signed is None:
            raise ApprovalError(f"approval request {approval_id} has not been approved yet")
        if signed.request != req:
            raise ApprovalError("the signed approval does not match the stored approval request")
        if req.environment != env.name:
            raise ApprovalError(f"approval {approval_id} is for {req.environment!r}, not {env.name!r}")
        if req.plan_digest != digest:
            raise ApprovalError("the plan changed since it was approved (digest mismatch); request a new approval")
        if req.requester != request.requester:
            raise ApprovalError(f"approval {approval_id} was requested by {req.requester!r}, "
                                f"not {request.requester!r}")
        if signed.approver not in env.approval.approvers:
            raise ApprovalError(f"{signed.approver!r} is not a named approver for {env.name!r}")
        key = self.config.approvers.get(signed.approver)
        if not key:
            raise ApprovalError(f"no public key configured for approver {signed.approver!r}")
        verify_signature(signed, key)
        approver_envs = [n for n, e in self.config.environments.items() if signed.approver in e.approval.approvers]
        authorize_approval(approver=signed.approver, approver_environments=approver_envs, environment=env.name,
                           tier=env.tier, requester=req.requester, max_severity=req.max_severity,
                           counts=req.counts, expired=req.expired())
        if self.approvals.is_consumed(approval_id):
            raise ApprovalError(f"approval {approval_id} was already used")
        self.approvals.consume(approval_id, digest)
        self._log("gate.approval.verified", {"request_id": request.request_id, "approval_id": approval_id,
                                             "approver": signed.approver, "signed_at": signed.signed_at})
        return signed.approver

"""HTTP API for the control plane.

Every change still goes through the policy gate: the service only decides
*who* is asking (from a verified OIDC token) and runs the work on a worker
pool. Long work answers ``202 Accepted`` with a run id; poll the run.

    GET  /healthz                         liveness (no auth)
    GET  /readyz                          audit sink and state store reachable (no auth)
    POST /v1/changes:compile              operator  plain-language request -> change graph (applies nothing)
    POST /v1/changes                      operator  run a change graph            -> 202 {run_id}
    GET  /v1/changes                      reader    recent runs
    GET  /v1/changes/{run_id}             reader    one run
    POST /v1/changes/{run_id}:resume      operator  carry on after approvals      -> 202
    GET  /v1/approvals                    reader    pending approval requests
    GET  /v1/approvals/{request_id}       reader    one request (what an approver signs)
    POST /v1/approvals/{request_id}       approver  submit a signature made offline with the approver's key
    GET  /v1/drift                        reader    drift events
    GET  /v1/drift/{event_id}             reader    one event
    POST /v1/drift:scan                   operator  one drift pass                -> 202
    POST /v1/drift/{event_id}:repair      operator  repair one event              -> 202
    GET  /v1/audit:verify                 auditor   verify the hash chain
"""

import logging
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Optional

from cloudctl.service.auth import AuthError, OIDCVerifier, Principal

log = logging.getLogger("cloudctl.service")

MAX_GRAPH_BYTES = 512_000


@dataclass
class ServiceContext:
    """Everything the app needs, built once by :func:`build_context` (or by
    tests with fakes)."""

    gate: Any
    kv: Any
    verifier: OIDCVerifier
    runs: Any
    drift_store: Any
    rollbacks: Any
    model_factory: Callable[[], Any]
    executor_factory: Optional[Callable[..., Any]] = None
    drift_loop_factory: Optional[Callable[..., Any]] = None
    workers: int = 4
    max_body_bytes: int = 1_048_576
    drift_interval: int = 0
    drift_repair: bool = True
    pool: ThreadPoolExecutor = field(init=False)
    jobs: dict[str, Future] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="cctl-worker")

    def orchestrator(self, requester: str) -> Any:
        from cloudctl.controlplane.orchestrator import Orchestrator  # noqa: PLC0415
        return Orchestrator(self.gate, self.runs, rollback=self.rollbacks, executor_factory=self.executor_factory,
                            requester=requester)

    def drift_loop(self, requester: str) -> Any:
        if self.drift_loop_factory:
            return self.drift_loop_factory(requester=requester)
        from cloudctl.controlplane.drift import DriftLoop  # noqa: PLC0415
        from cloudctl.controlplane.orchestrator import Orchestrator  # noqa: PLC0415
        return DriftLoop(self.gate, store=self.drift_store, runs=self.runs, requester=requester,
                         orchestrator_factory=lambda **k: Orchestrator(
                             self.gate, self.runs, rollback=self.rollbacks, executor_factory=k["executor_factory"],
                             requester=k["requester"]))

    def submit(self, name: str, fn: Callable[[], Any]) -> str:
        job = uuid.uuid4().hex
        fut = self.pool.submit(_logged, name, fn)
        self.jobs[job] = fut
        if len(self.jobs) > 1000:                          # forget finished jobs
            for k in [k for k, f in self.jobs.items() if f.done()][:500]:
                self.jobs.pop(k, None)
        return job


def _logged(name: str, fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except Exception:  # noqa: BLE001 — the run/event records the outcome; log the rest
        log.exception("background job %s failed", name)
        return None


def create_app(ctx: ServiceContext) -> Any:
    from fastapi import Body, Depends, FastAPI, HTTPException, Request  # noqa: PLC0415
    from fastapi.responses import JSONResponse  # noqa: PLC0415

    stop = threading.Event()

    @asynccontextmanager
    async def lifespan(app: Any) -> AsyncIterator[None]:
        t = None
        if ctx.drift_interval:
            t = threading.Thread(target=_drift_daemon, args=(ctx, stop), name="cctl-drift", daemon=True)
            t.start()
        yield
        stop.set()
        ctx.pool.shutdown(wait=True, cancel_futures=False)

    app = FastAPI(title="cctl control plane", version="1", lifespan=lifespan, docs_url=None, redoc_url=None,
                  openapi_url="/v1/openapi.json")

    @app.middleware("http")
    async def guard(request: Request, call_next: Any) -> Any:
        rid = uuid.uuid4().hex
        n = request.headers.get("content-length")
        if n is not None and (not n.isdigit() or int(n) > ctx.max_body_bytes):
            return JSONResponse({"error": "request body too large", "request_id": rid}, status_code=413)
        try:
            resp = await call_next(request)
        except Exception:  # noqa: BLE001 — never leak internals
            log.exception("request %s failed", rid)
            resp = JSONResponse({"error": "internal error", "request_id": rid}, status_code=500)
        resp.headers["X-Request-Id"] = rid
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return resp

    def principal(request: Request) -> Principal:
        try:
            return ctx.verifier.verify(request.headers.get("authorization"))
        except AuthError as e:
            raise HTTPException(401, str(e), headers={"WWW-Authenticate": "Bearer"}) from None

    def need(role: str) -> Callable[..., Principal]:
        def dep(p: Principal = Depends(principal)) -> Principal:
            if not p.has(role):
                raise HTTPException(403, f"needs the {role} role")
            return p
        return dep

    def bad(e: Exception, code: int = 400) -> HTTPException:
        return HTTPException(code, str(e)[:2000])

    # ── health ──────────────────────────────────────────────────────────────
    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.get("/readyz")
    def readyz() -> Any:
        failing = []
        for name, probe in (("audit", ctx.gate.audit.check_ready), ("state", ctx.kv.check_ready)):
            try:
                probe()
            except Exception:  # noqa: BLE001
                log.exception("readiness: %s", name)
                failing.append(name)
        return JSONResponse({"ready": not failing, "failing": failing}, status_code=503 if failing else 200)

    # ── changes ─────────────────────────────────────────────────────────────
    @app.post("/v1/changes:compile")
    def compile_change(body: dict = Body(...), p: Principal = Depends(need("operator"))) -> dict:
        from cloudctl.controlplane.compiler import RequestCompiler  # noqa: PLC0415
        req = body.get("request")
        if not isinstance(req, str) or not req.strip():
            raise HTTPException(400, "request: a non-empty string is required")
        roots = body.get("iac_roots") or []
        if not isinstance(roots, list) or not all(isinstance(r, str) for r in roots):
            raise HTTPException(400, "iac_roots: a list of strings")

        def audit(event: str, data: dict) -> None:
            ctx.gate.record(event, {**data, "requester": p.subject})

        res = RequestCompiler(ctx.gate.config, ctx.model_factory(), allowed_roots=roots, audit=audit).compile(req)
        return res.to_dict()

    @app.post("/v1/changes", status_code=202)
    def run_change(body: dict = Body(...), p: Principal = Depends(need("operator"))) -> dict:
        import json  # noqa: PLC0415

        from cloudctl.controlplane.graph import GraphError, parse_graph  # noqa: PLC0415
        from cloudctl.controlplane.orchestrator import OrchestratorError  # noqa: PLC0415
        graph_doc = body.get("graph")
        if not isinstance(graph_doc, dict) or len(json.dumps(graph_doc)) > MAX_GRAPH_BYTES:
            raise HTTPException(400, "graph: a change graph object is required")
        try:
            graph = parse_graph(graph_doc)
            orch = ctx.orchestrator(p.subject)
            run = orch.prepare(graph)
        except (GraphError, OrchestratorError) as e:
            raise bad(e) from None
        ctx.submit(f"run {run.run_id}", lambda: orch.drive(run.run_id))
        return {"run_id": run.run_id, "status": run.status, "requester": p.subject}

    @app.get("/v1/changes")
    def list_changes(limit: int = 50, p: Principal = Depends(need("reader"))) -> list:
        return [r.to_dict() for r in ctx.runs.list()[: max(1, min(limit, 200))]]

    @app.get("/v1/changes/{run_id}")
    def get_change(run_id: str, p: Principal = Depends(need("reader"))) -> dict:
        from cloudctl.controlplane.state import StateError  # noqa: PLC0415
        try:
            return ctx.runs.load(run_id).to_dict()
        except StateError as e:
            raise bad(e, 404) from None

    @app.post("/v1/changes/{run_id}:resume", status_code=202)
    def resume_change(run_id: str, body: dict = Body(default={}), p: Principal = Depends(need("operator"))) -> dict:
        from cloudctl.controlplane.state import StateError  # noqa: PLC0415
        approvals = body.get("approvals") or {}
        if not isinstance(approvals, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                                      for k, v in approvals.items()):
            raise HTTPException(400, "approvals: an object of node id to approval request id")
        try:
            run = ctx.runs.load(run_id)
        except StateError as e:
            raise bad(e, 404) from None
        if run.requester != p.subject:
            raise HTTPException(403, "only the requester who started a run can resume it")
        orch = ctx.orchestrator(p.subject)
        ctx.submit(f"resume {run_id}", lambda: orch.resume(run_id, approvals))
        return {"run_id": run_id, "accepted": True}

    # ── approvals ───────────────────────────────────────────────────────────
    @app.get("/v1/approvals")
    def pending_approvals(p: Principal = Depends(need("reader"))) -> list:
        return [r.to_dict() for r in ctx.gate.approvals.pending()]

    @app.get("/v1/approvals/{request_id}")
    def get_approval_request(request_id: str, p: Principal = Depends(need("reader"))) -> dict:
        from cloudctl.gate.models import ApprovalError  # noqa: PLC0415
        try:
            return ctx.gate.approvals.get_request(request_id).to_dict()
        except ApprovalError as e:
            raise bad(e, 404) from None

    @app.post("/v1/approvals/{request_id}", status_code=201)
    def submit_approval(request_id: str, body: dict = Body(...), p: Principal = Depends(need("approver"))) -> dict:
        from cloudctl.gate.approval.authz import authorize_approval  # noqa: PLC0415
        from cloudctl.gate.approval.signing import SignedApproval, verify_signature  # noqa: PLC0415
        from cloudctl.gate.models import ApprovalError, ConfigError  # noqa: PLC0415
        sig, signed_at = body.get("signature"), body.get("signed_at")
        if not isinstance(sig, str) or not isinstance(signed_at, str):
            raise HTTPException(400, "signature and signed_at are required strings")
        try:
            req = ctx.gate.approvals.get_request(request_id)
        except ApprovalError as e:
            raise bad(e, 404) from None
        approver = p.approver
        if not approver:
            raise HTTPException(403, "your token carries no approver name")
        if body.get("approver") not in (None, approver):
            raise HTTPException(403, "you can only submit your own approval")
        if req.requester in (approver, p.subject):
            raise HTTPException(403, "a requester cannot approve their own change")
        key = ctx.gate.config.approvers.get(approver)
        if not key:
            raise HTTPException(403, f"{approver!r} is not a configured approver")
        cfg = ctx.gate.config
        try:
            env = cfg.environment(req.environment)
            if approver not in env.approval.approvers:
                raise ApprovalError(f"{approver!r} is not a named approver for {env.name!r}")
            # The same Cedar check the gate runs when the approval is spent, made early.
            authorize_approval(approver=approver,
                               approver_environments=[n for n, e in cfg.environments.items()
                                                      if approver in e.approval.approvers],
                               environment=env.name, tier=env.tier, requester=req.requester,
                               max_severity=req.max_severity, counts=req.counts, expired=req.expired())
        except (ApprovalError, ConfigError) as e:
            raise bad(e, 403) from None
        signed = SignedApproval(request=req, approver=approver, signature=sig, signed_at=signed_at)
        try:
            verify_signature(signed, key)
            ctx.gate.approvals.put_approval(signed)
        except ApprovalError as e:
            raise bad(e) from None
        ctx.gate.record("service.approval.submitted", {"request_id": request_id, "approver": approver})
        return {"request_id": request_id, "approver": approver}

    # ── drift ───────────────────────────────────────────────────────────────
    @app.get("/v1/drift")
    def list_drift(include_resolved: bool = False, p: Principal = Depends(need("reader"))) -> list:
        return [e.to_dict() for e in ctx.drift_store.list() if include_resolved or e.status != "resolved"]

    @app.get("/v1/drift/{event_id}")
    def get_drift(event_id: str, p: Principal = Depends(need("reader"))) -> dict:
        try:
            return ctx.drift_store.load(event_id).to_dict()
        except KeyError as e:
            raise bad(e, 404) from None

    @app.post("/v1/drift:scan", status_code=202)
    def scan_drift(body: dict = Body(default={}), p: Principal = Depends(need("operator"))) -> dict:
        envs = body.get("environments") or None
        if envs is not None and (not isinstance(envs, list) or not all(isinstance(e, str) for e in envs)):
            raise HTTPException(400, "environments: a list of names")
        for e in envs or []:
            if e not in ctx.gate.config.environments:
                raise HTTPException(400, f"unknown environment {e!r}")
        repair = bool(body.get("repair", True))
        ctx.gate.record("service.drift.scan", {"asked_by": p.subject, "environments": envs, "repair": repair})
        loop = ctx.drift_loop(requester="cctl-drift-loop")
        job = ctx.submit("drift scan", lambda: loop.pass_once(envs, repair=repair, rollbacks=ctx.rollbacks))
        return {"job": job, "accepted": True}

    @app.post("/v1/drift/{event_id}:repair", status_code=202)
    def repair_drift(event_id: str, body: dict = Body(default={}), p: Principal = Depends(need("operator"))) -> dict:
        override = body.get("override") or ""
        if not isinstance(override, str) or len(override) > 500:
            raise HTTPException(400, "override: a reason of at most 500 characters")
        try:
            ev = ctx.drift_store.load(event_id)
        except KeyError as e:
            raise bad(e, 404) from None
        if ev.decision.get("mode") == "report" and not override.strip():
            raise HTTPException(409, "this event is report-only; give an override reason to repair it anyway")
        loop = ctx.drift_loop(requester=p.subject)
        job = ctx.submit(f"repair {event_id}", lambda: loop.repair(event_id, requester=p.subject, override=override))
        return {"job": job, "accepted": True}

    # ── audit ───────────────────────────────────────────────────────────────
    @app.get("/v1/audit:verify")
    def verify_audit(p: Principal = Depends(need("auditor"))) -> dict:
        r = ctx.gate.audit.verify()
        return {"ok": r.ok, "records": getattr(r, "count", None), "errors": list(getattr(r, "errors", []))[:20]}

    return app


def _drift_daemon(ctx: ServiceContext, stop: threading.Event) -> None:
    """Scheduled drift passes. The drift store's lease means only one replica
    runs a pass at a time; the others skip that round."""
    while not stop.wait(ctx.drift_interval):
        try:
            ctx.drift_loop(requester="cctl-drift-loop").pass_once(repair=ctx.drift_repair, rollbacks=ctx.rollbacks)
        except RuntimeError as e:          # another replica holds the lease
            log.info("drift pass skipped: %s", e)
        except Exception:  # noqa: BLE001
            log.exception("drift pass failed")

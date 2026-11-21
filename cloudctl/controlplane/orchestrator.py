"""Orchestrator: carry out a change graph, node by node, through the gate.

* Nodes run in dependency order (deterministic, one at a time).
* Every node goes through all five gate stages on its own: its own scoped
  credentials, plan, policy, approval and single-use authorization.
* A node whose gate decision is "needs approval" waits; nodes downstream of
  it are blocked until the run is resumed with that approval. Independent
  branches carry on.
* A node the gate rejects changes nothing; everything downstream of it is
  skipped.
* A node that fails while applying is never retried. Everything downstream is
  skipped, and a targeted rollback request for that node (with what had
  already been applied before it) goes to the drift repair loop.
* Run state is saved before and after every step, so a crash leaves a record
  of which node was running.
"""
from __future__ import annotations

import json
import os
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Protocol

from cloudctl.controlplane import state as S
from cloudctl.controlplane.executors import ExecutionError, Executor, default_executor_factory
from cloudctl.controlplane.graph import ChangeGraph, GraphError, Node, parse_graph
from cloudctl.gate.models import AuditError, ChangeRequest, ConfigError, Outcome, utcnow_iso

ExecutorFactory = Callable[[Node, Any], Executor]


@dataclass(frozen=True)
class RollbackRequest:
    """Ask the drift repair loop to put one failed node back to its last good
    state. Targeted: it names one node, never the whole run."""

    run_id: str
    node_id: str
    environment: str
    kind: str
    target: Mapping[str, Any]
    gate_request_id: str
    plan_digest: str
    error: str
    applied_before: tuple[str, ...] = ()
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "run_id": self.run_id, "node_id": self.node_id, "environment": self.environment,
                "kind": self.kind, "target": dict(self.target), "gate_request_id": self.gate_request_id,
                "plan_digest": self.plan_digest, "error": self.error[:2000],
                "applied_before": list(self.applied_before), "created_at": self.created_at}


class RollbackRequester(Protocol):
    def request(self, req: RollbackRequest) -> str: ...


def default_rollbacks_dir() -> Path:
    return Path(os.environ.get("CLOUDCTL_ROLLBACKS_DIR") or Path.home() / ".cloudctl" / "rollbacks")


class QueuedRollback:
    """Writes each rollback request to a queue directory (0600 files) for the
    drift repair loop to pick up. It never changes anything itself."""

    def __init__(self, directory: Optional[Path | str] = None) -> None:
        self.dir = Path(directory).expanduser() if directory else default_rollbacks_dir()

    def request(self, req: RollbackRequest) -> str:
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".rb-", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(req.to_dict(), fh, indent=1, sort_keys=True)
            os.replace(tmp, self.dir / f"{req.id}.json")
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return req.id

    def pending(self) -> list[dict[str, Any]]:
        if not self.dir.is_dir():
            return []
        out = []
        for p in sorted(self.dir.glob("*.json")):
            try:
                out.append(json.loads(p.read_text(encoding="utf-8")))
            except ValueError:
                continue
        return out


class OrchestratorError(Exception):
    pass


class Orchestrator:
    def __init__(self, gate: Any, store: Any, *, rollback: Optional[RollbackRequester] = None,
                 executor_factory: Optional[ExecutorFactory] = None, requester: Optional[str] = None) -> None:
        from cloudctl.gate.gate import default_requester  # noqa: PLC0415
        self.gate = gate
        self.store = store
        self.rollback = rollback or QueuedRollback()
        self.executor_factory = executor_factory or default_executor_factory
        self.requester = requester or default_requester()

    # ── public ──────────────────────────────────────────────────────────────
    def start(self, graph: ChangeGraph) -> S.RunState:
        if graph.questions:
            raise OrchestratorError("the graph still has open questions; answer them and compile again")
        if not graph.nodes:
            raise OrchestratorError("the graph has no nodes")
        from cloudctl.controlplane.compiler import validate_targets  # noqa: PLC0415
        v = validate_targets(self.gate.config, graph, check_planner=False)
        if v.questions or v.errors:
            raise GraphError(v.errors + [q.question for q in v.questions])
        order = graph.order()
        run = S.RunState.new(graph.to_dict(), graph.digest(), self.requester, order)
        self.store.save(run)
        self.gate.record("orchestrator.run.start", {"run_id": run.run_id, "graph_digest": run.graph_digest,
                                                    "request": graph.request[:500], "order": order,
                                                    "requester": self.requester})
        with self.store.lock(run.run_id):
            return self._drive(run, graph, {})

    def resume(self, run_id: str, approvals: Optional[Mapping[str, str]] = None) -> S.RunState:
        approvals = dict(approvals or {})
        with self.store.lock(run_id):
            run = self.store.load(run_id)
            if run.requester != self.requester:
                raise OrchestratorError(f"run {run_id} belongs to {run.requester!r}; only that requester can "
                                        "resume it")
            graph = parse_graph(run.graph)
            if graph.digest() != run.graph_digest:
                raise OrchestratorError(f"run {run_id}: the stored graph does not match its digest")
            for nid in approvals:
                if nid not in run.nodes:
                    raise OrchestratorError(f"run {run_id} has no node {nid!r}")
                if run.nodes[nid].status != S.AWAITING_APPROVAL:
                    raise OrchestratorError(f"node {nid} is {run.nodes[nid].status}, not awaiting approval")
            stale = [n.id for n in run.nodes.values() if n.status == S.RUNNING]
            for nid in stale:
                # a crash mid-apply: the outcome is unknown, so it is a failure, never a re-run
                self._fail(run, graph, graph.node(nid), "the previous process stopped while this node was "
                           "running; its outcome is unknown")
            self.gate.record("orchestrator.run.resume", {"run_id": run_id, "approvals": sorted(approvals)})
            return self._drive(run, graph, approvals)

    # ── internals ───────────────────────────────────────────────────────────
    def _save_and_audit(self, run: S.RunState, ns: S.NodeState) -> None:
        self.store.save(run)
        self.gate.record("orchestrator.node", {"run_id": run.run_id, "node_id": ns.id, "status": ns.status,
                                               "request_id": ns.request_id, "stage": ns.stage,
                                               "reasons": ns.reasons[:10], "rollback_id": ns.rollback_id})

    def _drive(self, run: S.RunState, graph: ChangeGraph, approvals: Mapping[str, str]) -> S.RunState:
        for nid in graph.order():
            node = graph.node(nid)
            ns = run.nodes[nid]
            if ns.status in S.TERMINAL:
                continue
            if ns.status == S.AWAITING_APPROVAL and nid not in approvals:
                continue
            deps = [run.nodes[d] for d in node.depends_on]
            bad = [d.id for d in deps if d.status in (S.FAILED, S.REJECTED, S.SKIPPED)]
            if bad:
                ns.status, ns.stage, ns.reasons = S.SKIPPED, "dependency", [f"skipped: {', '.join(bad)} did not "
                                                                            "succeed"]
                ns.ended_at = utcnow_iso()
                self._save_and_audit(run, ns)
                continue
            waiting = [d.id for d in deps if d.status != S.SUCCEEDED]
            if waiting:
                if ns.status != S.BLOCKED:
                    ns.status, ns.stage, ns.reasons = S.BLOCKED, "dependency", [f"waiting for {', '.join(waiting)}"]
                    self._save_and_audit(run, ns)
                continue
            self._run_node(run, graph, node, approvals.get(nid))
        self.store.save(run)
        self.gate.record("orchestrator.run.status", {"run_id": run.run_id, "status": run.status,
                                                     "nodes": {k: v.status for k, v in run.nodes.items()}})
        return run

    def _run_node(self, run: S.RunState, graph: ChangeGraph, node: Node, approval_id: Optional[str]) -> None:
        ns = run.nodes[node.id]
        try:
            env = self.gate.config.environment(node.environment)
            executor = self.executor_factory(node, env)
        except (ConfigError, ExecutionError) as e:
            ns.status, ns.stage, ns.reasons, ns.ended_at = S.REJECTED, "config", [str(e)], utcnow_iso()
            self._save_and_audit(run, ns)
            return
        request = ChangeRequest(kind=node.kind, environment=node.environment, summary=node.summary[:500],
                                requester=self.requester,
                                context={"run_id": run.run_id, "node_id": node.id, "graph_digest": run.graph_digest})
        ns.status, ns.started_at, ns.request_id = S.RUNNING, ns.started_at or utcnow_iso(), request.request_id
        ns.evaluations += 1
        self._save_and_audit(run, ns)

        result = self.gate.evaluate(request, executor.planner, approval_id=approval_id)
        d = result.decision
        ns.stage, ns.reasons = d.stage, list(d.reasons)
        ns.plan_digest, ns.plan_counts = d.plan_digest, dict(d.plan_counts)
        if d.outcome == Outcome.PENDING_APPROVAL:
            ns.status, ns.approval_id = S.AWAITING_APPROVAL, d.request_id
            self._save_and_audit(run, ns)
            return
        if not result.authorized:
            ns.status, ns.ended_at = S.REJECTED, utcnow_iso()
            self._save_and_audit(run, ns)
            return
        try:
            with result.authorization as auth:
                out = auth.execute(lambda creds, plan: executor.apply(creds, plan, env),
                                   what=f"{run.run_id}:{node.id}")
        except AuditError:
            raise
        except Exception as e:  # noqa: BLE001 — any failure ends this node, without a retry
            self._fail(run, graph, node, f"{type(e).__name__}: {e}")
            return
        ns.status, ns.result, ns.ended_at = S.SUCCEEDED, _plain(out), utcnow_iso()
        self._save_and_audit(run, ns)

    def _fail(self, run: S.RunState, graph: ChangeGraph, node: Node, error: str) -> None:
        ns = run.nodes[node.id]
        ns.status, ns.error, ns.ended_at = S.FAILED, error[:2000], utcnow_iso()
        ns.stage = ns.stage or "execution"
        target = {"iac_root": node.iac_root} if node.kind == "iac_apply" else {"issue": dict(node.issue)}
        applied = tuple(k for k, v in run.nodes.items() if v.status == S.SUCCEEDED)
        req = RollbackRequest(run_id=run.run_id, node_id=node.id, environment=node.environment, kind=node.kind,
                              target=target, gate_request_id=ns.request_id, plan_digest=ns.plan_digest,
                              error=ns.error, applied_before=applied)
        self.store.save(run)
        try:
            ns.rollback_id = self.rollback.request(req)
        except Exception as e:  # noqa: BLE001 — record it; the run is failed either way
            ns.reasons = ns.reasons + [f"rollback request could not be queued: {e}"]
        self.gate.record("orchestrator.rollback.requested", {**req.to_dict(), "queued": bool(ns.rollback_id)})
        self._save_and_audit(run, ns)


def _plain(v: Any) -> Any:
    try:
        return json.loads(json.dumps(v, default=str))
    except (TypeError, ValueError):
        return str(v)[:500]

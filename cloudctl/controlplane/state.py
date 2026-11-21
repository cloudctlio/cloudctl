"""Run state for the orchestrator.

A run is one change graph being carried out. Its state records, per node,
what the gate decided and what happened when it was applied, so that a run
waiting on approvals can be resumed later, by the same requester, without
re-doing (or blindly retrying) anything.

:class:`LocalRunStore` keeps each run as one JSON file (mode 0600) written
atomically, with a lock file so two processes cannot drive the same run at
once. Stage 4 adds a DynamoDB store with the same interface.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional, Protocol

from cloudctl.gate.models import utcnow_iso

PENDING = "pending"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
REJECTED = "rejected"
AWAITING_APPROVAL = "awaiting_approval"
SKIPPED = "skipped"
BLOCKED = "blocked"

NODE_STATES = (PENDING, RUNNING, SUCCEEDED, FAILED, REJECTED, AWAITING_APPROVAL, SKIPPED, BLOCKED)
#: States a node never leaves. A failed or rejected node is not retried.
TERMINAL = frozenset({SUCCEEDED, FAILED, REJECTED, SKIPPED})

RUN_ID = re.compile(r"^[0-9a-f]{32}$")


class StateError(Exception):
    pass


@dataclass
class NodeState:
    id: str
    status: str = PENDING
    request_id: str = ""
    approval_id: str = ""
    stage: str = ""
    reasons: list[str] = field(default_factory=list)
    plan_digest: str = ""
    plan_counts: dict[str, int] = field(default_factory=dict)
    result: Any = None
    error: str = ""
    rollback_id: str = ""
    started_at: str = ""
    ended_at: str = ""
    evaluations: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "NodeState":
        known = {k: d[k] for k in cls.__dataclass_fields__ if k in d}
        ns = cls(**known)
        if ns.status not in NODE_STATES:
            raise StateError(f"node {ns.id}: unknown status {ns.status!r}")
        return ns


@dataclass
class RunState:
    run_id: str
    graph: dict[str, Any]
    graph_digest: str
    requester: str
    nodes: dict[str, NodeState]
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)

    @classmethod
    def new(cls, graph: Mapping[str, Any], graph_digest: str, requester: str,
            order: list[str]) -> "RunState":
        return cls(run_id=uuid.uuid4().hex, graph=dict(graph), graph_digest=graph_digest, requester=requester,
                   nodes={nid: NodeState(id=nid) for nid in order})

    @property
    def status(self) -> str:
        """succeeded | running | awaiting_approval | failed | partial."""
        sts = [n.status for n in self.nodes.values()]
        if any(s == RUNNING for s in sts):
            return RUNNING
        if all(s == SUCCEEDED for s in sts):
            return SUCCEEDED
        if any(s == AWAITING_APPROVAL for s in sts):
            return AWAITING_APPROVAL
        if any(s in (FAILED, REJECTED) for s in sts):
            return FAILED
        if any(s == PENDING for s in sts):
            return RUNNING
        return "partial"

    def to_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "status": self.status, "graph": self.graph,
                "graph_digest": self.graph_digest, "requester": self.requester,
                "created_at": self.created_at, "updated_at": self.updated_at,
                "nodes": {k: v.to_dict() for k, v in self.nodes.items()}}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "RunState":
        try:
            nodes = {k: NodeState.from_dict(v) for k, v in d["nodes"].items()}
            rs = cls(run_id=d["run_id"], graph=d["graph"], graph_digest=d["graph_digest"],
                     requester=d["requester"], nodes=nodes, created_at=d.get("created_at", ""),
                     updated_at=d.get("updated_at", ""))
        except (KeyError, TypeError, AttributeError) as e:
            raise StateError(f"malformed run state: {e}") from e
        if not RUN_ID.match(rs.run_id):
            raise StateError(f"malformed run id {rs.run_id!r}")
        return rs


class RunStore(Protocol):
    def save(self, state: RunState) -> None: ...
    def load(self, run_id: str) -> RunState: ...
    def list(self) -> list[RunState]: ...
    def lock(self, run_id: str) -> Any: ...


def default_runs_dir() -> Path:
    return Path(os.environ.get("CLOUDCTL_RUNS_DIR") or Path.home() / ".cloudctl" / "runs")


class LocalRunStore:
    def __init__(self, directory: Optional[Path | str] = None) -> None:
        self.dir = Path(directory).expanduser() if directory else default_runs_dir()

    def _ensure(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    def _path(self, run_id: str) -> Path:
        if not RUN_ID.match(run_id or ""):
            raise StateError(f"not a run id: {run_id!r}")
        return self.dir / f"{run_id}.json"

    def save(self, state: RunState) -> None:
        self._ensure()
        state.updated_at = utcnow_iso()
        target = self._path(state.run_id)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".run-", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(state.to_dict(), fh, indent=1, sort_keys=True, default=str)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, target)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def load(self, run_id: str) -> RunState:
        p = self._path(run_id)
        if not p.is_file():
            raise StateError(f"no run {run_id}")
        try:
            return RunState.from_dict(json.loads(p.read_text(encoding="utf-8")))
        except ValueError as e:
            raise StateError(f"run {run_id} is not valid JSON: {e}") from e

    def list(self) -> list[RunState]:
        if not self.dir.is_dir():
            return []
        out = []
        for p in sorted(self.dir.glob("*.json")):
            try:
                out.append(self.load(p.stem))
            except StateError:
                continue
        return sorted(out, key=lambda r: r.created_at, reverse=True)

    @contextmanager
    def lock(self, run_id: str) -> Iterator[None]:
        """Exclusive lock on a run. Fails at once if another process holds it."""
        self._ensure()
        lp = self._path(run_id).with_suffix(".lock")
        try:
            fd = os.open(lp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise StateError(f"run {run_id} is locked by another process ({lp}); if none is running, "
                             "delete that file") from None
        try:
            os.write(fd, f"{os.getpid()} {utcnow_iso()}\n".encode())
            os.close(fd)
            yield
        finally:
            try:
                os.unlink(lp)
            except OSError:
                pass

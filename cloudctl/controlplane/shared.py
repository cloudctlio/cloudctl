"""The control plane's stores on the shared key-value contract (:mod:`.kv`),
so several service replicas on any cloud can share runs, drift events,
approvals and the rollback queue. Each mirrors the local store it replaces,
method for method; writes that must happen once are create-only."""
from __future__ import annotations

import uuid
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from cloudctl.controlplane import state as S
from cloudctl.controlplane.kv import ABSENT, Conflict, KVStore, Lease
from cloudctl.gate.models import ApprovalError, utcnow_iso


def _owner() -> str:
    return uuid.uuid4().hex


class KvRunStore:
    def __init__(self, kv: KVStore, *, lock_ttl: int = 900) -> None:
        self.kv = kv
        self.lock_ttl = lock_ttl

    def _id(self, run_id: str) -> str:
        if not S.RUN_ID.match(run_id or ""):
            raise S.StateError(f"not a run id: {run_id!r}")
        return run_id

    def save(self, state: S.RunState) -> None:
        state.updated_at = utcnow_iso()
        self.kv.put("runs", self._id(state.run_id), state.to_dict())

    def load(self, run_id: str) -> S.RunState:
        it = self.kv.get("runs", self._id(run_id))
        if it is None:
            raise S.StateError(f"no run {run_id}")
        try:
            return S.RunState.from_dict(it.doc)
        except (KeyError, TypeError, ValueError) as e:
            raise S.StateError(f"run {run_id} is malformed: {e}") from e

    def list(self) -> list[S.RunState]:
        out = []
        for it in self.kv.scan("runs"):
            try:
                out.append(S.RunState.from_dict(it.doc))
            except (KeyError, TypeError, ValueError):
                continue
        return sorted(out, key=lambda r: r.created_at, reverse=True)

    @contextmanager
    def lock(self, run_id: str) -> Iterator[Lease]:
        try:
            with Lease(self.kv, f"run-{self._id(run_id)}", _owner(), self.lock_ttl) as lease:
                yield lease
        except Conflict:
            raise S.StateError(f"run {run_id} is being driven by another worker") from None


class KvDriftStore:
    def __init__(self, kv: KVStore, *, lock_ttl: int = 1800) -> None:
        self.kv = kv
        self.lock_ttl = lock_ttl

    def save(self, ev: Any) -> None:
        self.kv.put("drift", ev.id, ev.to_dict())

    def load(self, event_id: str) -> Any:
        from cloudctl.controlplane.drift import _EVENT_ID, DriftEvent  # noqa: PLC0415
        if not _EVENT_ID.match(event_id or ""):
            raise KeyError(f"not a drift event id: {event_id!r}")
        it = self.kv.get("drift", event_id)
        if it is None:
            raise KeyError(f"no drift event {event_id}")
        return DriftEvent.from_dict(it.doc)

    def list(self) -> list[Any]:
        from cloudctl.controlplane.drift import DriftEvent  # noqa: PLC0415
        out = []
        for it in self.kv.scan("drift"):
            try:
                out.append(DriftEvent.from_dict(it.doc))
            except (TypeError, ValueError):
                continue
        return sorted(out, key=lambda e: e.last_seen, reverse=True)

    def live_for(self, environment: str, root: str) -> Optional[Any]:
        from cloudctl.controlplane.drift import _LIVE  # noqa: PLC0415
        for ev in self.list():
            if ev.environment == environment and ev.root == root and ev.status in _LIVE:
                return ev
        return None

    @contextmanager
    def lock(self) -> Iterator[Lease]:
        try:
            with Lease(self.kv, "drift-loop", _owner(), self.lock_ttl) as lease:
                yield lease
        except Conflict:
            raise RuntimeError("another drift pass is running on another worker") from None


class KvRollbackQueue:
    def __init__(self, kv: KVStore) -> None:
        self.kv = kv

    def request(self, req: Any) -> str:
        self.kv.put("rollbacks", req.id, {**req.to_dict(), "done": False}, expect=ABSENT)
        return req.id

    def pending(self) -> list[dict[str, Any]]:
        out = [{k: v for k, v in it.doc.items() if k != "done"} for it in self.kv.scan("rollbacks")
               if not it.doc.get("done")]
        return sorted(out, key=lambda d: d.get("created_at", ""))

    def done(self, request_id: str) -> None:
        it = self.kv.get("rollbacks", request_id)
        if it is None:
            raise ValueError(f"no rollback request {request_id!r}")
        self.kv.put("rollbacks", request_id, {**it.doc, "done": True, "done_at": utcnow_iso()}, expect=it.version)


class KvApprovalStore:
    """Requests, signed approvals and "consumed" markers are each create-only,
    exactly as in the local store: an approval can be used once."""

    def __init__(self, kv: KVStore) -> None:
        self.kv = kv

    def _key(self, request_id: str, kind: str) -> str:
        from cloudctl.gate.approval.store import _check_id  # noqa: PLC0415
        return f"{_check_id(request_id)}.{kind}"

    def _create(self, key: str, doc: dict) -> None:
        try:
            self.kv.put("approvals", key, doc, expect=ABSENT)
        except Conflict:
            raise ApprovalError(f"{key} already exists (approvals are write-once)") from None

    def put_request(self, req: Any) -> str:
        key = self._key(req.request_id, "request")
        self._create(key, req.to_dict())
        return f"{self.kv.name}:approvals/{key}"

    def get_request(self, request_id: str) -> Any:
        from cloudctl.gate.approval.signing import ApprovalRequest  # noqa: PLC0415
        it = self.kv.get("approvals", self._key(request_id, "request"))
        if it is None:
            raise ApprovalError(f"no approval request {request_id}")
        return ApprovalRequest.from_dict(it.doc)

    def put_approval(self, approval: Any) -> None:
        self.get_request(approval.request.request_id)
        self._create(self._key(approval.request.request_id, "approval"), approval.to_dict())

    def get_approval(self, request_id: str) -> Optional[Any]:
        from cloudctl.gate.approval.signing import SignedApproval  # noqa: PLC0415
        it = self.kv.get("approvals", self._key(request_id, "approval"))
        return SignedApproval.from_dict(it.doc) if it else None

    def consume(self, request_id: str, plan_digest: str) -> None:
        try:
            self._create(self._key(request_id, "consumed"), {"plan_digest": plan_digest, "at": utcnow_iso()})
        except ApprovalError:
            raise ApprovalError(f"approval {request_id} was already used") from None

    def is_consumed(self, request_id: str) -> bool:
        return self.kv.get("approvals", self._key(request_id, "consumed")) is not None

    def pending(self) -> Iterator[Any]:
        from cloudctl.gate.approval.signing import ApprovalRequest  # noqa: PLC0415
        items = {it.key: it for it in self.kv.scan("approvals")}
        for key, it in sorted(items.items()):
            if not key.endswith(".request"):
                continue
            rid = key[: -len(".request")]
            if f"{rid}.approval" in items or f"{rid}.consumed" in items:
                continue
            try:
                yield ApprovalRequest.from_dict(it.doc)
            except (KeyError, TypeError, ValueError):
                continue

"""Where approval requests, signed approvals and their single use live.

The local store is a private directory (0700, files 0600). Every write is
create-only, so a request, its approval and its "consumed" marker can each be
written exactly once; a second use of an approval fails. A shared store for
the control-plane service (DynamoDB conditional writes) follows the same
interface.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterator, Optional, Protocol

from cloudctl.gate.approval.signing import ApprovalRequest, SignedApproval
from cloudctl.gate.models import ApprovalError, utcnow_iso

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{7,63}$")


class ApprovalStore(Protocol):
    def put_request(self, req: ApprovalRequest) -> str: ...
    def get_request(self, request_id: str) -> ApprovalRequest: ...
    def put_approval(self, approval: SignedApproval) -> None: ...
    def get_approval(self, request_id: str) -> Optional[SignedApproval]: ...
    def consume(self, request_id: str, plan_digest: str) -> None: ...
    def is_consumed(self, request_id: str) -> bool: ...
    def pending(self) -> Iterator[ApprovalRequest]: ...


def _check_id(request_id: str) -> str:
    if not _ID.match(request_id or ""):
        raise ApprovalError(f"invalid approval request id {request_id!r}")
    return request_id


class LocalApprovalStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root).expanduser()

    def _dir(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        return self.root

    def _path(self, request_id: str, kind: str) -> Path:
        return self._dir() / f"{_check_id(request_id)}.{kind}.json"

    def _create(self, path: Path, doc: dict) -> None:
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise ApprovalError(f"{path.name} already exists (approvals are write-once)") from None
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, sort_keys=True, indent=2)
            fh.flush()
            os.fsync(fh.fileno())

    def _read(self, path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise
        except (OSError, ValueError) as e:
            raise ApprovalError(f"cannot read {path}: {e}") from e

    def put_request(self, req: ApprovalRequest) -> str:
        p = self._path(req.request_id, "request")
        self._create(p, req.to_dict())
        return str(p)

    def get_request(self, request_id: str) -> ApprovalRequest:
        try:
            return ApprovalRequest.from_dict(self._read(self._path(request_id, "request")))
        except FileNotFoundError:
            raise ApprovalError(f"no approval request {request_id}") from None

    def put_approval(self, approval: SignedApproval) -> None:
        self.get_request(approval.request.request_id)  # must exist
        self._create(self._path(approval.request.request_id, "approval"), approval.to_dict())

    def get_approval(self, request_id: str) -> Optional[SignedApproval]:
        try:
            return SignedApproval.from_dict(self._read(self._path(request_id, "approval")))
        except FileNotFoundError:
            return None

    def consume(self, request_id: str, plan_digest: str) -> None:
        try:
            self._create(self._path(request_id, "consumed"), {"plan_digest": plan_digest, "at": utcnow_iso()})
        except ApprovalError:
            raise ApprovalError(f"approval {request_id} was already used") from None

    def is_consumed(self, request_id: str) -> bool:
        return self._path(request_id, "consumed").exists()

    def pending(self) -> Iterator[ApprovalRequest]:
        if not self.root.is_dir():
            return
        for p in sorted(self.root.glob("*.request.json")):
            rid = p.name[: -len(".request.json")]
            if (self.root / f"{rid}.approval.json").exists() or (self.root / f"{rid}.consumed.json").exists():
                continue
            try:
                yield self.get_request(rid)
            except ApprovalError:
                continue

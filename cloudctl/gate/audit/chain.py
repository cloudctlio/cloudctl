"""Hash-chained audit records.

Each record carries the SHA-256 of the previous record, so deleting, editing
or reordering any record breaks every hash after it. The chain is the same no
matter where it is stored (local file, S3 Object Lock, Azure immutable Blob,
GCS bucket lock); only the sink differs.

Record layout (``v`` 1)::

    {"v": 1, "chain": "<chain id>", "seq": 7, "ts": "...Z",
     "event": "gate.decision", "actor": "arn:aws:sts::...",
     "data": {...}, "prev": "<64 hex>", "hash": "<64 hex>"}

``hash`` = SHA-256 over the canonical JSON of every other field.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Protocol

from cloudctl.gate.canonical import canonical_json, sha256_hex
from cloudctl.gate.models import AuditError, utcnow_iso

GENESIS = "0" * 64
RECORD_VERSION = 1

_SECRET_KEY_RE = re.compile(
    r"(secret|password|passwd|token|credential|private[_-]?key|session[_-]?key|"
    r"accesskey|access_key|authorization|assertion|signature_key|api[_-]?key)",
    re.IGNORECASE,
)
_SECRET_VALUE_RES = (
    re.compile(r"\bA(?:KIA|SIA)[A-Z0-9]{16}\b"),                     # AWS access key ids
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWTs
    re.compile(r"\bya29\.[A-Za-z0-9_\-]{20,}"),                        # Google OAuth tokens
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
_MAX_STRING = 4000


def redact(value: Any, _depth: int = 0) -> Any:
    """Return *value* with anything that looks like a secret removed.

    Keys whose name suggests a secret are replaced wholesale; string values
    are scanned for credential patterns. Long strings are truncated so a
    record can never smuggle a whole fetched payload.
    """
    if _depth > 20:
        return "[REDACTED:depth]"
    if isinstance(value, Mapping):
        out = {}
        for k, v in value.items():
            key = str(k)
            if _SECRET_KEY_RE.search(key) and not key.endswith(("_hash", "_digest", "_id_hash")):
                out[key] = "[REDACTED]"
            else:
                out[key] = redact(v, _depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth + 1) for v in value]
    if isinstance(value, str):
        s = value
        for rx in _SECRET_VALUE_RES:
            s = rx.sub("[REDACTED]", s)
        if len(s) > _MAX_STRING:
            s = s[:_MAX_STRING] + f"...[truncated {len(s) - _MAX_STRING}]"
        return s
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact(str(value), _depth + 1)


def record_hash(record: Mapping[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return sha256_hex(canonical_json(body))


def build_record(*, chain: str, seq: int, prev: str, event: str, actor: str,
                 data: Mapping[str, Any], ts: Optional[str] = None) -> dict[str, Any]:
    if seq < 0:
        raise ValueError("seq must be >= 0")
    if not re.fullmatch(r"[0-9a-f]{64}", prev):
        raise ValueError("prev must be a 64-char hex digest")
    record: dict[str, Any] = {
        "v": RECORD_VERSION,
        "chain": chain,
        "seq": seq,
        "ts": ts or utcnow_iso(),
        "event": event,
        "actor": actor,
        "data": redact(dict(data)),
        "prev": prev,
    }
    record["hash"] = record_hash(record)
    return record


@dataclass(frozen=True)
class ChainHead:
    seq: int          # seq of the last record; -1 for an empty chain
    hash: str         # hash of the last record; GENESIS for an empty chain

    @property
    def next_seq(self) -> int:
        return self.seq + 1


EMPTY_HEAD = ChainHead(seq=-1, hash=GENESIS)


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    head: ChainHead
    errors: tuple[str, ...] = ()


def verify_records(records: Iterable[Mapping[str, Any]], *, chain: Optional[str] = None,
                   start: ChainHead = EMPTY_HEAD) -> VerifyResult:
    """Verify a sequence of records forms one unbroken chain."""
    head = start
    errors: list[str] = []
    n = 0
    for rec in records:
        n += 1
        where = f"record #{n} (seq {rec.get('seq')!r})"
        if rec.get("v") != RECORD_VERSION:
            errors.append(f"{where}: unsupported record version {rec.get('v')!r}")
        if chain is not None and rec.get("chain") != chain:
            errors.append(f"{where}: belongs to chain {rec.get('chain')!r}, expected {chain!r}")
        if rec.get("seq") != head.next_seq:
            errors.append(f"{where}: expected seq {head.next_seq}")
        if rec.get("prev") != head.hash:
            errors.append(f"{where}: prev hash does not match the previous record")
        try:
            actual = record_hash(rec)
        except (TypeError, ValueError) as e:
            errors.append(f"{where}: cannot hash record ({e})")
            actual = ""
        if rec.get("hash") != actual:
            errors.append(f"{where}: hash mismatch (record was altered)")
        head = ChainHead(seq=int(rec.get("seq", head.next_seq)), hash=str(rec.get("hash", "")))
        if len(errors) > 50:
            errors.append("too many errors; stopped")
            break
    return VerifyResult(ok=not errors, records=n, head=head, errors=tuple(errors))


class AuditSink(Protocol):
    """Durable, append-only storage for one chain."""

    name: str
    #: True when the store itself prevents deletion/overwrite (WORM).
    immutable: bool

    def head(self) -> ChainHead: ...

    def append(self, record: Mapping[str, Any]) -> bool:
        """Store *record* if and only if no record with its seq exists.
        Returns False on a seq conflict (another writer got there first)."""
        ...

    def read_all(self) -> Iterable[Mapping[str, Any]]: ...

    def check_ready(self) -> None:
        """Raise AuditError if the sink cannot guarantee durable writes."""
        ...


class AuditLog:
    """Appends events to a hash chain in one or more sinks.

    The first sink is the system of record; the gate refuses to act if a
    write to it fails. With ``mirror`` sinks (e.g. a local copy beside S3),
    a mirror failure is reported but does not block.
    """

    MAX_CONFLICT_RETRIES = 8

    def __init__(self, sink: AuditSink, *, chain: str, actor: str = "",
                 mirrors: Iterable[AuditSink] = ()) -> None:
        if not chain or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", chain):
            raise ValueError("chain id must be 1-128 chars of [A-Za-z0-9._-]")
        self.sink = sink
        self.chain = chain
        self.actor = actor
        self.mirrors = tuple(mirrors)
        self.mirror_errors: list[str] = []

    @property
    def immutable(self) -> bool:
        return bool(getattr(self.sink, "immutable", False))

    def check_ready(self) -> None:
        self.sink.check_ready()

    def append(self, event: str, data: Mapping[str, Any], *, actor: Optional[str] = None) -> dict[str, Any]:
        """Append one event. Raises :class:`AuditError` if it cannot be stored."""
        if not re.fullmatch(r"[a-z][a-z0-9_.]{1,63}", event):
            raise ValueError(f"invalid audit event name {event!r}")
        last_err: Optional[Exception] = None
        for _ in range(self.MAX_CONFLICT_RETRIES):
            try:
                head = self.sink.head()
                record = build_record(chain=self.chain, seq=head.next_seq, prev=head.hash,
                                      event=event, actor=actor or self.actor, data=data)
                if self.sink.append(record):
                    for m in self.mirrors:
                        try:
                            m.append(record)
                        except Exception as e:  # noqa: BLE001 — mirrors never block
                            self.mirror_errors.append(f"{m.name}: {e}")
                    return record
            except AuditError:
                raise
            except Exception as e:  # noqa: BLE001
                last_err = e
                break
        raise AuditError(
            f"audit write to {self.sink.name} failed"
            + (f": {last_err}" if last_err else " after repeated sequence conflicts")
        )

    def verify(self) -> VerifyResult:
        return verify_records(self.sink.read_all(), chain=self.chain)

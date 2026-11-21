"""Local hash-chained audit file (the fallback when no immutable store is set).

JSONL, one record per line, fsync'd on every append. When the file grows past
``max_bytes`` it is renamed to ``<name>.<n>`` and a new segment starts; the
chain continues across segments, so nothing is ever truncated (the old
``~/.cloudctl/audit.log`` cut its oldest entries, which a chain cannot allow).

A local file is tamper-*evident*, not tamper-*proof*: anyone with write access
can rewrite it and recompute the hashes. Production environments therefore
require an immutable remote sink; see :mod:`cloudctl.gate.audit.objectstore`.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Iterable, Iterator, Mapping

from cloudctl.gate.audit.chain import EMPTY_HEAD, ChainHead
from cloudctl.gate.models import AuditError

_DIR_MODE = 0o700
_FILE_MODE = 0o600
_LOCK_STALE_SECONDS = 30.0


class LocalFileSink:
    immutable = False

    def __init__(self, path: Path | str, *, max_bytes: int = 10 * 1024 * 1024,
                 lock_timeout: float = 10.0) -> None:
        self.path = Path(path).expanduser()
        self.max_bytes = max_bytes
        self.lock_timeout = lock_timeout
        self.name = f"file:{self.path}"

    # ── locking (portable: O_EXCL lock file, works on Windows and POSIX) ──
    def _lock_path(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    def _acquire(self) -> None:
        lock = self._lock_path()
        deadline = time.monotonic() + self.lock_timeout
        while True:
            try:
                fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, _FILE_MODE)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return
            except FileExistsError:
                try:
                    if time.time() - lock.stat().st_mtime > _LOCK_STALE_SECONDS:
                        lock.unlink(missing_ok=True)
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise AuditError(f"timed out waiting for audit lock {lock}") from None
                time.sleep(0.02)

    def _release(self) -> None:
        try:
            self._lock_path().unlink(missing_ok=True)
        except OSError:
            pass

    # ── segments ──
    def segments(self) -> list[Path]:
        """All segment files, oldest first; the live file is last."""
        if not self.path.parent.exists():
            return []
        rx = re.compile(re.escape(self.path.name) + r"\.(\d+)$")
        rotated = []
        for p in self.path.parent.iterdir():
            m = rx.fullmatch(p.name)
            if m:
                rotated.append((int(m.group(1)), p))
        out = [p for _, p in sorted(rotated)]
        if self.path.exists():
            out.append(self.path)
        return out

    def check_ready(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self.path.parent.chmod(_DIR_MODE)
            except OSError:
                pass
            probe = self.path.parent / f".probe-{os.getpid()}"
            probe.write_bytes(b"")
            probe.unlink()
        except OSError as e:
            raise AuditError(f"audit directory {self.path.parent} is not writable: {e}") from e

    @staticmethod
    def _last_line(path: Path) -> bytes:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            if end == 0:
                return b""
            block = 4096
            pos = end
            buf = b""
            while pos > 0:
                step = min(block, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
                stripped = buf.rstrip(b"\n")
                if b"\n" in stripped:
                    return stripped.rsplit(b"\n", 1)[1]
            return buf.rstrip(b"\n")

    def head(self) -> ChainHead:
        for seg in reversed(self.segments()):
            line = self._last_line(seg)
            if not line:
                continue
            try:
                rec = json.loads(line)
                return ChainHead(seq=int(rec["seq"]), hash=str(rec["hash"]))
            except (ValueError, KeyError, TypeError) as e:
                raise AuditError(f"last record of {seg} is unreadable ({e}); "
                                 "run `cloudctl gate audit verify`") from e
        return EMPTY_HEAD

    def _rotate_if_needed(self) -> None:
        if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
            n = 1 + max((int(p.name.rsplit(".", 1)[1]) for p in self.segments()[:-1]), default=0)
            os.replace(self.path, self.path.with_name(f"{self.path.name}.{n}"))

    def append(self, record: Mapping) -> bool:
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n"
        self.check_ready()
        self._acquire()
        try:
            head = self.head()
            if record["seq"] != head.next_seq or record["prev"] != head.hash:
                return False
            self._rotate_if_needed()
            fd = os.open(str(self.path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, _FILE_MODE)
            try:
                os.write(fd, line.encode("ascii"))
                os.fsync(fd)
            finally:
                os.close(fd)
            return True
        finally:
            self._release()

    def read_all(self) -> Iterator[Mapping]:
        for seg in self.segments():
            with seg.open("r", encoding="ascii") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except ValueError:
                        yield {"_unparseable": f"{seg.name}:{i}"}


def iter_records(paths: Iterable[Path]) -> Iterator[Mapping]:
    for p in paths:
        with Path(p).open("r", encoding="ascii") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

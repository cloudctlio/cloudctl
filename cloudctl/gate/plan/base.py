"""Plan stage plumbing shared by every planner."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Protocol, Sequence

from cloudctl.gate.models import Plan, PlanError

#: Hard ceiling on any single plan-tool invocation.
DEFAULT_TIMEOUT = 600


class Planner(Protocol):
    platform: str

    def plan(self, *, env: Any, creds: Any, workdir: Path) -> Plan:
        """Produce a normalised plan using *creds* only. ``workdir`` is a
        private (0700) temporary directory for plan artifacts."""
        ...


@dataclass(frozen=True)
class ToolResult:
    returncode: int
    stdout: str
    stderr: str


def find_binary(name: str, explicit: Optional[str] = None) -> str:
    path = explicit or shutil.which(name)
    if not path:
        raise PlanError(f"`{name}` is not installed or not on PATH; the plan stage cannot run")
    return path


def run_tool(argv: Sequence[str], *, cwd: Path | str, env: Mapping[str, str],
             timeout: int = DEFAULT_TIMEOUT, ok_codes: Sequence[int] = (0,),
             what: str = "") -> ToolResult:
    """Run a plan tool without a shell, with only the scoped environment."""
    try:
        p = subprocess.run(  # noqa: S603 — argv list, no shell
            list(argv), cwd=str(cwd), env=dict(env), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False,
        )
    except FileNotFoundError as e:
        raise PlanError(f"{what or argv[0]}: binary not found ({e})") from e
    except subprocess.TimeoutExpired as e:
        raise PlanError(f"{what or argv[0]} timed out after {timeout}s") from e
    if p.returncode not in ok_codes:
        tail = (p.stderr or p.stdout or "").strip()[-2000:]
        raise PlanError(f"{what or ' '.join(argv[:3])} exited {p.returncode}: {tail}")
    return ToolResult(p.returncode, p.stdout, p.stderr)


def private_workdir(prefix: str = "cctl-plan-") -> Path:
    d = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def tool_version_matches(found: str, pinned: Optional[str]) -> bool:
    """True when *pinned* is unset or appears as a whole version in *found*."""
    if not pinned:
        return True
    import re  # noqa: PLC0415
    v = pinned.lstrip("v")
    return re.search(rf"(?<![\d.])v?{re.escape(v)}(?![\d.])", found) is not None

"""Record what the diff-first checks read from AWS, in the shape RecordedLive
replays. Set CLOUDCTL_DIFF_FIRST_RECORD=<file.json> on a live run; replay it
later with CLOUDCTL_DIFF_FIRST_REPLAY=<file.json> (no AWS needed)."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from cloudctl.debug.diff_first.model import Resource, iso


log = logging.getLogger("cloudctl.diff_first")


def normalize_path(path: str) -> Path:
    """Make a record path usable here. On Windows, a Git Bash / MSYS path
    (``/c/Users/me/x.json``) becomes ``C:/Users/me/x.json``; ``~`` and
    environment variables are expanded; the result is absolute."""
    p = os.path.expandvars(os.path.expanduser(str(path).strip().strip('"')))
    if os.name == "nt":
        p = msys_to_windows(p)
    return Path(p).resolve()


def msys_to_windows(p: str) -> str:
    """``/c/Users/me`` (Git Bash), ``/cygdrive/c/...`` or ``/mnt/c/...`` ->
    ``C:/Users/me``. Anything else is returned unchanged."""
    m = re.match(r"^/(?:cygdrive/|mnt/)?([a-zA-Z])(/.*)?$", p)
    return f"{m.group(1).upper()}:{m.group(2) or '/'}" if m else p


class RecordingLive:
    def __init__(self, inner: Any, path: str):
        self.inner, self.path = inner, path
        self.data: dict = {"now": iso(inner.now()), "configs": {}, "discovered": [], "events": [],
                           "metrics": {}, "stacks": {}, "config_history": {}}

    def now(self) -> datetime:
        return self.inner.now()

    @property
    def notes(self) -> list[str]:
        return list(getattr(self.inner, "notes", None) or [])

    def read(self, resource: Resource):
        cfg = self.inner.read(resource)
        if cfg is not None:
            self.data["configs"][resource.key] = cfg
        return cfg

    def discover(self):
        out = self.inner.discover()
        self.data["discovered"] = [{"key": r.key, "type": r.type, "name": r.name,
                                    "physical_id": r.physical_id, "arn": r.arn,
                                    "config": r.config} for r in out]
        return out

    def write_events(self, start, end):
        rows = self.inner.write_events(start, end)
        self.data["events"] = rows
        return rows

    def metrics(self, queries, start, end, period):
        got = self.inner.metrics(queries, start, end, period)
        for q in queries:
            if q["id"] in got:
                self.data["metrics"][q["key"]] = [[t, v] for t, v in got[q["id"]]]
        return got

    def stack_resources(self, stack):
        rows = self.inner.stack_resources(stack)
        self.data["stacks"].setdefault(stack, {})["resources"] = rows
        return rows

    def stack_drifts(self, stack, detect=False):
        rows = self.inner.stack_drifts(stack, detect=detect)
        self.data["stacks"].setdefault(stack, {})["drifts"] = rows
        return rows

    def config_history(self, resource, at):
        cfg = self.inner.config_history(resource, at)
        if cfg is not None:
            self.data["config_history"][resource.key] = cfg
        return cfg

    def save(self) -> str | None:
        """Write the recording. Best-effort: a path that can't be written is
        logged and returned as an error string, never raised, so the checks'
        own result is kept. Returns None on success."""
        try:
            target = normalize_path(self.path)
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, default=str, indent=1)
            self.saved_to = str(target)
            return None
        except Exception as exc:  # noqa: BLE001
            msg = f"could not save the diff-first recording to {self.path!r}: {exc}"
            log.warning(msg)
            return msg

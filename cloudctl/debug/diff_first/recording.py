"""Record what the diff-first checks read from AWS, in the shape RecordedLive
replays. Set CLOUDCTL_DIFF_FIRST_RECORD=<file.json> on a live run; replay it
later with CLOUDCTL_DIFF_FIRST_REPLAY=<file.json> (no AWS needed)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from cloudctl.debug.diff_first.model import Resource, iso


class RecordingLive:
    def __init__(self, inner: Any, path: str):
        self.inner, self.path = inner, path
        self.data: dict = {"now": iso(inner.now()), "configs": {}, "discovered": [], "events": [],
                           "metrics": {}, "stacks": {}, "config_history": {}}

    def now(self) -> datetime:
        return self.inner.now()

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

    def save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, default=str, indent=1)

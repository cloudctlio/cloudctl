"""Evidence sources: where the primitives read facts from.

The primitives never call a cloud API directly. They ask an ``EvidenceSource``
for raw reads (a metric series, log events, a config as of a time, change
events, a policy simulation, network attachments, failure lines, calls through
a node). A source that cannot answer raises :class:`Unavailable` naming the
missing signal, which the primitive turns into an UNAVAILABLE result. A missing
signal is never treated as a pass or a fail.

``FixtureEvidence`` answers from a dict (a recorded sweep or a hand-written
test fixture). An AWS-backed source belongs here too, routed through the
recorder so every read can be frozen and replayed exactly; it is not written
yet, so shadow mode runs on fixtures/recordings only (see shadow.py).

Times are epoch seconds (int). Fixture timestamps may be ISO-8601 strings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from cloudctl.verify.model import SystemModel


class Unavailable(Exception):
    """The signal needed to answer is not collected / not reachable."""

    def __init__(self, signal: str, reason: str = ""):
        self.signal = signal
        self.reason = reason or f"{signal} not available"
        super().__init__(self.reason)


def to_ts(value) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip()
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return int(float(s))
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())


@dataclass(frozen=True)
class Window:
    start: int
    end: int

    def __post_init__(self):
        if self.end < self.start:
            raise ValueError("window end before start")

    @property
    def length(self) -> int:
        return self.end - self.start

    def contains(self, ts: int) -> bool:
        return self.start <= ts <= self.end

    def to_dict(self) -> dict:
        return {"start": self.start, "end": self.end}


@dataclass(frozen=True)
class Incident:
    """Timing for one investigation.

    ``onset``     when the symptom started (from observation)
    ``end``       end of the incident window (usually "now")
    ``lookback``  how far before onset a cause may have happened (onset link)

    Named windows the primitives accept:
      incident   [onset, end]
      lookback   [onset - lookback, onset]
      pre_onset  [onset - lookback - L, onset - lookback], L = incident length
                 (at least ``min_control``). It ends before the lookback starts
                 so a change shortly before onset is not inside the control.
    """

    onset: int
    end: int
    lookback: int = 3600
    min_control: int = 900

    def window(self, name: str) -> Window:
        if name == "incident":
            return Window(self.onset, self.end)
        if name == "lookback":
            return Window(self.onset - self.lookback, self.onset)
        if name == "pre_onset":
            length = max(self.end - self.onset, self.min_control)
            stop = self.onset - self.lookback
            return Window(stop - length, stop)
        raise ValueError(f"unknown window {name!r}")

    def to_dict(self) -> dict:
        return {"onset": self.onset, "end": self.end, "lookback": self.lookback,
                "windows": {n: self.window(n).to_dict()
                            for n in ("incident", "lookback", "pre_onset")}}


class EvidenceSource(Protocol):
    def metric_series(self, node: str, metric: str, window: Window) -> list[tuple[int, float]]: ...
    def log_events(self, node: str, pattern: str, window: Window) -> list[tuple[int, str]]: ...
    def config_at(self, node: str, at: int | None) -> dict: ...
    def changes(self, node: str, window: Window) -> list[dict]: ...
    def simulate(self, principal: str, action: str, resource: str,
                 resource_policy: str, at: int | None) -> dict: ...
    def network(self, node: str, at: int | None) -> dict: ...
    def failure_signals(self, node: str, window: Window) -> list[tuple[int, str]]: ...
    def calls(self, node: str, window: Window) -> list[dict]: ...


def _match(pattern: str, message: str) -> bool:
    """CloudWatch-like term matching, kept deliberately simple and identical
    for every source: all space-separated terms must appear (case-insensitive);
    a quoted phrase must appear verbatim."""
    msg = message.lower()
    terms = re.findall(r'"([^"]+)"|(\S+)', pattern or "")
    for quoted, bare in terms:
        t = (quoted or bare).lower()
        if t and t not in msg:
            return False
    return True


class FixtureEvidence:
    """Evidence from a recorded sweep or a test fixture. Shape::

        {
          "metrics":  {node: {metric: [[ts, value], ...]}},
          "logs":     {node: [[ts, message], ...]},
          "config":   {node: [{"at": ts|null, "config": {...}}, ...]},
          "changes":  {node: [{"ts", "actor", "action", "paths": [...], "ref"}]},
          "simulate": [{"principal", "action", "resource", "at"?: ts,
                        "decision", "matched": [...]}],
          "network":  {node: [{"at": ts|null, "network": {...}}] | {...}},
          "failures": {node: [[ts, message], ...]},   # optional; else derived from logs
          "calls":    {node: [{"ts", "caller", "ref"}]},
          "unavailable": {"cloudtrail": "reason", "config_history": "reason",
                          "iam_simulation": "reason", "network": "reason"}
        }

    Node keys may be any identifier the model resolves (ARN, IaC address,
    name). A node with no entry in a section is UNAVAILABLE for that section.
    Config/network versions: ``at: null`` is the live (current) value; a
    timestamped version is the value from that time until the next version.
    """

    def __init__(self, data: dict, model: SystemModel):
        self.model = model
        self.off = dict(data.get("unavailable") or {})
        self._d = {sec: self._rekey(data.get(sec) or {})
                   for sec in ("metrics", "logs", "config", "changes", "network",
                               "failures", "calls")}
        self._simulate = list(data.get("simulate") or [])

    def _rekey(self, section: dict) -> dict:
        out = {}
        for k, v in section.items():
            out[self.model.resolve(k) or k] = v
        return out

    def _node(self, node: str) -> str:
        return self.model.resolve(node) or node

    def _section(self, sec: str, node: str, signal: str):
        if sec in self.off:
            raise Unavailable(signal, self.off[sec])
        nid = self._node(node)
        if nid not in self._d[sec]:
            raise Unavailable(signal, f"{signal} not collected for {nid}")
        return self._d[sec][nid]

    def metric_series(self, node, metric, window):
        series = self._section("metrics", node, "metrics")
        if metric not in series:
            raise Unavailable("metrics", f"metric {metric!r} not found for {self._node(node)} (ListMetrics)")
        return [(to_ts(t), float(v)) for t, v in series[metric] if window.contains(to_ts(t))]

    def log_events(self, node, pattern, window):
        lines = self._section("logs", node, "logs")
        return [(to_ts(t), m) for t, m in lines
                if window.contains(to_ts(t)) and _match(pattern, m)]

    @staticmethod
    def _versioned(versions, at: int | None, what: str):
        if isinstance(versions, dict) and "at" not in versions:
            versions = [{"at": None, what: versions}]
        live = [v for v in versions if v.get("at") is None]
        dated = sorted((v for v in versions if v.get("at") is not None),
                       key=lambda v: to_ts(v["at"]))
        if at is None:
            if live:
                return live[-1][what]
            if dated:
                return dated[-1][what]
            raise LookupError
        prior = [v for v in dated if to_ts(v["at"]) <= at]
        if prior:
            return prior[-1][what]
        raise LookupError

    def config_at(self, node, at):
        if at is not None and "config_history" in self.off:
            raise Unavailable("config_history", self.off["config_history"])
        versions = self._section("config", node, "config")
        try:
            return self._versioned(versions, at, "config")
        except LookupError:
            raise Unavailable("config_history" if at is not None else "config",
                              f"no config for {self._node(node)} as of {at}") from None

    def changes(self, node, window):
        if "cloudtrail" in self.off:
            raise Unavailable("cloudtrail", self.off["cloudtrail"])
        try:
            evs = self._section("changes", node, "cloudtrail")
        except Unavailable:
            # CloudTrail is on but recorded no writes for this node: that is an
            # answer (no changes), not a missing signal.
            evs = []
        return [dict(e, ts=to_ts(e.get("ts"))) for e in evs if window.contains(to_ts(e.get("ts")))]

    def simulate(self, principal, action, resource, resource_policy, at):
        if "iam_simulation" in self.off:
            raise Unavailable("iam_simulation", self.off["iam_simulation"])
        p, r = self._node(principal), self._node(resource) if resource else ""
        cands = [s for s in self._simulate
                 if self._node(s.get("principal", "")) == p
                 and s.get("action", "").lower() == action.lower()
                 and (self._node(s.get("resource", "")) if s.get("resource") else "") == r]
        if at is None:
            hit = [s for s in cands if s.get("at") is None] or \
                  sorted((s for s in cands if s.get("at") is not None), key=lambda s: to_ts(s["at"]))[-1:]
        else:
            hit = sorted((s for s in cands if s.get("at") is not None and to_ts(s["at"]) <= at),
                         key=lambda s: to_ts(s["at"]))[-1:]
        if not hit:
            raise Unavailable("iam_simulation" if at is None else "policy_history",
                              f"no simulation recorded for {p} {action} {r} as of {at}")
        return hit[-1]

    def network(self, node, at):
        if "network" in self.off:
            raise Unavailable("network", self.off["network"])
        versions = self._section("network", node, "network")
        try:
            return self._versioned(versions, at, "network")
        except LookupError:
            raise Unavailable("network_history" if at is not None else "network",
                              f"no network data for {self._node(node)} as of {at}") from None

    def failure_signals(self, node, window):
        nid = self._node(node)
        if nid in self._d["failures"]:
            return [(to_ts(t), m) for t, m in self._d["failures"][nid] if window.contains(to_ts(t))]
        if nid in self._d["logs"]:
            from cloudctl.debug.localize import _BENIGN, _ERROR_LINE
            return [(to_ts(t), m) for t, m in self._d["logs"][nid]
                    if window.contains(to_ts(t)) and _ERROR_LINE.search(m) and not _BENIGN.search(m)]
        if nid in self._d["metrics"]:
            return []  # observable (has metrics) and no failure lines recorded
        raise Unavailable("failure_signals", f"no logs or metrics for {nid}")

    def calls(self, node, window):
        if "cloudtrail" in self.off and "xray" in self.off:
            raise Unavailable("calls", "neither CloudTrail data events nor traces available")
        evs = self._section("calls", node, "calls")
        return [dict(e, ts=to_ts(e.get("ts"))) for e in evs if window.contains(to_ts(e.get("ts")))]

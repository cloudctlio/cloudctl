"""Which changes can be the cause? Only write calls made inside the incident
window that still hold.

A change is dropped (kept as context, never a cause candidate) when:

* the call failed (it changed nothing);
* it happened before the system was last seen healthy, or after the onset;
* a later call on the same resource set the same fields again (superseded);
* live config no longer has the values it set (reverted).
"""

from __future__ import annotations

import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from cloudctl.debug.diff_first.model import Change, IncidentWindow, Resource, iso, to_dt
from cloudctl.debug.diff_first.normalize import flatten, norm_key
from cloudctl.debug.diff_first.resolve import Resolver

_ID_SUFFIXES = ("name", "arn", "id", "url", "uuid", "identifier")


def _id_params(params: dict) -> list[tuple[str, Any]]:
    """Top-level (key, value) request parameters that identify the target. The
    resource is named by these, not by ARNs or names that happen to sit inside
    a policy document, a pattern or an environment block."""
    out: list[tuple[str, Any]] = []
    if not isinstance(params, dict):
        return out
    for k, v in params.items():
        nk = norm_key(k)
        if nk.endswith(_ID_SUFFIXES) and isinstance(v, (str, list)):
            out.append((k, v))
    return out


def match_resources(row: dict, rs: Resolver) -> list[str]:
    keys: set[str] = set()
    for x in row.get("resources") or []:
        if x:
            keys |= rs.resolve_str(str(x))
    for k, v in _id_params(row.get("params") or {}):
        keys |= rs.resolve(v, None, k)
    return sorted(keys)


def _value_keys(params: dict) -> dict[str, Any]:
    """Request parameters minus the ones that only identify the target."""
    flat = flatten(params or {})
    return {k: v for k, v in flat.items()
            if not k.split(".")[-1].endswith(_ID_SUFFIXES)}


_CALLER_FIELDS = ("cloud", "principal", "principal_type", "user_agent", "source_ip", "invoked_by",
                  "console", "client_app", "correlation_id")


def to_changes(rows: list[dict], resources: dict[str, Resource]) -> list[Change]:
    rs = Resolver(resources)
    points_at: dict[str, set[str]] = {}
    out: list[Change] = []
    for row in rows:
        keys = match_resources(row, rs)
        if len(keys) > 1:
            # PutRule names the rule and its bus; PutRolePolicy the policy and its
            # role. The change is to the one that points at the others.
            for k in keys:
                if k not in points_at:
                    points_at[k] = rs.resolve(resources[k].config, resources[k])
            specific = [k for k in keys if not any(k in points_at[o] for o in keys if o != k)]
            keys = specific or keys
        ch = Change(time=row.get("time") or "", event_name=row.get("event_name", ""),
                    event_source=row.get("event_source", ""), actor=row.get("actor", ""),
                    params=row.get("params") or {}, error_code=row.get("error_code", ""),
                    **{k: row[k] for k in _CALLER_FIELDS if row.get(k) not in (None, "")})
        ch.resource_key = ",".join(keys)
        ch.resource_name = ", ".join(dict.fromkeys(resources[k].label() for k in keys))
        out.append(ch)
    return sorted(out, key=lambda c: c.time or "")


def classify(changes: list[Change], window: IncidentWindow,
             live_configs: dict[str, dict] | None = None,
             observer_keys: set[str] | None = None) -> list[Change]:
    """Set ``status`` and ``reason`` on every change (in place) and return them.
    ``observer_keys``: resources that only watch the system; a change that
    touches nothing else gets status ``observer``."""
    start, end = to_dt(window.start), to_dt(window.end)
    live_configs = live_configs or {}
    for i, c in enumerate(changes):
        t = to_dt(c.time)
        if c.error_code:
            c.status, c.reason = "failed_call", f"the call failed ({c.error_code}), so it changed nothing"
            continue
        if not c.resource_key:
            c.status, c.reason = "unmatched", "touches nothing in the app's resources"
            continue
        if observer_keys and set(c.resource_key.split(",")) <= observer_keys:
            c.status = "observer"
            c.reason = ("changes a monitor (alarm, alert rule, dashboard or log pipeline): it can hide "
                        "an outage but cannot stop work flowing, so it is never a cause")
            continue
        if start and t and t < start:
            c.status = "before_window"
            c.reason = (f"made at {c.time}, before the system was last seen healthy "
                        f"({window.last_healthy}); a cause has to come after that")
            continue
        if end and t and t > end:
            c.status = "after_onset"
            c.reason = f"made at {c.time}, after the symptom started ({window.onset})"
            continue
        mine = set(c.resource_key.split(","))
        keys = set(_value_keys(c.params))
        later = None
        for d in changes[i + 1:]:
            if d.error_code or not d.resource_key:
                continue
            if mine & set(d.resource_key.split(",")) and (
                    keys & set(_value_keys(d.params)) or d.event_name.startswith("Delete")):
                later = d
                break
        if later is not None:
            c.status, c.superseded_by = "superseded", f"{later.event_name} at {later.time}"
            c.reason = f"{later.event_name} at {later.time} set the same fields again, so this change no longer holds"
            continue
        verdict = _holds_live(c, mine, live_configs)
        if verdict is False:
            c.status = "reverted"
            c.reason = "live config no longer has the values this change set"
            continue
        c.status = "candidate"
        c.reason = ("inside the incident window and live config still has its values"
                    if verdict else "inside the incident window; nothing later undid it")
    return changes


def _holds_live(c: Change, keys: set[str], live_configs: dict[str, dict]) -> bool | None:
    """True = live still has every comparable value; False = it differs; None = can't tell."""
    want = _value_keys(c.params)
    if not want:
        return None
    compared = False
    for k in keys:
        cfg = live_configs.get(k)
        if not isinstance(cfg, dict) or cfg.get("__not_found__"):
            continue
        have = flatten(cfg)
        # match on the leaf name: request params and live configs nest differently
        by_leaf: dict[str, Any] = {}
        for hk, hv in have.items():
            by_leaf.setdefault(hk.split(".")[-1], hv)
            by_leaf.setdefault(hk, hv)
        for wk, wv in want.items():
            hv = have.get(wk, by_leaf.get(wk.split(".")[-1], by_leaf.get(norm_key(wk))))
            if hv is None:
                continue
            compared = True
            if hv != wv:
                return False
    return True if compared else None


# ── IaC history (git) ────────────────────────────────────────────────────────

def iac_commits(iac_root: str | None, start: datetime | None, end: datetime | None,
                limit: int = 20) -> list[Change]:
    """Commits to the IaC root inside the window (when it is a git repo)."""
    if not iac_root or not start or not (Path(iac_root) / ".git").exists() and not _in_git(iac_root):
        return []
    cmd = ["git", "-C", str(iac_root), "log", f"--since={iso(start)}",
           f"--until={iso(end or datetime.now(start.tzinfo))}", f"-n{limit}",
           "--format=%H%x09%cI%x09%an%x09%s", "--name-only", "--", "."]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    commits: list[Change] = []
    cur: Change | None = None
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and len(parts[0]) == 40:
            cur = Change(time=iso(to_dt(parts[1])) or "", event_name=f"commit {parts[0][:8]}: {parts[3][:80]}",
                         actor=parts[2], origin="iac_commit", status="context",
                         reason="IaC commit inside the incident window", params={"files": []})
            commits.append(cur)
        elif line.strip() and cur is not None:
            cur.params["files"].append(line.strip())
    return commits


def _in_git(path: str) -> bool:
    try:
        r = subprocess.run(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
                           capture_output=True, text=True, timeout=5, check=False)
        return r.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


# ── Annotating the agent's own CloudTrail tool ───────────────────────────────
# The model can still call search_cloudtrail_events with a fixed look-back from
# now. While an investigation runs, every row it gets back is labelled with
# where it sits relative to the incident window, so a stale or undone change
# can't pass for a fresh one.

_LOCK = threading.Lock()
_ACTIVE: dict = {}


def set_active_window(window: IncidentWindow | None) -> None:
    with _LOCK:
        _ACTIVE.clear()
        if window and window.start:
            _ACTIVE.update({"start": window.start, "end": window.end, "onset": window.onset,
                            "last_healthy": window.last_healthy})


def annotate_rows(rows: list[dict]) -> list[dict]:
    with _LOCK:
        w = dict(_ACTIVE)
    if not w or not rows:
        return rows
    start, end = to_dt(w.get("start")), to_dt(w.get("end"))
    # newest-first input; group by resource to spot later calls on the same thing
    ordered = sorted(rows, key=lambda r: str(r.get("time") or r.get("event_time") or ""))
    for i, r in enumerate(ordered):
        t = to_dt(r.get("time") or r.get("event_time"))
        if t is None:
            continue
        if start and t < start:
            r["incident_window"] = (f"BEFORE: made before the last healthy point "
                                    f"({w.get('last_healthy')}); cannot have started this incident")
        elif end and t > end:
            r["incident_window"] = f"AFTER: made after the symptom began ({w.get('onset')})"
        else:
            r["incident_window"] = "INSIDE: between the last healthy point and the onset"
        res = {str(x).lower() for x in (r.get("resources") or []) if x}
        for later in ordered[i + 1:]:
            lres = {str(x).lower() for x in (later.get("resources") or []) if x}
            if res & lres and later.get("event_name") == r.get("event_name") and not later.get("error_code"):
                r["superseded_by"] = f"{later.get('event_name')} at {later.get('time') or later.get('event_time')}"
                break
    return rows


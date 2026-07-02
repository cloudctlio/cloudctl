"""recorder.py — record/replay layer for agent tool calls.

Record mode  (CLOUDCTL_RECORD=<path.jsonl>):
    every tool call's canonical input and output is appended as one JSON line.

Replay mode  (CLOUDCTL_REPLAY=<path.jsonl>):
    tool calls return recorded outputs instead of touching AWS. The reasoning
    layer (Bedrock) stays live — replay evaluates the AGENT against a frozen
    environment, so prompt/graph changes can be regression-tested in minutes
    without a deployment.

Matching on replay: exact canonical-input match first, then same tool with the
same primary identifier (resource name/hint), then any recording for the tool.
A fuzzy or missing match is flagged in the returned payload so evaluation can
tell how faithful the replay was.
"""
from __future__ import annotations

import functools
import inspect
import json
import os
import threading
import time
from datetime import datetime, timezone

_LOCK = threading.Lock()
_REPLAY_CACHE: dict[str, list[dict]] = {}
_REPLAY_PATH_LOADED: str | None = None

# Session cache: parallel investigation branches routinely repeat identical
# read calls (same list/describe on the same resources). Within one
# investigation these are idempotent, so identical calls inside the TTL are
# served from memory — cuts AWS traffic and tokens with no accuracy impact.
_SESSION_CACHE: dict[str, tuple[float, str]] = {}
_CACHE_TTL_SECONDS = 300.0

# Session-scoped fields that identify credentials, not the request — excluded
# from the canonical input so recordings replay across accounts/sessions.
_NON_CANONICAL = {"profile"}

# Primary identifier per tool for fuzzy matching, in priority order.
_ID_FIELDS = ("resource_name", "resource_hint", "service_type", "metric_name",
              "symptom", "action", "role")


def _canonical(fn, args, kwargs) -> dict:
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
        bound.apply_defaults()
        payload = dict(bound.arguments)
    except Exception:  # noqa: BLE001
        payload = {"args": [str(a) for a in args], **kwargs}
    return {k: v for k, v in payload.items() if k not in _NON_CANONICAL}


def _record(tool: str, canonical: dict, output: str) -> None:
    path = os.environ.get("CLOUDCTL_RECORD")
    if not path:
        return
    line = json.dumps({
        "ts":     datetime.now(timezone.utc).isoformat(),
        "tool":   tool,
        "input":  canonical,
        "output": output,
    }, default=str)
    with _LOCK:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def _load_replay(path: str) -> None:
    global _REPLAY_PATH_LOADED
    with _LOCK:
        if _REPLAY_PATH_LOADED == path:
            return
        _REPLAY_CACHE.clear()
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except Exception:  # noqa: BLE001
                    continue
                _REPLAY_CACHE.setdefault(rec.get("tool", "?"), []).append(rec)
        _REPLAY_PATH_LOADED = path


def _primary_id(canonical: dict) -> str:
    for f in _ID_FIELDS:
        v = canonical.get(f)
        if v:
            return str(v)
    return ""


def _lookup(tool: str, canonical: dict) -> str:
    path = os.environ["CLOUDCTL_REPLAY"]
    _load_replay(path)
    recs = _REPLAY_CACHE.get(tool, [])

    canon_str = json.dumps(canonical, sort_keys=True, default=str)
    for rec in recs:
        if json.dumps(rec.get("input", {}), sort_keys=True, default=str) == canon_str:
            return rec["output"]

    want = _primary_id(canonical).lower()
    if want:
        for rec in recs:
            if _primary_id(rec.get("input", {})).lower() == want:
                return rec["output"]
        # substring match (model phrased the hint differently)
        for rec in recs:
            got = _primary_id(rec.get("input", {})).lower()
            if got and (want in got or got in want):
                return rec["output"]

    if recs:
        return recs[0]["output"]
    return json.dumps({
        "replay_miss": True,
        "tool": tool,
        "note": "no recording for this tool in the replay fixture; "
                "treat as data unavailable",
    })


def recordable(tool_name: str):
    """Decorator for tool functions returning a JSON string."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            canonical = _canonical(fn, args, kwargs)
            if os.environ.get("CLOUDCTL_REPLAY"):
                return _lookup(tool_name, canonical)

            cache_key = tool_name + "|" + json.dumps(canonical, sort_keys=True, default=str)
            now = time.monotonic()
            with _LOCK:
                hit = _SESSION_CACHE.get(cache_key)
            if hit and now - hit[0] < _CACHE_TTL_SECONDS:
                return hit[1]

            out = fn(*args, **kwargs)
            # Don't pin transient failures — errors should retry on next call.
            if '"error"' not in out[:200]:
                with _LOCK:
                    _SESSION_CACHE[cache_key] = (now, out)
            _record(tool_name, canonical, out)
            return out
        return wrapper
    return deco


def recorded(tool_name: str, canonical: dict, compute) -> object:
    """Inline record/replay for non-decorated call sites.

    `compute` is a zero-arg callable producing a JSON-serializable value.
    """
    if os.environ.get("CLOUDCTL_REPLAY"):
        out = _lookup(tool_name, canonical)
        try:
            return json.loads(out)
        except Exception:  # noqa: BLE001
            return out
    value = compute()
    _record(tool_name, canonical, json.dumps(value, default=str))
    return value

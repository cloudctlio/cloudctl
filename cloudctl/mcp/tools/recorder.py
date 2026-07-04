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

# RLock: _model_queues() holds the lock while calling _load_replay(), which
# locks again — a plain Lock deadlocks on that reentry.
_LOCK = threading.RLock()
_REPLAY_CACHE: dict[str, list[dict]] = {}
_REPLAY_PATH_LOADED: str | None = None

# Replay fidelity accounting: exact prefix hits vs fuzzy matches vs misses.
# A replayed verdict is only comparable to the recorded one when fidelity is
# high — a run full of misses reasoned from thinner evidence than the
# original, and its divergence says nothing about the change under test.
REPLAY_STATS = {"exact": 0, "fuzzy": 0, "fallback": 0, "miss": 0}

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
            REPLAY_STATS["exact"] += 1
            return rec["output"]

    want = _primary_id(canonical).lower()
    if want:
        for rec in recs:
            if _primary_id(rec.get("input", {})).lower() == want:
                REPLAY_STATS["fuzzy"] += 1
                return rec["output"]
        # substring match (model phrased the hint differently)
        for rec in recs:
            got = _primary_id(rec.get("input", {})).lower()
            if got and (want in got or got in want):
                REPLAY_STATS["fuzzy"] += 1
                return rec["output"]

    if recs:
        REPLAY_STATS["fallback"] += 1
        return recs[0]["output"]
    REPLAY_STATS["miss"] += 1
    return json.dumps({
        "replay_miss": True,
        "tool": tool,
        "note": "no recording for this tool in the replay fixture; "
                "treat as data unavailable",
    })


def reset_replay_state() -> None:
    """Clear all module state (caches, queues, counters). Test support —
    production processes are one investigation per process and never need it."""
    with _LOCK:
        _REPLAY_CACHE.clear()
        _SESSION_CACHE.clear()
        _MODEL_QUEUES.clear()
        global _REPLAY_PATH_LOADED, _MODEL_QUEUES_PATH
        _REPLAY_PATH_LOADED = None
        _MODEL_QUEUES_PATH = None
        for k in REPLAY_STATS:
            REPLAY_STATS[k] = 0
        MODEL_STATS.update({"served": 0, "diverged_at": None, "live": 0})
        _MODEL_SEQ["n"] = 0


def replay_meta(path: str) -> dict:
    """Return the fixture's _meta record (symptom/region/minutes), if present."""
    _load_replay(path)
    for rec in _REPLAY_CACHE.get("_meta", []):
        return rec.get("input", {}) or {}
    return {}


def replay_fidelity() -> dict:
    """Fidelity summary for the current process's replay lookups."""
    total = sum(REPLAY_STATS.values())
    score = (REPLAY_STATS["exact"] + REPLAY_STATS["fuzzy"]) / total if total else 0.0
    return {**REPLAY_STATS, "total": total, "fidelity": round(score, 3)}


# ── Dual-plane recording: the model plane ─────────────────────────────────────
#
# Tool I/O alone is half the flight. Recording every model request/response as
# well enables two rigorous replay modes:
#   exact  — recorded model responses are served for byte-matching requests;
#            no live model, no nondeterminism: the trajectory reproduces by
#            construction. Used to PROVE a change is behavior-neutral (every
#            request the new code builds must hash-match the recording).
#   pinned — recorded responses are served while requests still match; the
#            live model takes over at the FIRST divergent request, so any
#            trajectory change is attributable to the edit under test, never
#            to server-side jitter upstream of it.
#
# cachePoint blocks are stripped before hashing: they are billing directives,
# not content, so cached and uncached agents compare as equal.

import hashlib
import time

MODEL_STATS = {"served": 0, "diverged_at": None, "live": 0}

# Per-process cost/latency accounting. Pure instrumentation: reads the usage
# fields Bedrock already returns; changes no token the model sees and no tool
# call, so it is behavior-neutral. Sonnet 4.6 Bedrock rates ($/M tokens).
_RATE = {"in": 3.00, "out": 15.00, "cache_write": 3.75, "cache_read": 0.30}
USAGE_STATS = {"calls": 0, "input": 0, "output": 0,
               "cache_read": 0, "cache_write": 0, "wall_seconds": 0.0}


def reset_usage_stats() -> None:
    USAGE_STATS.update({"calls": 0, "input": 0, "output": 0,
                        "cache_read": 0, "cache_write": 0, "wall_seconds": 0.0})


def usage_report() -> dict:
    u = USAGE_STATS
    cost = (u["input"] * _RATE["in"] + u["output"] * _RATE["out"]
            + u["cache_write"] * _RATE["cache_write"]
            + u["cache_read"] * _RATE["cache_read"]) / 1e6
    return {
        "model_calls":       u["calls"],
        "input_tokens":      u["input"],
        "output_tokens":     u["output"],
        "cache_read_tokens": u["cache_read"],
        "cache_write_tokens": u["cache_write"],
        "wall_seconds":      round(u["wall_seconds"], 1),
        "est_cost_usd":      round(cost, 4),
    }


def _accumulate_usage(resp: dict, elapsed: float) -> None:
    u = resp.get("usage", {}) or {}
    USAGE_STATS["calls"] += 1
    USAGE_STATS["input"] += u.get("inputTokens", 0)
    USAGE_STATS["output"] += u.get("outputTokens", 0)
    USAGE_STATS["cache_read"] += u.get("cacheReadInputTokens", 0)
    USAGE_STATS["cache_write"] += u.get("cacheWriteInputTokens", 0)
    USAGE_STATS["wall_seconds"] += elapsed


def _strip_cache_points(obj):
    if isinstance(obj, list):
        return [_strip_cache_points(x) for x in obj
                if not (isinstance(x, dict) and set(x.keys()) == {"cachePoint"})]
    if isinstance(obj, dict):
        return {k: _strip_cache_points(v) for k, v in obj.items()}
    return obj


def _request_hash(kwargs: dict) -> str:
    canon = _strip_cache_points({k: v for k, v in kwargs.items() if k != "modelId"})
    return hashlib.sha256(
        json.dumps(canon, sort_keys=True, default=str).encode()
    ).hexdigest()


_MODEL_QUEUES: dict[str, list[str]] = {}
_MODEL_QUEUES_PATH: str | None = None
_MODEL_SEQ = {"n": 0}


def _model_queues(path: str) -> dict[str, list[str]]:
    """Recorded model responses indexed by request hash (FIFO per hash).

    Hash matching (not sequence) is essential: investigation branches run in
    parallel threads whose interleaving differs run to run, so a global call
    order is not reproducible even between two identical live runs."""
    global _MODEL_QUEUES_PATH
    with _LOCK:
        if _MODEL_QUEUES_PATH != path:
            _load_replay(path)
            _MODEL_QUEUES.clear()
            for rec in _REPLAY_CACHE.get("_model", []):
                h = rec.get("input", {}).get("hash", "")
                _MODEL_QUEUES.setdefault(h, []).append(rec["output"])
            _MODEL_QUEUES_PATH = path
    return _MODEL_QUEUES


class RecordingBedrock:
    """Wraps a bedrock-runtime client; records/replays the model plane.

    Modes (CLOUDCTL_REPLAY_MODEL): unset/'' = live (record if CLOUDCTL_RECORD);
    'exact' = serve recorded responses by request hash, hard-fail on any
    unmatched request (proof of behavior-neutrality);
    'pinned' = serve while requests match, go live from the first mismatch
    (divergence attributable to the change under test, not upstream jitter).
    """

    def __init__(self, client):
        self._client = client

    def __getattr__(self, name):
        return getattr(self._client, name)

    def converse(self, **kwargs):
        mode = os.environ.get("CLOUDCTL_REPLAY_MODEL", "")
        h = _request_hash(kwargs)
        if mode in ("exact", "pinned") and os.environ.get("CLOUDCTL_REPLAY"):
            queues = _model_queues(os.environ["CLOUDCTL_REPLAY"])
            with _LOCK:
                q = queues.get(h)
                out = q.pop(0) if q else None
            if out is not None:
                MODEL_STATS["served"] += 1
                served = json.loads(out)
                _accumulate_usage(served, 0.0)   # replayed: no wall time
                return served
            if MODEL_STATS["diverged_at"] is None:
                MODEL_STATS["diverged_at"] = MODEL_STATS["served"]
            if mode == "exact":
                raise RuntimeError(
                    f"exact replay: no recorded response for request hash "
                    f"{h[:12]} (after {MODEL_STATS['served']} matched calls). "
                    f"The change under test is NOT behavior-neutral."
                )
        _t0 = time.monotonic()
        resp = self._client.converse(**kwargs)
        _accumulate_usage(resp, time.monotonic() - _t0)
        MODEL_STATS["live"] += 1
        if os.environ.get("CLOUDCTL_RECORD"):
            with _LOCK:
                seq = _MODEL_SEQ["n"]
                _MODEL_SEQ["n"] += 1
            slim = {k: v for k, v in resp.items() if k != "ResponseMetadata"}
            _record("_model", {"seq": seq, "hash": h},
                    json.dumps(slim, default=str))
        return resp


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

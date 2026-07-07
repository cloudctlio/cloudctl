"""Regression tests for the accuracy-audit fixes.

Each test pins a specific bug class the audit identified, so a future refactor
that reintroduces it fails loudly:

  #1  evidence-store key collision (tail_logs/query_metrics/aws_read/probe_*
      overwriting each other and each other's branches)
  #7  the wall-clock ceiling must PREEMPT — _invoke_bounded must not block on
      shutdown(wait=True)
  #8  the prose-confirmed loophole — a manufactured CONFIRMED prediction needs a
      traceable fact, not just prose
  #2  tail_logs must honor filter_pattern AND paginate for recency
  #9  calibration must pick the branch the report actually chose; arbitration
      resolves an otherwise-unresolved contest
  #12 truncation must keep valid JSON + the recent tail (no middle byte-cut)
"""
from __future__ import annotations

import json
import time

import pytest


# ── #1 evidence-store key uniqueness ───────────────────────────────────────────
from cloudctl.ai.graph_agent import _evidence_key, _store_unique, _merge_fetched


def test_evidence_key_distinguishes_tools_without_resource_name():
    # tail_logs / query_metrics / aws_read carry no resource_name — the old key
    # collapsed all of them to "tool:". Distinct calls must get distinct keys.
    k_logs = _evidence_key("tail_logs", {"resource_hint": "svc-a"})
    k_logs_b = _evidence_key("tail_logs", {"resource_hint": "svc-b"})
    k_metric = _evidence_key("query_metrics",
                             {"namespace": "AWS/SQS", "metric_name": "ApproximateAgeOfOldestMessage",
                              "dimensions": {"QueueName": "q1"}})
    k_read = _evidence_key("aws_read", {"service": "kms", "operation": "get_key_rotation_status"})
    keys = {k_logs, k_logs_b, k_metric, k_read}
    assert len(keys) == 4                      # all distinct
    assert all(k and k != "tail_logs" for k in (k_logs, k_logs_b))


def test_store_unique_never_overwrites_distinct_values():
    store = {}
    k1 = _store_unique(store, "query_metrics:m", {"v": 1})
    k2 = _store_unique(store, "query_metrics:m", {"v": 2})   # same key, different value
    assert k1 != k2
    assert store[k1] == {"v": 1}
    assert store[k2] == {"v": 2}                # earlier result preserved, not clobbered


def test_store_unique_dedupes_identical_values():
    store = {}
    k1 = _store_unique(store, "k", {"v": 1})
    k2 = _store_unique(store, "k", {"v": 1})     # identical -> same slot, no dup
    assert k1 == k2
    assert len(store) == 1


def test_merge_fetched_preserves_cross_branch_collisions():
    dst = {"tail_logs:resource_hint=svc": {"events": [1]}}
    src = {"tail_logs:resource_hint=svc": {"events": [2]}}   # different value, same key
    _merge_fetched(dst, src)
    # both branches' data survives (renamed), instead of the second clobbering
    all_values = list(dst.values())
    assert {"events": [1]} in all_values
    assert {"events": [2]} in all_values


# ── #7 the ceiling must actually preempt (no shutdown(wait=True) block) ─────────
def test_invoke_bounded_preempts_slow_callable(monkeypatch):
    """A graph.invoke that runs far longer than the ceiling must NOT keep the
    caller blocked: _invoke_bounded returns ~at the ceiling, not after the slow
    callable finishes. Mirrors the repo's slow-callable ceiling test pattern."""
    import cloudctl.ai.graph_agent as ga

    class _SlowGraph:
        def invoke(self, arg, config):
            time.sleep(30)          # much longer than the tiny ceiling below
            return {"final_report": {"root_cause": "done"}}

        def get_state(self, config):
            class _S:
                values = {}
            return _S()

    monkeypatch.setattr(ga, "_get_graph", lambda: _SlowGraph())
    monkeypatch.setenv("CLOUDCTL_INVESTIGATION_CEILING_S", "1")
    # Avoid real AWS/account calls
    monkeypatch.setattr(ga, "_make_bedrock", lambda *a, **k: None)
    import cloudctl.mcp.tools.debug as dbg
    monkeypatch.setattr(dbg, "_get_account_id", lambda *a, **k: "123")

    start = time.monotonic()
    raw, _ = ga.debug_incident_graph("svc is down", profile=None, region="us-east-1")
    elapsed = time.monotonic() - start
    # Must return well before the 30s callable completes (ceiling is 1s; allow
    # generous slack for interpreter/thread scheduling but far under 30s).
    assert elapsed < 15, f"ceiling did not preempt: took {elapsed:.1f}s"
    d = json.loads(raw)
    assert d.get("_timed_out") is True


# ── #8 prose-confirmed loophole ────────────────────────────────────────────────
from cloudctl.ai.graph_agent import _has_traceable_fact


def test_has_traceable_fact_requires_a_verified_specific():
    corpus = json.dumps({"config": {"MaxConnections": 50, "role": "arn:aws:iam::1:role/appworker"}}).lower()
    # prose with no specific fact -> not a verifiable confirmation
    assert _has_traceable_fact("the role lacks the required access", corpus) is False
    # carries a distinctive identifier that traces to the corpus -> verifiable
    assert _has_traceable_fact(
        "the caller role arn:aws:iam::1:role/appworker is denied", corpus) is True
    # carries a distinctive token that does NOT trace -> not verifiable
    assert _has_traceable_fact("connection cap is 9999999", corpus) is False


# ── #2 tail_logs honors filter_pattern + paginates for recency ─────────────────
def test_tail_logs_passes_filter_and_keeps_recent(monkeypatch):
    import cloudctl.mcp.tools.debug as dbg

    captured = {}

    class _Fetcher:
        def __init__(self, *_a, **_k):
            pass

        def cloudwatch_logs(self, log_group, minutes, filter_pattern="", max_events=100):
            captured["filter_pattern"] = filter_pattern
            captured["called"] = True
            # Return one event only for the first candidate
            if log_group == "svc":
                return [{"time": "t", "source": "s", "event": "ERROR boom"}]
            return []

        def discover_log_groups(self, hint):
            return []

        def tail_log_group(self, grp, lines=50):
            return []

    monkeypatch.setattr(dbg, "_make_session", lambda *a, **k: object())
    monkeypatch.setattr("cloudctl.debug.fetcher.DebugFetcher", _Fetcher)

    out = json.loads(dbg.tail_logs(
        resource_hint="svc", minutes=60, profile=None, region="us-east-1",
        max_events=50, filter_pattern="ERROR",
    ))
    assert captured.get("filter_pattern") == "ERROR"      # honored, not dropped
    assert out["filter_pattern"] == "ERROR"
    assert out["event_count"] == 1


def test_cloudwatch_logs_paginates_and_returns_recent(monkeypatch):
    """filter_log_events returns oldest-first; cloudwatch_logs must page and keep
    the most-recent max_events so a later error burst isn't hidden by startup
    chatter."""
    from cloudctl.debug.fetcher import DebugFetcher

    pages = [
        {"events": [{"timestamp": i, "message": f"old-{i}"} for i in range(1, 101)],
         "nextToken": "p2"},
        {"events": [{"timestamp": 1000 + i, "message": f"recent-{i}"} for i in range(1, 51)]},
    ]

    class _Logs:
        def __init__(self):
            self.calls = 0

        def filter_log_events(self, **kw):
            page = pages[self.calls]
            self.calls += 1
            return page

    class _Session:
        def client(self, name):
            return _Logs()

    f = DebugFetcher(_Session())
    evts = f.cloudwatch_logs(log_group="g", minutes=60, max_events=10)
    # Kept the 10 most-recent (highest timestamps) — all "recent-*", no "old-*"
    assert len(evts) == 10
    assert all("recent-" in e["event"] for e in evts)


# ── #9 calibration winner + arbitration ────────────────────────────────────────
from cloudctl.ai.graph_agent import _calibrate_confidence


def _br(service, evidence, confirmed=False, preds=()):
    return {
        "hypothesis": {"service": service},
        "evidence": list(evidence),
        "confirmed": confirmed,
        "conclusion": "c" if evidence else "",
        "predictions_tested": list(preds),
    }


def test_calibration_scores_the_chosen_branch_not_first():
    # branch order: A first (no confirmed pred), B second (confirmed pred). The
    # report chose B's cause. The HIGH raise must be computed off B, not A[0].
    A = _br("alpha", ["a1", "a2", "a3"], confirmed=False, preds=[])
    B = _br("bravo", ["b1", "b2", "b3"], confirmed=True, preds=[{"verdict": "CONFIRMED"}])
    conf, note = _calibrate_confidence(
        [A, B], agent_conf="MEDIUM",
        chosen_root_cause="the bravo service failed",
    )
    assert conf == "HIGH"                     # raised based on the chosen winner B
    assert note and "confirmed prediction" in note


def test_arbitration_resolves_two_confirmed_contest():
    A = _br("alpha", ["a1", "a2", "a3"], confirmed=True, preds=[{"verdict": "CONFIRMED"}])
    B = _br("bravo", ["b1", "b2", "b3"], confirmed=True, preds=[{"verdict": "CONFIRMED"}])
    # Without arbitration: unresolved -> capped MEDIUM.
    conf_unres, note_unres = _calibrate_confidence([A, B], agent_conf="HIGH")
    assert conf_unres == "MEDIUM" and "unresolved" in note_unres
    # With arbitration: the contest was resolved, defer to the chosen winner.
    conf_res, _ = _calibrate_confidence(
        [A, B], agent_conf="HIGH", chosen_root_cause="alpha failed", arbitrated=True,
    )
    assert conf_res == "HIGH"


# ── #12 truncation keeps valid JSON + recent tail ──────────────────────────────
def test_truncate_keeps_valid_json_and_recent_tail():
    from cloudctl.mcp.tools.debug import _truncate_tool_output, _MAX_TOOL_OUTPUT_CHARS

    big = {
        "resource_hint": "svc",
        "event_count": 400,
        "events": [{"time": i, "event": f"line-{i}-" + "x" * 40} for i in range(400)],
    }
    raw = json.dumps(big, separators=(",", ":"))
    assert len(raw) > _MAX_TOOL_OUTPUT_CHARS
    out = _truncate_tool_output(raw, "tail_logs")
    assert len(out) <= _MAX_TOOL_OUTPUT_CHARS + 80
    parsed = json.loads(out)                    # still valid JSON (no middle cut)
    # summary fields survive; the recent tail (highest indices) is retained
    assert parsed["resource_hint"] == "svc"
    kept = [e["time"] for e in parsed["events"]]
    assert max(kept) == 399                      # most-recent kept

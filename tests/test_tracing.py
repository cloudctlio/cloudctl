"""X-Ray distributed-tracing fusion (Feature 2).

get_traces distills AWS X-Ray into a compact structured signal — the service
dependency graph (per-edge latency/error/fault/throttle rates) plus the top
slow and top fault-bearing traces, each fault localized to its culprit segment.
No raw segment dumps. Graceful by design: an account with no X-Ray (not enabled,
empty window, or AccessDenied) yields a clear "no trace data" result, never an
exception, so incidents without tracing are unaffected.

Everything is mocked with a fake xray client — NO live AWS. All service/operation
names are invented to prove the distillation carries zero hardcoded service list.
"""
from __future__ import annotations

import json

import pytest

from botocore.exceptions import ClientError

from cloudctl.debug.fetcher import DebugFetcher


@pytest.fixture(autouse=True)
def _clear_tool_cache():
    """get_traces is @recordable, which session-caches results by input for 300s.
    Two tests that call it with identical args would otherwise see each other's
    cached output — clear the cache between tests for isolation."""
    from cloudctl.mcp.tools.recorder import reset_replay_state
    reset_replay_state()
    yield
    reset_replay_state()


# ── fake X-Ray client + session ───────────────────────────────────────────────

class _FakeXRay:
    def __init__(self, *, graph=None, summaries=None, traces=None,
                 raise_on=None):
        self._graph = graph if graph is not None else []
        self._summaries = summaries if summaries is not None else []
        self._traces = traces if traces is not None else []
        self._raise_on = raise_on or {}

    def _maybe_raise(self, op):
        if op in self._raise_on:
            raise self._raise_on[op]

    def get_service_graph(self, **kw):
        self._maybe_raise("get_service_graph")
        return {"Services": self._graph, "NextToken": None}

    def get_trace_summaries(self, **kw):
        self._maybe_raise("get_trace_summaries")
        return {"TraceSummaries": self._summaries, "NextToken": None}

    def batch_get_traces(self, **kw):
        self._maybe_raise("batch_get_traces")
        ids = set(kw.get("TraceIds", []))
        return {"Traces": [t for t in self._traces if t.get("Id") in ids]}


class _FakeSession:
    def __init__(self, client_obj):
        self._client = client_obj

    def client(self, name, **kw):
        return self._client


def _access_denied(op):
    return ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "no"}}, op
    )


def _stats(total, response_time_s, errors=0, faults=0, throttles=0):
    return {
        "TotalCount": total,
        "TotalResponseTime": response_time_s,
        "ErrorStatistics": {"TotalCount": errors, "ThrottleCount": throttles},
        "FaultStatistics": {"TotalCount": faults},
    }


def _seg_doc(name, *, start=0.0, end=1.0, fault=False, error=False,
             throttle=False, http_method=None, subsegments=None):
    doc = {"name": name, "start_time": start, "end_time": end}
    if fault:
        doc["fault"] = True
    if error:
        doc["error"] = True
    if throttle:
        doc["throttle"] = True
    if http_method:
        doc["http"] = {"request": {"method": http_method}}
    if subsegments:
        doc["subsegments"] = subsegments
    return doc


def _trace(trace_id, segment_docs):
    return {"Id": trace_id,
            "Segments": [{"Document": json.dumps(d)} for d in segment_docs]}


# ── (a) high-fault edge is surfaced and named ─────────────────────────────────

def test_high_fault_edge_named_in_service_graph():
    graph = [
        {"ReferenceId": 0, "Name": "frontgate-svc", "Type": "invented::Node",
         "SummaryStatistics": _stats(1000, 200.0, errors=1),
         "Edges": [
             {"ReferenceId": 1,
              "SummaryStatistics": _stats(500, 400.0, faults=450)},  # 90% fault
         ]},
        {"ReferenceId": 1, "Name": "ledger-store", "Type": "invented::Store",
         "SummaryStatistics": _stats(500, 400.0, faults=450), "Edges": []},
    ]
    f = DebugFetcher(_FakeSession(_FakeXRay(graph=graph)))
    out = f.xray_traces(minutes=60)

    assert out["available"] is True
    rows = out["service_graph_summary"]
    assert rows, "expected distilled service-graph rows"
    # Highest fault concentration must sort to the front and name the edge.
    top = rows[0]
    assert top["fault_rate"] >= 0.8
    assert "ledger-store" in top["edge"]
    assert top["service"] == "frontgate-svc"
    assert top["avg_latency_ms"] > 0


# ── (b) a slow trace is surfaced with its latency ─────────────────────────────

def test_slow_trace_surfaced_with_latency():
    summaries = [
        {"Id": "1-slow", "Duration": 4.5, "HasError": False,
         "HasFault": False, "HasThrottle": False},
        {"Id": "1-fast", "Duration": 0.05, "HasError": False,
         "HasFault": False, "HasThrottle": False},
    ]
    f = DebugFetcher(_FakeSession(_FakeXRay(summaries=summaries)))
    out = f.xray_traces(minutes=30)

    assert out["available"] is True
    slow = out["top_slow_traces"]
    assert slow[0]["trace_id"] == "1-slow"
    assert slow[0]["duration_ms"] == pytest.approx(4500.0)


def test_fault_trace_localized_to_culprit_segment():
    summaries = [
        {"Id": "1-badtrace", "Duration": 2.0, "HasError": False,
         "HasFault": True, "HasThrottle": False},
    ]
    # Root segment is fine; the fault lives in a downstream subsegment.
    root = _seg_doc(
        "frontgate-svc", start=0.0, end=2.0,
        subsegments=[_seg_doc("ledger-store", start=0.5, end=1.9,
                              fault=True, http_method="POST")],
    )
    traces = [_trace("1-badtrace", [root])]
    f = DebugFetcher(_FakeSession(_FakeXRay(summaries=summaries, traces=traces)))
    out = f.xray_traces(minutes=30)

    faults = out["top_fault_traces"]
    assert faults, "expected a localized fault trace"
    assert faults[0]["trace_id"] == "1-badtrace"
    assert faults[0]["culprit_service"] == "ledger-store"
    assert faults[0]["culprit_op"] == "POST"
    assert faults[0]["fault_type"] == "fault"


# ── (c) graceful degradation — no exception when X-Ray is unavailable ─────────

def test_empty_xray_returns_graceful_signal():
    f = DebugFetcher(_FakeSession(_FakeXRay(graph=[], summaries=[])))
    out = f.xray_traces(minutes=60)
    assert out["available"] is False
    assert "no trace data" in out["reason"].lower()
    assert out["service_graph_summary"] == []
    assert out["top_slow_traces"] == []
    assert out["top_fault_traces"] == []


def test_access_denied_is_graceful_not_raised():
    xray = _FakeXRay(raise_on={"get_service_graph": _access_denied("GetServiceGraph")})
    f = DebugFetcher(_FakeSession(xray))
    out = f.xray_traces(minutes=60)   # must NOT raise
    assert out["available"] is False
    assert "denied" in out["reason"].lower()


def test_no_session_returns_graceful_signal():
    f = DebugFetcher(None)
    out = f.xray_traces(minutes=60)
    assert out["available"] is False
    assert out["top_fault_traces"] == []


def test_tool_wrapper_degrades_on_unexpected_error(monkeypatch):
    """The get_traces tool must convert ANY failure into the informative signal
    (a trace lookup can never derail an investigation) and always return JSON."""
    import cloudctl.mcp.tools.debug as dbg

    def _boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(dbg, "_make_session", _boom)
    raw = dbg.get_traces(profile=None, region="us-east-1", minutes=60)
    out = json.loads(raw)
    assert out["available"] is False
    assert out["service_graph_summary"] == []


def test_tool_wrapper_returns_distilled_json(monkeypatch):
    import cloudctl.mcp.tools.debug as dbg

    graph = [
        {"ReferenceId": 0, "Name": "alpha-svc", "Type": "t",
         "SummaryStatistics": _stats(10, 5.0, faults=9), "Edges": []},
    ]
    monkeypatch.setattr(
        dbg, "_make_session",
        lambda *a, **k: _FakeSession(_FakeXRay(graph=graph)),
    )
    out = json.loads(dbg.get_traces(profile=None, region="us-east-1", minutes=60))
    assert out["available"] is True
    assert any(r["service"] == "alpha-svc" for r in out["service_graph_summary"])


# ── (d) fully generic — an invented service works with no hardcoded list ──────

def test_matching_is_generic_invented_service():
    graph = [
        {"ReferenceId": 0, "Name": "zqwibble-router", "Type": "made::Up",
         "SummaryStatistics": _stats(300, 90.0, throttles=120),
         "Edges": [{"ReferenceId": 1,
                    "SummaryStatistics": _stats(300, 90.0, throttles=120)}]},
        {"ReferenceId": 1, "Name": "flarnblat-queue", "Type": "made::Up2",
         "SummaryStatistics": _stats(300, 90.0, throttles=120), "Edges": []},
    ]
    summaries = [
        {"Id": "1-zzz", "Duration": 3.3, "HasError": False,
         "HasFault": False, "HasThrottle": True},
    ]
    traces = [_trace("1-zzz", [
        _seg_doc("zqwibble-router", start=0.0, end=3.3,
                 subsegments=[_seg_doc("flarnblat-queue", start=0.1, end=3.2,
                                      throttle=True, http_method="GET")]),
    ])]
    f = DebugFetcher(_FakeSession(_FakeXRay(
        graph=graph, summaries=summaries, traces=traces)))
    out = f.xray_traces(minutes=60)

    assert out["available"] is True
    # The distiller carries no service vocabulary — invented names flow through.
    assert any("flarnblat-queue" in r["edge"] for r in out["service_graph_summary"])
    assert out["top_fault_traces"][0]["culprit_service"] == "flarnblat-queue"
    assert out["top_fault_traces"][0]["fault_type"] == "throttle"


# ── (e) truncation — a huge trace set stays compact ───────────────────────────

def test_huge_trace_set_stays_within_output_cap():
    from cloudctl.mcp.tools.debug import (
        _truncate_tool_output, _MAX_TOOL_OUTPUT_CHARS,
    )

    # 5000 input trace summaries + a large graph. The distiller caps graph rows
    # (≤20) and offender lists (≤5 each), so the output is small regardless.
    summaries = [
        {"Id": f"1-{i:05d}", "Duration": (i % 50) / 10.0,
         "HasError": bool(i % 7 == 0), "HasFault": bool(i % 11 == 0),
         "HasThrottle": False}
        for i in range(5000)
    ]
    graph = [
        {"ReferenceId": i, "Name": f"svc-{i}", "Type": "t",
         "SummaryStatistics": _stats(100, 10.0, faults=i % 10),
         "Edges": [{"ReferenceId": (i + 1) % 200,
                    "SummaryStatistics": _stats(100, 10.0, faults=i % 10)}]}
        for i in range(200)
    ]
    faulted_id = "1-00011"
    traces = [_trace(faulted_id, [
        _seg_doc("svc-a", start=0.0, end=2.0,
                 subsegments=[_seg_doc("svc-b", start=0.2, end=1.8, fault=True)]),
    ])]
    f = DebugFetcher(_FakeSession(_FakeXRay(
        graph=graph, summaries=summaries, traces=traces)))
    out = f.xray_traces(minutes=60)

    assert len(out["service_graph_summary"]) <= 20
    assert len(out["top_slow_traces"]) <= 5
    assert len(out["top_fault_traces"]) <= 5

    distilled = json.dumps(out, separators=(",", ":"))
    # Already compact — well within the tool-output budget before truncation.
    assert len(distilled) <= _MAX_TOOL_OUTPUT_CHARS
    # And truncation leaves it valid JSON untouched.
    kept = _truncate_tool_output(distilled, "get_traces")
    assert json.loads(kept)["available"] is True


# ── observability-gap recommendation (Feature 2 addendum) ─────────────────────

def _unavailable_corpus():
    """all_fetched as it looks after get_traces returned no data."""
    return {"get_traces": {"available": False,
                           "reason": "no trace data available",
                           "service_graph_summary": [],
                           "top_slow_traces": [], "top_fault_traces": []}}


def _available_corpus():
    return {"get_traces": {"available": True, "reason": "",
                           "service_graph_summary": [{"service": "x", "edge": "x",
                                                      "fault_rate": 0.5}],
                           "top_slow_traces": [], "top_fault_traces": []}}


def test_recommendation_added_for_latency_class_when_traces_unavailable():
    from cloudctl.ai.graph_agent import _maybe_add_tracing_recommendation
    report = {"root_cause": "rc", "confidence": "MEDIUM", "remediation_steps": ["fix it"]}
    out = _maybe_add_tracing_recommendation(
        dict(report), "checkout requests are slow and timing out",
        _unavailable_corpus(),
    )
    joined = " ".join(out["remediation_steps"])
    assert "distributed tracing was available" in joined
    # remediation-only: root_cause and confidence untouched
    assert out["root_cause"] == "rc"
    assert out["confidence"] == "MEDIUM"


def test_recommendation_not_added_when_traces_available():
    from cloudctl.ai.graph_agent import _maybe_add_tracing_recommendation
    report = {"root_cause": "rc", "remediation_steps": ["fix it"]}
    out = _maybe_add_tracing_recommendation(
        dict(report), "latency spike, requests timing out", _available_corpus(),
    )
    assert all("distributed tracing" not in str(s) for s in out["remediation_steps"])


def test_recommendation_not_added_for_non_latency_symptom():
    from cloudctl.ai.graph_agent import _maybe_add_tracing_recommendation
    report = {"root_cause": "rc", "remediation_steps": ["fix it"]}
    out = _maybe_add_tracing_recommendation(
        dict(report), "access denied writing to the bucket", _unavailable_corpus(),
    )
    assert all("distributed tracing" not in str(s) for s in out["remediation_steps"])


def test_recommendation_not_added_when_traces_never_queried():
    from cloudctl.ai.graph_agent import _maybe_add_tracing_recommendation
    report = {"root_cause": "rc", "remediation_steps": ["fix it"]}
    out = _maybe_add_tracing_recommendation(
        dict(report), "everything is slow and degraded", {},  # no get_traces call
    )
    assert all("distributed tracing" not in str(s) for s in out["remediation_steps"])


def test_recommendation_not_duplicated():
    from cloudctl.ai.graph_agent import (
        _maybe_add_tracing_recommendation, _TRACING_RECOMMENDATION,
    )
    report = {"root_cause": "rc",
              "remediation_steps": ["fix it", _TRACING_RECOMMENDATION]}
    out = _maybe_add_tracing_recommendation(
        dict(report), "slow latency timeout", _unavailable_corpus(),
    )
    n = sum(1 for s in out["remediation_steps"]
            if "distributed tracing was available" in str(s))
    assert n == 1


def test_generic_latency_classification_no_service_literals():
    """Classification keys off symptom SHAPE only — an invented service in a
    latency-shaped symptom still classifies, and a non-latency symptom does not,
    regardless of service words."""
    from cloudctl.ai.graph_agent import _is_latency_propagation_class
    assert _is_latency_propagation_class("the zqwibble-router is responding slowly")
    assert _is_latency_propagation_class("errors propagate downstream from flarnblat")
    assert not _is_latency_propagation_class("zqwibble-router returns wrong data")
    assert not _is_latency_propagation_class("permission denied on flarnblat-queue")

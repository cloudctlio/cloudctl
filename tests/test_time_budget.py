"""Time budget: an agent-mode investigation ends with a verdict inside its
wall-clock budget, even when the model never stops asking for tools and some
AWS reads are slow or hang.

Everything here is stubbed: no AWS and no model. Latencies are scaled down
(a budget of a few seconds instead of 8 minutes) so the suite stays fast; the
phase plan is fractional, so the same proportions apply at full size.
"""
from __future__ import annotations

import json
import threading
import time

import pytest

import cloudctl.ai.budget as B
import cloudctl.ai.graph_agent as g


# ── RunBudget unit behavior ───────────────────────────────────────────────────

class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_unbounded_budget_never_limits():
    b = B.RunBudget.unbounded()
    assert not b.bounded
    assert b.left("observe") == float("inf")
    assert b.room_for(1000)
    assert not b.should_wrap_up("investigate")
    assert all(b.take_tool_call() for _ in range(500))


def test_phase_plan_leaves_a_verdict_reserve():
    clk = _Clock()
    b = B.RunBudget(100.0, clock=clk)
    assert b.left("observe") == pytest.approx(15.0)
    assert b.left("triage") == pytest.approx(25.0)
    assert b.left("investigate") == pytest.approx(70.0)
    assert b.left("verdict") == pytest.approx(100.0)
    clk.t += 80
    assert b.left("investigate") == 0.0           # branches must be done
    assert b.left("verdict") == pytest.approx(20.0)  # verdict stages still have time


def test_wrap_up_when_less_than_two_calls_remain():
    clk = _Clock()
    b = B.RunBudget(100.0, clock=clk)
    b.observe_call(5.0)                            # first sample replaces the prior
    assert b.est_call_s() == pytest.approx(5.0)
    clk.t += 70 - 11                               # 11 s of investigate left
    assert not b.should_wrap_up("investigate")
    clk.t += 2                                     # 9 s left < 2 x 5 s
    assert b.should_wrap_up("investigate")


def test_wrap_up_counts_the_tool_round_a_turn_triggers():
    """A tool-using turn costs the model call AND the tool round it asks for;
    wrapping up on model time alone left branches with no time to conclude."""
    clk = _Clock()
    b = B.RunBudget(100.0, clock=clk)
    b.observe_call(1.0)
    clk.t += 70 - 5                                # 5 s of investigate left
    assert not b.should_wrap_up("investigate")     # 2 x 1 s model time fits
    b.observe_tool_round(4.0)                      # but a slow tool round doesn't
    assert b.should_wrap_up("investigate")


def test_open_phase_never_eats_the_verdict_reserve():
    clk = _Clock()
    b = B.RunBudget(100.0, clock=clk)
    b.observe_call(10.0)
    clk.t += 60                                    # 40 s left overall
    granted = b.open_phase("arbitration", seconds=300, reserve_calls=3)
    assert granted == pytest.approx(10.0)          # 40 - 3 x 10
    assert b.left("arbitration") == pytest.approx(10.0)
    clk.t += 35                                    # 5 s left: nothing to grant
    assert b.open_phase("reinvestigate", seconds=300, reserve_calls=3) == 0.0


def test_cancel_stops_everything():
    b = B.RunBudget(100.0)
    b.cancel()
    assert b.left("verdict") == 0.0
    assert b.should_wrap_up("observe")
    with pytest.raises(B.BudgetSpent):
        B.converse(b, object(), "verdict", modelId="m")


def test_run_wide_tool_cap():
    b = B.RunBudget(100.0, max_tool_calls=3)
    assert [b.take_tool_call() for _ in range(5)] == [True, True, True, False, False]


def test_env_off_switch(monkeypatch):
    monkeypatch.setenv("CLOUDCTL_TIME_BUDGET_S", "off")
    assert not B.RunBudget.from_env().bounded
    monkeypatch.setenv("CLOUDCTL_TIME_BUDGET_S", "300")
    b = B.RunBudget.from_env()
    assert b.total == 300
    monkeypatch.delenv("CLOUDCTL_INVESTIGATION_CEILING_S", raising=False)
    assert B.ceiling_s(b) == 360                   # budget + 60 s grace
    monkeypatch.delenv("CLOUDCTL_TIME_BUDGET_S")
    assert B.RunBudget.from_env().total == B.DEFAULT_BUDGET_S == 480
    assert B.ceiling_s(B.RunBudget.from_env()) <= 600   # never past 10 minutes


# ── abandonable calls ─────────────────────────────────────────────────────────

def test_run_with_timeout_abandons_a_hung_call():
    t0 = time.monotonic()
    with pytest.raises(B.BudgetSpent):
        B.run_with_timeout(lambda: time.sleep(5), 0.3)
    assert time.monotonic() - t0 < 1.0


def test_run_with_timeout_reraises_errors_and_returns_values():
    assert B.run_with_timeout(lambda: 42, 1.0) == 42
    with pytest.raises(ValueError):
        B.run_with_timeout(lambda: (_ for _ in ()).throw(ValueError("x")), 1.0)


def test_budgeted_converse_feeds_the_estimate_and_abandons_slow_calls():
    class Slow:
        def __init__(self, s):
            self.s = s

        def converse(self, **kw):
            time.sleep(self.s)
            return {"ok": True}

    b = B.RunBudget(10.0)
    assert B.converse(b, Slow(0.1), "verdict", modelId="m") == {"ok": True}
    assert b.est_call_s() == pytest.approx(0.1, abs=0.08)
    b2 = B.RunBudget(0.5)
    t0 = time.monotonic()
    with pytest.raises(B.BudgetSpent):
        B.converse(b2, Slow(5), "verdict", modelId="m")
    assert time.monotonic() - t0 < 1.5


# ── parallel tool dispatch ────────────────────────────────────────────────────

def _sleepy(seconds_by_tool):
    def fetch(name, inp):
        time.sleep(seconds_by_tool.get(name, 0))
        return json.dumps({"tool": name})
    return fetch


def test_tools_in_one_turn_run_in_parallel():
    b = B.RunBudget(30.0)
    calls = [("a", {}), ("b", {}), ("c", {})]
    t0 = time.monotonic()
    out = B.run_tools(b, "verdict", calls, _sleepy({"a": 0.5, "b": 0.5, "c": 0.5}))
    took = time.monotonic() - t0
    assert [json.loads(o)["tool"] for o in out] == ["a", "b", "c"]   # order kept
    assert took < 1.0                               # serial would be 1.5 s


def test_hung_tool_is_abandoned_at_the_tool_timeout():
    b = B.RunBudget(30.0, tool_timeout_s=0.4)
    t0 = time.monotonic()
    out = B.run_tools(b, "verdict", [("fast", {}), ("hung", {})],
                      _sleepy({"fast": 0.05, "hung": 10}))
    assert time.monotonic() - t0 < 1.0
    assert json.loads(out[0])["tool"] == "fast"
    assert json.loads(out[1])["timed_out"] is True


def test_tool_caps_answer_without_running():
    ran = []

    def fetch(name, inp):
        ran.append(name)
        return "{}"

    b = B.RunBudget(30.0, max_tool_calls=2)
    out = B.run_tools(b, "verdict", [("a", {}), ("b", {}), ("c", {})], fetch)
    assert sorted(ran) == ["a", "b"]
    assert "budget" in json.loads(out[2])["error"]
    ran.clear()
    b2 = B.RunBudget(30.0)
    out = B.run_tools(b2, "verdict", [("a", {}), ("b", {})], fetch, per_call_cap=1)
    assert ran == ["a"] and "budget" in json.loads(out[1])["error"]


def test_consent_tools_never_run_in_parallel():
    active = {"n": 0, "max": 0}
    lock = threading.Lock()

    def fetch(name, inp):
        with lock:
            active["n"] += 1
            active["max"] = max(active["max"], active["n"])
        time.sleep(0.1)
        with lock:
            active["n"] -= 1
        return "{}"

    b = B.RunBudget(30.0)
    B.run_tools(b, "verdict", [("probe_http", {}), ("probe_http", {})], fetch)
    assert active["max"] == 1


def test_unbounded_dispatch_is_sequential_and_unchanged():
    order = []

    def fetch(name, inp):
        order.append(name)
        return name

    assert B.run_tools(B.RunBudget.unbounded(), "x", [("a", {}), ("b", {})], fetch) == ["a", "b"]
    assert order == ["a", "b"]


# ── tool-plane caching and pacing ─────────────────────────────────────────────

def test_concurrent_identical_reads_share_one_fetch(monkeypatch):
    from cloudctl.mcp.tools import recorder as rec
    monkeypatch.delenv("CLOUDCTL_REPLAY", raising=False)
    monkeypatch.delenv("CLOUDCTL_RECORD", raising=False)
    rec.reset_replay_state()
    calls = {"n": 0}

    @rec.recordable("t_singleflight")
    def slow_read(resource_name: str) -> str:
        calls["n"] += 1
        time.sleep(0.3)
        return json.dumps({"r": resource_name})

    threads = [threading.Thread(target=slow_read, args=("x",)) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert calls["n"] == 1
    rec.reset_replay_state()


def test_inventory_is_enumerated_once_for_many_filters(monkeypatch):
    import cloudctl.mcp.tools.debug as D
    from cloudctl.mcp.tools import recorder as rec
    monkeypatch.delenv("CLOUDCTL_REPLAY", raising=False)
    rec.reset_replay_state()
    n = {"enum": 0}

    def enum(session):
        n["enum"] += 1
        return [{"arn": "arn:aws:dynamodb:us-east-1:1:table/orders",
                 "service": "dynamodb", "name": "orders"},
                {"arn": "arn:aws:lambda:us-east-1:1:function:api",
                 "service": "lambda", "name": "api"}]

    monkeypatch.setattr(D, "_enumerate_resources", enum)
    monkeypatch.setattr(D, "_make_session", lambda p, r: object())
    a = json.loads(D.list_resources("dynamodb", None, "us-east-1"))
    b = json.loads(D.list_resources("lambda", None, "us-east-1"))
    c = json.loads(D.list_resources("", None, "us-east-1"))
    assert n["enum"] == 1
    assert a["resources"] == ["orders"] and b["resources"] == ["api"] and c["count"] == 2
    rec.reset_replay_state()


def test_cloudtrail_lookups_are_paced_across_threads(monkeypatch):
    from cloudctl.debug.fetcher import DebugFetcher, ct_pace
    monkeypatch.setattr(DebugFetcher, "_CT_MIN_INTERVAL", 0.1)
    DebugFetcher._ct_next[0] = 0.0
    stamps = []
    lock = threading.Lock()

    def worker():
        for _ in range(3):
            ct_pace()
            with lock:
                stamps.append(time.monotonic())

    ts = [threading.Thread(target=worker) for _ in range(3)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    stamps.sort()
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    assert len(stamps) == 9
    assert min(gaps) >= 0.08          # never two lookups closer than the interval


def test_tail_logs_returns_partial_results_at_its_soft_cap(monkeypatch):
    import cloudctl.mcp.tools.debug as D
    import cloudctl.debug.fetcher as F
    from cloudctl.mcp.tools import recorder as rec
    monkeypatch.delenv("CLOUDCTL_REPLAY", raising=False)
    rec.reset_replay_state()
    monkeypatch.setenv("CLOUDCTL_TAIL_LOGS_SOFT_S", "0.3")
    tried = []

    class FakeFetcher:
        def __init__(self, session):
            pass

        def cloudwatch_logs(self, log_group, **kw):
            tried.append(log_group)
            time.sleep(0.2)
            return []

        def discover_log_groups(self, hint):
            return [f"/g/{i}" for i in range(5)]

        def tail_log_group(self, grp, lines=50):
            return []

    monkeypatch.setattr(F, "DebugFetcher", FakeFetcher)
    monkeypatch.setattr(D, "_make_session", lambda p, r: object())
    t0 = time.monotonic()
    out = json.loads(D.tail_logs("svc", 60, None, "us-east-1", 50))
    assert time.monotonic() - t0 < 1.0     # uncapped: 6 + 5 groups x 0.2 s = 2.2 s
    assert "partial" in out
    assert len(tried) < 11
    rec.reset_replay_state()


# ── fallback verdicts ─────────────────────────────────────────────────────────

def _br(service, conclusion, confirmed=False, preds=(), evidence=("e1",)):
    return {"hypothesis": {"service": service, "reason": f"{service} broke",
                           "focus": f"{service}-res"},
            "conclusion": conclusion, "confirmed": confirmed,
            "evidence": list(evidence), "predictions_tested": list(preds)}


def test_fallback_names_a_confirmed_cause_never_high():
    rep = g._fallback_verdict([
        _br("lambda", "lambda fine"),
        _br("dynamodb", "table throttled", confirmed=True,
            preds=[{"verdict": "CONFIRMED", "observed": "x"}], evidence=("ThrottledRequests=412",)),
    ], "test")
    assert rep["root_cause"] == "table throttled"
    assert rep["verdict_status"] == "BEST_SUPPORTED"
    assert rep["confidence"] == "MEDIUM"
    assert rep["evidence"] == ["ThrottledRequests=412"]
    assert rep["alternatives_considered"][0]["hypothesis"] == "lambda broke"


def test_fallback_says_cant_verify_when_nothing_confirmed():
    rep = g._fallback_verdict([_br("ecs", "tasks restarting", evidence=("a", "b")),
                               _br("alb", "targets healthy")], "test")
    assert rep["verdict_status"] == "UNVERIFIED"
    assert rep["confidence"] == "LOW"
    assert rep["root_cause"].startswith("Could not verify a root cause")
    assert "tasks restarting" in rep["root_cause"]     # best-evidenced lead named


def test_ceiling_report_uses_progress_notes_when_no_branch_finished():
    b = B.RunBudget(10.0)
    b.note_branch("dynamodb:orders", {"hypothesis": {"service": "dynamodb"},
                                      "phase": 1, "conclusion": "write capacity at limit",
                                      "evidence": ["ConsumedWCU=1000"], "confirmed": True})
    rep = g._ceiling_report({}, b, "exceeded the 9s time ceiling")
    assert rep["verdict_status"] == "UNVERIFIED"     # an unfinished branch never confirms
    assert "write capacity at limit" in rep["root_cause"]
    assert rep["evidence"] == ["ConsumedWCU=1000"]


# ── whole-graph timing: a model that never stops asking for tools ─────────────

_HYPS = [
    {"service": "dynamodb", "reason": "orders table is throttling writes",
     "focus": "orders — write throttling",
     "predictions": [{"if_true": "WriteThrottleEvents > 0", "check": "query_metrics",
                      "if_absent": "refutes"}]},
    {"service": "lambda", "reason": "api function is erroring", "focus": "api — errors",
     "predictions": []},
    {"service": "iam", "reason": "api role lost a permission", "focus": "api-role — policy",
     "predictions": []},
]

_EVID = "WriteThrottleEvents=412 on orders"


class _GreedyModel:
    """Stands in for every model call in the graph. Tool-capable steps ALWAYS
    ask for more tools (three per turn) until the wrap-up note arrives — the
    behavior behind the 20-minute runs. Each call takes `latency` seconds."""

    def __init__(self, latency=0.15):
        self.latency = latency
        self.calls = 0
        self.after_wrap_up_tool_requests = 0
        self._lock = threading.Lock()

    @staticmethod
    def _last_user_text(msgs):
        for m in reversed(msgs):
            if m.get("role") == "user":
                return " ".join(c.get("text", "") for c in m.get("content", [])
                                if isinstance(c, dict))
        return ""

    def converse(self, **kw):
        with self._lock:
            self.calls += 1
            n = self.calls
        time.sleep(self.latency)
        system = " ".join(x.get("text", "") for x in kw.get("system", [])
                          if isinstance(x, dict))
        msgs = kw.get("messages", [])
        wrap = B.WRAP_UP_NOTE in self._last_user_text(msgs)

        def text(obj):
            return {"stopReason": "end_turn", "usage": {},
                    "output": {"message": {"role": "assistant",
                                           "content": [{"text": json.dumps(obj)}]}}}

        if kw.get("toolConfig") and not wrap:
            if "triage specialist" in system:
                uses = [("list_resources", {"service_type": "dynamodb"}),
                        ("list_resources", {"service_type": "lambda"})]
            elif "measurement specialist" in system:
                uses = [("query_metrics", {"namespace": "AWS/DynamoDB",
                                           "metric_name": "WriteThrottleEvents"}),
                        ("tail_logs", {"resource_hint": "api"})]
            else:
                uses = [("query_metrics", {"namespace": "AWS/DynamoDB",
                                           "metric_name": f"M{n}"}),
                        ("tail_logs", {"resource_hint": f"api{n}"}),
                        ("get_service_config", {"service_type": "dynamodb",
                                                "resource_name": "orders"})]
            return {"stopReason": "tool_use", "usage": {},
                    "output": {"message": {"role": "assistant", "content": [
                        {"toolUse": {"toolUseId": f"t{n}-{i}", "name": nm, "input": inp}}
                        for i, (nm, inp) in enumerate(uses)]}}}
        if "measurement specialist" in system:
            return text({"symptom_observable_now": True, "onset_estimate": "unknown",
                         "affected_scope": "orders writes", "unaffected_scope": "reads",
                         "measurements": [_EVID]})
        if "triage specialist" in system:
            return {"stopReason": "end_turn", "usage": {},
                    "output": {"message": {"role": "assistant",
                                           "content": [{"text": json.dumps(_HYPS)}]}}}
        if "AWS incident investigator" in system:
            return text({"conclusion": "orders table is throttling writes",
                         "evidence": [_EVID], "confidence": "MEDIUM", "confirmed": True,
                         "phase2_needed": False,
                         "predictions_tested": [{"prediction": "throttle",
                                                 "verdict": "CONFIRMED",
                                                 "observed": _EVID}]})
        if "causal reasoning specialist" in system:
            return text({"cause_category": "infrastructure",
                         "cause_category_confidence": "MEDIUM",
                         "investigation_constraint": "capacity"})
        if "behavioral_consistency" in system or "log analysis specialist" in system:
            return text({"behavioral_consistency": "uniform"})
        if "FALSIFICATION" in system:
            return text({"survived": True, "contradicting_evidence": []})
        if "skeptical senior SRE" in system:
            return text({"verdict": "confirmed"})
        return text({"root_cause": "orders table is throttling writes",
                     "evidence": [_EVID], "remediation_steps": ["raise WCU"],
                     "severity": "HIGH", "confidence": "MEDIUM",
                     "resources_investigated": ["orders"],
                     "alternatives_considered": [
                         {"hypothesis": "lambda errors", "reason": "no errors seen"},
                         {"hypothesis": "iam", "reason": "no denials"}]})


@pytest.fixture()
def _graph_env(monkeypatch, tmp_path):
    """Stub every AWS-touching tool (with latency; tail_logs hangs) and the
    run's side effects, so debug_incident_graph runs end to end offline."""
    import cloudctl.mcp.tools.debug as dbg
    import cloudctl.ai.guardrails as gr
    from cloudctl.mcp.tools import recorder as rec

    monkeypatch.setenv("HOME", str(tmp_path))
    for k in ("CLOUDCTL_REPLAY", "CLOUDCTL_RECORD", "CLOUDCTL_INTERACTIVE",
              "CLOUDCTL_INVESTIGATION_CEILING_S", "CLOUDCTL_INVESTIGATION_BUDGET_USD",
              "CLOUDCTL_RESUME_THREAD"):
        monkeypatch.delenv(k, raising=False)
    rec.reset_replay_state()
    monkeypatch.setattr(g, "_graph", None)

    def slow(payload, seconds):
        def f(*a, **k):
            time.sleep(seconds)
            return json.dumps(payload)
        return f

    inv = {"service_type": "", "count": 2, "resources": ["orders", "api"],
           "resources_detailed": [{"service": "dynamodb", "name": "orders", "arn": "a"},
                                  {"service": "lambda", "name": "api", "arn": "b"}]}
    monkeypatch.setattr(dbg, "list_resources", slow(inv, 0.3))
    monkeypatch.setattr(dbg, "get_dependency_graph", slow({"nodes": ["orders", "api"]}, 0.4))
    monkeypatch.setattr(dbg, "get_event_timeline", slow({"timeline": [], "note": _EVID}, 0.5))
    monkeypatch.setattr(dbg, "query_metrics", slow({"datapoints": [_EVID]}, 0.3))
    monkeypatch.setattr(dbg, "get_service_config", slow({"config": "orders WCU=1000"}, 0.3))
    monkeypatch.setattr(dbg, "get_deployment_info", slow({"deployment_source": "unknown"}, 0.1))
    # A log read that hangs, like a FilterLogEvents scan on a flooded group.
    monkeypatch.setattr(dbg, "tail_logs", slow({"events": []}, 30))
    monkeypatch.setattr(dbg, "_get_account_id", lambda p, r: "123456789012")
    monkeypatch.setattr(g, "_log_survey", lambda p, r, m: (time.sleep(0.5), {
        "events": [f"[t] [api] {_EVID}"], "groups": ["/aws/lambda/api"],
        "templates": [], "error": "", "failure_map": []})[1])
    for name in ("audit_log_tool_call", "audit_log_agent_call"):
        monkeypatch.setattr(gr, name, lambda **k: None)
    monkeypatch.setattr(gr, "check_rate_limit",
                        lambda: gr.GuardrailResult(allowed=True, reason="", sanitised=""))
    model = _GreedyModel()
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: model)
    yield model
    rec.reset_replay_state()


def test_greedy_run_ends_with_a_verdict_inside_the_budget(monkeypatch, _graph_env):
    model = _graph_env
    monkeypatch.setenv("CLOUDCTL_TIME_BUDGET_S", "8")
    monkeypatch.setenv("CLOUDCTL_TOOL_TIMEOUT_S", "1.5")
    t0 = time.monotonic()
    raw, fetched = g.debug_incident_graph("orders API returns 500s", profile=None)
    took = time.monotonic() - t0
    rep = json.loads(raw)

    assert took < 8 + 1.0, f"took {took:.1f}s for an 8s budget"
    assert not rep.get("_timed_out"), rep.get("_timing")
    assert "throttling" in rep["root_cause"]
    timing = rep["_timing"]
    assert timing["budget_s"] == 8 and timing["within_budget"]
    # the hung log reads were abandoned, not waited for
    assert any("tail_logs abandoned" in e for e in timing["events"])
    # nothing ran past the forced last turn: once told to wrap up, the model
    # was never handed another tool result
    assert timing["tool_calls"] <= B.DEFAULT_MAX_TOOL_CALLS


def test_outer_ceiling_still_returns_a_verdict_and_stops_the_worker(monkeypatch, _graph_env):
    model = _graph_env
    # The ceiling (3 s) fires mid-investigation, well before the 8 s budget.
    monkeypatch.setenv("CLOUDCTL_TIME_BUDGET_S", "8")
    monkeypatch.setenv("CLOUDCTL_INVESTIGATION_CEILING_S", "3")
    monkeypatch.setenv("CLOUDCTL_TOOL_TIMEOUT_S", "1.5")
    t0 = time.monotonic()
    raw, _ = g.debug_incident_graph("orders API returns 500s", profile=None)
    assert time.monotonic() - t0 < 3 + 1.0
    rep = json.loads(raw)
    assert rep["_timed_out"] is True
    assert rep["root_cause"]                       # never "no conclusion"
    assert rep["confidence"] in ("LOW", "MEDIUM")
    # The abandoned graph worker sees the cancel flag and stops calling the
    # model (it used to keep running in the background).
    time.sleep(1.0)
    settled = model.calls
    time.sleep(1.5)
    assert model.calls - settled <= 1


def test_without_the_budget_the_same_model_makes_many_serial_calls(monkeypatch, _graph_env):
    """Evidence for the diagnosis: with the budget off and zero latency, count
    how many model calls the old turn limits allow when the model keeps asking
    for tools. At ~15-25 s per real Sonnet call this is the 20-minute run."""
    import cloudctl.mcp.tools.debug as dbg
    model = _graph_env
    model.latency = 0.0
    monkeypatch.setattr(dbg, "tail_logs", lambda *a, **k: json.dumps({"events": []}))
    monkeypatch.setenv("CLOUDCTL_TIME_BUDGET_S", "off")
    raw, _ = g.debug_incident_graph("orders API returns 500s", profile=None)
    rep = json.loads(raw)
    # observe 8 + triage 6 + branches 3 x (6 + 7 + 4 at most) + verdict calls
    assert model.calls >= 30, model.calls
    assert rep["_timing"]["budget_s"] is None

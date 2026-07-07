"""Value-of-information adaptive scheduling (Feature 5).

A branch may STOP its tool loop early only when its hypothesis is DECISIVELY
resolved AND the accuracy floor is satisfied (mandatory tools called +
predictions tested, with a traceable confirmation). Otherwise it keeps
investigating, and the hard per-phase ceiling is always respected. VOI only ever
stops EARLIER than today — never adds a call.

NOTE (honesty): the deterministic stop predicate + ceiling/floor are unit-proven
here. The VOI next-tool STEER is a prompt rule whose speed/accuracy effect is
only measurable live — no accuracy claim is made from these tests.
"""
from __future__ import annotations

import json

import pytest

from cloudctl.ai import graph_agent as g
from cloudctl.ai.guardrails import _MANDATORY_TOOLS


_MAND = set(_MANDATORY_TOOLS["always"])
_CORPUS = "pool-token-9931 saturation; error-4913 at 100/100".lower()


def _confirmed(observed="pool-token-9931 saturated"):
    return {"predictions_tested": [{"verdict": "CONFIRMED", "observed": observed}]}


# ── (a) decisively confirmed + floor met → STOP ───────────────────────────────

def test_stop_when_confirmed_and_floor_met():
    assert g._voi_should_stop_branch(_confirmed(), _MAND, "svc is slow", _CORPUS) is True


def test_refuted_prediction_is_decisive_stop():
    concl = {"predictions_tested": [{"verdict": "REFUTED", "observed": "x"}]}
    assert g._voi_should_stop_branch(concl, _MAND, "svc is slow", _CORPUS) is True


# ── (b) floor NOT met → do NOT stop (cannot cut accuracy) ─────────────────────

def test_no_stop_when_mandatory_tool_missing():
    missing = _MAND - {"tail_logs"}
    assert g._voi_should_stop_branch(_confirmed(), missing, "svc is slow", _CORPUS) is False


def test_no_stop_when_predictions_untested():
    concl = {"predictions_tested": [{"verdict": "UNTESTED", "observed": "x"}]}
    assert g._voi_should_stop_branch(concl, _MAND, "svc is slow", _CORPUS) is False


def test_no_stop_when_no_predictions_at_all():
    assert g._voi_should_stop_branch({"predictions_tested": []}, _MAND, "s", _CORPUS) is False


def test_no_stop_when_confirmation_not_traceable():
    # confirmed but the observed fact appears nowhere in the fetched corpus
    concl = {"predictions_tested": [{"verdict": "CONFIRMED", "observed": "imaginary-xyz-thing"}]}
    assert g._voi_should_stop_branch(concl, _MAND, "svc is slow", _CORPUS) is False


# ── (c) unresolved / ambiguous → do NOT stop (conservative default) ───────────

def test_no_stop_when_no_conclusion_yet():
    assert g._voi_should_stop_branch(None, _MAND, "svc is slow", _CORPUS) is False


def test_no_stop_on_non_dict_conclusion():
    assert g._voi_should_stop_branch("not a dict", _MAND, "svc is slow", _CORPUS) is False


# ── (e) VOI prompt rule present + hint-free ───────────────────────────────────

_BLOCKLIST = [
    "dynamodb", "lambda", "s3", "cognito", "throttle", "oom", "kms",
    "bedrock", "sagemaker", "opensearch", "vector", "iam", "rds", "sqs",
    "sns", "ec2", "ecs", "alb", "nacl", "vpc", "cloudwatch", "kinesis",
    "429", "5xx", "accessdenied",
]


def test_voi_rule_present_in_branch_prompt():
    assert "VALUE-OF-INFORMATION rule" in g._PHASE2_SYSTEM
    assert "most CHANGE which hypothesis is favored" in g._PHASE2_SYSTEM


def test_voi_rule_is_hint_free():
    # isolate the VOI rule paragraph and check it names no service/scenario
    txt = g._PHASE2_SYSTEM
    start = txt.index("VALUE-OF-INFORMATION rule")
    para = txt[start:start + 600].lower()
    hits = [w for w in _BLOCKLIST if w in para]
    assert hits == [], f"VOI rule leaked hint literals: {hits}"
    for connective in (" then ", " means ", " indicates ", "implies "):
        assert connective not in para


# ── (d)/(f) loop integration: ceiling respected, early-stop fires, no regression

def _msg_tool_use(tool_name, tool_input, text=None):
    content = []
    if text is not None:
        content.append({"text": text})
    content.append({"toolUse": {"toolUseId": "t1", "name": tool_name, "input": tool_input}})
    return {"stopReason": "tool_use",
            "output": {"message": {"role": "assistant", "content": content}}}


def _msg_end(conclusion: dict):
    return {"stopReason": "end_turn",
            "output": {"message": {"role": "assistant",
                                   "content": [{"text": json.dumps(conclusion)}]}}}


class _ScriptedBedrock:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def converse(self, **kw):
        self.calls += 1
        if self._responses:
            return self._responses.pop(0)
        # After the script is exhausted, keep returning a bare tool_use so a
        # runaway loop would be visible as an over-ceiling call count.
        return _msg_tool_use("query_metrics",
                             {"namespace": "N", "metric_name": "M", "dimensions": {}})


_QM = ("query_metrics", {"namespace": "N", "metric_name": "M", "dimensions": {}})
_TL = ("tail_logs", {"resource_hint": "r1"})
_LR = ("list_resources", {"service_type": "svc"})
_GSC = ("get_service_config", {"service_type": "svc", "resource_name": "r1"})


@pytest.fixture()
def _stub_branch_env(monkeypatch):
    """Stub every branch tool to a cheap traceable result and silence audit I/O,
    so _run_branch can be driven with a scripted model and no live AWS."""
    import cloudctl.mcp.tools.debug as dbg
    import cloudctl.ai.guardrails as gr

    stub = lambda *a, **k: json.dumps({"data": "pool-token-9931 saturation observed"})
    for name in ("list_resources", "get_service_config", "tail_logs",
                 "query_metrics", "search_cloudtrail", "get_event_timeline",
                 "get_deployment_info", "probe_permission",
                 "get_dependency_graph", "aws_read", "get_traces"):
        monkeypatch.setattr(dbg, name, stub, raising=False)
    monkeypatch.setattr(gr, "audit_log_tool_call", lambda **k: None, raising=False)


def _run(monkeypatch, responses):
    fake = _ScriptedBedrock(responses)
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: fake)
    result = g._run_branch(
        hypothesis={"service": "svc", "reason": "svc is slow", "focus": "r1"},
        symptom="svc is slow", profile=None, region="us-east-1",
        minutes=60, session_id="sess-voi",
    )
    return fake, result


def test_ceiling_respected_when_never_resolving(monkeypatch, _stub_branch_env):
    # phase1 concludes immediately (no tools) → phase2 always tool_use, never a
    # decisive text → phase2 must run EXACTLY its 7-turn ceiling, then phase3
    # (mandatory unmet, only query_metrics called) runs its 4-turn ceiling.
    phase1 = _msg_end({"conclusion": "config ok", "confirmed": False,
                       "phase2_needed": True, "evidence": []})
    # everything after phase1 is a bare tool_use (script exhausts → fallback QM)
    fake, result = _run(monkeypatch, [phase1])
    # 1 (phase1) + 7 (phase2 ceiling) + 4 (phase3 ceiling) = 12, never more
    assert fake.calls == 12
    # branch still returns a well-formed result (no crash, no runaway)
    assert result.hypothesis.service == "svc"


def test_no_early_stop_on_normal_multicall_branch(monkeypatch, _stub_branch_env):
    # A normal branch: 4 mandatory tool calls, THEN a decisive end_turn. The
    # early-stop must NOT fire (decisive verdict arrived via end_turn, not mixed
    # tool_use), and all four investigative calls happen — no regression.
    phase1 = _msg_end({"conclusion": "config ok", "confirmed": False,
                       "phase2_needed": True, "evidence": []})
    responses = [
        phase1,
        _msg_tool_use(*_QM),
        _msg_tool_use(*_TL),
        _msg_tool_use(*_LR),
        _msg_tool_use(*_GSC),
        _msg_end({"conclusion": "saturated", "confirmed": True,
                  "evidence": ["pool-token-9931 at 100/100"],
                  "predictions_tested": [{"verdict": "CONFIRMED",
                                          "observed": "pool-token-9931 at 100/100"}]}),
    ]
    fake, result = _run(monkeypatch, responses)
    assert fake.calls == 6                       # 1 phase1 + 5 phase2, nothing extra
    assert result.confirmed is True
    assert result.voi_early_stop is False        # decisive via end_turn, not VOI
    # all four mandatory tools actually ran
    assert _MAND.issubset(set(result.tools_called))


def test_early_stop_fires_after_floor_met(monkeypatch, _stub_branch_env):
    # 4 mandatory calls satisfy the floor; the 5th turn is a MIXED message that
    # narrates a decisive, traceable CONFIRMED conclusion AND queues another
    # tool call. VOI must end the branch there — skipping that 5th call and the
    # remaining ceiling.
    phase1 = _msg_end({"conclusion": "config ok", "confirmed": False,
                       "phase2_needed": True, "evidence": []})
    decisive = json.dumps({
        "conclusion": "saturated", "confirmed": True,
        "evidence": ["pool-token-9931 at 100/100"],
        "predictions_tested": [{"verdict": "CONFIRMED",
                                "observed": "pool-token-9931 at 100/100"}],
    })
    responses = [
        phase1,
        _msg_tool_use(*_QM),
        _msg_tool_use(*_TL),
        _msg_tool_use(*_LR),
        _msg_tool_use(*_GSC),
        # mixed: decisive text + a pending (would-be 5th) tool call
        _msg_tool_use(_QM[0], _QM[1], text=decisive),
    ]
    fake, result = _run(monkeypatch, responses)
    # phase1(1) + phase2 turns 1-5 (5) = 6; the 5th turn early-stops instead of
    # dispatching, so NO phase3 and no extra turns.
    assert fake.calls == 6
    assert result.voi_early_stop is True             # the gate actually fired
    assert result.confirmed is True
    assert _MAND.issubset(set(result.tools_called))  # floor was genuinely met

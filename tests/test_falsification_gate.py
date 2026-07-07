"""Adversarial falsification gate (Feature 4).

Before the verdict ships, the gate tries to DISPROVE the leading root cause using
the same evidence. It is deliberately conservative and must NOT over-correct:
  - survived               → root_cause + confidence UNCHANGED.
  - not survived + budget  → ONE targeted reinvestigation (shared round bound).
  - not survived + no budget → confidence weakened ONE step + doubt recorded;
                               root cause STANDS (never blindly flipped).
  - model-call failure     → treated as survived (graceful, no crash).

NOTE (honesty): this is a PROMPT + wiring feature. These unit tests prove the
wiring, the conservative behavior, the shared round bound, and hint-freeness.
The falsification's real accuracy effect is only observable in a live run and is
NOT asserted here.
"""
from __future__ import annotations

from cloudctl.ai import graph_agent as g


def _report(confidence="HIGH"):
    return {
        "root_cause": "resource alpha exhausted its connection pool",
        "evidence": ["alpha pool at 100/100", "callers time out waiting"],
        "remediation_steps": ["raise the pool limit"],
        "severity": "HIGH",
        "confidence": confidence,
        "resources_investigated": ["alpha"],
    }


# ── (a) clear contradiction → does NOT survive → conservative action ──────────

def test_contradiction_with_budget_triggers_one_reinvestigation():
    fals = {
        "survived": False,
        "contradicting_evidence": ["pool metric shows 12/100 utilization, not exhausted"],
        "stronger_alternative": None,
        "reasoning": "the pool was not actually saturated",
    }
    out = g._falsification_outcome(_report(), fals, critique_round=0)
    # budget remains → reinvestigate (feedback set), root_cause + confidence
    # UNCHANGED at this stage (the alternative must be CONFIRMED first).
    assert out["critique_feedback"]
    assert out["final_report"]["root_cause"] == _report()["root_cause"]
    assert out["final_report"]["confidence"] == "HIGH"


def test_contradiction_without_budget_weakens_and_records_but_keeps_root_cause():
    fals = {
        "survived": False,
        "contradicting_evidence": ["pool metric shows 12/100 utilization"],
        "stronger_alternative": {"hypothesis": "downstream dependency beta is slow",
                                 "why": "beta latency rose at the same onset"},
        "reasoning": "beta latency fits the timing better",
    }
    out = g._falsification_outcome(_report("HIGH"), fals, critique_round=1)
    rep = out["final_report"]
    # weakened exactly one step, NOT hard-capped to LOW
    assert rep["confidence"] == "MEDIUM"
    assert "weakened" in rep.get("confidence_override_reason", "").lower()
    # root cause STANDS — never blindly flipped to the alternative
    assert rep["root_cause"] == _report()["root_cause"]
    # doubt recorded as an alternative
    alts = rep["alternatives_considered"]
    assert any(a["verdict"] == "unresolved_falsification_doubt" for a in alts)
    assert any("beta" in a["hypothesis"] for a in alts)
    assert out["critique_feedback"] == ""   # no further loop


def test_weaken_from_medium_goes_to_low_not_below():
    fals = {"survived": False, "contradicting_evidence": ["x contradicts"],
            "stronger_alternative": None, "reasoning": "r"}
    out = g._falsification_outcome(_report("MEDIUM"), fals, critique_round=1)
    assert out["final_report"]["confidence"] == "LOW"
    # LOW cannot go below LOW
    out2 = g._falsification_outcome(_report("LOW"), fals, critique_round=1)
    assert out2["final_report"]["confidence"] == "LOW"


# ── (b) fully consistent → survives → NOTHING changes (no over-correction) ────

def test_survived_leaves_report_completely_untouched():
    before = _report("HIGH")
    fals = {"survived": True, "contradicting_evidence": [],
            "stronger_alternative": None, "reasoning": "evidence is consistent"}
    out = g._falsification_outcome(before, fals, critique_round=0)
    rep = out["final_report"]
    assert rep["root_cause"] == before["root_cause"]
    assert rep["confidence"] == "HIGH"
    assert rep["evidence"] == before["evidence"]
    assert out["critique_feedback"] == ""
    assert rep["_falsification"]["survived"] is True


def test_nonsurvival_with_no_substance_is_treated_as_survived():
    """A 'survived: false' with NOTHING concrete behind it must not over-correct:
    no contradicting evidence and no alternative → treated as inconclusive/survive."""
    fals = {"survived": False, "contradicting_evidence": [],
            "stronger_alternative": None, "reasoning": "felt uneasy"}
    out = g._falsification_outcome(_report("HIGH"), fals, critique_round=1)
    assert out["final_report"]["confidence"] == "HIGH"         # untouched
    assert out["final_report"]["root_cause"] == _report()["root_cause"]
    assert out["critique_feedback"] == ""


def test_empty_stronger_alternative_dict_is_not_substantive():
    # an alternative object with no hypothesis text is not a real alternative
    fals = {"survived": False, "contradicting_evidence": [],
            "stronger_alternative": {"hypothesis": "", "why": ""},
            "reasoning": "r"}
    out = g._falsification_outcome(_report("HIGH"), fals, critique_round=1)
    assert out["final_report"]["confidence"] == "HIGH"   # not weakened


# ── (c) the round bound is respected (no infinite loop) ───────────────────────

def test_round_bound_respected_by_router():
    # once a reinvestigation has run (critique_round >= 1), routing ENDs even if
    # the falsification gate set feedback — the budget is shared, not doubled.
    assert g._after_falsify({"critique_round": 1, "critique_feedback": "x"}) == g.END
    assert g._after_falsify({"critique_round": 0, "critique_feedback": "x"}) == "reinvestigate"
    assert g._after_falsify({"critique_round": 0, "critique_feedback": ""}) == g.END


def test_falsify_node_defers_when_critique_already_reinvestigating(monkeypatch):
    # If critique already set feedback, falsify must NOT run a call or change
    # anything — it defers so the two gates share one round.
    called = {"n": 0}
    monkeypatch.setattr(g, "_run_falsification",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
    out = g.falsify_node({
        "final_report": _report(), "critique_feedback": "critique wants X",
        "critique_round": 0, "profile": None, "region": "us-east-1",
        "symptom": "s", "all_fetched": {},
    })
    assert out == {}
    assert called["n"] == 0   # no falsification call made


def test_no_budget_after_reinvestigation_weakens_instead_of_looping():
    # second pass (round already 1): a still-standing contradiction weakens once
    # and STOPS — it cannot request another reinvestigation.
    fals = {"survived": False, "contradicting_evidence": ["still contradicts"],
            "stronger_alternative": None, "reasoning": "r"}
    out = g._falsification_outcome(_report("HIGH"), fals, critique_round=1)
    assert out["critique_feedback"] == ""      # no new loop requested
    assert out["final_report"]["confidence"] == "MEDIUM"


# ── (d) model-call failure → graceful survive, no crash ───────────────────────

def test_model_failure_is_graceful_survive(monkeypatch):
    class _Boom:
        def converse(self, **kw):
            raise RuntimeError("bedrock down")
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: _Boom())
    fals = g._run_falsification(
        {"profile": None, "region": "us-east-1", "symptom": "s",
         "all_fetched": {"k": {"v": 1}}},
        _report(),
    )
    assert fals["survived"] is True
    assert fals.get("_error") is True


def test_unparseable_response_is_graceful_survive(monkeypatch):
    class _Junk:
        def converse(self, **kw):
            return {"output": {"message": {"content": [{"text": "not json at all"}]}}}
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: _Junk())
    fals = g._run_falsification(
        {"profile": None, "region": "us-east-1", "symptom": "s", "all_fetched": {}},
        _report(),
    )
    assert fals["survived"] is True


def test_falsify_node_skips_report_with_no_evidence(monkeypatch):
    called = {"n": 0}
    monkeypatch.setattr(g, "_run_falsification",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or {})
    out = g.falsify_node({
        "final_report": {"root_cause": "rc", "evidence": [], "confidence": "LOW"},
        "critique_feedback": "", "critique_round": 0,
        "profile": None, "region": "us-east-1", "symptom": "s", "all_fetched": {},
    })
    assert out == {}
    assert called["n"] == 0


def test_falsify_node_full_survive_path(monkeypatch):
    monkeypatch.setattr(g, "_run_falsification", lambda *a, **k: {
        "survived": True, "contradicting_evidence": [],
        "stronger_alternative": None, "reasoning": "consistent"})
    before = _report("HIGH")
    out = g.falsify_node({
        "final_report": before, "critique_feedback": "", "critique_round": 0,
        "profile": None, "region": "us-east-1", "symptom": "s",
        "all_fetched": {"k": {"v": 1}},
    })
    assert out["final_report"]["confidence"] == "HIGH"
    assert out["final_report"]["root_cause"] == before["root_cause"]


# ── (e) hint-freeness — no service/scenario, no symptom→cause mapping ──────────

_BLOCKLIST = [
    "dynamodb", "lambda", "s3", "cognito", "throttle", "oom", "kms",
    "bedrock", "sagemaker", "opensearch", "vector", "iam", "rds", "sqs",
    "sns", "ec2", "ecs", "alb", "nacl", "vpc", "cloudwatch", "kinesis",
    "429", "5xx", "accessdenied",
]


def test_falsification_prompt_has_no_service_or_scenario_literals():
    low = g._FALSIFICATION_SYSTEM.lower()
    hits = [w for w in _BLOCKLIST if w in low]
    assert hits == [], f"falsification prompt leaked hint literals: {hits}"


def test_falsification_prompt_maps_no_symptom_to_cause():
    low = g._FALSIFICATION_SYSTEM.lower()
    for connective in (" then ", " means ", " indicates ", "implies "):
        assert connective not in low, f"prompt contains mapping connective {connective!r}"
    # It is genuinely adversarial and allows BOTH outcomes.
    assert "disprove" in low
    assert "survives" in low or "survived" in low
    assert "common result" in low or "legitimate and common" in low

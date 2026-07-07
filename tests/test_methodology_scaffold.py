"""Generic diagnostic methodology scaffold (Feature 3).

The scaffold gives the model domain-agnostic REASONING FRAMES (USE / RED /
dependency-walk / change-first) — methodology, never scenario answers. These
tests prove it is (a) wired into the triage and branch-investigation prompts,
(b) hint-free (names no service/resource/error, maps no symptom to a cause), and
(c) does not break hypothesis generation.

NOTE (honesty): this is a PROMPT feature. Unit tests can prove it is wired and
hint-free; its accuracy effect is only observable in a live investigation and is
NOT asserted here.
"""
from __future__ import annotations

import json

from cloudctl.ai import graph_agent as g


# ── (a) the scaffold is present in the constructed prompts ────────────────────

def test_scaffold_present_in_triage_prompt():
    assert g._DIAGNOSTIC_SCAFFOLD in g._TRIAGE_SYSTEM


def test_scaffold_present_in_branch_prompt():
    assert g._DIAGNOSTIC_SCAFFOLD in g._PHASE2_SYSTEM
    # survives .format() of the per-branch fields (scaffold has no braces)
    formatted = g._PHASE2_SYSTEM.format(
        reason="r", service="s", phase1_conclusion="c", predictions="[]",
    )
    assert g._DIAGNOSTIC_SCAFFOLD in formatted


def test_scaffold_contains_the_four_frames():
    s = g._DIAGNOSTIC_SCAFFOLD
    for frame in ("USE", "RED", "DEPENDENCY-WALK", "CHANGE-FIRST"):
        assert frame in s, f"missing frame: {frame}"


# ── (b) hint-freeness — no service/scenario literals, no symptom→cause map ─────

# Service names, resource types, error codes, and scenario words the scaffold
# must NOT contain. If any appears, the scaffold has leaked a hint.
_BLOCKLIST = [
    "dynamodb", "lambda", "s3", "cognito", "throttle", "oom", "kms",
    "bedrock", "sagemaker", "opensearch", "vector", "iam", "rds", "sqs",
    "sns", "ec2", "ecs", "alb", "nacl", "vpc", "cloudwatch", "kinesis",
    "efs", "dms", "aurora", "redis", "429", "5xx", "accessdenied",
]


def test_scaffold_has_no_service_or_scenario_literals():
    low = g._DIAGNOSTIC_SCAFFOLD.lower()
    hits = [w for w in _BLOCKLIST if w in low]
    assert hits == [], f"scaffold leaked hint literals: {hits}"


def test_scaffold_maps_no_symptom_to_cause():
    """A lookup-table would connect an observation to a cause with 'then'/'means'
    /'indicates'. The scaffold is methodology only, so it carries no such
    connective (it explicitly says it maps no symptom to any cause)."""
    low = g._DIAGNOSTIC_SCAFFOLD.lower()
    for connective in (" then ", " means ", " indicates ", "implies "):
        assert connective not in low, f"scaffold contains mapping connective {connective!r}"
    assert "map no symptom to any cause" in low   # the explicit disclaimer


# ── (c) hypothesis generation still parses/works with the scaffold present ─────

class _FakeBedrock:
    """Minimal Converse-shaped client: returns a canned end_turn hypotheses
    array on the first call, so triage_node's parse path runs end-to-end."""

    def __init__(self, payload_text):
        self._payload = payload_text
        self.calls = 0

    def converse(self, **kwargs):
        self.calls += 1
        return {
            "stopReason": "end_turn",
            "output": {"message": {"role": "assistant",
                                   "content": [{"text": self._payload}]}},
        }


def test_triage_still_parses_hypotheses_with_scaffold(monkeypatch):
    # Three well-formed hypotheses in the exact contract triage expects. Invented
    # service names — the test asserts the PARSE path, not any scenario knowledge.
    payload = json.dumps([
        {"service": "zqwibble", "reason": "candidate 1",
         "focus": "zqwibble-1 — check config",
         "predictions": [{"if_true": "x", "check": "y", "if_absent": "refutes"}]},
        {"service": "flarnblat", "reason": "candidate 2",
         "focus": "flarnblat-1 — check config", "predictions": []},
        {"service": "gromulon", "reason": "candidate 3",
         "focus": "gromulon-1 — check config", "predictions": []},
    ])
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: _FakeBedrock(payload))

    state = {
        "symptom": "requests are slow", "profile": None, "region": "us-east-1",
        "minutes": 60, "session_id": "sess-test", "account_id": "123",
        "observation": {},
    }
    out = g.triage_node(state)
    hyps = out["hypotheses"]
    assert len(hyps) == 3
    assert {h["service"] for h in hyps} == {"zqwibble", "flarnblat", "gromulon"}
    # every hypothesis round-trips through the Hypothesis model
    assert all("focus" in h and "reason" in h for h in hyps)

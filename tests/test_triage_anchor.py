"""ANCHOR-ON-SELF triage rule + deterministic backstop.

Failure mode closed: the measurement localizes the failure to ONE component,
yet every triage hypothesis targets the layers AROUND it (permissions,
dependencies, adjacent services) and no branch is anchored on the failing
component itself — so a causal value sitting in that component's own
configuration is never framed as a candidate root cause.

Two layers, mirroring the calibration-fix pattern:
  (a) a generic prompt rule in the triage system prompt — presence and
      hint-freeness are asserted here; its live accuracy effect is only
      observable in a real investigation and is NOT asserted;
  (b) a pure deterministic backstop (_ensure_anchor_hypothesis) that appends
      one neutral own-configuration hypothesis when anchor coverage is missing.

All test data is abstract (invented component names) — no scenario vocabulary.
"""
from __future__ import annotations

import json

from cloudctl.ai import graph_agent as g


# ── helpers (abstract, scenario-free) ─────────────────────────────────────────

def _obs(affected="", unaffected="", measurements=()):
    return {
        "symptom_observable_now": True,
        "affected_scope": affected,
        "unaffected_scope": unaffected,
        "measurements": list(measurements),
    }


def _disc(*names, svc="zqserv"):
    return {svc: {
        "resources": list(names),
        "resources_detailed": [
            {"service": svc, "name": n, "arn": f"arn:{n}"} for n in names
        ],
    }}


def _hyp(focus, service="zqserv", reason="candidate"):
    return {"service": service, "reason": reason, "focus": focus,
            "predictions": []}


# ── (a) the rule is present in the triage prompt ──────────────────────────────

def test_rule_present_in_triage_prompt():
    assert g._ANCHOR_ON_SELF_RULE in g._TRIAGE_SYSTEM
    assert "ANCHOR-ON-SELF" in g._TRIAGE_SYSTEM


def test_rule_demands_own_configuration_of_the_failing_component():
    low = g._ANCHOR_ON_SELF_RULE.lower()
    assert "own configuration" in low
    assert "at least one" in low


# ── (a) hint-freeness — no service, field, or mechanism literals ──────────────

# Service names, resource types, error codes, and mechanism words the rule must
# NOT contain (same discipline as test_methodology_scaffold._BLOCKLIST). If any
# appears, the rule has leaked scenario knowledge.
_BLOCKLIST = [
    "dynamodb", "lambda", "s3", "cognito", "kms", "bedrock", "sagemaker",
    "opensearch", "iam", "rds", "sqs", "sns", "ec2", "ecs", "alb", "nacl",
    "vpc", "cloudwatch", "kinesis", "kafka", "msk", "efs", "dms", "aurora",
    "redis", "429", "5xx", "accessdenied",
    # mechanism words — the rule must stay about WHERE hypotheses point, never
    # about what any specific fault looks like
    "throttle", "timeout", "timed out", "delay", "sleep", "oom",
    "environment variable", "env var", "env_", "flag",
]


def test_rule_has_no_service_or_mechanism_literals():
    low = g._ANCHOR_ON_SELF_RULE.lower()
    hits = [w for w in _BLOCKLIST if w in low]
    assert hits == [], f"anchor-on-self rule leaked hint literals: {hits}"


def test_backstop_hypothesis_text_has_no_service_or_mechanism_literals():
    h = g._self_config_hypothesis("comp-aleph", _disc("comp-aleph"))
    low = json.dumps(h).lower()
    hits = [w for w in _BLOCKLIST if w in low]
    assert hits == [], f"backstop hypothesis leaked hint literals: {hits}"


# ── (b) anchor identification (pure, structural) ──────────────────────────────

def test_anchor_is_the_affected_discovered_component():
    obs = _obs(
        affected="comp-aleph fails on every operation",
        unaffected="comp-beth and comp-gimel are healthy",
        measurements=["comp-aleph failure count rising at T0"],
    )
    disc = _disc("comp-aleph", "comp-beth", "comp-gimel")
    assert g._anchor_component(obs, disc) == "comp-aleph"


def test_component_named_only_as_unaffected_is_not_the_anchor():
    obs = _obs(affected="operations failing somewhere upstream",
               unaffected="comp-beth is fine")
    disc = _disc("comp-beth")
    assert g._anchor_component(obs, disc) == ""


def test_no_observation_or_no_discovery_yields_no_anchor():
    assert g._anchor_component({}, _disc("comp-aleph")) == ""
    assert g._anchor_component(_obs(affected="comp-aleph failing"), {}) == ""


def test_component_in_both_affected_and_unaffected_is_ambiguous():
    obs = _obs(affected="comp-aleph slow on one path",
               unaffected="comp-aleph healthy on the rest")
    assert g._anchor_component(obs, _disc("comp-aleph")) == ""


def test_more_specific_name_wins_over_its_prefix():
    obs = _obs(affected="comp-aleph-worker is failing")
    disc = _disc("comp-aleph", "comp-aleph-worker")
    assert g._anchor_component(obs, disc) == "comp-aleph-worker"


# ── (b) anchor coverage (exact identifier, not embedding) ─────────────────────

def test_focus_on_the_component_itself_covers():
    hyps = [_hyp("comp-aleph — inspect its configuration")]
    assert g._hypotheses_cover_anchor(hyps, "comp-aleph")


def test_focus_on_adjacent_resource_embedding_the_name_does_not_cover():
    # A branch on a NEIGHBOR named after the component (a binding, helper, or
    # sibling) is not anchored on the component itself — this near-miss is the
    # exact gap the backstop exists to catch.
    hyps = [
        _hyp("comp-aleph-binding — check its policy"),
        _hyp("comp-daleth — check the upstream path"),
    ]
    assert not g._hypotheses_cover_anchor(hyps, "comp-aleph")


def test_empty_anchor_counts_as_covered():
    assert g._hypotheses_cover_anchor([], "")


# ── (b) the backstop appends exactly one neutral own-config hypothesis ────────

def test_backstop_appends_own_config_hypothesis_when_uncovered():
    obs = _obs(affected="comp-aleph fails all operations",
               unaffected="comp-beth healthy")
    disc = _disc("comp-aleph", "comp-beth")
    hyps = [
        _hyp("comp-beth — check the downstream dependency"),
        _hyp("comp-aleph-binding — check its permissions"),
        _hyp("comp-gimel — check the upstream producer"),
    ]
    out = g._ensure_anchor_hypothesis(hyps, obs, disc)
    assert len(out) == 4
    assert out[:3] == hyps                       # model hypotheses untouched
    added = out[-1]
    assert added["focus"].startswith("comp-aleph ")
    assert "own configuration" in added["focus"]
    assert added["service"] == "zqserv"          # resolved from discovery


def test_backstop_no_op_when_anchor_already_covered():
    obs = _obs(affected="comp-aleph fails all operations")
    disc = _disc("comp-aleph")
    hyps = [_hyp("comp-aleph — inspect its configuration")]
    assert g._ensure_anchor_hypothesis(hyps, obs, disc) == hyps


def test_backstop_no_op_without_observation():
    hyps = [_hyp("comp-beth — check the dependency")]
    assert g._ensure_anchor_hypothesis(hyps, {}, _disc("comp-aleph")) == hyps


def test_appended_hypothesis_round_trips_pydantic():
    h = g._self_config_hypothesis("comp-aleph", _disc("comp-aleph"))
    m = g.Hypothesis(**h)
    assert m.focus.startswith("comp-aleph")
    assert m.predictions == []


# ── (b) wired end-to-end through triage_node ──────────────────────────────────

class _ToolThenAnswerBedrock:
    """Converse-shaped fake: first call requests list_resources (so triage's
    discovery inventory is populated), second call returns the hypotheses."""

    def __init__(self, payload_text):
        self._payload = payload_text
        self.calls = 0

    def converse(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return {"stopReason": "tool_use", "output": {"message": {
                "role": "assistant",
                "content": [{"toolUse": {
                    "toolUseId": "t1", "name": "list_resources",
                    "input": {"service_type": "zqserv"},
                }}],
            }}}
        return {"stopReason": "end_turn", "output": {"message": {
            "role": "assistant", "content": [{"text": self._payload}],
        }}}


def test_triage_node_appends_anchor_branch_when_model_missed_it(monkeypatch):
    import cloudctl.mcp.tools.debug as dbg

    monkeypatch.setattr(dbg, "list_resources", lambda svc, p, r: json.dumps({
        "service_type": svc, "count": 2,
        "resources": ["comp-aleph", "comp-beth"],
        "resources_detailed": [
            {"service": "zqserv", "name": "comp-aleph", "arn": "arn:a"},
            {"service": "zqserv", "name": "comp-beth", "arn": "arn:b"},
        ],
    }))
    payload = json.dumps([
        {"service": "zqserv", "reason": "adjacent binding suspect",
         "focus": "comp-aleph-binding — check its policy", "predictions": []},
        {"service": "flarnserv", "reason": "downstream suspect",
         "focus": "comp-beth — check the downstream path", "predictions": []},
        {"service": "gromserv", "reason": "upstream suspect",
         "focus": "comp-gimel — check the upstream producer", "predictions": []},
    ])
    monkeypatch.setattr(g, "_make_bedrock",
                        lambda *a, **k: _ToolThenAnswerBedrock(payload))

    state = {
        "symptom": "operations against one component are failing",
        "profile": None, "region": "us-east-1", "minutes": 60,
        "session_id": "sess-test", "account_id": "123",
        "observation": _obs(
            affected="comp-aleph failing 100% of operations",
            unaffected="comp-beth healthy",
        ),
    }
    out = g.triage_node(state)
    hyps = out["hypotheses"]
    assert len(hyps) == 4
    assert hyps[3]["focus"].startswith("comp-aleph ")
    assert "own configuration" in hyps[3]["focus"]


def test_triage_node_unchanged_when_model_anchored_itself(monkeypatch):
    import cloudctl.mcp.tools.debug as dbg

    monkeypatch.setattr(dbg, "list_resources", lambda svc, p, r: json.dumps({
        "service_type": svc, "count": 1,
        "resources": ["comp-aleph"],
        "resources_detailed": [
            {"service": "zqserv", "name": "comp-aleph", "arn": "arn:a"},
        ],
    }))
    payload = json.dumps([
        {"service": "zqserv", "reason": "own configuration suspect",
         "focus": "comp-aleph — inspect its configuration", "predictions": []},
        {"service": "flarnserv", "reason": "downstream suspect",
         "focus": "comp-beth — check the downstream path", "predictions": []},
        {"service": "gromserv", "reason": "upstream suspect",
         "focus": "comp-gimel — check the upstream producer", "predictions": []},
    ])
    monkeypatch.setattr(g, "_make_bedrock",
                        lambda *a, **k: _ToolThenAnswerBedrock(payload))

    state = {
        "symptom": "operations against one component are failing",
        "profile": None, "region": "us-east-1", "minutes": 60,
        "session_id": "sess-test", "account_id": "123",
        "observation": _obs(affected="comp-aleph failing 100% of operations"),
    }
    out = g.triage_node(state)
    assert len(out["hypotheses"]) == 3

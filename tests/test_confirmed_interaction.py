"""UNCONFIRMED-INTERACTION rule + deterministic guard, and IAM-DENIAL
platform-semantics rule.

Failure modes closed:
  (A) an interaction between two components is INFERRED (naming, graph
      adjacency, wiring) rather than directly observed, a FACET of it (a
      permission, a setting) is then verified, and the verified facet gets
      promoted into "the interaction occurs and is the cause" — even when the
      observation window holds zero records of the interaction ever occurring;
  (B) a causal claim of the form "an authorization denial on a direct
      synchronous API call makes the caller hang" — which contradicts general
      AWS platform behavior (IAM denials fail fast with an error and are still
      recorded by request auditing).

Layers, mirroring the anchor-rule pattern:
  (a) generic prompt rules in the discrimination + synthesis prompts —
      presence and hint-freeness are asserted here; live accuracy effect is
      only observable in a real investigation and is NOT asserted;
  (b) for (A) only: a pure deterministic guard (_apply_interaction_guard)
      acting on the model's OWN interaction_dependency self-classification —
      caps the category confidence at LOW and appends a neutral epistemic
      note when the load-bearing interaction is labeled inferred-only.

All test data is abstract (invented component names) — no scenario vocabulary.
"""
from __future__ import annotations

import json
import re

from cloudctl.ai import graph_agent as g


def _norm(text: str) -> str:
    """Lowercase + collapse whitespace so phrase assertions survive line wraps."""
    return " ".join(text.lower().split())


def _blocklist_hits(text: str, words: list[str]) -> list[str]:
    """Boundary-aware blocklist scan: 'rds' must not match inside 'records'.
    Lookbehind/lookahead applied only where the word starts/ends alphanumeric,
    so prefix entries like 'env_' still catch 'env_foo'."""
    low = _norm(text)
    hits = []
    for w in words:
        pat = re.escape(w)
        if w[0].isalnum():
            pat = r"(?<![a-z0-9])" + pat
        if w[-1].isalnum():
            pat = pat + r"(?![a-z0-9])"
        if re.search(pat, low):
            hits.append(w)
    return hits


# ── blocklists ────────────────────────────────────────────────────────────────

# (A) must be PURE structure/epistemics: no service names, no resource types,
# no error codes, and no mechanism words. Same discipline as the ANCHOR-ON-SELF
# blocklist, plus the platform words that rule (B) is allowed but (A) is not.
_STRUCTURAL_BLOCKLIST = [
    "dynamodb", "lambda", "s3", "cognito", "kms", "bedrock", "sagemaker",
    "opensearch", "iam", "rds", "sqs", "sns", "ec2", "ecs", "alb", "nacl",
    "vpc", "cloudwatch", "kinesis", "kafka", "msk", "efs", "dms", "aurora",
    "redis", "429", "5xx", "accessdenied", "cloudtrail", "step functions",
    "stepfunctions", "states:", "startexecution", "sasl", "streaming",
    # mechanism words — the rule must stay about HOW an interaction is known,
    # never about what any specific fault looks like
    "throttle", "timeout", "timed out", "delay", "sleep", "oom", "hang",
    "deny", "denied", "denial", "environment variable", "env var", "env_",
    "flag", "retry loop", "backoff",
]

# (B) may name GENERAL platform concepts (IAM, CloudTrail, SDK, synchronous
# API, authorization) but nothing scenario-specific: no individual service's
# API, no incident vocabulary.
_SCENARIO_BLOCKLIST = [
    "step functions", "stepfunctions", "states:", "startexecution",
    "streaming", "etl", "kafka", "msk", "sasl", "lambda", "consumer",
    "processing_delay", "kinesis", "dynamodb", "s3", "sqs", "sns",
]


# ── (a) rule A: presence in both prompts ──────────────────────────────────────

def test_interaction_rule_present_in_discriminate_prompt():
    assert g._INFERRED_INTERACTION_RULE in g._DISCRIMINATE_SYSTEM
    assert "UNCONFIRMED-INTERACTION" in g._DISCRIMINATE_SYSTEM


def test_interaction_rule_present_in_synthesize_prompt():
    assert g._INFERRED_INTERACTION_RULE in g._SYNTHESIZE_PROMPT


def test_interaction_rule_separates_observed_from_inferred():
    low = _norm(g._INFERRED_INTERACTION_RULE)
    assert "directly observed" in low
    assert "inferred only" in low
    assert "graph adjacency" in low


def test_interaction_rule_facet_does_not_confirm_occurrence():
    low = _norm(g._INFERRED_INTERACTION_RULE)
    assert "facet" in low
    assert "never that the interaction" in low
    assert "independently confirmed" in low


def test_interaction_rule_absence_is_evidence_against():
    low = _norm(g._INFERRED_INTERACTION_RULE)
    assert "evidence against" in low
    assert "never performs this interaction" in low


# ── (a) rule A: hint-freeness — pure structure, zero platform/mechanism words ─

def test_interaction_rule_has_no_service_or_mechanism_literals():
    low = _norm(g._INFERRED_INTERACTION_RULE)
    hits = _blocklist_hits(low, _STRUCTURAL_BLOCKLIST)
    assert hits == [], f"unconfirmed-interaction rule leaked hint literals: {hits}"


def test_guard_note_has_no_service_or_mechanism_literals():
    low = _norm(g._UNCONFIRMED_INTERACTION_NOTE)
    hits = _blocklist_hits(low, _STRUCTURAL_BLOCKLIST)
    assert hits == [], f"interaction guard note leaked hint literals: {hits}"


# ── (a) rule B: presence in both prompts ──────────────────────────────────────

def test_iam_semantics_rule_present_in_discriminate_prompt():
    assert g._IAM_DENIAL_SEMANTICS_RULE in g._DISCRIMINATE_SYSTEM
    assert "IAM-DENIAL SEMANTICS" in g._DISCRIMINATE_SYSTEM


def test_iam_semantics_rule_present_in_synthesize_prompt():
    assert g._IAM_DENIAL_SEMANTICS_RULE in g._SYNTHESIZE_PROMPT


def test_iam_semantics_rule_states_fast_fail_and_audit_recording():
    low = _norm(g._IAM_DENIAL_SEMANTICS_RULE)
    assert "fails fast" in low
    assert "cloudtrail" in low
    assert "never makes that call" in low


def test_iam_semantics_rule_names_the_legitimate_blocking_mechanisms():
    # The rule must not overfit to "never blame IAM for a hang": the two real
    # categories of IAM-related blocking must be named as identifiable
    # alternatives (protocol handshake; caller's own retry loop).
    low = _norm(g._IAM_DENIAL_SEMANTICS_RULE)
    assert "handshake" in low
    assert "retry" in low


# ── (a) rule B: generality — no scenario-specific vocabulary ──────────────────

def test_iam_semantics_rule_has_no_scenario_literals():
    low = _norm(g._IAM_DENIAL_SEMANTICS_RULE)
    hits = _blocklist_hits(low, _SCENARIO_BLOCKLIST)
    assert hits == [], f"IAM semantics rule leaked scenario literals: {hits}"


# ── (b) schema: discriminate output self-classifies the interaction ───────────

def test_discriminate_schema_has_interaction_dependency_field():
    assert '"interaction_dependency"' in g._DISCRIMINATE_SYSTEM
    assert "inferred_only" in g._DISCRIMINATE_SYSTEM


# ── (b) guard: pure, structural, acts only on self-labels ─────────────────────

def _disc_out(occurrence="inferred_only", depends=True, conf="HIGH",
              constraint="The cause is comp-aleph invoking comp-beth."):
    return {
        "cause_category": "dependency",
        "cause_category_confidence": conf,
        "investigation_constraint": constraint,
        "interaction_dependency": {
            "depends_on_interaction": depends,
            "interaction": "comp-aleph -> comp-beth",
            "occurrence": occurrence,
        },
        "evidence_classifications": [{"evidence": "e1"}],
    }


def test_guard_caps_confidence_and_appends_note_when_inferred_only():
    out = g._apply_interaction_guard(_disc_out())
    assert out["cause_category_confidence"] == "LOW"
    assert out["investigation_constraint"].startswith(
        "The cause is comp-aleph invoking comp-beth.")
    assert g._UNCONFIRMED_INTERACTION_NOTE in out["investigation_constraint"]
    # everything else untouched
    assert out["cause_category"] == "dependency"
    assert out["evidence_classifications"] == [{"evidence": "e1"}]


def test_guard_no_op_when_interaction_directly_observed():
    d = _disc_out(occurrence="observed")
    assert g._apply_interaction_guard(d) == d


def test_guard_no_op_when_cause_does_not_depend_on_interaction():
    for depends in (False, "false", None):
        d = _disc_out(depends=depends)
        assert g._apply_interaction_guard(d) == d


def test_guard_accepts_string_true_and_bare_inferred_label():
    out = g._apply_interaction_guard(_disc_out(occurrence="inferred",
                                               depends="true"))
    assert out["cause_category_confidence"] == "LOW"


def test_guard_no_op_when_self_label_missing_or_malformed():
    d = {"cause_category": "configuration", "cause_category_confidence": "HIGH",
         "investigation_constraint": "c"}
    assert g._apply_interaction_guard(d) == d
    d2 = dict(d, interaction_dependency="not-a-dict")
    assert g._apply_interaction_guard(d2) == d2
    err = {"_error": "unparseable"}
    assert g._apply_interaction_guard(err) == err


def test_guard_does_not_mutate_input():
    d = _disc_out()
    g._apply_interaction_guard(d)
    assert d["cause_category_confidence"] == "HIGH"
    assert g._UNCONFIRMED_INTERACTION_NOTE not in d["investigation_constraint"]


def test_guard_is_idempotent():
    once = g._apply_interaction_guard(_disc_out())
    twice = g._apply_interaction_guard(once)
    assert twice == once
    assert twice["investigation_constraint"].count(
        g._UNCONFIRMED_INTERACTION_NOTE) == 1


def test_guard_handles_empty_constraint():
    out = g._apply_interaction_guard(_disc_out(constraint=""))
    assert out["investigation_constraint"] == g._UNCONFIRMED_INTERACTION_NOTE


# ── (b) wired end-to-end through discriminate_node ────────────────────────────

class _AnswerBedrock:
    """Converse-shaped fake returning a fixed discriminate payload."""

    def __init__(self, payload_text):
        self._payload = payload_text

    def converse(self, **kwargs):
        return {"output": {"message": {
            "role": "assistant", "content": [{"text": self._payload}],
        }}}


def _state():
    return {
        "symptom": "operations against one component are failing",
        "profile": None, "region": "us-east-1", "minutes": 60,
        "branch_results": [
            {"hypothesis": {"service": "zqserv"},
             "evidence": ["comp-aleph shows failures"],
             "predictions_tested": [], "conclusion": "c", "confirmed": False},
        ],
        "log_insights": {},
    }


def test_discriminate_node_caps_inferred_only_interaction(monkeypatch):
    payload = json.dumps(_disc_out())
    monkeypatch.setattr(g, "_make_bedrock",
                        lambda *a, **k: _AnswerBedrock(payload))
    out = g.discriminate_node(_state())
    disc = out["discrimination"]
    assert disc["cause_category_confidence"] == "LOW"
    assert g._UNCONFIRMED_INTERACTION_NOTE in disc["investigation_constraint"]


def test_discriminate_node_untouched_when_interaction_observed(monkeypatch):
    payload = json.dumps(_disc_out(occurrence="observed"))
    monkeypatch.setattr(g, "_make_bedrock",
                        lambda *a, **k: _AnswerBedrock(payload))
    out = g.discriminate_node(_state())
    disc = out["discrimination"]
    assert disc["cause_category_confidence"] == "HIGH"
    assert g._UNCONFIRMED_INTERACTION_NOTE not in disc["investigation_constraint"]

"""VERDICT confidence calibration policy (_calibrate_confidence).

Confidence reflects what the ANALYSIS earned — it is never capped just to be
safe. A single dominant, self-consistent branch keeps the level its reasoning
earned (HIGH included); confidence is lowered only for concrete, analysis-
grounded reasons (no real evidence, an unresolved contest between hypotheses, or
a winner that refuted its own prediction) and raised when an under-rated answer
carries objective verification.
"""
from __future__ import annotations

from cloudctl.ai.graph_agent import _calibrate_confidence


def _branch(evidence=(), confirmed=False, preds=()):
    return {
        "evidence": list(evidence),
        "confirmed": confirmed,
        "conclusion": "cause X" if evidence else "",
        "predictions_tested": list(preds),
    }


def _pred(v):
    return {"verdict": v}


# ── the fix: a dominant evidenced branch keeps the confidence it earned ────────
def test_dominant_evidenced_branch_keeps_high():
    # one branch with conclusive traceable evidence, others empty, model says HIGH
    branches = [
        _branch(evidence=["e1", "e2", "e3"], confirmed=False),  # dominant
        _branch(evidence=[], confirmed=False),
        _branch(evidence=[], confirmed=False),
    ]
    conf, _ = _calibrate_confidence(branches, agent_conf="HIGH")
    assert conf == "HIGH"          # not capped to MEDIUM — confidence follows analysis


def test_dominant_evidenced_branch_keeps_medium():
    branches = [_branch(evidence=["e1", "e2", "e3"], confirmed=False)]
    conf, _ = _calibrate_confidence(branches, agent_conf="MEDIUM")
    assert conf == "MEDIUM"        # honored, neither inflated nor capped


def test_dominant_evidenced_branch_low_stays_low():
    # respect the synthesizer's own low self-assessment
    branches = [_branch(evidence=["e1", "e2", "e3"], confirmed=False)]
    conf, _ = _calibrate_confidence(branches, agent_conf="LOW")
    assert conf == "LOW"


# ── grounded downgrades (analysis-based, not caution) ─────────────────────────
def test_two_evidenced_unconfirmed_is_unresolved_medium():
    branches = [
        _branch(evidence=["a1", "a2", "a3"], confirmed=False),
        _branch(evidence=["b1", "b2", "b3"], confirmed=False),
    ]
    conf, note = _calibrate_confidence(branches, agent_conf="HIGH")
    assert conf == "MEDIUM"
    assert "unresolved" in note


def test_thin_evidence_stays_low():
    branches = [_branch(evidence=["only-one"], confirmed=False)]
    conf, _ = _calibrate_confidence(branches, agent_conf="HIGH")
    assert conf == "LOW"


def test_self_refuted_winner_drops_to_low():
    branches = [
        _branch(evidence=["e1", "e2", "e3"], confirmed=False, preds=[_pred("REFUTED")]),
    ]
    conf, note = _calibrate_confidence(branches, agent_conf="HIGH")
    assert conf == "LOW"
    assert "refuted" in note


def test_no_standing_branch_is_low():
    branches = [_branch(evidence=[], confirmed=False), _branch(evidence=["x"], confirmed=False)]
    conf, _ = _calibrate_confidence(branches, agent_conf="HIGH")
    assert conf == "LOW"


# ── verification can RAISE an under-rated answer ──────────────────────────────
def test_confirmed_prediction_raises_underrated_low_to_high():
    branches = [
        _branch(evidence=["e1"], confirmed=True, preds=[_pred("CONFIRMED")]),
        _branch(evidence=[], confirmed=False),
    ]
    conf, note = _calibrate_confidence(branches, agent_conf="LOW")
    assert conf == "HIGH"
    assert "confirmed prediction" in note


def test_confirmed_winner_keeps_high():
    branches = [_branch(evidence=["e1"], confirmed=True, preds=[_pred("CONFIRMED")])]
    conf, _ = _calibrate_confidence(branches, agent_conf="HIGH")
    assert conf == "HIGH"


# ── elimination is not confirmation ─────────────────────────────────────────
# A hypothesis that "wins" only because rivals were refuted/ruled out, with
# neither a confirmed NOR a refuted prediction of its own (an untested
# assumption), must not keep high confidence when a DIFFERENT branch actually
# confirmed a prediction. Surviving elimination is not the same as being
# verified — this is the mirror case of the existing "raise if under-rated"
# check, for the over-rated direction.

def test_untested_winner_capped_when_rival_confirmed():
    # Only the winner is branch-level "confirmed" (so it alone is the standing
    # candidate — two confirmed branches would instead hit the earlier
    # unresolved-contest check). The rival is not branch-level confirmed, but DID
    # verify one of its own predictions — that is what must trigger the cap.
    branches = [
        _branch(evidence=["e1", "e2", "e3"], confirmed=True, preds=[]),  # winner: untested
        _branch(evidence=["e1"], confirmed=False, preds=[_pred("CONFIRMED")]),  # rival: verified
    ]
    conf, note = _calibrate_confidence(branches, agent_conf="HIGH")
    assert conf == "LOW"
    assert "no confirmed prediction" in note


def test_untested_winner_with_no_verified_rival_is_unaffected():
    # Same shape, but nothing else is confirmed either — the new check must not
    # fire just because the winner is untested; it needs a verified alternative.
    branches = [
        _branch(evidence=["e1", "e2", "e3"], confirmed=True, preds=[]),
        _branch(evidence=["e1"], confirmed=False, preds=[]),
    ]
    conf, _ = _calibrate_confidence(branches, agent_conf="HIGH")
    assert conf == "HIGH"


# ── two verified, contradicting causes → genuinely ambiguous ──────────────────
def test_two_confirmed_contradicting_is_medium():
    branches = [
        _branch(evidence=["e1"], confirmed=True),
        _branch(evidence=["e2"], confirmed=True),
    ]
    conf, _ = _calibrate_confidence(branches, agent_conf="HIGH")
    assert conf == "MEDIUM"

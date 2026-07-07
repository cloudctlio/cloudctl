"""Regression tests for the identifier-grounding heuristic: hyphenated English
PROSE must not be treated as an infra identifier (which produced false
under-confidence downgrades in live runs — e.g. "hard-coded", "sign-ins",
"env-var", "fast-fails" were flagged as identifiers absent from evidence).
Real resource identifiers must still be grounding-checked."""

from cloudctl.ai.guardrails import check_evidence_grounding


def test_hyphenated_prose_is_not_flagged_as_ungrounded_identifier():
    # Correct, well-evidenced conclusion whose prose happens to contain
    # hyphenated English compounds not present verbatim in the evidence.
    conclusion = (
        "The pre-auth trigger raises a hard-coded error, so every sign-in "
        "fast-fails at the env-var guard clause."
    )
    evidence = ["FAIL_ALWAYS=1 set on the function; RuntimeError at handler.py line 17"]
    res = check_evidence_grounding(conclusion, evidence, {})
    # None of hard-coded / sign-in / fast-fails / env-var may drive a downgrade.
    assert res.grounded, f"prose wrongly flagged: {res.ungrounded_claims}"
    for prose in ("hard-coded", "sign-in", "fast-fails", "env-var"):
        assert prose not in " ".join(res.ungrounded_claims).lower()


def test_real_identifier_absent_from_evidence_still_flagged():
    # A fabricated resource identifier (digit + multi-segment) not in evidence
    # must still be caught — the fix must not blind the check to real names.
    conclusion = "The fault is on table orders-prod-42 in region us-west-9."
    evidence = ["observed table cognito-auth-users in us-east-1"]
    res = check_evidence_grounding(conclusion, evidence, {})
    joined = " ".join(res.ungrounded_claims).lower()
    assert not res.grounded
    assert "orders-prod-42" in joined or "us-west-9" in joined


def test_real_identifier_present_in_evidence_is_grounded():
    conclusion = "IAM role cognito-auth-authorizer lost its inline policy."
    evidence = ["get_role_policy on cognito-auth-authorizer returned empty"]
    res = check_evidence_grounding(conclusion, evidence, {})
    assert res.grounded

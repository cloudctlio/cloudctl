"""Phase 2a — a 'healthy / false-alarm' verdict on a reported failure must not
ship confidently unless the failing path was POSITIVELY verified to work.
Regression against the live miss where the agent declared a genuine incident a
false positive ('making the stack appear unhealthy … all components are fully
healthy') without ever exercising the sign-in path."""

from cloudctl.ai.guardrails import (
    is_symptom_dismissal, cap_speculative_dismissal, _has_positive_success_reproduction,
)


def test_appear_unhealthy_wording_is_detected_as_dismissal():
    out = {"root_cause": "The probe makes the stack appear unhealthy; all components "
                          "are fully healthy.", "evidence": [], "confidence": "MEDIUM"}
    assert is_symptom_dismissal(out)


def test_unverified_healthy_verdict_is_capped_and_flagged():
    # No positive success reproduction, no grounded alarm defect -> cap + flag.
    out = {"root_cause": "This is a false-positive alert; the stack is healthy.",
           "evidence": ["No error metrics found on any Lambda."],
           "confidence": "HIGH"}
    fetched = {"query_metrics:x": {"errors": 0}}  # absence of errors only
    capped = cap_speculative_dismissal(out, fetched)
    assert capped["confidence"] == "LOW"
    assert capped.get("unverified_healthy_dismissal") is True


def test_dismissal_with_positive_success_reproduction_is_exempt():
    # The failing path was actually exercised and returned 2xx -> legitimately healthy.
    out = {"root_cause": "The alert is a false positive; the endpoint is healthy.",
           "evidence": ["probe_http on the user path returned 200"],
           "confidence": "MEDIUM"}
    fetched = {"probe_http:https://api/live": {"status_code": 200, "body": "ok"}}
    assert _has_positive_success_reproduction(fetched)
    out2 = cap_speculative_dismissal(out, fetched)
    assert out2["confidence"] == "MEDIUM"          # not capped
    assert "unverified_healthy_dismissal" not in out2


def test_absence_of_errors_alone_does_not_count_as_success():
    fetched = {"query_metrics:lambda": {"Errors": 0, "Invocations": 0}}
    assert not _has_positive_success_reproduction(fetched)


def test_real_fault_diagnosis_is_not_treated_as_dismissal():
    # Asserts a concrete fault -> not a dismissal -> untouched.
    out = {"root_cause": "The app client lost ALLOW_USER_PASSWORD_AUTH, so InitiateAuth "
                         "rejects every sign-in.", "evidence": ["explicit_auth_flows=[ALLOW_REFRESH_TOKEN_AUTH]"],
           "confidence": "HIGH"}
    assert not is_symptom_dismissal(out)
    assert cap_speculative_dismissal(out, {})["confidence"] == "HIGH"

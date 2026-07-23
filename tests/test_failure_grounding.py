"""Frontier-honest core — observed-failure grounding + enforcement.

A confident diagnosis should be transparent about whether it actually OBSERVED a
failure or only inferred one from configuration; and it must NOT confidently
assert a runtime failure (a denial, an error, a non-2xx) that appears nowhere in
the evidence. Both are service-agnostic (universal failure signals, never any
service's 'correct config') and silent-fault safe."""

from cloudctl.ai.guardrails import (
    assess_observed_failure_grounding, annotate_failure_grounding,
    enforce_failure_grounding,
)


def test_denial_is_an_observed_failure():
    fetched = {"probe_permission:role=r": {"decision": "implicitDeny", "matched": []}}
    r = assess_observed_failure_grounding(fetched)
    assert r.observed_failure and "permission_denied" in r.signals


def test_http_5xx_and_nonzero_errors_are_observed_failures():
    assert assess_observed_failure_grounding(
        {"probe_http:x": {"status_code": 503}}).observed_failure
    assert assess_observed_failure_grounding(
        {"query_metrics:x": {"Errors": 7}}).observed_failure


def test_camelcase_status_code_is_an_observed_failure():
    # Regression: AWS/AppSync/API-Gateway/Lambda all render this field as
    # "statusCode" (camelCase). The http_error_status pattern was missing
    # re.I, so camelCase-only evidence silently failed to ground a correct
    # verdict, capping it to LOW even when a real 401/5xx was directly quoted.
    assert assess_observed_failure_grounding(
        {"_evidence": ["response statusCode=401 UnauthorizedException"]}
    ).observed_failure
    assert assess_observed_failure_grounding(
        {"tail_logs:x": {"statusCode": 500}}).observed_failure


def test_timeout_status_is_an_observed_failure():
    # Regression: a terminal status of "timeout"/"timed_out" is the standard way
    # runtimes report an operation that hit its time limit and did not complete —
    # exactly as terminal as "failed". The failed_state pattern only accepted
    # failed/failing/unhealthy/impaired/critical, and the error-code pattern only
    # the compound "*TimeoutException", so evidence directly quoting
    # "Status=timeout" was not recognized as an observed failure and a correct,
    # fully-cited verdict got capped to LOW.
    assert assess_observed_failure_grounding(
        {"_evidence": ["Every REPORT line: Duration=30000.00ms, Status=timeout"]}
    ).observed_failure
    assert assess_observed_failure_grounding(
        {"_evidence": ["execution Status: timeout after hitting the limit"]}
    ).observed_failure
    assert assess_observed_failure_grounding(
        {"describe_run:x": {"status": "TIMED_OUT"}}).observed_failure


def test_configured_timeout_value_is_not_an_observed_failure():
    # A CONFIGURED timeout value ("Timeout": 30) is a setting, not an observed
    # outcome — only a status/state FIELD reporting a timeout may trigger.
    r = assess_observed_failure_grounding(
        {"get_service_config:x": {"Timeout": 30, "MemorySize": 128}})
    assert not r.observed_failure and r.signals == []


def test_zero_errors_is_not_an_observed_failure():
    r = assess_observed_failure_grounding({"query_metrics:x": {"Errors": 0, "Invocations": 0}})
    assert not r.observed_failure and r.signals == []


def test_config_only_corpus_reports_no_observed_failure():
    fetched = {"get_service_config:authorizer": {"Environment": {"EXPECTED_CLIENT_ID": "abc"}},
               "tail_logs:authorizer": {"events": [], "count": 0}}
    assert not assess_observed_failure_grounding(fetched).observed_failure


def test_silent_fault_diagnosis_is_not_capped():
    # ecr-style silent fault: a correct diagnosis with no error signal AND no
    # runtime-failure claim in the root cause. Must be left at HIGH.
    out = {"root_cause": "EventBridge pattern expects COMPLETED but ECR emits COMPLETE; "
                         "zero matches, remediation never fires.",
           "evidence": ["event_pattern scan-status=[COMPLETED]", "invocations=0"],
           "confidence": "HIGH"}
    fetched = {"get_service_config:rule": {"EventPattern": {"detail": {"scan-status": ["COMPLETED"]}}}}
    enforced = enforce_failure_grounding(out, fetched)
    assert enforced["failure_grounding"]["observed_failure"] is False
    assert enforced["confidence"] == "HIGH"          # NOT capped
    assert "frontier" not in enforced


def test_claimed_but_unobserved_denial_is_capped_to_frontier():
    # pre_auth-style hallucination: claims "AccessDenied blocked all invocations"
    # but the corpus has NO observed failure (the IAM probe returned ALLOWED).
    out = {"root_cause": "The role was detached; AccessDenied blocked all invocations, "
                         "causing 100% errors with zero log output.",
           "evidence": ["probe_permission lambda:InvokeFunction returned ALLOWED"],
           "confidence": "HIGH"}
    fetched = {"probe_permission:x": {"decision": "allowed"},
               "tail_logs:x": {"events": [], "count": 0}}
    enforced = enforce_failure_grounding(out, fetched)
    assert enforced["confidence"] == "LOW"
    assert enforced["frontier"]["observed_failure"] is False
    assert "runtime failure" in enforced["confidence_override_reason"]


def test_claimed_denial_that_WAS_observed_is_not_capped():
    # secrets kms-denied style: claims a denial AND the denial is in the corpus.
    out = {"root_cause": "The rotator role is denied kms:Decrypt (AccessDenied).",
           "evidence": ["probe_permission kms:Decrypt -> implicitDeny"],
           "confidence": "HIGH"}
    fetched = {"probe_permission:kms": {"decision": "implicitDeny"}}
    enforced = enforce_failure_grounding(out, fetched)
    assert enforced["confidence"] == "HIGH"          # observed -> not capped
    assert "frontier" not in enforced


def test_absence_diagnosis_not_capped_by_tangential_failure():
    # rotation_not_enabled shape (CORRECT diagnosis): the cause is an absence —
    # rotation is disabled — grounded in a state the verdict directly read, not an
    # error. A tangential denial elsewhere in the corpus must NOT cap it; an absence
    # diagnosis does not claim a runtime failure, so it keeps its confidence.
    out = {"root_cause": "RotationEnabled is false and no rotation schedule is bound, "
                         "so the scheduler never fires and rotation never runs.",
           "evidence": ["describe_secret: RotationEnabled=false",
                        "RotationAttempted metric: 0 datapoints"],
           "confidence": "HIGH"}
    fetched = {"probe_permission:tangential": {"decision": "implicitDeny"}}
    enforced = enforce_failure_grounding(out, fetched)
    assert enforced["confidence"] == "HIGH"          # absence diagnosis -> not capped
    assert "frontier" not in enforced


def test_claimed_failure_that_cites_its_denial_survives():
    # Claims a denial AND cites the observed denial in its evidence -> grounded.
    out = {"root_cause": "The rotator role is denied kms:Decrypt (access denied), so "
                         "rotation cannot decrypt the secret.",
           "evidence": ["probe_permission kms:Decrypt -> implicitDeny"],
           "confidence": "HIGH"}
    fetched = {"probe_permission:kms": {"decision": "implicitDeny"}}
    assert enforce_failure_grounding(out, fetched)["confidence"] == "HIGH"


def test_claimed_failure_citing_no_observed_failure_is_capped():
    # Claims a denial but its evidence cites none observed -> fabricated/coincidental.
    out = {"root_cause": "AccessDenied blocked every invocation of the rotator.",
           "evidence": ["the handler is a no-op stub"],
           "confidence": "HIGH"}
    fetched = {"probe_permission:x": {"decision": "allowed"}}
    enforced = enforce_failure_grounding(out, fetched)
    assert enforced["confidence"] == "LOW" and "frontier" in enforced


def test_annotate_is_metadata_only():
    out = {"root_cause": "AccessDenied everywhere", "evidence": [], "confidence": "HIGH"}
    a = annotate_failure_grounding(out, {"x": {"ok": 1}})
    assert a["confidence"] == "HIGH" and a["failure_grounding"]["observed_failure"] is False

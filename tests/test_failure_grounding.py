"""Frontier-honest core — the observed-failure grounding detector.

A confident diagnosis should be transparent about whether it actually OBSERVED a
failure or only inferred one from configuration. The detector is service-agnostic
(keys off universal failure signals, never any service's 'correct config') and,
crucially, is honest-metadata only: it must NOT be used to cap a correctly
diagnosed SILENT fault (a real fault that emits no error signal)."""

from cloudctl.ai.guardrails import (
    assess_observed_failure_grounding, annotate_failure_grounding,
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


def test_zero_errors_is_not_an_observed_failure():
    r = assess_observed_failure_grounding({"query_metrics:x": {"Errors": 0, "Invocations": 0}})
    assert not r.observed_failure and r.signals == []


def test_config_only_corpus_reports_no_observed_failure():
    # pre_auth-style: only config was read, no failure captured.
    fetched = {"get_service_config:authorizer": {"Environment": {"EXPECTED_CLIENT_ID": "abc"}},
               "tail_logs:authorizer": {"events": [], "count": 0}}
    r = assess_observed_failure_grounding(fetched)
    assert not r.observed_failure   # honest: this rests on config inference


def test_silent_fault_diagnosis_is_not_penalized_by_the_detector():
    # ecr-style silent fault: a pattern that never matches. There is no error
    # signal, yet this is a CORRECT diagnosis. The detector must only REPORT
    # observed_failure=False — annotate must NOT touch confidence.
    out = {"root_cause": "EventBridge pattern expects COMPLETED but ECR emits COMPLETE; "
                         "zero matches, remediation never fires.",
           "evidence": ["event_pattern scan-status=[COMPLETED]", "invocations=0"],
           "confidence": "HIGH"}
    fetched = {"get_service_config:rule": {"EventPattern": {"detail": {"scan-status": ["COMPLETED"]}}}}
    annotated = annotate_failure_grounding(out, fetched)
    assert annotated["failure_grounding"]["observed_failure"] is False
    assert annotated["confidence"] == "HIGH"     # NOT capped — silent fault safe


def test_annotation_is_attached_and_lists_signals():
    out = {"root_cause": "x", "evidence": [], "confidence": "MEDIUM"}
    fetched = {"probe_permission:r": {"decision": "explicitDeny"}}
    a = annotate_failure_grounding(out, fetched)
    assert a["failure_grounding"]["observed_failure"] is True
    assert "permission_denied" in a["failure_grounding"]["signals"]

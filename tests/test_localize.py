"""LOCALIZE pillar — anchor the diagnosis on the component actually emitting the
failure, not on a quiet component that happens to look unusual."""

from cloudctl.debug.localize import (
    localize_failures, scan_component_failures,
    diagnosis_is_anchored, enforce_localization_anchor,
)


def test_mislocalized_verdict_is_capped_to_localization_boundary():
    # pre_auth-shaped miss: pre-auth is emitting the failure, but the verdict
    # blames the (quiet) IAM role / authorizer.
    fmap = [{"component": "cognito-auth-pre-auth", "error_count": 5,
             "sample": "RuntimeError: PreAuthentication check failed"}]
    out = {"root_cause": "The cognito-auth-authorizer role was detached, causing failures.",
           "confidence": "HIGH"}
    enforced = enforce_localization_anchor(out, fmap)
    assert enforced["confidence"] == "LOW"
    assert enforced["localization"]["anchored"] is False
    assert "cognito-auth-pre-auth" in enforced["localization"]["emitting_components"]


def test_correctly_anchored_verdict_is_untouched():
    fmap = [{"component": "cognito-auth-pre-auth", "error_count": 5, "sample": "x"}]
    out = {"root_cause": "cognito-auth-pre-auth throws on every sign-in (FAIL_ALWAYS=1).",
           "confidence": "HIGH"}
    assert diagnosis_is_anchored(out["root_cause"], fmap)
    assert enforce_localization_anchor(out, fmap)["confidence"] == "HIGH"


def test_empty_map_imposes_no_constraint():
    out = {"root_cause": "anything", "confidence": "HIGH"}
    assert diagnosis_is_anchored("anything", [])
    assert enforce_localization_anchor(out, [])["confidence"] == "HIGH"


def test_emitting_component_is_localized_with_message():
    # pre_auth-shaped: the failing Lambda logs the RuntimeError; the authorizer
    # and role are quiet. The map must point at pre-auth.
    logs = {
        "cognito-auth-pre-auth": [
            '[ERROR] pre_authentication RuntimeError: PreAuthentication check failed: '
            'account verification service unreachable',
            'Traceback (most recent call last): ...',
        ],
        "cognito-auth-authorizer": [
            '{"level":"INFO","context":"authorize","allow":true}',
        ],
    }
    fm = localize_failures(logs)
    assert fm and fm[0]["component"] == "cognito-auth-pre-auth"
    assert "preauthentication check failed" in fm[0]["sample"].lower()
    # the quiet authorizer is NOT in the failure map
    assert all(e["component"] != "cognito-auth-authorizer" for e in fm)


def test_ranked_by_error_count():
    logs = {"a": ["ERROR x", "ERROR y"], "b": ["Exception z"]}
    fm = localize_failures(logs)
    assert [e["component"] for e in fm] == ["a", "b"]


def test_no_failure_yields_empty_map_for_silent_faults():
    # A silent fault emits nothing; the map is correctly empty and the frontier
    # core takes over instead of fabricating.
    logs = {"svc": ['{"level":"INFO"}', '"Errors": 0', "no errors this window"]}
    assert localize_failures(logs) == []


def test_zero_error_metric_is_not_a_failure():
    assert localize_failures({"svc": ['{"errorCount": 0, "invocations": 5}']}) == []


def test_scan_uses_real_fetcher_interface_defensively():
    class FakeFetcher:
        def discover_log_groups(self, prefix, limit=3):
            return [f"/aws/lambda/{prefix}"] if "pre-auth" in prefix else []
        def tail_log_group(self, log_group, lines=60):
            if "pre-auth" in log_group:
                return [{"message": "[ERROR] RuntimeError: PreAuthentication check failed"}]
            return []
    fm = scan_component_failures(FakeFetcher(),
                                 ["cognito-auth-pre-auth", "cognito-auth-authorizer"])
    assert len(fm) == 1 and fm[0]["component"] == "cognito-auth-pre-auth"


def test_scan_survives_fetcher_exceptions():
    class Broken:
        def discover_log_groups(self, prefix, limit=3):
            raise RuntimeError("no access")
        def tail_log_group(self, log_group, lines=60):
            raise RuntimeError("no access")
    assert scan_component_failures(Broken(), ["x", "y"]) == []

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


# ── Upstream / downstream causes ─────────────────────────────────────────────
# Live regression (small app): a Lambda writing to a DynamoDB table at 1 WCU.
# The verdict correctly blamed the table's capacity; the errors surfaced on the
# Lambda. The anchor check capped HIGH to LOW because the root cause did not
# name the Lambda. A cause that evidence ties to the emitting component is
# localized; a cause nothing ties to it is still capped.

_LAMBDA_ERRORS = [
    "[ERROR] ClientError: An error occurred (ProvisionedThroughputExceededException) "
    "when calling the PutItem operation (reached max retries: 1): The level of "
    "configured provisioned throughput for the table was exceeded.",
    "[ERROR] Runtime.UnhandledException ProvisionedThroughputExceededException",
    '{"level":"INFO","msg":"received order"}',
]


def _fmap():
    return localize_failures({"cctl-smallapp-ingest": _LAMBDA_ERRORS})


def test_failure_map_carries_error_identifiers():
    fm = _fmap()
    assert fm[0]["component"] == "cctl-smallapp-ingest"
    assert "ProvisionedThroughputExceededException" in fm[0]["error_ids"]
    assert "ClientError" not in fm[0]["error_ids"]          # generic wrapper
    assert len(fm[0]["samples"]) == 2


def test_upstream_cause_explaining_the_emitting_error_is_not_capped():
    out = {"root_cause": "DynamoDB table cctl-smallapp-orders is provisioned at 1 WCU; "
                         "writes exceed it and fail with ProvisionedThroughputExceededException.",
           "confidence": "HIGH"}
    enforced = enforce_localization_anchor(out, _fmap())
    assert enforced["confidence"] == "HIGH"
    assert enforced["localization"]["anchored"] is True
    assert enforced["localization"]["linked_via"] == "error_id_in_root_cause"
    assert "confidence_override_reason" not in enforced


def test_upstream_cause_named_in_the_emitting_errors_is_not_capped():
    fm = localize_failures({"orders-api": [
        "ERROR timeout connecting to payments-db.cluster-x.us-east-1.rds.amazonaws.com:5432"]})
    out = {"root_cause": "payments-db.cluster-x.us-east-1.rds.amazonaws.com hit max_connections.",
           "confidence": "HIGH"}
    enforced = enforce_localization_anchor(out, fm)
    assert enforced["confidence"] == "HIGH"
    assert enforced["localization"]["linked_via"] == "error_names_cause"


def test_evidence_line_linking_emitting_component_to_cause_is_enough():
    out = {"root_cause": "Table cctl-smallapp-orders has only 1 WCU and no auto scaling.",
           "evidence": ["cctl-smallapp-ingest writes to cctl-smallapp-orders and its "
                        "logs show 1,338 failed PutItem calls"],
           "confidence": "HIGH"}
    enforced = enforce_localization_anchor(out, _fmap())
    assert enforced["confidence"] == "HIGH"
    assert enforced["localization"]["linked_via"] == "evidence_links"


def test_declared_dependency_in_emitting_component_config_is_enough():
    out = {"root_cause": "Table cctl-smallapp-orders has only 1 WCU and no auto scaling.",
           "confidence": "HIGH"}
    fetched = {"get_service_config:lambda:cctl-smallapp-ingest": {
        "environment": {"TABLE_NAME": "cctl-smallapp-orders"}}}
    enforced = enforce_localization_anchor(out, _fmap(), fetched)
    assert enforced["confidence"] == "HIGH"
    assert enforced["localization"]["linked_via"] == "declared_dependency"
    # Config of some OTHER component referencing the table is not a link.
    other = {"get_service_config:lambda:reporting-job": {
        "environment": {"TABLE_NAME": "cctl-smallapp-orders"}}}
    assert enforce_localization_anchor(out, _fmap(), other)["confidence"] == "LOW"


def test_unconnected_blame_is_still_capped():
    out = {"root_cause": "The cognito-auth-authorizer role was detached, rejecting requests.",
           "evidence": ["cctl-smallapp-ingest logs show ProvisionedThroughputExceededException",
                        "cognito-auth-authorizer role policy changed yesterday"],
           "confidence": "HIGH"}
    fetched = {"get_service_config:lambda:cctl-smallapp-ingest": {
        "environment": {"TABLE_NAME": "cctl-smallapp-orders"}}}
    enforced = enforce_localization_anchor(out, _fmap(), fetched)
    assert enforced["confidence"] == "LOW"
    assert enforced["localization"]["anchored"] is False
    assert "no evidence links" in enforced["confidence_override_reason"]


def test_generic_language_error_is_not_a_link():
    # pre_auth-shaped: a generic RuntimeError on the emitting Lambda cannot
    # vouch for a verdict that blames a quiet authorizer.
    fm = localize_failures({"cognito-auth-pre-auth": [
        "[ERROR] RuntimeError: PreAuthentication check failed"]})
    out = {"root_cause": "cognito-auth-authorizer raises RuntimeError on every call.",
           "confidence": "HIGH"}
    assert enforce_localization_anchor(out, fm)["confidence"] == "LOW"


def test_plain_words_shared_with_logs_are_not_a_link():
    fm = localize_failures({"checkout-fn": ["ERROR failed to save orders: timeout"]})
    out = {"root_cause": "The billing-cron schedule drifted, so orders stopped.",
           "confidence": "HIGH"}
    assert enforce_localization_anchor(out, fm)["confidence"] == "LOW"


def test_old_failure_map_records_without_new_fields_still_link():
    # Recordings made before error_ids/samples existed carry only "sample".
    fm = [{"component": "cctl-smallapp-ingest", "error_count": 3,
           "sample": _LAMBDA_ERRORS[0]}]
    out = {"root_cause": "cctl-smallapp-orders throttles writes: "
                         "ProvisionedThroughputExceededException.",
           "confidence": "HIGH"}
    assert enforce_localization_anchor(out, fm)["confidence"] == "HIGH"


def test_region_and_service_endpoint_are_not_a_link():
    fm = localize_failures({"checkout-fn": [
        "ERROR timeout calling dynamodb.us-east-1.amazonaws.com in us-east-1"]})
    out = {"root_cause": "The us-east-1 billing-authorizer was misconfigured "
                         "(dynamodb.us-east-1.amazonaws.com unaffected).",
           "confidence": "HIGH"}
    assert enforce_localization_anchor(out, fm)["confidence"] == "LOW"

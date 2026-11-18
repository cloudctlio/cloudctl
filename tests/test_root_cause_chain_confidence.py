"""Confidence is scored on the root-cause chain, not on every sentence.

Live regression (run 3, small app: Lambda writing to a 1 WCU DynamoDB table):
the verdict named the right root cause, but HIGH was weakened to MEDIUM
because 2 of 8 claims traced to no fetched data. Both were side claims, not
part of the root cause ("ConsumedWriteCapacityUnits=1,498 in one 30-min
window", "Lambda runtime healthy: Duration=20,999ms, Memory=107/256MB").

Now: an untraceable side claim is moved to unverified_claims and does not
lower confidence; an untraceable claim the root cause rests on still does.
"""
from __future__ import annotations

import copy

from cloudctl.ai.graph_agent import _root_cause_chain
from cloudctl.ai.graph_agent import _score_on_root_cause_chain as _score_pair


def _score_on_root_cause_chain(report, fetched):
    out, hal = _score_pair(report, fetched)
    assert hal.hallucination_rate <= 1.0
    return out

FETCHED = {
    "list_resources": {"resources": ["cctl-smallapp-orders", "cctl-smallapp-ingest"]},
    "get_service_config:service_type=dynamodb|resource_name=cctl-smallapp-orders": {
        "table_name": "cctl-smallapp-orders", "billing_mode": "PROVISIONED",
        "provisioned_throughput": {"write_capacity_units": 1}},
    "query_metrics:namespace=AWS/DynamoDB|metric=WriteThrottleEvents": {
        "metric": "WriteThrottleEvents", "table": "cctl-smallapp-orders", "sum": 1338},
    "tail_logs:resource_hint=cctl-smallapp-ingest": {"events": [
        "ProvisionedThroughputExceededException when calling the PutItem operation",
        "batch done: 800 orders, 270 failed"]},
}

ROOT_CAUSE = ("DynamoDB table cctl-smallapp-orders is provisioned at 1 WCU with no "
              "auto scaling, so 270 of 800 writes from cctl-smallapp-ingest fail "
              "with ProvisionedThroughputExceededException.")

SOURCED = [
    "cctl-smallapp-orders WriteThrottleEvents=1338 in the window",
    "cctl-smallapp-ingest logs show ProvisionedThroughputExceededException on PutItem",
    "Table billing mode is PROVISIONED with write_capacity_units of 1",
]
SIDE_UNSOURCED = [
    "ConsumedWriteCapacityUnits=1,498 in one 30-min window",
    "Lambda runtime healthy: Duration=20,999ms, Memory=107/256MB",
]


def _report(**kw):
    r = {
        "root_cause": ROOT_CAUSE,
        "evidence": SOURCED + SIDE_UNSOURCED,
        "confidence": "HIGH",
        "alternatives_considered": [
            {"hypothesis": "IAM denial", "reason": "no AccessDenied"},
            {"hypothesis": "Lambda bug", "reason": "only throttle errors"}],
    }
    r.update(kw)
    return r


def test_unsourced_side_claims_keep_confidence_and_are_flagged():
    out = _score_on_root_cause_chain(_report(), copy.deepcopy(FETCHED))
    assert out["confidence"] == "HIGH"
    assert "confidence_override_reason" not in out
    # Not presented as fact: moved out of evidence, listed as unverified.
    assert out["unverified_claims"] == SIDE_UNSOURCED
    assert all(s not in out["evidence"] for s in SIDE_UNSOURCED)
    assert set(SIDE_UNSOURCED) <= set(out["unsourced_claims"])
    assert out["claim_chain"]["unverified_side_claims"] == 2
    # Sourced claims, side or chain, stay as evidence.
    assert out["evidence"] == SOURCED


def test_unsourced_claim_repeated_in_root_cause_still_weakens():
    rc = ROOT_CAUSE + " Consumption peaked at ConsumedWriteCapacityUnits=1,498 per 30-min window."
    out = _score_on_root_cause_chain(_report(root_cause=rc), copy.deepcopy(FETCHED))
    assert out["confidence"] in ("MEDIUM", "LOW")
    assert "confidence_override_reason" in out
    # A chain claim is never set aside as a side claim.
    assert SIDE_UNSOURCED[0] in out["evidence"]


def test_evidence_the_verdict_says_it_rests_on_counts_even_without_shared_tokens():
    out = _score_on_root_cause_chain(_report(root_cause_evidence=[0, 1, 3]),
                                     copy.deepcopy(FETCHED))
    assert out["confidence"] in ("MEDIUM", "LOW")
    assert SIDE_UNSOURCED[0] in out["evidence"]
    # The other side claim is still set aside, not counted.
    assert out.get("unverified_claims") == [SIDE_UNSOURCED[1]]


def test_declaring_a_narrow_chain_cannot_drop_a_linked_claim():
    rc = ROOT_CAUSE + " Consumption peaked at ConsumedWriteCapacityUnits=1,498 per 30-min window."
    chain, side = _root_cause_chain(_report(root_cause=rc, root_cause_evidence=[0]))
    assert SIDE_UNSOURCED[0] in chain
    assert SIDE_UNSOURCED[1] in side


def test_fully_sourced_report_is_unchanged():
    rep = _report(evidence=list(SOURCED))
    out = _score_on_root_cause_chain(copy.deepcopy(rep), copy.deepcopy(FETCHED))
    assert out["confidence"] == "HIGH"
    assert "confidence_override_reason" not in out
    assert "unverified_claims" not in out
    assert out["evidence"] == SOURCED


def test_unsourced_root_cause_sentence_still_weakens():
    rc = ROOT_CAUSE + " The table was recreated by stack orders-v2-9f3a at 14:02."
    out = _score_on_root_cause_chain(_report(root_cause=rc, evidence=list(SOURCED)),
                                     copy.deepcopy(FETCHED))
    assert out["confidence"] in ("MEDIUM", "LOW")


def test_enforce_confidence_without_side_claims_keeps_old_behaviour():
    from cloudctl.ai.guardrails import HallucinationReport, enforce_confidence
    rep = _report()
    rep["unsourced_claims"] = list(SIDE_UNSOURCED)
    rep["provenance"] = [{"claim": c} for c in SOURCED + [ROOT_CAUSE]]
    clean = HallucinationReport(hallucination_rate=0.0, verdict="clean", unsupported=[])
    old = enforce_confidence(copy.deepcopy(rep), FETCHED, clean)
    assert old["confidence"] == "MEDIUM"                 # 2 of 6 untraced
    new = enforce_confidence(copy.deepcopy(rep), FETCHED, clean, side_claims=SIDE_UNSOURCED)
    assert new["confidence"] == "HIGH"

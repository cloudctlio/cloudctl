"""Anti-fabrication traceability (_observed_is_traceable).

A CONFIRMED prediction's observation must quote real fetched data. The old rule
(>=50% of ALL words present) over-downgraded legitimate observations whose facts
were real but wrapped in prose. The rule now checks the DISTINCTIVE tokens
(identifiers/values/error codes), ignoring plain words.
"""
from __future__ import annotations

from cloudctl.ai.graph_agent import _observed_is_traceable


CORPUS = (
    '{"table":"platform-inventory","writecapacityunits":1,'
    '"error":"provisionedthroughputexceededexception","arn":'
    '"arn:aws:dynamodb:us-east-1:123:table/platform-inventory"}'
).lower()


def test_real_facts_in_prose_pass():
    # real identifiers/values, surrounded by ordinary prose words
    observed = ("The DynamoDB table platform-inventory was throttling with "
                "writecapacityunits=1 and threw ProvisionedThroughputExceededException")
    ok, reason = _observed_is_traceable(observed, CORPUS)
    assert ok is True, reason


def test_fabricated_facts_are_caught():
    # specific identifiers that do NOT appear anywhere in the corpus
    observed = ("table orders-cache had readcapacityunits=999 and threw "
                "ResourceNotFoundException on arn:aws:s3:::made-up-bucket-name")
    ok, _ = _observed_is_traceable(observed, CORPUS)
    assert ok is False


def test_prose_only_observation_not_penalised():
    # no specific fact to fabricate — must not be downgraded on this check
    observed = "the queue had no messages and everything looked healthy"
    ok, _ = _observed_is_traceable(observed, CORPUS)
    assert ok is True


def test_partial_facts_majority_real_passes():
    observed = "platform-inventory at writecapacityunits=1 (arn ...dynamodb...)"
    ok, _ = _observed_is_traceable(observed, CORPUS)
    assert ok is True


def test_empty_observation_not_penalised():
    ok, _ = _observed_is_traceable("", CORPUS)
    assert ok is True


def test_downgrade_reason_reports_specific_token_count():
    observed = "orders-cache readcapacityunits=999 resourcenotfoundexception-xyz"
    ok, reason = _observed_is_traceable(observed, CORPUS)
    assert ok is False
    assert "specific tokens" in reason

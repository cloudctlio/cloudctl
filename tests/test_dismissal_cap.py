"""The speculative-dismissal cap must downgrade unfounded "false positive"
verdicts to LOW, but must NOT penalize a valid, evidenced diagnosis of a
genuinely misconfigured alarm — while still refusing to be fooled by an
INVENTED alarm (the confabulation loophole)."""
from __future__ import annotations

from cloudctl.ai.guardrails import cap_speculative_dismissal as cap


def _conf(out):
    return out["confidence"]


def test_plain_dismissal_capped():
    d = {"confidence": "HIGH",
         "root_cause": "the alert is a false positive; system is fully operational",
         "evidence": []}
    assert _conf(cap(d)) == "LOW"


def test_grounded_misconfigured_alarm_exempt():
    # a REAL alarm with a REAL threshold in fetched data → valid diagnosis, keep it
    d = {"confidence": "HIGH",
         "root_cause": "false positive: the CloudWatch alarm threshold is set to 10 "
                       "not 90 — misconfigured alarm",
         "evidence": ["alarm threshold wrong"]}
    fetched = {"describe_alarms": {"MetricAlarms": [{"AlarmName": "cpu-high",
                                                     "Threshold": 10.0}]}}
    assert _conf(cap(d, fetched)) == "HIGH"


def test_confabulated_alarm_still_capped():
    # alerting-defect language but NO real alarm in fetched (describe_alarms empty)
    # → the invented-mechanism loophole stays closed
    d = {"confidence": "HIGH",
         "root_cause": "false positive: alarm TreatMissingData=breaching fires on "
                       "metric absence",
         "evidence": []}
    fetched = {"describe_alarms": {"MetricAlarms": [], "CompositeAlarms": []}}
    assert _conf(cap(d, fetched)) == "LOW"


def test_real_fault_diagnosis_untouched():
    d = {"confidence": "HIGH",
         "root_cause": "GSI owner-index deleted; the query fails",
         "evidence": ["DynamoDbException"]}
    assert _conf(cap(d)) == "HIGH"


def test_no_fetched_data_defaults_to_cap():
    # cannot verify grounding without fetched data → safe default is to cap
    d = {"confidence": "HIGH",
         "root_cause": "false positive: misconfigured alarm threshold",
         "evidence": []}
    assert _conf(cap(d, None)) == "LOW"

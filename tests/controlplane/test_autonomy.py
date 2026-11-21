"""The autonomy table: class first, then tier × severity, then the platform cap, then θ."""
import pytest

from cloudctl.controlplane import autonomy as A
from cloudctl.gate.config import parse_config
from cloudctl.gate.models import ConfigError
from tests.gate.conftest import aws_env, config_doc

T = A.AutonomyTable()


@pytest.mark.parametrize("tier", A.TIERS)
@pytest.mark.parametrize("sev", A.SEVERITIES)
def test_security_incident_is_report_everywhere_even_at_full_confidence(tier, sev):
    d = T.decide(tier=tier, severity=sev, drift_class=A.SECURITY_INCIDENT, confidence=1.0, platform="terraform")
    assert d.mode == A.REPORT and "security incident" in d.reasons[0]


def test_tier_and_severity_come_before_confidence():
    # full confidence never lifts an approve cell
    assert T.decide(tier="prod", severity="MEDIUM", drift_class=A.CONFIG_DRIFT, confidence=1.0).mode == A.APPROVE
    assert T.decide(tier="dev", severity="HIGH", drift_class=A.CONFIG_DRIFT, confidence=1.0).mode == A.APPROVE
    assert T.decide(tier="dev", severity="CRITICAL", drift_class=A.CONFIG_DRIFT, confidence=1.0).mode == A.REPORT
    # θ only matters inside an auto cell
    assert T.decide(tier="prod", severity="LOW", drift_class=A.CONFIG_DRIFT, confidence=0.95).mode == A.AUTO
    d = T.decide(tier="prod", severity="LOW", drift_class=A.CONFIG_DRIFT, confidence=0.85)
    assert d.mode == A.APPROVE and "below θ 0.90" in d.reasons[-1]
    assert T.decide(tier="dev", severity="MEDIUM", drift_class=A.CONFIG_DRIFT, confidence=0.6).mode == A.AUTO
    assert T.decide(tier="staging", severity="LOW", drift_class=A.CONFIG_DRIFT, confidence=0.75).mode == A.APPROVE


def test_failed_change_never_auto_and_cfn_is_report_only():
    assert T.decide(tier="dev", severity="LOW", drift_class=A.FAILED_CHANGE, confidence=1.0).mode == A.APPROVE
    for p in ("cloudformation", "cdk"):
        d = T.decide(tier="dev", severity="LOW", drift_class=A.CONFIG_DRIFT, confidence=1.0, platform=p)
        assert d.mode == A.REPORT and "does not revert drift" in d.reasons[-1]


def test_unknown_inputs_fail_closed():
    with pytest.raises(A.AutonomyConfigError):
        T.decide(tier="qa", severity="LOW", drift_class=A.CONFIG_DRIFT, confidence=1.0)
    with pytest.raises(A.AutonomyConfigError):
        T.decide(tier="dev", severity="SEVERE", drift_class=A.CONFIG_DRIFT, confidence=1.0)
    with pytest.raises(A.AutonomyConfigError):
        T.decide(tier="dev", severity="LOW", drift_class="whatever", confidence=1.0)


def test_parse_overrides_cells_and_theta():
    t = A.parse_autonomy({"autonomy": {"staging": {"medium": "auto"}}, "theta": {"staging": 0.7}})
    assert t.table["staging"]["MEDIUM"] == A.AUTO and t.theta["staging"] == 0.7
    assert t.table["prod"] == A.DEFAULT_TABLE["prod"]


@pytest.mark.parametrize("doc,msg", [
    ({"autonomy": {"dev": {"CRITICAL": "auto"}}}, "never auto-repaired"),
    ({"autonomy": {"prod": {"HIGH": "auto"}}}, "HIGH drift in prod"),
    ({"autonomy": {"dev": {"LOW": "report", "MEDIUM": "auto"}}}, "more autonomous than a lower"),
    ({"theta": {"prod": 0.4}}, "at least 0.5"),
    ({"theta": {"dev": 1.5}}, "from 0 to 1"),
    ({"theta": {"dev": True}}, "from 0 to 1"),
    ({"autonomy": {"qa": {}}}, "unknown tier"),
    ({"autonomy": {"dev": {"LOW": "yolo"}}}, "is not one of"),
    ({"bogus": 1}, "unknown key"),
])
def test_parse_refuses_unsafe_or_malformed_tables(doc, msg):
    with pytest.raises(A.AutonomyConfigError, match=msg):
        A.parse_autonomy(doc)


def test_gate_config_carries_the_table(tmp_path):
    doc = config_doc({"dev": aws_env("dev")}, tmp=tmp_path)
    assert parse_config(doc).drift.table == A.DEFAULT_TABLE
    doc["drift"] = {"theta": {"dev": 0.7}}
    assert parse_config(doc).drift.theta["dev"] == 0.7
    doc["drift"] = {"autonomy": {"prod": {"HIGH": "auto"}}}
    with pytest.raises(ConfigError, match="drift"):
        parse_config(doc)

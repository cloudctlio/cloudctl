"""Monitor drift and who made each change, on AWS, Azure and Google Cloud.

Everything runs from recordings; nothing calls a cloud. The AWS replays use
the complex orders app: D3 (QUEUE_URL changed by hand with boto3) against C2
(the same change made by ``terraform apply``), plus monitor drift (S3).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import diff_first_fixtures as fx  # noqa: E402
import drift_attribution_fixtures as dfx  # noqa: E402
from cloudctl.debug.diff_first import apply_to_report, run_diff_first  # noqa: E402
from cloudctl.debug.diff_first.attribution import (  # noqa: E402
    arm_parent, attribute, caller_signal, is_write, normalize_azure_activity,
    normalize_cloudtrail, normalize_gcp_audit, principal_hint,
)
from cloudctl.debug.diff_first.live import NOT_FOUND, RecordedLive  # noqa: E402
from cloudctl.debug.diff_first.live_clouds import (  # noqa: E402
    AzureLive, GcpLive, MultiCloudLive, _arm_shape, gcp_url,
)
from cloudctl.debug.diff_first.model import Resource  # noqa: E402
from cloudctl.debug.diff_first.normalize import (  # noqa: E402
    canonical_type, cloud_of_type, diff_configs, flatten, is_observer, loose_equal,
)


def _run(state: dict, data: dict, tmp_path: Path) -> dict:
    (tmp_path / "main.tf").write_text("# app\n")
    (tmp_path / "terraform.tfstate").write_text(json.dumps(state))
    return run_diff_first(RecordedLive(data), iac_root=str(tmp_path),
                          account=fx.ACCT, region=fx.REGION).to_dict()


def _change(rep: dict, prefix: str) -> dict:
    hits = [c for c in rep["changes"] if c["event_name"].startswith(prefix)]
    assert hits, [c["event_name"] for c in rep["changes"]]
    return hits[-1]


def _app_drift(rep: dict) -> list[dict]:
    return [d for d in rep["drift"] if not d.get("observer")]


# ── AWS: D3 hand change vs C2 Terraform change ───────────────────────────────

def test_d3_hand_change_with_boto3_is_manual_and_drifts(tmp_path):
    rep = _run(*dfx.aws_case("d3"), tmp_path)
    drift = _app_drift(rep)
    assert [d["resource_key"] for d in drift] == ["aws_lambda_function.api"]
    assert drift[0]["fields"][0]["field"].endswith("queueurl")
    assert drift[0]["route"] == "manual" and drift[0]["fix_direction"] == "reapply_iac"
    ch = _change(rep, "UpdateFunctionConfiguration")
    assert (ch["route"], ch["route_how"], ch["route_confidence"]) == ("manual", "sdk", "high")
    assert ch["matches_iac"] is False and ch["fix_direction"] == "reapply_iac"
    assert ch["principal"].endswith("dev@example.com")
    causes = rep["explanation"]["causes"]
    assert causes and "made by hand" in causes[0]["summary"]
    assert causes[0]["evidence"]["route"] == "manual"


def test_c2_same_change_through_terraform_is_iac_with_no_drift(tmp_path):
    rep = _run(*dfx.aws_case("c2"), tmp_path)
    assert _app_drift(rep) == []
    ch = _change(rep, "UpdateFunctionConfiguration")
    assert (ch["route"], ch["route_how"], ch["route_confidence"]) == ("iac", "terraform", "high")
    assert ch["matches_iac"] is True and ch["fix_direction"] == "edit_iac"
    causes = rep["explanation"]["causes"]
    assert causes and "deployed by Terraform" in causes[0]["summary"]
    assert causes[0]["evidence"]["fix_direction"] == "edit_iac"


def test_d3_and_c2_have_the_same_principal_but_different_labels(tmp_path):
    # Same SSO user both times: only the caller's tool and the IaC match differ.
    (tmp_path / "d3").mkdir()
    (tmp_path / "c2").mkdir()
    d3 = _change(_run(*dfx.aws_case("d3"), tmp_path / "d3"), "UpdateFunctionConfiguration")
    c2 = _change(_run(*dfx.aws_case("c2"), tmp_path / "c2"), "UpdateFunctionConfiguration")
    assert d3["principal"] == c2["principal"]
    assert d3["route"] != c2["route"]
    assert d3["fix_direction"] != c2["fix_direction"]


def test_console_change_is_manual_console(tmp_path):
    rep = _run(*dfx.aws_case("console"), tmp_path)
    ch = _change(rep, "UpdateFunctionConfiguration")
    assert (ch["route"], ch["route_how"]) == ("manual", "console")
    assert _app_drift(rep)[0]["route"] == "manual"


def test_terraform_agent_but_state_disagrees_is_reconcile(tmp_path):
    rep = _run(*dfx.aws_case("tf_other"), tmp_path)
    ch = _change(rep, "UpdateFunctionConfiguration")
    assert ch["route"] == "iac" and ch["route_how"] == "terraform"
    assert ch["matches_iac"] is False and ch["fix_direction"] == "reconcile"
    assert "does not hold it" in ch["route_label"]


def test_cloudformation_change_in_a_terraform_app_is_reconcile(tmp_path):
    rep = _run(*dfx.aws_case("cfn"), tmp_path)
    ch = _change(rep, "UpdateFunctionConfiguration")
    assert (ch["route"], ch["route_how"]) == ("iac", "cloudformation")
    assert ch["fix_direction"] == "reconcile"


# ── AWS: monitor drift ───────────────────────────────────────────────────────

def test_alarm_threshold_raised_by_hand_is_reported_but_never_a_cause(tmp_path):
    rep = _run(*dfx.aws_case("s3"), tmp_path)
    obs = rep["observer_drift"]
    assert [o["resource_key"] for o in obs] == ["aws_cloudwatch_metric_alarm.dlq"]
    assert obs[0]["fields"] == [{"field": "threshold", "expected": 0.0, "live": 100.0}]
    assert obs[0]["route"] == "manual"
    assert rep["explanation"]["causes"] == []
    put = _change(rep, "PutMetricAlarm")
    assert put["status"] == "observer"
    assert (put["route"], put["route_how"]) == ("manual", "cli")


def test_silenced_alarm_never_displaces_the_real_cause(tmp_path):
    rep = _run(*dfx.aws_case("s3_symptom"), tmp_path)
    causes = rep["explanation"]["causes"]
    assert causes and all("alarm" not in c["summary"].lower() for c in causes)
    assert all("PutMetricAlarm" not in c["summary"] for c in causes
               + rep["explanation"].get("alternatives", []))
    assert any("UpdateFunctionConfiguration" in c["summary"] for c in causes)
    assert [o["resource_key"] for o in rep["observer_drift"]] == ["aws_cloudwatch_metric_alarm.dlq"]
    assert all(not c.get("observer") for c in rep["context"] if c.get("kind") == "candidate")


def test_disable_alarm_actions_is_attributed_through_the_resource(tmp_path):
    rep = _run(*dfx.aws_case("alarm_actions"), tmp_path)
    obs = rep["observer_drift"]
    assert obs and obs[0]["fields"][0]["field"] == "actionsenabled"
    assert (obs[0]["route"], obs[0]["route_label"].split(" in ")[-1]) == ("manual", "the AWS console, outside the IaC")
    assert _change(rep, "DisableAlarmActions")["status"] == "observer"


def test_monitor_drift_reaches_the_prompt_and_the_report(tmp_path):
    rep = _run(*dfx.aws_case("s3_symptom"), tmp_path)
    from cloudctl.debug.diff_first.run import prompt_text
    text = prompt_text(rep, max_chars=20000)
    assert "MONITOR DRIFT" in text and "never the cause" in text
    assert "Fix direction" in text
    out = apply_to_report({"root_cause": "api QUEUE_URL points at a queue that doesn't exist",
                           "confidence": "HIGH", "evidence": []}, rep)
    df = out["diff_first"]
    assert df["monitor_drift"] and "threshold" in df["monitor_drift"][0]
    assert df["causes"][0]["route"] == "manual"
    assert df["causes"][0]["fix_direction"] == "reapply_iac"


def test_debug_command_renders_a_monitor_drift_row():
    from rich.table import Table
    from cloudctl.commands.debug_cmd import _render_diff_first_rows
    t = Table()
    t.add_column("k")
    t.add_column("v")
    _render_diff_first_rows(t, {"diff_first": {"ran": True, "causes": [],
                                               "monitor_drift": ["alarm x: threshold 0 -> 100"]}})
    labels = [str(c) for c in t.columns[0]._cells]
    assert "MONITOR DRIFT" in labels


# ── Azure ────────────────────────────────────────────────────────────────────

def test_azure_alert_disabled_in_portal_is_monitor_drift_by_hand(tmp_path):
    rep = _run(*dfx.azure_case("portal_alert"), tmp_path)
    assert rep["clouds"] == ["azure"]
    obs = rep["observer_drift"]
    assert [o["resource_key"] for o in obs] == ["azurerm_monitor_metric_alert.http5xx"]
    assert obs[0]["fields"] == [{"field": "enabled", "expected": True, "live": False}]
    assert obs[0]["route"] == "manual" and "Azure console" in obs[0]["route_label"]
    writes = [c for c in rep["changes"] if c["event_name"].endswith("metricAlerts/write")]
    assert len(writes) == 1                          # the Started record is dropped
    assert writes[0]["status"] == "observer" and writes[0]["route_how"] == "console"
    assert rep["explanation"]["causes"] == []
    assert any("only read AWS metrics" in n for n in rep["notes"])


def test_azure_deploy_service_principal_is_iac(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOUDCTL_IAC_PRINCIPALS", dfx.DEPLOY_SP)
    rep = _run(*dfx.azure_case("tf_sp"), tmp_path)
    assert _app_drift(rep) == []
    ch = _change(rep, "Microsoft.Web/sites/config/write")
    assert ch["resource_key"] == "azurerm_linux_function_app.orders"      # child id -> the site
    assert ch["route"] == "iac" and ch["matches_iac"] is True
    assert ch["route_confidence"] in ("high", "medium")


def test_azure_cli_change_that_drifts_is_manual_medium(tmp_path):
    rep = _run(*dfx.azure_case("cli_hand"), tmp_path)
    drift = _app_drift(rep)
    assert drift and drift[0]["fields"][0]["field"] == "appsettings.queuename"
    ch = _change(rep, "Microsoft.Web/sites/config/write")
    # The Activity Log keeps no user agent: `az` and Terraform signed in with
    # `az login` look the same, so the IaC match decides, at medium.
    assert (ch["route"], ch["route_how"], ch["route_confidence"]) == ("manual", "cli", "medium")
    assert drift[0]["route"] == "manual"


def test_azure_cli_change_that_the_state_holds_is_iac(tmp_path):
    rep = _run(*dfx.azure_case("cli_tf"), tmp_path)
    ch = _change(rep, "Microsoft.Web/sites/config/write")
    assert ch["route"] == "iac" and ch["matches_iac"] is True
    assert ch["route_confidence"] != "high"


def test_azure_arm_deployment_is_found_by_correlation_id(tmp_path):
    rep = _run(*dfx.azure_case("arm"), tmp_path)
    ch = _change(rep, "Microsoft.Web/sites/config/write")
    assert (ch["route"], ch["route_how"]) == ("iac", "arm")
    assert ch["fix_direction"] == "reconcile"          # the app's own IaC is Terraform


# ── Google Cloud ─────────────────────────────────────────────────────────────

def test_gcp_alert_policy_changed_in_console_is_monitor_drift_by_hand(tmp_path):
    rep = _run(*dfx.gcp_case("console_policy"), tmp_path)
    assert rep["clouds"] == ["gcp"]
    obs = rep["observer_drift"]
    assert [o["resource_key"] for o in obs] == ["google_monitoring_alert_policy.api_5xx"]
    assert obs[0]["fields"][0]["field"].endswith("thresholdvalue")
    assert obs[0]["route"] == "manual" and "Google Cloud console" in obs[0]["route_label"]
    upd = [c for c in rep["changes"] if "AlertPolicy" in c["event_name"]]
    assert [c["event_name"].rsplit(".", 1)[-1] for c in upd] == ["UpdateAlertPolicy"]   # Get dropped
    assert upd[0]["status"] == "observer"
    assert _app_drift(rep) == []                       # short name vs full path is not drift
    assert rep["explanation"]["causes"] == []


def test_gcp_terraform_change_is_iac(tmp_path):
    rep = _run(*dfx.gcp_case("tf_run"), tmp_path)
    assert _app_drift(rep) == []
    ch = _change(rep, "google.cloud.run.v2.Services.UpdateService")
    assert (ch["route"], ch["route_how"], ch["matches_iac"]) == ("iac", "terraform", True)
    assert ch["fix_direction"] == "edit_iac"


def test_gcp_gcloud_change_that_drifts_is_manual(tmp_path):
    rep = _run(*dfx.gcp_case("gcloud_run"), tmp_path)
    drift = _app_drift(rep)
    assert [f["field"] for f in drift[0]["fields"]] == ["template.containers.env.topic"]
    ch = _change(rep, "google.cloud.run.v2.Services.UpdateService")
    assert (ch["route"], ch["route_how"]) == ("manual", "cli")
    assert drift[0]["route"] == "manual" and drift[0]["fix_direction"] == "reapply_iac"


# ── Normalizers ──────────────────────────────────────────────────────────────

def test_normalize_cloudtrail_reads_the_caller_fields():
    row = normalize_cloudtrail(dfx.cloudtrail(5, "PutMetricAlarm", "monitoring.amazonaws.com",
                                              {"alarmName": "a"}, ua=dfx.CLI_UA, console=True))
    assert row["cloud"] == "aws" and row["event_name"] == "PutMetricAlarm"
    assert row["principal"] == dfx.SSO_ARN and row["principal_type"] == "AssumedRole"
    assert row["user_agent"].startswith("aws-cli/") and row["console"] is True
    assert row["source_ip"] == "203.0.113.10"


def test_normalize_azure_activity_handles_snake_case_and_failures():
    row = normalize_azure_activity({
        "caller": "x@contoso.example", "event_timestamp": "2026-11-18T21:00:00Z",
        "operation_name": {"value": "Microsoft.Web/sites/write"}, "resource_id": dfx.APP_ID,
        "status": {"value": "Failed"}, "sub_status": {"value": "Forbidden"},
        "claims": {"appid": dfx.PORTAL_APP.upper(), "idtyp": "user"}})
    assert row["cloud"] == "azure" and row["error_code"] == "Forbidden"
    assert row["client_app"] == dfx.PORTAL_APP and row["principal_type"] == "user"
    assert row["resources"] == [dfx.APP_ID]


def test_normalize_gcp_audit_reads_principal_and_agent():
    row = normalize_gcp_audit(dfx.gcp_audit(3, "google.cloud.run.v2.Services.UpdateService",
                                            "run.googleapis.com", dfx.RUN_SVC, ua=dfx.GCLOUD_UA,
                                            code=7))
    assert row["cloud"] == "gcp" and row["principal"] == "dev@example.com"
    assert row["user_agent"].startswith("google-cloud-sdk") and row["error_code"]
    assert dfx.RUN_SVC in row["resources"][0]


@pytest.mark.parametrize("row,expected", [
    ({"cloud": "azure", "event_name": "Microsoft.Web/sites/write", "status": "Succeeded"}, True),
    ({"cloud": "azure", "event_name": "Microsoft.Web/sites/write", "status": "Started"}, False),
    ({"cloud": "azure", "event_name": "Microsoft.Web/sites/read", "status": "Succeeded"}, False),
    ({"cloud": "azure", "event_name": "Microsoft.Web/sites/restart/action", "status": "Succeeded"}, True),
    ({"cloud": "gcp", "event_name": "google.monitoring.v3.AlertPolicyService.GetAlertPolicy"}, False),
    ({"cloud": "gcp", "event_name": "google.monitoring.v3.AlertPolicyService.ListAlertPolicies"}, False),
    ({"cloud": "gcp", "event_name": "google.monitoring.v3.AlertPolicyService.UpdateAlertPolicy"}, True),
    ({"cloud": "aws", "event_name": "PutMetricAlarm"}, True),
])
def test_is_write(row, expected):
    assert is_write(row) is expected


def test_arm_parent():
    base = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/app"
    assert arm_parent(base + "/config/appsettings") == base
    assert arm_parent(base) == base
    assert arm_parent("/subscriptions/s/resourceGroups/rg") == "/subscriptions/s/resourceGroups/rg"


# ── Caller fingerprints and the decision matrix ──────────────────────────────

def _row(**kw):
    base = {"cloud": "aws", "principal": dfx.SSO_ARN, "actor": "dev@example.com", "user_agent": ""}
    base.update(kw)
    return base


@pytest.mark.parametrize("row,kind,tool", [
    (_row(user_agent=dfx.TF_AWS_UA), "iac", "terraform"),
    (_row(user_agent="aws-cdk/2.170.0 aws-sdk-js/3"), "iac", "cdk"),
    (_row(user_agent="pulumi/3.140 (+https://pulumi.com) aws-sdk-go"), "iac", "pulumi"),
    (_row(user_agent="OpenTofu/1.8.5 terraform-provider-aws/5.80"), "iac", "opentofu"),
    (_row(invoked_by="cloudformation.amazonaws.com"), "iac", "cloudformation"),
    (_row(console=True, user_agent="AWS Internal"), "console", ""),
    (_row(user_agent="AWS Internal", invoked_by="lambda.amazonaws.com"), "cloud_service", ""),
    (_row(user_agent=dfx.CLI_UA), "cli", ""),
    (_row(user_agent=dfx.BOTO3_UA), "sdk", ""),
    (_row(cloud="gcp", user_agent=dfx.CONSOLE_UA), "console", ""),
    (_row(cloud="gcp", user_agent=dfx.TF_GCP_UA), "iac", "terraform"),
    (_row(cloud="gcp", user_agent=dfx.GCLOUD_UA), "cli", ""),
    (_row(cloud="azure", client_app=dfx.PORTAL_APP), "console", ""),
    (_row(cloud="azure", client_app=dfx.CLI_APP), "cli", ""),
    (_row(), "unknown", ""),
])
def test_caller_signal(row, kind, tool):
    s = caller_signal(row)
    assert s.kind == kind
    if tool:
        assert s.tool == tool


def test_azure_cli_appid_is_not_a_strong_signal():
    assert caller_signal(_row(cloud="azure", client_app=dfx.CLI_APP)).strong is False
    assert caller_signal(_row(user_agent=dfx.CLI_UA)).strong is True


def test_arm_correlation_marks_a_deployment():
    row = _row(cloud="azure", client_app=dfx.CLI_APP, correlation_id="c-9")
    s = caller_signal(row, {"c-9"})
    assert (s.kind, s.tool) == ("iac", "arm")


@pytest.mark.parametrize("principal,hint", [
    ("arn:aws:sts::1:assumed-role/github-actions-deploy/run-42", "pipeline_named"),
    ("arn:aws:sts::1:assumed-role/terraform/x", "pipeline_named"),
    (dfx.SSO_ARN, "human"),
])
def test_principal_hint(principal, hint):
    assert principal_hint({"principal": principal})[0] == hint


def test_principal_hint_people_and_service_accounts_on_other_clouds():
    assert principal_hint({"cloud": "azure", "principal": "dev@contoso.example"})[0] == "human"
    assert principal_hint({"cloud": "gcp", "principal": "dev@example.com"})[0] == "human"
    assert principal_hint({"cloud": "gcp", "principal": "app@p.iam.gserviceaccount.com"})[0] == ""


def test_configured_iac_principal_wins(monkeypatch):
    monkeypatch.setenv("CLOUDCTL_IAC_PRINCIPALS", r"deploy-bot")
    assert principal_hint({"principal": "arn:aws:iam::1:user/deploy-bot"})[0] == "pipeline_configured"
    a = attribute(_row(principal="arn:aws:iam::1:user/deploy-bot"), True, "terraform")
    assert a.route == "iac"


@pytest.mark.parametrize("row,match,route,fix", [
    (_row(user_agent=dfx.TF_AWS_UA), True, "iac", "edit_iac"),
    (_row(user_agent=dfx.TF_AWS_UA), False, "iac", "reconcile"),
    (_row(user_agent=dfx.BOTO3_UA), False, "manual", "reapply_iac"),
    (_row(user_agent=dfx.BOTO3_UA), True, "manual", "reapply_iac"),
    (_row(console=True), None, "manual", "reapply_iac"),
    (_row(user_agent=dfx.BOTO3_UA, principal="arn:aws:sts::1:assumed-role/github-actions/x"),
     None, "automation", None),
    (_row(user_agent="AWS Internal", invoked_by="autoscaling.amazonaws.com"), None, "automation", None),
    (_row(cloud="azure", client_app=dfx.CLI_APP), False, "manual", "reapply_iac"),
    (_row(cloud="azure", client_app=dfx.CLI_APP), True, "iac", "edit_iac"),
    (_row(cloud="azure", client_app=dfx.CLI_APP), None, "unknown", None),
    (_row(principal="console-admin", actor="console-admin"), False, "outside_iac", "reapply_iac"),
])
def test_attribute_matrix(row, match, route, fix):
    a = attribute(row, match, "terraform")
    assert a.route == route
    if fix:
        assert a.fix_direction == fix
    assert a.evidence                       # always says why


def test_attribute_cdk_change_in_a_cdk_app_is_not_reconcile():
    a = attribute(_row(invoked_by="cloudformation.amazonaws.com"), True, "cdk")
    assert a.route == "iac" and a.fix_direction == "edit_iac"


# ── Comparison helpers ───────────────────────────────────────────────────────

def test_name_value_lists_flatten_to_maps():
    flat = flatten({"env": [{"name": "TOPIC", "value": "a"}, {"name": "MODE", "value": "b"}]})
    assert flat == {"env.topic": "a", "env.mode": "b"}


def test_loose_equal():
    assert loose_equal([{"a": 1, "b": None}], {"a": 1})       # one-element block list
    assert loose_equal([{"a": 1}, {"b": 2}], [{"b": 2}, {"a": 1}])
    assert not loose_equal([{"a": 1}], [{"a": 2}])
    assert not loose_equal(1, 2)


def test_short_name_against_full_path_is_not_drift():
    assert diff_configs({"name": "svc"}, {"name": "projects/p/locations/l/services/svc"}) == []
    assert diff_configs({"name": "svc"}, {"name": "projects/p/locations/l/services/other"})
    # Only name/id fields get this: a value that happens to end the same way still drifts.
    assert diff_configs({"topic": "orders"}, {"topic": "projects/p/topics/orders"})


@pytest.mark.parametrize("tf,cloud,observer", [
    ("aws_cloudwatch_metric_alarm", "aws", True),
    ("aws_cloudwatch_composite_alarm", "aws", True),
    ("aws_cloudwatch_log_metric_filter", "aws", True),
    ("aws_lambda_function", "aws", False),
    ("azurerm_monitor_metric_alert", "azure", True),
    ("azurerm_monitor_action_group", "azure", True),
    ("azurerm_linux_function_app", "azure", False),
    ("google_monitoring_alert_policy", "gcp", True),
    ("google_cloud_run_v2_service", "gcp", False),
])
def test_cloud_and_observer_by_type(tf, cloud, observer):
    c = canonical_type(tf)
    assert cloud_of_type(c, tf) == cloud
    assert is_observer(c) is observer


def test_arm_shape_lifts_properties_and_single_criteria():
    got = _arm_shape({"id": "x", "properties": {"enabled": True, "criteria": {
        "odata.type": "t", "allOf": [{"metricName": "Http5xx", "threshold": 10}]}}})
    assert got["enabled"] is True and "properties" not in got
    assert got["criteria"]["metricName"] == "Http5xx" and "allOf" not in got["criteria"]


# ── Live sources (fakes, no SDKs or network) ─────────────────────────────────

class _RT:
    def __init__(self, t, versions):
        self.resource_type, self.api_versions = t, versions


class _FakeRM:
    def __init__(self, body=None, exc=None):
        self.calls = []
        self.providers = self
        self.resources = self
        self._body, self._exc = body, exc

    def get(self, namespace):
        self.calls.append(("provider", namespace))
        prov = type("P", (), {})()
        prov.resource_types = [_RT("metricAlerts", ["2018-03-01", "2024-03-01-preview"])]
        return prov

    def get_by_id(self, rid, api):
        self.calls.append(("get", rid, api))
        if self._exc:
            raise self._exc
        return self._body


def _alert_resource():
    return Resource(key="azurerm_monitor_metric_alert.http5xx", type="Microsoft.Insights/metricAlerts",
                    config={"id": dfx.ALERT_ID}, source="terraform",
                    source_type="azurerm_monitor_metric_alert")


def test_azure_live_reads_by_id_with_a_stable_api_version():
    rm = _FakeRM(body={"id": dfx.ALERT_ID, "properties": {"enabled": False}})
    live = AzureLive(credential=object())
    live._rm[dfx.SUB] = rm
    got = live.read(_alert_resource())
    assert got["enabled"] is False
    assert ("get", dfx.ALERT_ID, "2018-03-01") in rm.calls          # preview skipped
    assert dfx.SUB in live.subscriptions


def test_azure_live_404_is_not_found_and_other_errors_are_noted():
    class NotFound(Exception):
        status_code = 404
    live = AzureLive(credential=object())
    live._rm[dfx.SUB] = _FakeRM(exc=NotFound())
    assert live.read(_alert_resource()) is NOT_FOUND
    live2 = AzureLive(credential=object())
    live2._rm[dfx.SUB] = _FakeRM(exc=RuntimeError("boom"))
    assert live2.read(_alert_resource()) is None and live2.notes


class _Resp:
    def __init__(self, code, body):
        self.status_code, self._body = code, body

    def json(self):
        return self._body


class _FakeSession:
    def __init__(self, get=None, pages=None):
        self._get, self._pages, self.urls, self.bodies = get, list(pages or []), [], []

    def get(self, url, timeout=0):
        self.urls.append(url)
        return self._get

    def post(self, url, json=None, timeout=0):  # noqa: A002
        self.urls.append(url)
        self.bodies.append(dict(json or {}))
        return self._pages.pop(0)


def _policy_resource():
    return Resource(key="google_monitoring_alert_policy.api_5xx", type="monitoring.googleapis.com/AlertPolicy",
                    config={"name": dfx.POLICY, "project": dfx.PROJECT}, source="terraform",
                    source_type="google_monitoring_alert_policy")


def test_gcp_url_and_read():
    r = _policy_resource()
    assert gcp_url(r) == "https://monitoring.googleapis.com/v3/" + dfx.POLICY
    s = _FakeSession(get=_Resp(200, {"name": dfx.POLICY, "enabled": False}))
    live = GcpLive(session=s)
    assert live.read(r)["enabled"] is False and dfx.PROJECT in live.projects
    assert GcpLive(session=_FakeSession(get=_Resp(404, {}))).read(r) is NOT_FOUND
    live403 = GcpLive(session=_FakeSession(get=_Resp(403, {})))
    assert live403.read(r) is None and "403" in live403.notes[0]


def test_gcp_write_events_pages_and_keeps_writes_only():
    upd = dfx.gcp_audit(5, "google.monitoring.v3.AlertPolicyService.UpdateAlertPolicy",
                        "monitoring.googleapis.com", dfx.POLICY, ua=dfx.CONSOLE_UA)
    get = dfx.gcp_audit(4, "google.monitoring.v3.AlertPolicyService.GetAlertPolicy",
                        "monitoring.googleapis.com", dfx.POLICY, ua=dfx.CONSOLE_UA)
    s = _FakeSession(pages=[_Resp(200, {"entries": [upd], "nextPageToken": "n"}),
                            _Resp(200, {"entries": [get]})])
    live = GcpLive(project=dfx.PROJECT, session=s)
    now = datetime(2026, 11, 18, 22, tzinfo=timezone.utc)
    rows = live.write_events(now.replace(hour=19), now)
    assert [r["event_name"].rsplit(".", 1)[-1] for r in rows] == ["UpdateAlertPolicy"]
    assert s.bodies[1].get("pageToken") == "n"
    assert "cloudaudit.googleapis.com%2Factivity" in s.bodies[0]["filter"]


class _Src:
    def __init__(self, cloud, rows=None, exc=None):
        self.cloud, self._rows, self._exc, self.reads, self.notes = cloud, rows or [], exc, [], []

    def read(self, r):
        self.reads.append(r.key)
        return {"from": self.cloud}

    def write_events(self, start, end):
        if self._exc:
            raise self._exc
        return list(self._rows)

    def metrics(self, *a):
        return {}


def test_multicloud_sends_each_resource_to_its_cloud():
    aws, az, gcp = _Src("aws"), _Src("azure", [{"cloud": "azure"}]), _Src("gcp", [{"cloud": "gcp"}])
    live = MultiCloudLive(aws, azure=lambda: az, gcp=lambda: gcp)
    lam = Resource(key="aws_lambda_function.api", type="AWS::Lambda::Function", source_type="aws_lambda_function")
    assert live.read(lam) == {"from": "aws"}
    assert live.read(_alert_resource()) == {"from": "azure"}
    assert live.read(_policy_resource()) == {"from": "gcp"}
    now = datetime.now(timezone.utc)
    assert [r["cloud"] for r in live.write_events(now, now)] == ["azure", "gcp"]


def test_multicloud_isolates_one_clouds_audit_failure():
    aws = _Src("aws", exc=RuntimeError("expired token"))
    live = MultiCloudLive(aws, azure=lambda: _Src("azure", [{"cloud": "azure"}]))
    live.read(_alert_resource())
    now = datetime.now(timezone.utc)
    assert [r["cloud"] for r in live.write_events(now, now)] == ["azure"]
    assert any("aws audit trail unavailable" in n for n in live.notes)


def test_multicloud_aws_only_still_raises_so_the_run_says_it_failed():
    live = MultiCloudLive(_Src("aws", exc=RuntimeError("expired token")))
    now = datetime.now(timezone.utc)
    with pytest.raises(RuntimeError):
        live.write_events(now, now)


def test_multicloud_without_a_cloud_source_reads_nothing():
    live = MultiCloudLive(_Src("aws"))
    assert live.read(_alert_resource()) is None

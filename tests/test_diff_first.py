"""Diff-first checks: replays of the complex-app scenarios (s1, s3, s4, s5),
a CloudFormation/CDK variant, a no-IaC variant, and unit tests of the parts.

Everything runs from recordings (RecordedLive); nothing calls AWS.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import diff_first_fixtures as fx  # noqa: E402

from cloudctl.debug.diff_first import apply_to_report, run_diff_first  # noqa: E402
from cloudctl.debug.diff_first.changes import annotate_rows, classify, set_active_window  # noqa: E402
from cloudctl.debug.diff_first.iac import PulumiAdapter, TerraformAdapter, load_expected_state  # noqa: E402
from cloudctl.debug.diff_first.live import RecordedLive  # noqa: E402
from cloudctl.debug.diff_first.model import Change, IncidentWindow  # noqa: E402
from cloudctl.debug.diff_first.normalize import canonical_type, diff_configs  # noqa: E402
from cloudctl.debug.diff_first.run import prompt_text, run_for_agent, seed_hypotheses  # noqa: E402
from cloudctl.debug.diff_first.window import detect_anomaly  # noqa: E402


# ── helpers ──────────────────────────────────────────────────────────────────

def _tf_root(tmp_path: Path, state: dict) -> str:
    (tmp_path / "main.tf").write_text("# app\n")
    (tmp_path / "terraform.tfstate").write_text(json.dumps(state))
    return str(tmp_path)


def _run_tf(sid: str, tmp_path: Path) -> dict:
    state, data = fx.scenario(sid)
    return run_diff_first(RecordedLive(data), iac_root=_tf_root(tmp_path, state),
                          account=fx.ACCT, region=fx.REGION).to_dict()


def _causes(rep: dict) -> list[dict]:
    return rep["explanation"]["causes"]


def _status(rep: dict, event: str) -> list[str]:
    return [c["status"] for c in rep["changes"] if c["event_name"] == event]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("CLOUDCTL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CLOUDCTL_TF_SHOW", "0")
    monkeypatch.setenv("CLOUDCTL_PULUMI_EXPORT", "0")
    for k in ("CLOUDCTL_TF_STATE_JSON", "CLOUDCTL_TF_PLAN_JSON", "CLOUDCTL_CFN_STACK",
              "CLOUDCTL_PULUMI_STATE", "CLOUDCTL_DIFF_FIRST_REPLAY", "CLOUDCTL_DIFF_FIRST_RECORD"):
        monkeypatch.delenv(k, raising=False)
    yield
    set_active_window(None)


# ── scenario replays (Terraform) ─────────────────────────────────────────────

def test_s1_iam_policy_change_is_the_one_cause(tmp_path):
    rep = _run_tf("s1", tmp_path)
    assert rep["expected_kind"] == "terraform"
    causes = _causes(rep)
    assert len(causes) == 1
    assert "PutRolePolicy" in causes[0]["summary"] and "worker-policy" in causes[0]["summary"]
    assert rep["explanation"]["unexplained_symptoms"] == []
    assert rep["explanation"]["confidence"] == "HIGH"
    kinds = {s["kind"] for s in rep["symptoms"]}
    assert "errors_up" in kinds and "backlog_up" in kinds
    # unrelated writes in the account are not candidates
    assert all(c["status"] == "unmatched" for c in rep["changes"]
               if c["resource_name"] in ("billing-export", "unrelated-role", ""))


def test_window_brackets_the_fault(tmp_path):
    rep = _run_tf("s1", tmp_path)
    onset = datetime.fromisoformat(rep["window"]["onset"].replace("Z", "+00:00"))
    assert fx.NOW - timedelta(minutes=17) <= onset <= fx.NOW - timedelta(minutes=13)
    assert rep["window"]["method"] == "metrics"


def test_s3_wrong_queue_url_explains_quiet_queue(tmp_path):
    rep = _run_tf("s3", tmp_path)
    causes = _causes(rep)
    assert len(causes) == 1
    c = causes[0]
    assert "UpdateFunctionConfiguration" in c["summary"] and f"{fx.P}-api" in c["summary"]
    assert "repointed" in c["explains"].values()
    assert rep["explanation"]["unexplained_symptoms"] == []
    # the fix target is the api function, not anything downstream
    assert all("worker" not in x["summary"] for x in causes)


def test_s4_two_faults_both_found(tmp_path):
    rep = _run_tf("s4", tmp_path)
    summaries = [c["summary"] for c in _causes(rep)]
    assert len(summaries) == 2
    assert any("UpdateFunctionConfiguration" in s and f"{fx.P}-worker" in s for s in summaries)
    assert any("PutRule" in s and "order-processed" in s for s in summaries)
    assert rep["explanation"]["unexplained_symptoms"] == []
    assert not any("PutRolePolicy" in s for s in summaries)   # no invented IAM fault


def test_s5_stale_reverted_iam_changes_are_not_causes(tmp_path):
    rep = _run_tf("s5", tmp_path)
    causes = _causes(rep)
    assert len(causes) == 1
    c = causes[0]
    assert "UpdateEventSourceMapping" in c["summary"] and fx.ESM_ID in c["summary"]
    assert "live differs from declared" in c["summary"]       # drift and change agree
    assert set(_status(rep, "PutRolePolicy")) <= {"before_window", "unmatched"}
    assert "before_window" in _status(rep, "PutRolePolicy")
    # the leftover DLQ backlog from s1 is flat and must not count as a symptom
    assert not any(s["kind"] == "backlog_up" and "dlq" in s["node"] for s in rep["symptoms"])
    drift_keys = [d["resource_key"] for d in rep["drift"]]
    assert any("event_source_mapping" in k for k in drift_keys)


def test_s5_answer_blaming_iam_is_capped_low(tmp_path):
    rep = _run_tf("s5", tmp_path)
    agent = {"root_cause": f"IAM policy change on {fx.P}-worker-policy denies S3 writes",
             "confidence": "HIGH", "evidence": ["PutRolePolicy at 21:13"]}
    out = apply_to_report(agent, rep)
    assert out["confidence"] == "LOW"
    assert out["additional_causes"]
    assert "diff_first" in out and out["diff_first"]["not_causes"]


def test_s4_answer_with_one_of_two_causes_is_capped_medium(tmp_path):
    rep = _run_tf("s4", tmp_path)
    agent = {"root_cause": f"{fx.P}-worker timeout reduced to 2 seconds", "confidence": "HIGH",
             "evidence": []}
    out = apply_to_report(agent, rep)
    assert out["confidence"] == "MEDIUM"
    assert any("order-processed" in s for s in out["additional_causes"])


def test_s4_answer_with_both_causes_is_not_capped(tmp_path):
    rep = _run_tf("s4", tmp_path)
    agent = {"root_cause": f"{fx.P}-worker timeout reduced to 2s and rule {fx.P}-order-processed "
                           "pattern changed", "confidence": "HIGH", "evidence": []}
    out = apply_to_report(agent, rep)
    assert out["confidence"] == "HIGH"
    assert "additional_causes" not in out


def test_prompt_text_and_seed_hypotheses(tmp_path):
    rep = _run_tf("s5", tmp_path)
    txt = prompt_text(rep)
    assert "Incident window" in txt and "NOT a cause" in txt and "CAUSE CANDIDATE" in txt
    seeds = seed_hypotheses(rep, existing=[{"service": "s3"}])
    assert len(seeds) == 1 and seeds[0]["_source"] == "diff_first"
    # already-covered causes are not seeded twice
    assert seed_hypotheses(rep, existing=[{"service": fx.ESM_ID}]) == []


# ── CloudFormation / CDK and no-IaC ──────────────────────────────────────────

def test_cdk_s5_uses_cloudformation_drift(tmp_path):
    man, tpl, data = fx.cdk_s5()
    (tmp_path / "cdk.json").write_text("{}")
    (tmp_path / "cdk.out").mkdir()
    (tmp_path / "cdk.out" / "manifest.json").write_text(json.dumps(man))
    (tmp_path / "cdk.out" / f"{fx.CFN_STACK}.template.json").write_text(json.dumps(tpl))
    rep = run_diff_first(RecordedLive(data), iac_root=str(tmp_path)).to_dict()
    assert rep["expected_kind"] in ("cdk", "cloudformation")
    causes = _causes(rep)
    assert len(causes) == 1 and "UpdateEventSourceMapping" in causes[0]["summary"]
    assert rep["explanation"]["confidence"] == "HIGH"
    edges = {(a, b) for a, b, _ in rep["topology"]["flow_edges"]}
    assert (f"{fx.CFN_STACK}/OrdersQueue", f"{fx.CFN_STACK}/WorkerMapping") in edges
    assert (f"{fx.CFN_STACK}/OrderProcessedRule", f"{fx.CFN_STACK}/NotifierFn") in edges


def test_no_iac_uses_config_history_baseline():
    rep = run_diff_first(RecordedLive(fx.no_iac_s5()), iac_root=None,
                         account=fx.ACCT, region=fx.REGION).to_dict()
    causes = _causes(rep)
    assert len(causes) == 1 and fx.ESM_ID in causes[0]["summary"]
    assert any("AWS Config" in n for n in rep["notes"] + rep["expected_notes"])
    edges = {(a, b) for a, b, _ in rep["topology"]["flow_edges"]}
    # the queue and table share a name; the mapping must wire to the queue
    assert (f"sqs:{fx.P}-orders", f"esm:{fx.ESM_ID}") in edges


def test_run_for_agent_replay_and_disable(tmp_path, monkeypatch):
    state, data = fx.scenario("s5")
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps(data))
    monkeypatch.setenv("CLOUDCTL_DIFF_FIRST_REPLAY", str(rec))
    out = run_for_agent(None, fx.REGION, _tf_root(tmp_path, state), account=fx.ACCT)
    assert out["explanation"]["causes"]
    monkeypatch.setenv("CLOUDCTL_DIFF_FIRST", "0")
    assert run_for_agent(None, fx.REGION, None) == {}


def test_run_for_agent_never_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("CLOUDCTL_DIFF_FIRST_REPLAY", str(tmp_path / "missing.json"))
    out = run_for_agent(None, fx.REGION, None)
    assert "error" in out


def test_tool_replay_without_recording_is_skipped(monkeypatch):
    monkeypatch.setenv("CLOUDCTL_REPLAY", "/some/tool/recording")
    assert "skipped" in run_for_agent(None, fx.REGION, None)["error"]


# ── units ────────────────────────────────────────────────────────────────────

def test_pulumi_export_and_type_mapping():
    data = {"deployment": {"resources": [
        {"urn": "urn:pulumi:dev::app::aws:lambda/eventSourceMapping:EventSourceMapping::m",
         "type": "aws:lambda/eventSourceMapping:EventSourceMapping", "id": fx.ESM_ID,
         "outputs": {"enabled": True, "eventSourceArn": fx.arn("sqs", f"{fx.P}-orders"),
                     "functionName": fx.arn("lambda", f"function:{fx.P}-worker")}},
        {"urn": "urn:pulumi:dev::app::pulumi:pulumi:Stack::app", "type": "pulumi:pulumi:Stack"},
    ]}}
    rs = PulumiAdapter.parse_export(data)
    assert len(rs) == 1
    assert rs[0].type == "AWS::Lambda::EventSourceMapping"
    assert rs[0].physical_id == fx.ESM_ID
    assert canonical_type("aws_sqs_queue") == "AWS::SQS::Queue"


def test_pulumi_root_detected(tmp_path, monkeypatch):
    (tmp_path / "Pulumi.yaml").write_text("name: app\n")
    st_file = tmp_path / "state.json"
    st_file.write_text(json.dumps({"deployment": {"resources": [
        {"urn": "u1", "type": "aws:sqs/queue:Queue", "id": fx.Q_URL, "outputs": {"name": f"{fx.P}-orders"}}]}}))
    monkeypatch.setenv("CLOUDCTL_PULUMI_STATE", str(st_file))
    st = load_expected_state(str(tmp_path))
    assert st.kind == "pulumi" and len(st.resources) == 1


def test_terraform_plan_drift_parse():
    plan = {"resource_drift": [
        {"address": "aws_lambda_event_source_mapping.worker", "type": "aws_lambda_event_source_mapping",
         "change": {"actions": ["update"], "before": {"enabled": True, "batch_size": 1},
                    "after": {"enabled": False, "batch_size": 1}}},
        {"address": "aws_sqs_queue.gone", "type": "aws_sqs_queue",
         "change": {"actions": ["delete"], "before": {"name": "gone"}, "after": None}},
    ]}
    items = TerraformAdapter.parse_plan_drift(plan)
    assert items[0].fields == [{"field": "enabled", "expected": True, "live": False}]
    assert items[1].kind == "deleted"


def test_diff_configs_aliases_and_policy_json():
    exp = {"enabled": True, "batch_size": 1,
           "policy": json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:PutObject"}]})}
    live = {"State": "Disabled", "BatchSize": 1,
            "Policy": {"Statement": [{"Action": "s3:PutObject", "Effect": "Allow"}]}}
    fields = diff_configs(exp, live)
    names = [f["field"] for f in fields]
    assert len(fields) == 1 and "enab" in names[0]


def _series(values, start=None):
    start = start or datetime(2026, 11, 18, 20, 0, tzinfo=timezone.utc)
    return [(start + timedelta(minutes=i), v) for i, v in enumerate(values)]


def test_past_error_spike_is_not_a_current_symptom():
    vals = [0.0] * 60 + [50.0] * 10 + [0.0] * 40
    assert detect_anomaly(_series(vals), "errors") is None


def test_current_error_run_found_with_onset():
    vals = [0.0] * 90 + [40.0] * 20
    a = detect_anomaly(_series(vals), "errors")
    assert a is not None and a.onset == _series(vals)[90][0]


def test_flat_leftover_backlog_is_ignored():
    vals = [0.0] * 40 + [float(i * 10) for i in range(10)] + [100.0] * 60
    assert detect_anomaly(_series(vals), "backlog") is None


def test_classify_superseded_reverted_and_before_window():
    w = IncidentWindow(onset="2026-11-18T21:45:00Z", last_healthy="2026-11-18T21:44:00Z",
                       start="2026-11-18T21:39:00Z", end="2026-11-18T21:47:00Z")
    ch = [
        Change(time="2026-11-18T21:10:00Z", event_name="PutRolePolicy", resource_key="role.a",
               params={"policyDocument": "x"}),
        Change(time="2026-11-18T21:40:00Z", event_name="UpdateFunctionConfiguration",
               resource_key="fn.a", params={"timeout": 2}),
        Change(time="2026-11-18T21:41:00Z", event_name="UpdateFunctionConfiguration",
               resource_key="fn.a", params={"timeout": 10}),
        Change(time="2026-11-18T21:42:00Z", event_name="UpdateEventSourceMapping",
               resource_key="esm.a", params={"batchSize": 5}),
        Change(time="2026-11-18T21:43:00Z", event_name="PutRule", resource_key="rule.a",
               params={"state": "DISABLED"}),
    ]
    classify(ch, w, {"esm.a": {"BatchSize": 1}, "rule.a": {"State": "DISABLED"}})
    assert [c.status for c in ch] == ["before_window", "superseded", "candidate", "reverted", "candidate"]


def test_annotate_rows_labels_against_window():
    set_active_window(IncidentWindow(onset="2026-11-18T21:45:00Z", last_healthy="2026-11-18T21:44:00Z",
                                     start="2026-11-18T21:39:00Z", end="2026-11-18T21:47:00Z"))
    rows = [{"time": "2026-11-18T21:50:00Z", "event_name": "X", "resources": ["a"]},
            {"time": "2026-11-18T21:42:00Z", "event_name": "PutRolePolicy", "resources": ["r"]},
            {"time": "2026-11-18T21:13:00Z", "event_name": "PutRolePolicy", "resources": ["r"]}]
    annotate_rows(rows)
    assert rows[0]["incident_window"].startswith("AFTER")
    assert rows[1]["incident_window"].startswith("INSIDE")
    assert rows[2]["incident_window"].startswith("BEFORE")
    assert "superseded_by" in rows[2]
    set_active_window(None)
    plain = [{"time": "2026-11-18T21:42:00Z"}]
    assert "incident_window" not in annotate_rows(plain)[0]


# ── wiring into debug --agent ────────────────────────────────────────────────

def test_graph_runs_diff_first_between_observe_and_triage():
    from cloudctl.ai import graph_agent as g
    graph = g._build_graph()
    edges = {(e.source, e.target) for e in graph.get_graph().edges}
    assert ("observe", "diff_first") in edges and ("diff_first", "triage") in edges
    assert ("observe", "triage") not in edges


def test_diff_first_node_replays_and_sets_window(tmp_path, monkeypatch):
    from cloudctl.ai import graph_agent as g
    from cloudctl.debug.diff_first import changes as ch
    state, data = fx.scenario("s5")
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps(data))
    monkeypatch.setenv("CLOUDCTL_DIFF_FIRST_REPLAY", str(rec))
    out = g.diff_first_node({"profile": None, "region": fx.REGION, "account_id": fx.ACCT,
                             "iac_root": _tf_root(tmp_path, state)})
    assert out["diff_first"]["explanation"]["causes"]
    assert ch._ACTIVE.get("onset") == out["diff_first"]["window"]["onset"]
    txt = g._diff_first_text({"diff_first": out["diff_first"]})
    assert "DIFF-FIRST CHECKS" in txt


def test_triage_seeds_a_branch_for_each_found_cause(tmp_path, monkeypatch):
    from cloudctl.ai import graph_agent as g
    rep = _run_tf("s4", tmp_path)

    class _Bedrock:
        def converse(self, **kw):
            text = json.dumps([{"service": "s3", "reason": "guess", "focus": "f", "predictions": []}])
            return {"output": {"message": {"content": [{"text": text}]}}, "stopReason": "end_turn",
                    "usage": {}}

    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: _Bedrock())
    out = g.triage_node({"symptom": "orders stuck", "profile": None, "region": fx.REGION,
                         "session_id": "t", "observation": {}, "all_fetched": {},
                         "diff_first": rep})
    seeded = [h for h in out["hypotheses"] if h.get("_source") == "diff_first"]
    assert len(seeded) == 2


def test_debug_incident_graph_applies_checks(tmp_path, monkeypatch):
    from cloudctl.ai import graph_agent as g
    import cloudctl.mcp.tools.debug as dbg
    rep = _run_tf("s5", tmp_path)
    final = {"final_report": {"root_cause": f"IAM policy {fx.P}-worker-policy denies writes",
                              "evidence": [], "remediation_steps": [], "confidence": "HIGH",
                              "severity": "HIGH"},
             "all_fetched": {}, "hypotheses": [], "branch_results": [], "diff_first": rep}

    class _Graph:
        def invoke(self, arg, config):
            assert arg["iac_root"] == "/x/app"
            return final

    monkeypatch.setattr(g, "_get_graph", lambda: _Graph())
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: None)
    monkeypatch.setattr(dbg, "_get_account_id", lambda *a, **k: fx.ACCT)
    raw, _ = g.debug_incident_graph("orders stuck", profile=None, region=fx.REGION, iac_root="/x/app")
    d = json.loads(raw)
    assert d["confidence"] == "LOW"
    assert d["diff_first"]["causes"] and d["additional_causes"]
    from cloudctl.debug.diff_first import changes as ch
    assert ch._ACTIVE == {}


def test_render_shows_diff_first_rows(tmp_path):
    from rich.console import Console
    from cloudctl.commands import debug_cmd
    rep = _run_tf("s4", tmp_path)
    d = apply_to_report({"root_cause": f"{fx.P}-worker timeout too low", "confidence": "HIGH",
                         "evidence": []}, rep)
    con = Console(record=True, width=160)
    old = debug_cmd.console
    debug_cmd.console = con
    try:
        debug_cmd._render_agent_result(d, fx.ACCT)
    finally:
        debug_cmd.console = old
    out = con.export_text()
    assert "CHANGE CHECK" in out and "not in the diagnosis above" in out and "WINDOW" in out

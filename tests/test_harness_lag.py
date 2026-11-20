"""Replays of the two failures from live complex-app run 3 (s4, s5).

Both come from how the live harness runs: scenarios back to back in one
deployment, the next fault injected a minute or two before cctl starts. The
metrics then end before the new fault shows and still carry the previous
scenario's symptoms (see harness_timeline.py). These tests hold diff-first to
what it can honestly say in that state, with no scenario-specific rules.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import diff_first_fixtures as fx  # noqa: E402
import harness_timeline as ht  # noqa: E402

from cloudctl.debug.diff_first import apply_to_report, run_diff_first  # noqa: E402
from cloudctl.debug.diff_first.changes import annotate_rows, classify, set_active_window  # noqa: E402
from cloudctl.debug.diff_first.explain import explains  # noqa: E402
from cloudctl.debug.diff_first.live import RecordedLive  # noqa: E402
from cloudctl.debug.diff_first.model import Candidate, Change, IncidentWindow, Symptom  # noqa: E402
from cloudctl.debug.diff_first.run import prompt_text, seed_hypotheses  # noqa: E402

ESM = "aws_lambda_event_source_mapping.worker"


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("CLOUDCTL_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CLOUDCTL_TF_SHOW", "0")
    yield
    set_active_window(None)


def _run(last: str, inj_ago: float, tmp_path: Path) -> dict:
    state, data = ht.build(last, inj_ago=inj_ago)
    (tmp_path / "main.tf").write_text("# app\n")
    (tmp_path / "terraform.tfstate").write_text(json.dumps(state))
    return run_diff_first(RecordedLive(data), iac_root=str(tmp_path), account=fx.ACCT,
                          region=fx.REGION).to_dict()


# ── s5: the disabled trigger, two minutes after s4 was reverted ──────────────

def test_s5_after_s4_old_symptoms_are_flagged_and_the_disabled_trigger_is_a_lead(tmp_path):
    d = _run("s5", 2.5, tmp_path)
    ex = d["explanation"]
    # The metrics still show s4's symptoms; the s4 revert came after they began
    # and live config there matches what is declared, so they may be over.
    over = {s["node"] for s in ex["may_be_over"]}
    assert "aws_lambda_function.worker" in over
    assert "aws_cloudwatch_event_rule.order_processed" in over
    assert not ex["unexplained_symptoms"]
    # The reverts are not causes (they put back the values s4 changed) ...
    restored = [c for c in d["changes"] if c["status"] == "restored"]
    assert {c["resource_name"] for c in restored} >= {f"{fx.P}-worker", f"{fx.P}-order-processed"}
    assert not ex["causes"]
    # ... and the real fault, the event source mapping switched off (no
    # CloudTrail row yet), is surfaced instead of credited with s4's errors.
    leads = ex["unplaced_drift"]
    assert [c["resource_key"] for c in leads] == [ESM]
    assert "event source mapping" in leads[0]["match_names"]
    txt = prompt_text(d)
    assert "LIVE DIFFERS FROM DECLARED" in txt and "MAY BE OVER" in txt
    assert txt.rstrip().endswith("Do not blame a change listed as NOT a cause.")
    seeds = seed_hypotheses(d, [])
    assert seeds and "check it directly" in seeds[0]["reason"]


def test_s5_answer_that_blames_the_old_worker_errors_is_capped(tmp_path):
    d = _run("s5", 2.5, tmp_path)
    wrong = {"root_cause": f"{fx.P}-worker times out after 2 seconds, so messages fail",
             "confidence": "HIGH", "evidence": ["Errors rose on the worker"]}
    out = apply_to_report(wrong, d)
    assert out["confidence"] == "MEDIUM"
    assert any("enabled" in c for c in out["additional_causes"])
    right = {"root_cause": f"The event source mapping {fx.ESM_ID} was disabled, so {fx.P}-worker "
                           "stopped reading the orders queue", "confidence": "HIGH", "evidence": []}
    assert apply_to_report(right, d)["confidence"] == "HIGH"


# ── s4: two faults applied with terraform a few minutes before the run ───────

def test_s4_faults_too_new_for_the_metrics_are_leads_not_dropped(tmp_path):
    d = _run("s4", 3.5, tmp_path)
    ex = d["explanation"]
    assert not d["symptoms"]                       # nothing shows in the metrics yet
    newer = {c["resource_name"] for c in ex["newer_than_metrics"]}
    assert newer == {f"{fx.P}-worker", f"{fx.P}-order-processed"}
    # A purge sets nothing, so it is not a configuration lead.
    assert not any("PurgeQueue" in c["summary"] for c in ex["newer_than_metrics"])
    txt = prompt_text(d)
    assert txt.count("NEWER THAN THE METRICS C") == 2
    assert len(seed_hypotheses(d, [])) == 2
    one = {"root_cause": f"{fx.P}-worker timeout was cut to 2 seconds", "confidence": "HIGH",
           "evidence": []}
    out = apply_to_report(one, d)
    assert out["confidence"] == "MEDIUM"            # the second fault is left out
    assert any("order-processed" in c for c in out["additional_causes"])


def test_s4_once_the_metrics_catch_up_both_faults_are_causes(tmp_path):
    d = _run("s4", 6, tmp_path)
    causes = {c["resource_name"] for c in d["explanation"]["causes"]}
    assert causes == {f"{fx.P}-worker", f"{fx.P}-order-processed"}
    assert not d["explanation"]["newer_than_metrics"]


# ── the generic rules underneath ─────────────────────────────────────────────

def _change(ago, name, params, key):
    c = Change(time=fx.t(ago), event_name=name, event_source="x", actor="", params=params)
    c.resource_key = key
    c.resource_name = key
    return c


def test_a_change_that_puts_back_earlier_values_is_restored_not_a_cause():
    w = IncidentWindow(onset=fx.t(30), last_healthy=fx.t(31), start=fx.t(36), end=fx.t(28),
                       metrics_end=fx.t(3))
    chs = [_change(60, "Create", {"functionName": "f", "timeout": 10}, "fn"),
           _change(33, "Update", {"functionName": "f", "timeout": 2}, "fn"),
           _change(3.5, "Update", {"functionName": "f", "timeout": 10}, "fn")]
    classify(chs, w, {"fn": {"timeout": 10}})
    assert chs[2].status == "restored"
    # A first-time change this recent is a lead the metrics can't judge yet.
    chs = [_change(60, "Create", {"functionName": "f", "timeout": 10}, "fn"),
           _change(3.5, "Update", {"functionName": "f", "timeout": 2}, "fn")]
    classify(chs, w, {"fn": {"timeout": 2}})
    assert chs[1].status == "after_metrics"


def test_an_old_change_after_the_onset_is_still_after_onset():
    w = IncidentWindow(onset=fx.t(30), last_healthy=fx.t(31), start=fx.t(36), end=fx.t(28),
                       metrics_end=fx.t(3))
    chs = [_change(20, "Update", {"functionName": "f", "timeout": 2}, "fn")]
    classify(chs, w, {})
    assert chs[0].status == "after_onset"


def test_agent_cloudtrail_rows_newer_than_the_metrics_are_labelled_so():
    set_active_window(IncidentWindow(onset=fx.t(30), last_healthy=fx.t(31), start=fx.t(36),
                                     end=fx.t(28), metrics_end=fx.t(3)))
    rows = annotate_rows([{"time": fx.t(2), "event_name": "UpdateEventSourceMapping"},
                          {"time": fx.t(20), "event_name": "UpdateFunctionConfiguration"}])
    labels = {r["event_name"]: r["incident_window"] for r in rows}
    assert labels["UpdateEventSourceMapping"].startswith("NEWER THAN THE METRICS")
    assert labels["UpdateFunctionConfiguration"].startswith("AFTER")


def test_a_switched_off_connector_explains_a_stopped_flow_but_not_errors():
    state, data = ht.build("s5", inj_ago=2.5)
    from cloudctl.debug.diff_first.iac import TerraformAdapter
    from cloudctl.debug.diff_first.topology import build_topology
    topo = build_topology({r.key: r for r in TerraformAdapter.parse_state(state)})
    off = Candidate(id="C1", kind="drift", resource_key=ESM, resource_name=fx.ESM_ID, time=None,
                    summary="disabled", evidence={"drift": [{"fields": [
                        {"field": "enabled", "expected": True, "live": False}]}]})
    err = Symptom(id="S1", kind="errors_up", node="aws_lambda_function.worker", onset=fx.t(30),
                  detail="", scope=[ESM, "aws_lambda_function.worker"])
    stop = Symptom(id="S2", kind="flow_stopped", node="aws_lambda_function.worker",
                   onset=fx.t(30), detail="", scope=[ESM, "aws_lambda_function.worker"])
    assert explains(off, err, topo) == ""
    assert explains(off, stop, topo) == "direct"
    # A connector change that is not only an off switch still explains errors.
    moved = Candidate(id="C2", kind="drift", resource_key=ESM, resource_name=fx.ESM_ID, time=None,
                      summary="batch", evidence={"drift": [{"fields": [
                          {"field": "batch_size", "expected": 1, "live": 50}]}]})
    assert explains(moved, err, topo) == "direct"


# ── s4 time: the command must end at its time limit ──────────────────────────

_EXIT_SCRIPT = textwrap.dedent("""
    import concurrent.futures, json, sys, time
    import cloudctl.ai.graph_agent as g
    import cloudctl.mcp.tools.debug as dbg
    from cloudctl.commands import debug_cmd

    class Graph:
        def invoke(self, arg, config):
            # Like langgraph: the node runs in a pool worker, which Python
            # joins at exit. It outlives the ceiling by far.
            ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            return ex.submit(time.sleep, 30).result()
        def get_state(self, config):
            return None

    g._get_graph = lambda: Graph()
    dbg._get_account_id = lambda *a, **k: "111122223333"
    g._start_diff_first = lambda *a, **k: None
    import cloudctl.ai.guardrails as gr
    gr.check_rate_limit = lambda: gr.GuardrailResult(True, "", "")
    t0 = time.monotonic()
    raw, _ = g.debug_incident_graph("orders fail", profile=None)
    print(json.dumps({"timed_out": json.loads(raw).get("_timed_out"),
                      "elapsed": round(time.monotonic() - t0, 1)}), flush=True)
    debug_cmd._exit_if_abandoned()
""")


def test_command_exits_at_the_ceiling_instead_of_waiting_for_the_abandoned_graph(tmp_path):
    env = {**__import__("os").environ, "CLOUDCTL_TIME_BUDGET_S": "2",
           "CLOUDCTL_TIME_GRACE_S": "1", "CLOUDCTL_HOME": str(tmp_path / "home"),
           "CLOUDCTL_DIFF_FIRST": "0", "HOME": str(tmp_path)}
    t0 = time.monotonic()
    r = subprocess.run([sys.executable, "-c", _EXIT_SCRIPT], capture_output=True, text=True,
                       timeout=60, env=env)
    wall = time.monotonic() - t0
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["timed_out"] is True
    assert out["elapsed"] < 5
    # The process used to stay until the 30 s worker finished.
    assert wall < 15, (wall, r.stderr[-500:])


def test_iac_fix_proposal_and_check_stop_at_the_command_deadline(tmp_path, monkeypatch):
    from cloudctl.debug import iac_fix
    (tmp_path / "main.tf").write_text(
        'resource "aws_lambda_function" "worker" {\n  function_name = "cctl-complexapp-worker"\n'
        '  timeout = 2\n}\n')

    def slow(*a, **k):
        time.sleep(30)
        return {}

    monkeypatch.setattr(iac_fix, "_propose", slow)
    t0 = time.monotonic()
    out = iac_fix.suggest_fix({"root_cause": "cctl-complexapp-worker timeout is too low"},
                              str(tmp_path), client=object(), model_id="m",
                              deadline=time.monotonic() + 13)
    assert time.monotonic() - t0 < 6
    assert out["status"] == "error" and "time" in out["detail"]

    monkeypatch.setenv("CLOUDCTL_TERRAFORM_BIN", sys.executable)
    res = iac_fix._check(tmp_path, "terraform", {}, deadline=time.monotonic() + 1)
    assert res["status"] == "not_run" and "no time left" in res["detail"]


def test_iac_fix_check_reuses_installed_providers(tmp_path, monkeypatch):
    from cloudctl.debug import iac_fix
    (tmp_path / "main.tf").write_text("# app\n")
    (tmp_path / ".terraform" / "providers").mkdir(parents=True)
    seen: list[list[str]] = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setenv("CLOUDCTL_TERRAFORM_BIN", "terraform")
    monkeypatch.setattr(iac_fix.subprocess, "run", fake_run)
    assert iac_fix._check(tmp_path, "terraform", {})["status"] == "passed"
    assert any(a.startswith("-plugin-dir=") for a in seen[0])

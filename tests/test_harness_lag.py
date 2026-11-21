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


def _run(last: str, inj_ago: float, tmp_path: Path, run3: bool = False) -> dict:
    state, data = ht.build(last, inj_ago=inj_ago, run3=run3)
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
    assert txt.rstrip().endswith("are not evidence of the current fault.")
    seeds = seed_hypotheses(d, [])
    assert seeds and "check it directly" in seeds[0]["reason"]


def test_s5_run3_revert_and_purge_inside_the_window_are_not_causes(tmp_path):
    # Live run 3: the api kept returning 5xx under load, so the window opened
    # at the start of the s4 load, and the s3 revert on the api and the queue
    # purge landed just inside it. Both were ranked as causes and the agent
    # blamed them. Now one is a likely revert and the other a one-off action.
    d = _run("s5", 2.5, tmp_path, run3=True)
    ex = d["explanation"]
    blamed = " ".join(c["summary"] for c in ex["causes"] + ex["alternatives"])
    assert "PurgeQueue" not in blamed and f"{fx.P}-api " not in blamed
    assert [c["resource_name"] for c in ex["likely_reverts"]] == [f"{fx.P}-api"]
    assert [c["event"] for c in [{"event": x["summary"].split(" ")[0]} for x in ex["one_off_actions"]]] == ["PurgeQueue"]
    # The api's 5xx are a current symptom nothing in config explains: say so.
    assert any(s["node"] == "aws_lambda_function.api" for s in ex["unexplained_symptoms"])
    assert [c["resource_key"] for c in ex["unplaced_drift"]] == [ESM]
    txt = prompt_text(d)
    assert "LIKELY A REVERT" in txt and "ONE-OFF ACTION" in txt
    out = apply_to_report({"root_cause": "x", "confidence": "HIGH"}, d)
    assert out["diff_first"]["likely_reverts"] and out["diff_first"]["one_off_actions"]


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


def test_s4_answer_shaped_like_the_agents_report_does_not_crash(tmp_path):
    # PR 47's laptop rerun: s3 and s4 crashed with a TypeError in run.py. The
    # agent's report sets additional_causes to None (IncidentReport default),
    # and apply_to_report appended to it when the answer missed a cause.
    from cloudctl.ai.graph_agent import IncidentReport
    d = _run("s4", 6, tmp_path)
    assert d["explanation"]["causes"]
    wrong = IncidentReport(
        root_cause=f"The worker role lost s3:PutObject on {fx.P}-receipts", evidence=["AccessDenied"],
        remediation_steps=[], severity="HIGH", confidence="HIGH",
        resources_investigated=[f"{fx.P}-receipts"]).model_dump()
    assert wrong["additional_causes"] is None
    out = apply_to_report(wrong, d)
    assert out["confidence"] == "LOW"
    assert {c for c in out["additional_causes"] if isinstance(c, str)} == {
        c["summary"] for c in d["explanation"]["causes"]}
    # The agent's own confirmed faults are kept, not overwritten.
    own = {"cause": "worker timeout"}
    wrong["additional_causes"] = [own]
    out = apply_to_report(wrong, d)
    assert out["additional_causes"][0] == own and len(out["additional_causes"]) == 3


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
    classify(chs, w, {"fn": {"timeout": 10}}, in_line={"fn"})
    assert chs[2].status == "restored"
    # Without a declared state to compare with, nothing is called a revert.
    classify(chs, w, {"fn": {"timeout": 10}})
    assert chs[2].status == "after_metrics"
    # A first-time change this recent is a lead the metrics can't judge yet.
    chs = [_change(60, "Create", {"functionName": "f", "timeout": 10}, "fn"),
           _change(3.5, "Update", {"functionName": "f", "timeout": 2}, "fn")]
    classify(chs, w, {"fn": {"timeout": 2}}, in_line=set())
    assert chs[1].status == "after_metrics"


def test_a_fault_applied_again_is_not_taken_for_a_revert():
    # A -> B (fault), A (revert), B again: the last change "puts back" B, but
    # live now differs from what is declared, so it stays a lead.
    w = IncidentWindow(onset=fx.t(30), last_healthy=fx.t(31), start=fx.t(36), end=fx.t(28),
                       metrics_end=fx.t(3))
    chs = [_change(60, "Create", {"functionName": "f", "timeout": 10}, "fn"),
           _change(50, "Update", {"functionName": "f", "timeout": 2}, "fn"),
           _change(40, "Update", {"functionName": "f", "timeout": 10}, "fn"),
           _change(3.5, "Update", {"functionName": "f", "timeout": 2}, "fn")]
    classify(chs, w, {"fn": {"timeout": 2}}, in_line=set())
    assert chs[3].status == "after_metrics" and not chs[3].restores


def test_an_in_window_revert_and_a_purge_are_leads_not_causes():
    # Run 3 s5: the s3 revert on the api (21:23:05) and the harness's queue
    # purge (21:23:15) landed in the window and were ranked as causes.
    w = IncidentWindow(onset=fx.t(30), last_healthy=fx.t(31), start=fx.t(36), end=fx.t(28),
                       metrics_end=fx.t(3))
    chs = [_change(60, "Create", {"functionName": "api", "memorySize": 256}, "api"),
           _change(40, "Update", {"functionName": "api", "memorySize": 64}, "api"),
           _change(30.5, "Update", {"functionName": "api", "memorySize": 256}, "api"),
           _change(30.4, "PurgeQueue", {"queueUrl": "https://q/orders"}, "q"),
           _change(30.3, "DeleteQueue", {"queueUrl": "https://q/other"}, "q2")]
    classify(chs, w, {"api": {"memorySize": 256}, "q": {}, "q2": {}}, in_line={"api", "q", "q2"})
    assert chs[2].status == "candidate" and chs[2].restores and not chs[2].one_off
    assert chs[3].status == "candidate" and chs[3].one_off and not chs[3].restores
    assert not chs[4].one_off      # a call that takes something away can leave a lasting fault
    # Not read live, or no declared state: neither flag.
    classify(chs, w, {"api": {"memorySize": 256}}, in_line=set())
    assert not chs[2].restores and not chs[3].one_off


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
                      "models": json.loads(raw).get("_models"),
                      "elapsed": round(time.monotonic() - t0, 1)}), flush=True)
    debug_cmd._exit_if_abandoned()
""")


def test_command_exits_at_the_ceiling_instead_of_waiting_for_the_abandoned_graph(tmp_path):
    env = {**__import__("os").environ, "CLOUDCTL_TIME_BUDGET_S": "2", "CLOUDCTL_MODEL": "test-model-id",
           "CLOUDCTL_TIME_GRACE_S": "1", "CLOUDCTL_HOME": str(tmp_path / "home"),
           "CLOUDCTL_DIFF_FIRST": "0", "HOME": str(tmp_path)}
    t0 = time.monotonic()
    r = subprocess.run([sys.executable, "-c", _EXIT_SCRIPT], capture_output=True, text=True,
                       timeout=60, env=env)
    wall = time.monotonic() - t0
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["timed_out"] is True
    assert out["elapsed"] < 5
    # The model ids are recorded even on a timed-out run (the rerun couldn't say which model ran).
    assert out["models"]["investigator"] == "test-model-id"
    # The process used to stay until the 30 s worker finished.
    assert wall < 15, (wall, r.stderr[-500:])


_RESUME_SCRIPT = textwrap.dedent("""
    import concurrent.futures, json, time
    import cloudctl.ai.graph_agent as g
    import cloudctl.mcp.tools.debug as dbg

    class Intr:
        value = {"question": "more context?"}

    class Graph:
        def invoke(self, arg, config):
            if isinstance(arg, dict):          # first run: ends in a clarify question
                time.sleep(2.5)
                return {"__interrupt__": [Intr()]}
            ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            return ex.submit(time.sleep, 30).result()   # the resume hangs
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
    import os
    os._exit(0)
""")


def test_a_resume_after_a_clarify_question_shares_the_run_deadline(tmp_path):
    # The resume used to get a fresh ceiling of its own, so a run could last
    # about twice the ceiling. Run 3 s4 lasted 912 s against a 540 s ceiling.
    env = {**__import__("os").environ, "CLOUDCTL_TIME_BUDGET_S": "2",
           "CLOUDCTL_TIME_GRACE_S": "1.5", "CLOUDCTL_HOME": str(tmp_path / "home"),
           "CLOUDCTL_DIFF_FIRST": "0", "HOME": str(tmp_path)}
    r = subprocess.run([sys.executable, "-c", _RESUME_SCRIPT], capture_output=True, text=True,
                       timeout=60, env=env, stdin=subprocess.DEVNULL)
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["timed_out"] is True, r.stderr[-500:]
    assert out["elapsed"] < 5, out      # one 3.5 s ceiling, not 2.5 s + a fresh 3.5 s


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


def test_scorer_flags_a_root_cause_that_also_blames_a_leftover_fault():
    # PR 47 rerun: s5 named the disabled mapping but also blamed s1's missing
    # s3:PutObject grant (reverted long before), and the scorer passed it.
    score = Path(__file__).resolve().parents[1] / "e2e" / "complex-app" / "score.py"
    r = subprocess.run([sys.executable, str(score), "--selftest"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout[-1500:]
    assert "s5.partial-blames-leftover.json: want PARTIAL, got PARTIAL" in r.stdout


def test_replay_script_works_after_teardown(tmp_path):
    # e2e/complex-app/replay_diff_first.py replays a run's recorded diff-first
    # inputs offline. After teardown terraform.tfstate lists nothing, so it
    # falls back to terraform.tfstate.backup.
    state, data = ht.build("s5", inj_ago=2.5, run3=True)
    runs, app = tmp_path / "runs", tmp_path / "app"
    runs.mkdir(), app.mkdir()
    (runs / "s5.diff-first.json").write_text(json.dumps(data))
    (app / "main.tf").write_text("# app\n")
    (app / "terraform.tfstate").write_text(json.dumps({**state, "resources": []}))
    (app / "terraform.tfstate.backup").write_text(json.dumps(state))
    script = Path(__file__).resolve().parents[1] / "e2e" / "complex-app" / "replay_diff_first.py"
    env = {**__import__("os").environ, "CLOUDCTL_HOME": str(tmp_path / "home"), "HOME": str(tmp_path)}
    r = subprocess.run([sys.executable, str(script), "s5", "--runs", str(runs), "--app", str(app)],
                       capture_output=True, text=True, timeout=60, env=env)
    assert r.returncode == 0, r.stderr[-1500:]
    assert "terraform.tfstate.backup" in r.stdout
    assert "likely_reverts: UpdateFunctionConfiguration" in r.stdout
    assert "one_off_actions: PurgeQueue" in r.stdout
    assert "unplaced_drift:" in r.stdout


def test_harness_summary_prints_models_and_diff_first_groups(tmp_path):
    """run.py summary reads only runs/ files and shows verdict, models and diff-first groups."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("cx_run", Path(__file__).parent.parent / "e2e/complex-app/run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    (tmp_path / "scorecard.json").write_text(json.dumps([{"scenario": "s5", "verdict": "PASS",
                                                           "confidence": "LOW", "notes": ["n1"]}]))
    (tmp_path / "s5.meta.json").write_text(json.dumps({"wall_seconds": 200.3, "exit_code": 0,
                                                        "model_env": {"CLOUDCTL_MODEL": "m-env"},
                                                        "models": {"investigator": "m-used"}}))
    (tmp_path / "s5.json").write_text(json.dumps({"diff_first": {
        "ran": True, "window": {"onset": "t1"}, "causes": [{"summary": "ESM disabled", "explains": ["S1"]}],
        "likely_reverts": ["api route restored"], "one_off_actions": ["queue purged"]}}))
    (tmp_path / "s3.json").write_text(json.dumps({"diff_first": {"ran": False, "error": "boom"}}))
    out = mod.summary(tmp_path)
    assert "s5: verdict PASS" in out and "200.3 s" in out
    assert "m-env" in out and "m-used" in out
    assert "diff_first keys: causes, likely_reverts, one_off_actions, ran, window" in out
    assert "likely_reverts (1): api route restored" in out and "causes (1): ESM disabled" in out
    assert "s3: verdict ?" in out and "DID NOT RUN: boom" in out
    assert mod.summary(tmp_path / "missing").endswith("no results in " + str(tmp_path / "missing"))


def test_live_pass_script_is_valid_bash_and_always_tears_down():
    """The one-shot laptop pass parses, stops before AWS on a wrong head, and traps teardown."""
    import subprocess
    sh = Path(__file__).parent.parent / "e2e/complex-app/live_pass.sh"
    assert subprocess.run(["bash", "-n", str(sh)]).returncode == 0
    text = sh.read_text()
    assert "trap finish EXIT" in text and "python run.py teardown" in text
    # Guards come before the first AWS or terraform call.
    first_aws = min(text.index("aws sts"), text.index("run.py deploy"))
    assert text.index("expected $want") < first_aws and text.index("tracked edits") < first_aws
    for s in ("s1", "s3", "s4", "s5"):
        assert s in text.split("for s in", 1)[1].split("\n", 1)[0]


def _load_harness(name, rel):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent.parent / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(Path(spec.origin).parent))
    spec.loader.exec_module(mod)
    return mod


def test_pause_watch_counts_a_wall_clock_jump_as_sleep(monkeypatch):
    """A jump in wall time between ticks (laptop suspended) is counted; normal ticks are not."""
    mod = _load_harness("cx_run2", "e2e/complex-app/run.py")
    clock = {"t": 1000.0, "n": 0}

    def fake_time():
        clock["n"] += 1
        clock["t"] += 0.05 + (300.0 if clock["n"] == 4 else 0.0)
        return clock["t"]
    monkeypatch.setattr(mod.time, "time", fake_time)
    with mod.PauseWatch(tick_s=0.05, slack_s=1.0) as pw:
        while clock["n"] < 8:
            time.sleep(0.02)
    assert 299 <= pw.paused_s <= 301


def test_score_takes_host_sleep_out_of_the_time_and_says_so():
    mod = _load_harness("cx_score2", "e2e/complex-app/score.py")
    cfg = mod.load_cfg()
    res = {"root_cause": "x", "confidence": "LOW"}
    slept = mod.score_one(mod.by_id(cfg, "s5"), res, {"wall_seconds": 3371.7, "host_paused_s": 2940.0}, cfg)
    assert slept["seconds"] == 431.7 and slept["time_ok"]
    assert any("host asleep 2940 s" in n for n in slept["notes"])
    awake = mod.score_one(mod.by_id(cfg, "s5"), res, {"wall_seconds": 912.0}, cfg)
    assert awake["seconds"] == 912.0 and not awake["time_ok"]

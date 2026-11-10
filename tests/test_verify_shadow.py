"""Shadow mode and the remediation stubs."""
from __future__ import annotations

import copy
import json
import os

import pytest

from cloudctl.verify import shadow as S
from cloudctl.verify.profiles import ModelProfile
from cloudctl.verify.proposer import TOOL_NAME
from cloudctl.verify.remediation import blast_radius, plan_check
from tests.verify_support import (
    END,
    FIXTURES,
    FN,
    ROLE,
    TABLE,
    T,
    orders_evidence_data,
    orders_model,
)

PROFILE = ModelProfile(name="fake", provider="bedrock", model_id="fake", structured_mode="tool_use")
ROLE_HYP = {"node": ROLE, "property": "policy:dynamodb:PutItem", "claim": "c", "predictions": [
    {"primitive": "permit", "args_json": json.dumps({"principal": ROLE, "action": "dynamodb:PutItem",
                                                     "resource": TABLE}), "expect": "FAIL"}]}


class FakeClient:
    def __init__(self, payload=None, exc=None):
        self.payload, self.exc, self.calls = payload, exc, 0

    def converse(self, **kw):
        self.calls += 1
        if self.exc:
            raise self.exc
        return {"output": {"message": {"content": [{"toolUse": {"name": TOOL_NAME, "input": self.payload}}]}},
                "usage": {"inputTokens": 100, "outputTokens": 20}}


@pytest.fixture
def env(tmp_path, monkeypatch):
    log = tmp_path / "shadow.jsonl"
    monkeypatch.setenv("CLOUDCTL_VERIFY_SHADOW_LOG", str(log))
    for k in ("CLOUDCTL_VERIFY_SWEEP", "CLOUDCTL_IAC_PATHS", "CLOUDCTL_REPLAY", "CLOUDCTL_RECORD"):
        monkeypatch.delenv(k, raising=False)
    return tmp_path, log


def _sweep(tmp_path, monkeypatch, **over):
    m = orders_model()
    live = [{"arn": FN, "type": "lambda", "name": "orders-fn", "config": {"Role": ROLE}}]
    sweep = {"incident": {"onset": T, "end": END}, "anchor": "orders-fn",
             "graph": {"live_resources": live}, "evidence": orders_evidence_data(), **over}
    p = tmp_path / "sweep.json"
    p.write_text(json.dumps(sweep))
    monkeypatch.setenv("CLOUDCTL_VERIFY_SWEEP", str(p))
    monkeypatch.setenv("CLOUDCTL_IAC_PATHS", os.path.join(FIXTURES, "orders.tfstate.json"))
    return m


REPORT = {"root_cause": "The orders-role lost dynamodb:PutItem", "confidence": "HIGH",
          "resources_investigated": ["orders-fn"]}


def test_skipped_without_sweep_and_logged(env):
    _, log = env
    report = copy.deepcopy(REPORT)
    out = S.run_shadow(symptom="s", report=report, final_state={}, all_fetched={},
                       client=FakeClient(), model_profile=PROFILE)
    assert out["status"] == "skipped" and "evidence source is not built" in out["reason"]
    assert report == REPORT
    assert json.loads(log.read_text().splitlines()[0])["status"] == "skipped"


def test_runs_with_sweep_and_fake_model_and_never_touches_the_report(env, monkeypatch):
    tmp_path, log = env
    _sweep(tmp_path, monkeypatch)
    report = copy.deepcopy(REPORT)
    client = FakeClient({"hypotheses": [ROLE_HYP]})
    out = S.run_shadow(symptom="orders failing", report=report, final_state={"failure_map": []},
                       all_fetched={}, client=client, model_profile=PROFILE)
    assert out["status"] == "ran", out.get("error")
    assert out["decision_status"] == "VERIFIED" and out["verdict"]["node"] == ROLE
    assert out["agent_names_verified_node"] is True
    assert out["usage"]["calls"] == client.calls == 1
    assert out["discovery"]["iac"][0]["kind"] == "terraform_state"
    assert report == REPORT
    assert json.loads(log.read_text().splitlines()[-1])["verdict"]["node"] == ROLE


def test_errors_are_swallowed_and_logged(env, monkeypatch):
    tmp_path, _ = env
    _sweep(tmp_path, monkeypatch)
    out = S.run_shadow(symptom="s", report=REPORT, final_state={}, all_fetched={},
                       client=FakeClient(exc=RuntimeError("model down")), model_profile=PROFILE)
    # a proposer failure is a trace entry in the loop, not a crash
    assert out["status"] == "ran" and out["decision_status"] == "UNVERIFIED"
    monkeypatch.setenv("CLOUDCTL_VERIFY_SWEEP", str(tmp_path / "missing.json"))
    out2 = S.run_shadow(symptom="s", report=REPORT, final_state={}, all_fetched={},
                        client=FakeClient(), model_profile=PROFILE)
    assert out2["status"] == "error" and "FileNotFoundError" in out2["error"]


def test_anchor_from_failure_map_and_missing_anchor(env, monkeypatch):
    tmp_path, _ = env
    m = _sweep(tmp_path, monkeypatch, anchor="ghost")
    assert S.pick_anchor(m, {"anchor": "ghost"}, [{"component": "orders-fn"}]) == FN
    out = S.run_shadow(symptom="s", report=REPORT, final_state={"failure_map": [{"component": "nope"}]},
                       all_fetched={}, client=FakeClient(), model_profile=PROFILE)
    assert out["status"] == "skipped" and "anchor" in out["reason"]


def test_bad_iac_artifact_does_not_stop_discovery(tmp_path):
    bad = tmp_path / "junk.json"
    bad.write_text("{}")
    m, rep = S.build_model({}, [str(bad), os.path.join(FIXTURES, "orders.tfstate.json")])
    assert rep["errors"] and m.resolve("orders-fn") == FN
    assert "VPC flow logs" in rep["observability_gaps"]


def test_shadow_client_replays_recorded_calls(tmp_path, monkeypatch):
    kw = {"modelId": "m", "messages": []}
    h = S._ShadowModelClient._hash(kw)
    rec = tmp_path / "rec.jsonl"
    rec.write_text(json.dumps({"tool": "_verify_model", "input": {"hash": h},
                               "output": json.dumps({"output": {"message": {"content": []}}})}) + "\n")
    monkeypatch.setenv("CLOUDCTL_REPLAY", str(rec))
    monkeypatch.setenv("CLOUDCTL_VERIFY_REPLAY_MODEL", "1")
    assert S._ShadowModelClient(None).converse(**kw) == {"output": {"message": {"content": []}}}
    with pytest.raises(RuntimeError, match="no recorded"):
        S._ShadowModelClient(None).converse(modelId="other")


def test_graph_agent_shadow_hook_is_off_by_default():
    import inspect

    from cloudctl.ai import graph_agent
    src = inspect.getsource(graph_agent)
    assert 'CLOUDCTL_VERIFY_SHADOW") == "1"' in src


# ── remediation stubs ───────────────────────────────────────────────────────

def test_plan_check_never_runs_anything(monkeypatch):
    monkeypatch.delenv("CLOUDCTL_VERIFY_PLAN_CHECK", raising=False)
    assert plan_check("/x")["status"] == "not_run"
    monkeypatch.setenv("CLOUDCTL_VERIFY_PLAN_CHECK", "1")
    assert plan_check("/x")["status"] == "not_implemented"


def test_blast_radius():
    m = orders_model()
    rc = lambda addr, *a: {"address": addr, "change": {"actions": list(a)}}
    ok = blast_radius({"resource_changes": [rc("module.orders.aws_iam_role.orders", "update"),
                                            rc("module.orders.aws_lambda_function.orders", "no-op")]}, m, ROLE)
    assert ok["ok"] and len(ok["touched"]) == 1
    far = blast_radius({"resource_changes": [rc("module.users.aws_lambda_function.users", "update")]}, m, ROLE)
    assert not far["ok"] and "outside the verified node" in far["violations"][0]
    rep = blast_radius({"resource_changes": [rc("module.orders.aws_iam_role.orders", "delete", "create")]}, m, ROLE)
    assert not rep["ok"] and "replace without a stated reason" in rep["violations"][0]
    assert blast_radius({"resource_changes": [rc("module.orders.aws_iam_role.orders", "delete", "create")]},
                        m, ROLE, allow_replace_reason="rename")["ok"]
    assert not blast_radius({}, m, "ghost")["ok"]

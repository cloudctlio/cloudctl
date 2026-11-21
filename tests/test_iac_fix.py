"""IaC-grounded fix suggestion: locate the blamed resource in Terraform / CDK
Python, get a minimal edit from a stand-in model, show a diff, never write to
the operator's tree, never touch root-cause confidence. Offline."""
import json
import os
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cloudctl.debug import iac_fix

FIX = Path(__file__).parent / "fixtures" / "iac_fix"
DIAG = {
    "root_cause": "DynamoDB table orders is provisioned at 1 WCU, so writes from Lambda "
                  "orders-writer are throttled (ProvisionedThroughputExceededException).",
    "evidence": ["WriteThrottleEvents 412 in 15 min", "ConsumedWriteCapacityUnits at 1.0"],
    "remediation_steps": ["Raise write capacity or switch to on-demand"],
    "resources_investigated": ["orders-writer", "orders"],
    "confidence": "MEDIUM",
}


def _model(reply: dict):
    c = MagicMock()
    c.converse.return_value = {"stopReason": "end_turn", "output": {"message": {
        "role": "assistant", "content": [{"text": json.dumps(reply)}]}}}
    return c


@pytest.fixture
def tf(tmp_path):
    d = tmp_path / "tf"
    shutil.copytree(FIX / "terraform", d)
    return d


@pytest.fixture
def cdk(tmp_path):
    d = tmp_path / "cdk"
    shutil.copytree(FIX / "cdk_python", d)
    return d


@pytest.fixture
def no_tools(tmp_path, monkeypatch):
    empty = tmp_path / "emptybin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.delenv("CLOUDCTL_TERRAFORM_BIN", raising=False)
    monkeypatch.delenv("CLOUDCTL_CDK_BIN", raising=False)


def _snapshot(d: Path) -> dict:
    return {p: p.read_bytes() for p in d.rglob("*") if p.is_file()}


# ── locate ────────────────────────────────────────────────────────────────────

def test_candidates_put_the_blamed_resource_first():
    assert iac_fix.candidate_names(DIAG)[:2] == ["orders", "orders-writer"]
    lam = {**DIAG, "root_cause": "Lambda orders-writer has a 3 s timeout; writes to orders time out."}
    assert iac_fix.candidate_names(lam)[0] == "orders-writer"
    arn = {"root_cause": "x", "affected_resources": ["arn:aws:dynamodb:us-east-1:1:table/orders"]}
    assert "orders" in iac_fix.candidate_names(arn)


def test_terraform_table_found_through_variable_default_not_lambda_env(tf):
    hits, kinds = iac_fix.locate(tf, iac_fix.candidate_names(DIAG))
    assert kinds == ["terraform"]
    assert [h.address for h in hits] == ["aws_dynamodb_table.orders"]
    assert "var.table_name" in hits[0].how
    assert {r["address"] for r in hits[0].related} == {"var.table_name", "var.orders_wcu"}


def test_terraform_state_match_wins(tf):
    (tf / "terraform.tfstate").write_text(json.dumps({"resources": [
        {"mode": "managed", "type": "aws_dynamodb_table", "name": "orders",
         "instances": [{"attributes": {"name": "prod-orders-7f3", "arn": "arn:aws:dynamodb:x:1:table/prod-orders-7f3"}}]}]}))
    hits, _ = iac_fix.locate(tf, ["prod-orders-7f3"])
    assert [h.address for h in hits] == ["aws_dynamodb_table.orders"]
    assert "tfstate" in hits[0].how


def test_cdk_python_table_found_by_keyword(cdk):
    hits, kinds = iac_fix.locate(cdk, iac_fix.candidate_names(DIAG))
    assert kinds == ["cdk"]
    assert hits[0].address == "OrdersTable (dynamodb.Table)"
    assert hits[0].file == "stacks/orders_stack.py" and "write_capacity=1" in hits[0].text


def test_ambiguous_match_gives_no_diff(tf):
    (tf / "other.tf").write_text('resource "aws_sqs_queue" "q" {\n  name = "orders"\n}\n'
                                 'resource "aws_sns_topic" "t" {\n  name = "orders"\n}\n')
    client = _model({"edits": []})
    out = iac_fix.suggest_fix({"root_cause": "orders is slow", "resources_investigated": ["orders"]},
                              str(tf), client=client, model_id="m")
    assert out["status"] == "ambiguous" and len(out["candidates"]) >= 2
    client.converse.assert_not_called()


def test_not_found_says_so_and_never_calls_the_model(tf):
    client = _model({"edits": []})
    out = iac_fix.suggest_fix({"root_cause": "bucket media-assets denies reads",
                               "resources_investigated": ["media-assets"]}, str(tf), client=client, model_id="m")
    assert out["status"] == "not_found" and "media-assets" in out["searched_for"]
    client.converse.assert_not_called()


def test_no_iac_in_directory(tmp_path):
    out = iac_fix.suggest_fix(DIAG, str(tmp_path), client=_model({}), model_id="m")
    assert out["status"] == "no_iac"


# ── propose + diff ────────────────────────────────────────────────────────────

def test_terraform_suggestion_is_a_diff_and_tree_is_untouched(tf, no_tools):
    before = _snapshot(tf)
    client = _model({"edits": [{"file": "variables.tf", "old": "  default = 1", "new": "  default = 10"}],
                     "summary": "Raise the table's write capacity from 1 to 10 WCU."})
    out = iac_fix.suggest_fix(DIAG, str(tf), client=client, model_id="any-model")
    assert out["status"] == "suggested"
    assert out["resource"] == "aws_dynamodb_table.orders"
    assert "-  default = 1\n+  default = 10" in out["diff"]
    assert out["verified"] is False and out["check"]["status"] == "not_run"
    assert _snapshot(tf) == before
    sent = json.loads(client.converse.call_args.kwargs["messages"][0]["content"][0]["text"])
    assert client.converse.call_args.kwargs["modelId"] == "any-model"
    assert {t["address"] for t in sent["iac_text"]} == {"aws_dynamodb_table.orders", "var.table_name",
                                                         "var.orders_wcu"}
    assert "aws_lambda_function" not in json.dumps(sent)


def test_edit_outside_the_located_resource_is_rejected(tf, no_tools):
    client = _model({"edits": [{"file": "main.tf", "old": 'TABLE_NAME = "orders"', "new": 'TABLE_NAME = "x"'}]})
    out = iac_fix.suggest_fix(DIAG, str(tf), client=client, model_id="m")
    assert out["status"] == "error" and "not inside the located resource" in out["detail"]


def test_model_declines_with_reason(tf, no_tools):
    out = iac_fix.suggest_fix(DIAG, str(tf), client=_model({"edits": [], "reason_if_no_edit": "fix is in app code"}),
                              model_id="m")
    assert out["status"] == "no_edit" and out["detail"] == "fix is in app code"


@pytest.mark.posix_only
def test_terraform_check_passes_or_fails_with_a_stand_in_binary(tf, tmp_path, monkeypatch):
    fake = tmp_path / "terraform"
    edit = {"edits": [{"file": "variables.tf", "old": "  default = 1", "new": "  default = 10"}]}
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("CLOUDCTL_TERRAFORM_BIN", str(fake))
    ok = iac_fix.suggest_fix(DIAG, str(tf), client=_model(edit), model_id="m")
    assert ok["verified"] is True and ok["check"]["status"] == "passed"
    fake.write_text("#!/bin/sh\necho 'Error: Unsupported argument' >&2\nexit 1\n")
    bad = iac_fix.suggest_fix(DIAG, str(tf), client=_model(edit), model_id="m")
    assert bad["verified"] is False and bad["check"]["status"] == "failed"
    assert "Unsupported argument" in bad["check"]["detail"]


def test_cdk_suggestion_diff(cdk, no_tools, monkeypatch):
    monkeypatch.setenv("CLOUDCTL_IAC_FIX_CHECK", "0")
    client = _model({"edits": [{"file": "stacks/orders_stack.py",
                                "old": "            write_capacity=1,", "new": "            write_capacity=10,"}]})
    out = iac_fix.suggest_fix(DIAG, str(cdk), client=client, model_id="m")
    assert out["status"] == "suggested" and out["kind"] == "cdk"
    assert "+            write_capacity=10," in out["diff"]
    assert out["verified"] is False


_CDK_PY = Path(os.environ.get("CCTL_TEST_CDK_PYTHON", "/nonexistent/python3"))


@pytest.mark.skipif(not _CDK_PY.exists(), reason="set CCTL_TEST_CDK_PYTHON to a python with aws-cdk-lib")
def test_cdk_synth_check_runs_the_app_on_a_temp_copy(cdk, monkeypatch):
    monkeypatch.setenv("PATH", f"{_CDK_PY.parent}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.delenv("CLOUDCTL_CDK_BIN", raising=False)
    monkeypatch.setattr(iac_fix.shutil, "which", lambda n: None if n == "cdk" else shutil.which(n))
    good = {"edits": [{"file": "stacks/orders_stack.py", "old": "            write_capacity=1,",
                       "new": "            write_capacity=10,"}]}
    out = iac_fix.suggest_fix(DIAG, str(cdk), client=_model(good), model_id="m")
    assert out["check"]["status"] == "passed", out["check"]
    broken = {"edits": [{"file": "stacks/orders_stack.py", "old": "            write_capacity=1,",
                         "new": "            write_capacity=dynamodb.NoSuchThing,"}]}
    out = iac_fix.suggest_fix(DIAG, str(cdk), client=_model(broken), model_id="m")
    assert out["check"]["status"] == "failed"


# ── CLI wiring ────────────────────────────────────────────────────────────────

def test_cli_agent_shows_fix_and_keeps_confidence(tf, tmp_path, no_tools, monkeypatch):
    monkeypatch.setenv("PATH", os.pathsep.join([str(Path(sys.executable).parent), "/usr/bin", "/bin"]))
    from typer.testing import CliRunner
    from cloudctl.main import app
    client = _model({"edits": [{"file": "variables.tf", "old": "  default = 1", "new": "  default = 10"}],
                     "summary": "Raise WCU to 10."})
    out_json = tmp_path / "out.json"
    with patch("cloudctl.commands.debug_cmd.require_init", return_value={}), \
         patch("cloudctl.ai.graph_agent.debug_incident_graph", return_value=(json.dumps(DIAG), {})), \
         patch("cloudctl.ai.model_providers.make_model_client", return_value=client):
        r = CliRunner().invoke(app, ["debug", "--agent", "--verdict", "skip", "--iac-root", str(tf),
                                     "--json-out", str(out_json), "orders writes throttled"],
                               env={"COLUMNS": "160", "HOME": str(tmp_path)})
    assert r.exit_code == 0, r.output
    assert "IaC FIX SUGGESTION" in r.output and "UNVERIFIED" in r.output
    d = json.loads(out_json.read_text())
    assert d["confidence"] == "MEDIUM"
    assert d["iac_fix"]["status"] == "suggested"
    assert d["deployment_source"] == "terraform" and d["iac_file_hint"].startswith("main.tf:13-24")

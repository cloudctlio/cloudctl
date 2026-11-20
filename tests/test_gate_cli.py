"""`cloudctl gate ...` commands, offline."""
import json
import os

import pytest
import yaml
from typer.testing import CliRunner

pytest.importorskip("regopy")
pytest.importorskip("cedarpy")
pytest.importorskip("cryptography")

from cloudctl.commands import gate_cmd  # noqa: E402
from cloudctl.gate.approval import ApprovalRequest, LocalApprovalStore  # noqa: E402
from cloudctl.gate.config import parse_config  # noqa: E402
from tests.gate.conftest import AWS_ACCT, SUB, TENANT, aws_env, config_doc  # noqa: E402

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CLOUDCTL_GATE_CONFIG", str(tmp_path / "cp.yaml"))
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.delenv("CLOUDCTL_APPROVER_PASSPHRASE", raising=False)
    gate_cmd.console.width = 200


def _run(*args, input=None):
    return runner.invoke(gate_cmd.app, list(args), input=input, catch_exceptions=False)


@pytest.mark.parametrize("args", [
    ["--cloud", "aws", "--account-id", AWS_ACCT, "--region", "us-east-1", "--profile", "dev"],
    ["--cloud", "azure", "--tenant-id", TENANT, "--subscription-id", SUB, "--resource-group", "rg-app"],
    ["--cloud", "gcp", "--project-id", "proj-app", "--region", "us-central1"],
])
def test_init_writes_valid_private_config_for_each_cloud(tmp_path, args):
    r = _run("init", *args)
    assert r.exit_code == 0, r.output
    path = tmp_path / "cp.yaml"
    assert os.stat(path).st_mode & 0o077 == 0
    cfg = parse_config(yaml.safe_load(path.read_text()))
    assert cfg.environment("dev").tier == "dev"
    assert _run("init", *args).exit_code == 1            # refuses to overwrite
    assert _run("init", *args, "--force").exit_code == 0


def test_init_requires_scope_flags():
    r = runner.invoke(gate_cmd.app, ["init", "--cloud", "aws"])
    assert r.exit_code != 0


def _write_cfg(tmp_path, doc):
    (tmp_path / "cp.yaml").write_text(yaml.safe_dump(doc))


def test_validate_and_engines(tmp_path):
    _write_cfg(tmp_path, config_doc({"dev": aws_env()}, tmp=tmp_path))
    r = _run("validate")
    assert r.exit_code == 0 and "dev" in r.output
    r = _run("engines")
    assert r.exit_code == 0
    for name in ("rego", "checkov", "trivy", "aws_native"):
        assert name in r.output


def test_validate_reports_bad_config(tmp_path):
    _write_cfg(tmp_path, {"version": 1, "environments": {"dev": {"tier": "dev"}}})
    r = _run("validate")
    assert r.exit_code == 1


PLAN = {"format_version": "1.2", "terraform_version": "1.10.5", "resource_changes": [
    {"address": "aws_security_group.ssh", "mode": "managed", "type": "aws_security_group", "name": "ssh",
     "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": None, "after_unknown": {},
                "after": {"region": "us-east-1", "ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp",
                                                              "cidr_blocks": ["0.0.0.0/0"]}]}}}]}


def test_policy_eval_rejects_open_ssh_with_exit_2(tmp_path):
    _write_cfg(tmp_path, config_doc({"dev": aws_env()}, tmp=tmp_path))
    pf = tmp_path / "plan.json"
    pf.write_text(json.dumps(PLAN))
    r = _run("policy", "eval", str(pf), "--env", "dev", "--json")
    assert r.exit_code == 2, r.output
    out = json.loads(r.output)
    assert out["rejected"] is True and "aws_native" in out["skipped_need_credentials"]
    assert any(f["rule_id"] == "CCTL-NET-001" for f in out["findings"])


def test_policy_eval_clean_plan_exit_0(tmp_path):
    _write_cfg(tmp_path, config_doc({"dev": aws_env()}, tmp=tmp_path))
    clean = json.loads(json.dumps(PLAN))
    clean["resource_changes"][0]["change"]["after"]["ingress"][0]["cidr_blocks"] = ["10.0.0.0/8"]
    pf = tmp_path / "plan.json"
    pf.write_text(json.dumps(clean))
    r = _run("policy", "eval", str(pf), "--env", "dev")
    assert r.exit_code == 0, r.output
    assert "No HIGH/CRITICAL findings" in r.output


def test_policy_eval_unreadable_plan(tmp_path):
    _write_cfg(tmp_path, config_doc({"dev": aws_env()}, tmp=tmp_path))
    assert _run("policy", "eval", str(tmp_path / "missing.json"), "--env", "dev").exit_code == 1


def _approval_setup(tmp_path, approver="bob"):
    key = tmp_path / "bob.pem"
    r = _run("keygen", "--approver", approver, "--out", str(key), "--no-passphrase")
    assert r.exit_code == 0, r.output
    pub = r.output.split('public_key: "')[1].split('"')[0]
    env = aws_env(approval={"approvers": [approver], "threshold": 1})
    _write_cfg(tmp_path, config_doc({"staging": {**env, "tier": "staging"}},
                                    approvers={approver: {"public_key": pub}}, tmp=tmp_path))
    store = LocalApprovalStore(tmp_path / "approvals")
    req = ApprovalRequest.new(request_id="req-cli-0001", environment="staging", tier="staging",
                              plan_digest="sha256:abc", summary="tag 3 instances", requester="alice",
                              counts={"modify": 3}, max_severity="MEDIUM", ttl_seconds=900)
    store.put_request(req)
    return key, store


def test_keygen_refuses_overwrite(tmp_path):
    key = tmp_path / "k.pem"
    assert _run("keygen", "--approver", "bob", "--out", str(key), "--no-passphrase").exit_code == 0
    assert os.stat(key).st_mode & 0o077 == 0
    assert _run("keygen", "--approver", "bob", "--out", str(key), "--no-passphrase").exit_code == 1


def test_approve_flow_signs_audits_and_is_write_once(tmp_path):
    key, store = _approval_setup(tmp_path)
    r = _run("approvals", "list")
    assert "req-cli-0001" in r.output
    r = _run("approve", "req-cli-0001", "--approver", "bob", "--key", str(key), input="n\n")
    assert r.exit_code == 1 and store.get_approval("req-cli-0001") is None
    r = _run("approve", "req-cli-0001", "--approver", "bob", "--key", str(key), "--yes")
    assert r.exit_code == 0, r.output
    assert store.get_approval("req-cli-0001").approver == "bob"
    assert "No approval requests" in _run("approvals", "list").output
    assert _run("approve", "req-cli-0001", "--approver", "bob", "--key", str(key), "--yes").exit_code == 1
    r = _run("audit", "verify")
    assert r.exit_code == 0 and "intact" in r.output


def test_approve_refuses_unlisted_approver_and_wrong_key(tmp_path):
    key, store = _approval_setup(tmp_path)
    assert _run("approve", "req-cli-0001", "--approver", "carol", "--key", str(key), "--yes").exit_code == 1
    other = tmp_path / "other.pem"
    _run("keygen", "--approver", "x", "--out", str(other), "--no-passphrase")
    r = _run("approve", "req-cli-0001", "--approver", "bob", "--key", str(other), "--yes")
    assert r.exit_code == 1 and "not the public key" in r.output
    assert store.get_approval("req-cli-0001") is None


def test_approve_refuses_own_request(tmp_path):
    key, store = _approval_setup(tmp_path, approver="alice")
    r = _run("approve", "req-cli-0001", "--approver", "alice", "--key", str(key), "--yes")
    assert r.exit_code == 1 and "not authorized" in r.output


def test_audit_verify_detects_tampering(tmp_path):
    key, _ = _approval_setup(tmp_path)
    _run("approve", "req-cli-0001", "--approver", "bob", "--key", str(key), "--yes")
    log = next((tmp_path / "audit").glob("chain*.jsonl"))
    lines = log.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["data"]["approver"] = "mallory"
    lines[0] = json.dumps(rec)
    log.write_text("\n".join(lines) + "\n")
    r = _run("audit", "verify")
    assert r.exit_code == 1 and "BROKEN" in r.output

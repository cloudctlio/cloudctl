"""Cost and security fixers under the policy gate, for AWS, Azure and GCP.

Each fixer declares its change with plan(); the gate checks that plan; only
an authorization calls apply() with the gate's scoped credentials. Cloud SDK
calls are mocked: nothing here talks to a cloud.
"""
from datetime import timedelta
from unittest.mock import MagicMock

import pytest

pytest.importorskip("regopy")

from cloudctl.ai import fixer as fixer_mod  # noqa: E402
from cloudctl.ai.fixer import AIFixer, gated_apply  # noqa: E402
from cloudctl.fixers.aws.cost import (  # noqa: E402
    AWSDeleteOldSnapshotFixer, AWSDeleteOrphanedVolumeFixer, AWSStopIdleInstanceFixer,
)
from cloudctl.fixers.aws.security import AWSOpenSecurityGroupFixer, AWSS3PublicAccessFixer  # noqa: E402
from cloudctl.fixers.azure.cost import AzureDeallocateIdleVMFixer, AzureDeleteOrphanedDiskFixer  # noqa: E402
from cloudctl.fixers.base import BaseFixer  # noqa: E402
from cloudctl.fixers.gcp.security import GCPOpenFirewallFixer  # noqa: E402
from cloudctl.fixers.registry import _REGISTRY, _ensure_loaded  # noqa: E402
from cloudctl.gate.audit import AuditLog, LocalFileSink  # noqa: E402
from cloudctl.gate.config import parse_config  # noqa: E402
from cloudctl.gate.credentials.base import ScopedCredentials, capped_expiry  # noqa: E402
from cloudctl.gate.gate import PolicyGate  # noqa: E402
from cloudctl.gate.models import Action, ConfigError, Outcome, PlanError, Severity  # noqa: E402
from cloudctl.gate.policy.rego import RegoEngine  # noqa: E402
from cloudctl.gate.models import utcnow  # noqa: E402
from tests.gate.conftest import AWS_ACCT, SUB, aws_env, azure_env, config_doc, gcp_env  # noqa: E402
from tests.gate.test_gate import PROD_POLICY, S3, FakeScanner, _keypair  # noqa: E402


class Broker:
    """Fake broker whose credentials build mocked SDK objects."""

    def __init__(self, cloud, sdk=None):
        self.cloud, self.sdk, self.issued = cloud, sdk or MagicMock(), []

    def acquire(self, env, *, request_id, requester):
        now = utcnow()
        kind = {"aws": "session", "azure": "credential", "gcp": "credentials"}[self.cloud]
        c = ScopedCredentials(cloud=self.cloud, identity="fake", scope=dict(env.scope),
                              expires_at=capped_expiry(now, now + timedelta(hours=1)), acquired_at=now,
                              _secret={"t": "x"}, _builders={kind: lambda *a, **k: self.sdk})
        self.issued.append(c)
        return c


def _gate(tmp_path, cfg, cloud, sdk=None, extra_engines=()):
    broker = Broker(cloud, sdk)
    engines = [RegoEngine.from_config(builtin=True, rule_paths=[], rego_paths=[], params={}), *extra_engines]
    gate = PolicyGate(cfg, audit=AuditLog(LocalFileSink(tmp_path / "a.jsonl"), chain="t"),
                      brokers={cloud: broker}, policy=([], engines))
    return gate, broker


def _dev(tmp_path, envf):
    return parse_config(config_doc({"dev": envf()}, tmp=tmp_path))


def test_every_registered_fixer_declares_a_plan():
    _ensure_loaded()
    assert _REGISTRY, "no fixers registered"
    missing = [c.__name__ for c in _REGISTRY if c.plan is BaseFixer.plan]
    assert missing == []
    assert {c.cloud for c in _REGISTRY} >= {"aws", "azure", "gcp"}


# ── AWS ──────────────────────────────────────────────────────────────────────

def _ec2_session(**describe):
    ec2 = MagicMock()
    for k, v in describe.items():
        getattr(ec2, k).return_value = v
    session = MagicMock()
    session.client.return_value = ec2
    return session, ec2


SG_ISSUE = {"resource": "sg/sg-0abc (web)", "issue": "allows 0.0.0.0/0 inbound", "region": "us-east-1",
            "account": "dev"}
OPEN_SG = {"SecurityGroups": [{"GroupName": "web", "IpPermissions": [
    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]}]}


def test_aws_sg_fix_goes_through_gate_and_applies_with_scoped_creds(tmp_path):
    session, ec2 = _ec2_session(describe_security_groups=OPEN_SG)
    gate, broker = _gate(tmp_path, _dev(tmp_path, aws_env), "aws", session)
    out = gated_apply(gate, AWSOpenSecurityGroupFixer(), SG_ISSUE, {"action": "revoke"}, env_name="dev",
                      requester="alice")
    assert out.applied and out.decision.outcome == Outcome.AUTHORIZED
    ec2.revoke_security_group_ingress.assert_called_once()
    assert ec2.revoke_security_group_ingress.call_args.kwargs["GroupId"] == "sg-0abc"
    assert broker.issued[0]._destroyed


def test_aws_sg_plan_declares_before_and_after():
    session, _ = _ec2_session(describe_security_groups=OPEN_SG)
    creds = MagicMock()
    creds.client.return_value = session
    env = _dev_env(aws_env)
    [c] = AWSOpenSecurityGroupFixer().plan(SG_ISSUE, {}, creds=creds, env=env)
    assert c.action == Action.UPDATE and c.cloud == "aws" and c.location == "us-east-1"
    assert len(c.before["ingress"]) == 2 and c.after["ingress"] == [
        {"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]}]


def _dev_env(envf):
    return parse_config(config_doc({"dev": envf()})).environment("dev")


def test_aws_sg_nothing_open_is_no_change(tmp_path):
    session, ec2 = _ec2_session(describe_security_groups={"SecurityGroups": [{"IpPermissions": []}]})
    gate, _ = _gate(tmp_path, _dev(tmp_path, aws_env), "aws", session)
    out = gated_apply(gate, AWSOpenSecurityGroupFixer(), SG_ISSUE, {}, env_name="dev", requester="alice")
    assert not out.applied and out.decision.stage == "plan"
    ec2.revoke_security_group_ingress.assert_not_called()


def test_aws_region_outside_scope_rejected(tmp_path):
    session, ec2 = _ec2_session(describe_security_groups=OPEN_SG)
    gate, _ = _gate(tmp_path, _dev(tmp_path, aws_env), "aws", session)
    out = gated_apply(gate, AWSOpenSecurityGroupFixer(), {**SG_ISSUE, "region": "eu-west-1"}, {},
                      env_name="dev", requester="alice")
    assert not out.applied and any(f.rule_id == "CCTL-SCOPE-001" for f in out.decision.findings)
    ec2.revoke_security_group_ingress.assert_not_called()


def test_aws_volume_plan_refuses_attached_volume():
    session, _ = _ec2_session(describe_volumes={"Volumes": [{"Attachments": [{"InstanceId": "i-1"}]}]})
    creds = MagicMock()
    creds.client.return_value = session
    with pytest.raises(PlanError, match="attached"):
        AWSDeleteOrphanedVolumeFixer().plan({"resource": "vol-0abc", "issue": "orphaned"}, {}, creds=creds,
                                            env=_dev_env(aws_env))


def test_aws_prod_volume_delete_rejected_even_with_approval_config(tmp_path):
    _, pub = _keypair(tmp_path)
    env = aws_env("prod", approval={"approvers": ["bob"], "threshold": 5})
    cfg = parse_config(config_doc({"prod": env}, approvers={"bob": {"public_key": pub}}, policy=PROD_POLICY,
                                  sink=S3, tmp=tmp_path))
    session, ec2 = _ec2_session(describe_volumes={"Volumes": [{"Size": 8, "State": "available"}]})
    gate, _ = _gate(tmp_path, cfg, "aws", session, extra_engines=[FakeScanner()])
    issue = {"resource": "ebs vol-0abc", "issue": "orphaned volume", "region": "us-east-1"}
    out = gated_apply(gate, AWSDeleteOrphanedVolumeFixer(), issue, {}, env_name="prod", requester="alice")
    assert not out.applied
    assert any(f.rule_id == "CCTL-DEL-001" and f.severity == Severity.CRITICAL for f in out.decision.findings)
    ec2.delete_volume.assert_not_called()


def test_aws_other_fixer_plans():
    env = _dev_env(aws_env)
    [stop] = AWSStopIdleInstanceFixer().plan({"resource": "ec2 i-0abc", "issue": "idle"}, {}, creds=None, env=env)
    assert stop.after["instance_state"] == "stopped" and stop.location == "us-east-1"
    [snap] = AWSDeleteOldSnapshotFixer().plan({"resource": "snap-0abc", "issue": "old"}, {}, creds=None, env=env)
    assert snap.action == Action.DELETE and snap.type == "aws_ebs_snapshot"
    [pab] = AWSS3PublicAccessFixer().plan({"resource": "s3/logs-bucket", "issue": "public"}, {}, creds=None,
                                          env=env)
    assert pab.after["block_public_policy"] is True


# ── Azure ────────────────────────────────────────────────────────────────────

def _disk_issue(rg="rg-app"):
    return {"resource": f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Compute/disks/d1",
            "issue": "unattached disk", "account": SUB}


def test_azure_disk_delete_in_dev_is_medium_and_authorized(tmp_path, monkeypatch):
    gate, _ = _gate(tmp_path, _dev(tmp_path, azure_env), "azure")
    applied = []
    monkeypatch.setattr(AzureDeleteOrphanedDiskFixer, "apply",
                        lambda self, issue, fix, creds=None: applied.append(creds.scope["resource_group"]))
    out = gated_apply(gate, AzureDeleteOrphanedDiskFixer(), _disk_issue(), {}, env_name="dev", requester="alice")
    assert out.applied and applied == ["rg-app"]
    assert {f.rule_id: f.severity for f in out.decision.findings}["CCTL-DEL-002"] == Severity.MEDIUM


def test_azure_resource_group_outside_scope_rejected(tmp_path, monkeypatch):
    gate, _ = _gate(tmp_path, _dev(tmp_path, azure_env), "azure")
    monkeypatch.setattr(AzureDeleteOrphanedDiskFixer, "apply", lambda *a, **k: pytest.fail("applied"))
    out = gated_apply(gate, AzureDeleteOrphanedDiskFixer(), _disk_issue("rg-other"), {}, env_name="dev",
                      requester="alice")
    assert not out.applied and any(f.rule_id == "CCTL-SCOPE-001" for f in out.decision.findings)


def test_azure_other_subscription_is_a_plan_error(tmp_path):
    gate, _ = _gate(tmp_path, _dev(tmp_path, azure_env), "azure")
    issue = {**_disk_issue(), "account": "99999999-0000-0000-0000-000000000000"}
    out = gated_apply(gate, AzureDeleteOrphanedDiskFixer(), issue, {}, env_name=None, requester="alice")
    assert not out.applied


def test_azure_vm_deallocate_plan():
    rid = f"/subscriptions/{SUB}/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/vm1"
    [c] = AzureDeallocateIdleVMFixer().plan({"resource": rid, "issue": "idle vm"}, {}, creds=None,
                                            env=_dev_env(azure_env))
    assert c.address == rid and c.after["power_state"] == "deallocated" and c.cloud == "azure"


# ── GCP ──────────────────────────────────────────────────────────────────────

def test_gcp_firewall_delete_in_scope_authorized(tmp_path, monkeypatch):
    gate, _ = _gate(tmp_path, _dev(tmp_path, gcp_env), "gcp")
    calls = []
    monkeypatch.setattr(GCPOpenFirewallFixer, "apply",
                        lambda self, issue, fix, creds=None: calls.append(creds.scope["project_id"]))
    issue = {"resource": "firewalls/allow-all", "issue": "0.0.0.0/0 open", "account": "proj-app"}
    out = gated_apply(gate, GCPOpenFirewallFixer(), issue, {}, env_name="dev", requester="alice")
    assert out.applied and calls == ["proj-app"]


def test_gcp_other_project_rejected(tmp_path, monkeypatch):
    gate, _ = _gate(tmp_path, _dev(tmp_path, gcp_env), "gcp")
    monkeypatch.setattr(GCPOpenFirewallFixer, "apply", lambda *a, **k: pytest.fail("applied"))
    issue = {"resource": "firewalls/allow-all", "issue": "0.0.0.0/0 open", "account": "someone-else"}
    out = gated_apply(gate, GCPOpenFirewallFixer(), issue, {}, env_name="dev", requester="alice")
    assert not out.applied and any(f.rule_id == "CCTL-SCOPE-001" for f in out.decision.findings)


# ── AIFixer.apply routing ─────────────────────────────────────────────────────

def _bare_fixer():
    return AIFixer.__new__(AIFixer)


def test_aifixer_applies_nothing_without_gate_config(monkeypatch):
    monkeypatch.setattr(fixer_mod, "_default_gate", lambda: (_ for _ in ()).throw(ConfigError("no config")))
    proposals = [{"issue": SG_ISSUE, "fix": {"a": 1}, "approved": True, "applied": False}]
    out = _bare_fixer().apply(proposals)
    assert out[0]["applied"] is False and out[0]["gate"]["stage"] == "config"


def test_aifixer_skips_unapproved_and_records_decisions(tmp_path):
    session, ec2 = _ec2_session(describe_security_groups=OPEN_SG)
    gate, _ = _gate(tmp_path, _dev(tmp_path, aws_env), "aws", session)
    proposals = [{"issue": SG_ISSUE, "fix": {"a": 1}, "approved": True, "applied": False},
                 {"issue": SG_ISSUE, "fix": {"a": 1}, "approved": False, "applied": False}]
    out = _bare_fixer().apply(proposals, gate=gate, env_name="dev", requester="alice")
    assert out[0]["applied"] is True and out[0]["gate"]["outcome"] == "authorized"
    assert out[1]["applied"] is False and "gate" not in out[1]
    assert ec2.revoke_security_group_ingress.call_count == 1


def test_aifixer_pending_approval_does_not_apply(tmp_path):
    _, pub = _keypair(tmp_path)
    env = aws_env("prod", approval={"approvers": ["bob"], "threshold": 0})
    cfg = parse_config(config_doc({"prod": env}, approvers={"bob": {"public_key": pub}}, policy=PROD_POLICY,
                                  sink=S3, tmp=tmp_path))
    session, ec2 = _ec2_session(describe_security_groups=OPEN_SG)
    gate, _ = _gate(tmp_path, cfg, "aws", session)
    proposals = [{"issue": SG_ISSUE, "fix": {"a": 1}, "approved": True, "applied": False}]
    out = _bare_fixer().apply(proposals, gate=gate, env_name="prod", requester="alice")
    assert out[0]["applied"] is False and out[0]["gate"]["outcome"] == "pending_approval"
    ec2.revoke_security_group_ingress.assert_not_called()
    assert AWS_ACCT in str(cfg.environment("prod").scope)

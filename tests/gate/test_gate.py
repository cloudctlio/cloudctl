"""The five-stage gate end to end, offline.

Credentials come from a fake broker, plans from a fake planner, and the
policy stage runs the real built-in Rego rules (regopy) plus small fake
engines. The audit log is the real hash-chained local file.
"""
import pytest

pytest.importorskip("regopy")
pytest.importorskip("cedarpy")
pytest.importorskip("cryptography")

from cloudctl.gate.approval.signing import generate_keypair, load_private_key, sign, write_private_key  # noqa: E402
from cloudctl.gate.audit import AuditLog, LocalFileSink  # noqa: E402
from cloudctl.gate.config import parse_config  # noqa: E402
from cloudctl.gate.gate import PolicyGate  # noqa: E402
from cloudctl.gate.models import (  # noqa: E402
    Action, AuditError, ChangeRequest, CredentialError, EngineError, Finding, GateError, Outcome, ResourceChange,
    Severity,
)
from cloudctl.gate.policy.rego import RegoEngine  # noqa: E402
from tests.gate.conftest import (  # noqa: E402
    FakeCredsBroker, FakePlanner, aws_env, azure_env, config_doc, gcp_env, sg_change, tag_change,
)

S3 = {"type": "s3", "bucket": "audit", "region": "us-east-1", "retain_days": 400}
PROD_POLICY = {"engines": {"checkov": {"enabled": True, "version": "3.4.6"}}}


class FakeScanner:
    """Stands in for a baseline scanner (checkov) that ran and found nothing."""

    def __init__(self, name="checkov", findings=(), fail=None):
        self.name, self._findings, self.fail, self.last_detail = name, list(findings), fail, ""

    def applies_to(self, ctx):
        return True

    def evaluate(self, ctx):
        if self.fail:
            raise self.fail
        return list(self._findings)


def _rego():
    return RegoEngine.from_config(builtin=True, rule_paths=[], rego_paths=[], params={})


def _audit(tmp_path):
    return AuditLog(LocalFileSink(tmp_path / "audit" / "chain.jsonl"), chain="test", actor="alice")


def _events(audit):
    return [r["event"] for r in audit.sink.read_all()]


def _gate(tmp_path, cfg, cloud="aws", engines=None, broker=None):
    audit = _audit(tmp_path)
    broker = broker or FakeCredsBroker(cloud)
    gate = PolicyGate(cfg, audit=audit, brokers={cloud: broker},
                      policy=([], engines if engines is not None else [_rego()]))
    return gate, broker


def _req(env="dev", requester="alice", summary="change"):
    return ChangeRequest(kind="api_action", environment=env, summary=summary, requester=requester)


def _dev_cfg(tmp_path, envf=aws_env):
    return parse_config(config_doc({"dev": envf()}, tmp=tmp_path))


def _prod_cfg(tmp_path, pub, envf=aws_env, approvers=("bob",)):
    env = envf("prod", approval={"approvers": list(approvers), "threshold": 1})
    return parse_config(config_doc({"prod": env}, approvers={a: {"public_key": pub} for a in approvers},
                                   policy=PROD_POLICY, sink=S3, tmp=tmp_path))


def _keypair(tmp_path, name="bob"):
    pem, pub = generate_keypair()
    path = tmp_path / f"{name}.pem"
    write_private_key(path, pem)
    return path, pub


# ── happy path ──────────────────────────────────────────────────────────────

def test_dev_change_is_authorized_and_executes_once(tmp_path):
    gate, broker = _gate(tmp_path, _dev_cfg(tmp_path))
    res = gate.evaluate(_req(), FakePlanner([tag_change(1)]))
    assert res.authorized and res.decision.outcome == Outcome.AUTHORIZED
    assert res.decision.plan_counts == {"add": 0, "modify": 1, "destroy": 0}
    creds = broker.issued[0]
    seen = {}

    def apply(c, plan):
        seen["token"] = c.client("env")["FAKE_TOKEN"]
        seen["changes"] = len(plan.changes)
        return {"ok": True}

    with res.authorization as auth:
        assert auth.execute(apply, what="test.apply") == {"ok": True}
        with pytest.raises(GateError, match="already used"):
            auth.execute(apply)
    assert seen == {"token": f"tok-{res.decision.request_id}", "changes": 1}
    with pytest.raises(CredentialError):
        creds.ensure_valid()        # destroyed after use
    ev = _events(gate.audit)
    assert ev == ["gate.request", "gate.credentials", "gate.plan", "gate.policy", "gate.decision",
                  "execution.start", "execution.end"]
    assert gate.audit.verify().ok


def test_failed_execution_is_audited_and_creds_destroyed(tmp_path):
    gate, broker = _gate(tmp_path, _dev_cfg(tmp_path))
    res = gate.evaluate(_req(), FakePlanner([tag_change(1)]))

    def boom(c, p):
        raise RuntimeError("api down")

    with pytest.raises(RuntimeError):
        res.authorization.execute(boom)
    last = list(gate.audit.sink.read_all())[-1]
    assert last["event"] == "execution.end" and last["data"]["ok"] is False
    with pytest.raises(CredentialError):
        broker.issued[0].ensure_valid()


@pytest.mark.parametrize("envf,cloud", [(aws_env, "aws"), (azure_env, "azure"), (gcp_env, "gcp")])
def test_every_cloud_goes_through_the_same_stages(tmp_path, envf, cloud):
    change = ResourceChange(address="x.y", type="tagged_thing", action=Action.UPDATE, cloud=cloud,
                            before={"tags": {}}, after={"tags": {"a": "b"}})
    gate, broker = _gate(tmp_path, _dev_cfg(tmp_path, envf), cloud=cloud)
    res = gate.evaluate(_req(), FakePlanner([change]))
    assert res.authorized, res.decision.reasons
    res.authorization.close()
    assert broker.issued[0].cloud == cloud


# ── rejections ──────────────────────────────────────────────────────────────

def test_high_finding_rejects_and_destroys_creds(tmp_path):
    gate, broker = _gate(tmp_path, _dev_cfg(tmp_path))
    res = gate.evaluate(_req(), FakePlanner([sg_change(cidr="0.0.0.0/0", port=22)]))
    assert not res.authorized and res.decision.outcome == Outcome.REJECTED
    assert res.decision.stage == "approval"
    assert any(f.rule_id == "CCTL-NET-001" and f.severity == Severity.HIGH for f in res.decision.findings)
    with pytest.raises(CredentialError):
        broker.issued[0].ensure_valid()


def test_credential_failure_rejects(tmp_path):
    gate, _ = _gate(tmp_path, _dev_cfg(tmp_path), broker=FakeCredsBroker("aws", fail=CredentialError("no role")))
    res = gate.evaluate(_req(), FakePlanner([tag_change(1)]))
    assert res.decision.stage == "credentials" and "no role" in res.decision.reasons[0]


def test_empty_plan_and_wrong_environment_reject(tmp_path):
    gate, _ = _gate(tmp_path, _dev_cfg(tmp_path))
    assert gate.evaluate(_req(), FakePlanner([])).decision.reasons == ("the plan changes nothing",)
    res = gate.evaluate(_req(), FakePlanner([tag_change(1)], env_name="other"))
    assert res.decision.stage == "plan" and "not 'dev'" in res.decision.reasons[0]


def test_unknown_environment_rejects(tmp_path):
    gate, _ = _gate(tmp_path, _dev_cfg(tmp_path))
    res = gate.evaluate(_req(env="nope"), FakePlanner([tag_change(1)]))
    assert res.decision.outcome == Outcome.REJECTED and res.decision.stage == "config"


def test_engine_failure_fails_closed(tmp_path):
    gate, _ = _gate(tmp_path, _dev_cfg(tmp_path), engines=[FakeScanner(fail=EngineError("checkov crashed"))])
    res = gate.evaluate(_req(), FakePlanner([tag_change(1)]))
    assert res.decision.stage == "policy" and "fail closed" in res.decision.reasons[0]


def test_engine_returning_garbage_fails_closed(tmp_path):
    class Bad(FakeScanner):
        def evaluate(self, ctx):
            return ["not a finding"]

    gate, _ = _gate(tmp_path, _dev_cfg(tmp_path), engines=[Bad()])
    assert gate.evaluate(_req(), FakePlanner([tag_change(1)])).decision.stage == "policy"


def test_audit_failure_fails_closed(tmp_path):
    class BrokenSink:
        name = "broken"

        def head(self):
            raise AuditError("disk gone")

    gate = PolicyGate(_dev_cfg(tmp_path), audit=AuditLog(BrokenSink(), chain="t"),
                      brokers={"aws": FakeCredsBroker("aws")}, policy=([], [_rego()]))
    res = gate.evaluate(_req(), FakePlanner([tag_change(1)]))
    assert not res.authorized and res.decision.stage == "audit"


# ── prod ────────────────────────────────────────────────────────────────────

def test_prod_needs_a_baseline_scanner_to_have_run(tmp_path):
    _, pub = _keypair(tmp_path)
    gate, _ = _gate(tmp_path, _prod_cfg(tmp_path, pub))
    planner = FakePlanner([tag_change(1), tag_change(2)], platform="terraform")
    res = gate.evaluate(_req(env="prod"), planner)
    assert res.decision.stage == "policy" and "baseline scanner" in res.decision.reasons[0]


def test_prod_rejects_automated_delete_of_stateful_data(tmp_path):
    _, pub = _keypair(tmp_path)
    gate, _ = _gate(tmp_path, _prod_cfg(tmp_path, pub), engines=[_rego(), FakeScanner()])
    vol = ResourceChange(address="ebs/vol-1", type="aws_ebs_volume", action=Action.DELETE, cloud="aws",
                         location="us-east-1", before={"size": 10}, after=None)
    res = gate.evaluate(_req(env="prod"), FakePlanner([vol]))
    assert res.decision.outcome == Outcome.REJECTED
    assert any(f.rule_id == "CCTL-DEL-001" and f.severity == Severity.CRITICAL for f in res.decision.findings)


def test_prod_approval_round_trip(tmp_path):
    key_path, pub = _keypair(tmp_path)
    cfg = _prod_cfg(tmp_path, pub)
    gate, _ = _gate(tmp_path, cfg, engines=[_rego(), FakeScanner()])
    changes = [tag_change(1), tag_change(2), tag_change(3)]

    first = gate.evaluate(_req(env="prod"), FakePlanner(changes, platform="terraform"))
    assert first.decision.outcome == Outcome.PENDING_APPROVAL and not first.authorized
    rid = first.decision.request_id
    stored = gate.approvals.get_request(rid)
    assert stored.plan_digest == first.decision.plan_digest and stored.requester == "alice"

    # not signed yet
    res = gate.evaluate(_req(env="prod"), FakePlanner(changes, platform="terraform"), approval_id=rid)
    assert res.decision.stage == "approval" and "not been approved" in res.decision.reasons[0]

    gate.approvals.put_approval(sign(stored, "bob", load_private_key(key_path)))
    ok = gate.evaluate(_req(env="prod"), FakePlanner(changes, platform="terraform"), approval_id=rid)
    assert ok.authorized and ok.decision.approver == "bob"
    ok.authorization.close()

    again = gate.evaluate(_req(env="prod"), FakePlanner(changes, platform="terraform"), approval_id=rid)
    assert not again.authorized and "already used" in again.decision.reasons[0]
    assert "gate.approval.verified" in _events(gate.audit)


def test_prod_approval_bound_to_exact_plan_and_requester(tmp_path):
    key_path, pub = _keypair(tmp_path)
    gate, _ = _gate(tmp_path, _prod_cfg(tmp_path, pub), engines=[_rego(), FakeScanner()])
    changes = [tag_change(1), tag_change(2)]
    rid = gate.evaluate(_req(env="prod"), FakePlanner(changes, platform="terraform")).decision.request_id
    gate.approvals.put_approval(sign(gate.approvals.get_request(rid), "bob", load_private_key(key_path)))

    more = gate.evaluate(_req(env="prod"), FakePlanner(changes + [tag_change(3)], platform="terraform"),
                         approval_id=rid)
    assert not more.authorized and "digest mismatch" in more.decision.reasons[0]
    other = gate.evaluate(_req(env="prod", requester="mallory"), FakePlanner(changes, platform="terraform"),
                          approval_id=rid)
    assert not other.authorized and "requested by 'alice'" in other.decision.reasons[0]


def test_prod_signature_by_wrong_key_rejected(tmp_path):
    _, pub = _keypair(tmp_path)
    evil_path, _ = _keypair(tmp_path, name="evil")
    gate, _ = _gate(tmp_path, _prod_cfg(tmp_path, pub), engines=[_rego(), FakeScanner()])
    changes = [tag_change(1), tag_change(2)]
    rid = gate.evaluate(_req(env="prod"), FakePlanner(changes, platform="terraform")).decision.request_id
    gate.approvals.put_approval(sign(gate.approvals.get_request(rid), "bob", load_private_key(evil_path)))
    res = gate.evaluate(_req(env="prod"), FakePlanner(changes, platform="terraform"), approval_id=rid)
    assert not res.authorized and "does not verify" in res.decision.reasons[0]


def test_prod_self_approval_refused_by_cedar(tmp_path):
    key_path, pub = _keypair(tmp_path, name="alice")
    gate, _ = _gate(tmp_path, _prod_cfg(tmp_path, pub, approvers=("alice",)), engines=[_rego(), FakeScanner()])
    changes = [tag_change(1), tag_change(2)]
    rid = gate.evaluate(_req(env="prod"), FakePlanner(changes, platform="terraform")).decision.request_id
    gate.approvals.put_approval(sign(gate.approvals.get_request(rid), "alice", load_private_key(key_path)))
    res = gate.evaluate(_req(env="prod"), FakePlanner(changes, platform="terraform"), approval_id=rid)
    assert not res.authorized and "not authorized" in res.decision.reasons[0]


def test_medium_findings_do_not_block(tmp_path):
    med = Finding(rule_id="X-1", severity=Severity.MEDIUM, message="m", engine="checkov")
    gate, _ = _gate(tmp_path, _dev_cfg(tmp_path), engines=[FakeScanner(findings=[med])])
    res = gate.evaluate(_req(), FakePlanner([tag_change(1)]))
    assert res.authorized and [f.rule_id for f in res.decision.findings] == ["X-1"]
    res.authorization.close()

"""CLI policy engines (Trivy, Checkov, cfn-guard, Kyverno, Infracost, OPA).

The real binaries are not installed in this test environment. Each adapter
runs against a fake binary on PATH that prints sample output in the tool's
documented JSON format, so these tests prove the command line we build, the
version pin, exit-code handling and the mapping into the gate's findings —
not the tools' own check content.
"""
import json
import os
import stat

import pytest

from cloudctl.gate.config import parse_config
from cloudctl.gate.models import Action, ChangeRequest, EngineError, Plan, ResourceChange, Severity
from cloudctl.gate.policy.cost import InfracostEnricher, parse_infracost
from cloudctl.gate.policy.engine import PolicyContext
from cloudctl.gate.policy.scanners import (
    CfnGuardEngine, CheckovEngine, KyvernoEngine, TrivyEngine, parse_cfn_guard, parse_checkov, parse_kyverno,
    parse_trivy,
)
from tests.gate.conftest import aws_env, config_doc

TRIVY = {"Results": [{"Target": "main.tf", "Misconfigurations": [
    {"AVDID": "AVD-AWS-0107", "Status": "FAIL", "Severity": "CRITICAL", "Message": "SG allows 0.0.0.0/0 on 22",
     "Resolution": "Restrict ingress", "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0107",
     "CauseMetadata": {"Resource": "aws_security_group.ssh"}},
    {"AVDID": "AVD-AWS-0086", "Status": "PASS", "Severity": "HIGH"}]}]}
CHECKOV = [{"check_type": "terraform_plan", "results": {"failed_checks": [
    {"check_id": "CKV_AWS_24", "check_name": "Ensure no SG allows ingress from 0.0.0.0/0 to port 22",
     "resource": "aws_security_group.ssh", "guideline": "https://docs.prismacloud.io/x", "severity": None},
    {"check_id": "CKV_AWS_18", "check_name": "Ensure S3 access logging", "resource": "aws_s3_bucket.b"}]}},
    {"check_type": "secrets", "summary": {"passed": 0, "failed": 0}}]
GUARD = {"name": "template.yaml", "status": "FAIL", "not_compliant": [{"Rule": {
    "name": "S3_BUCKET_SSL_REQUESTS_ONLY", "checks": [{"Clause": {"Unary": {"check": {"UnResolved": {
        "value": {"path": "/Resources/Logs/Properties"}}}, "context": "x",
        "custom_message": "Bucket must deny non-TLS requests"}}}]}}]}
KYVERNO = """apiVersion: wgpolicyk8s.io/v1alpha2
kind: PolicyReport
results:
- policy: disallow-privileged
  rule: privileged-containers
  result: fail
  severity: high
  message: Privileged mode is disallowed
  resources:
  - kind: Deployment
    namespace: shop
    name: web
- policy: require-labels
  rule: team
  result: pass
"""
INFRACOST = {"currency": "USD", "totalMonthlyCost": "150.5", "pastTotalMonthlyCost": "100",
             "diffTotalMonthlyCost": "50.5"}


def test_parsers_map_into_gate_findings():
    t = parse_trivy(TRIVY)
    assert [(f.rule_id, f.severity, f.resource) for f in t] == [("AVD-AWS-0107", Severity.CRITICAL,
                                                                  "aws_security_group.ssh")]
    c = parse_checkov(CHECKOV, severity_map={"CKV_AWS_24": Severity.HIGH})
    assert {(f.rule_id, f.severity) for f in c} == {("CKV_AWS_24", Severity.HIGH), ("CKV_AWS_18", Severity.MEDIUM)}
    g = parse_cfn_guard(json.dumps(GUARD))
    assert [(f.rule_id, f.resource, f.message) for f in g] == [
        ("S3_BUCKET_SSL_REQUESTS_ONLY", "Logs", "Bucket must deny non-TLS requests")]
    k = parse_kyverno(KYVERNO)
    assert [(f.rule_id, f.severity, f.resource) for f in k] == [
        ("disallow-privileged/privileged-containers", Severity.HIGH, "Deployment/shop/web")]
    cost = parse_infracost(INFRACOST)
    assert cost["monthly_delta_usd"] == 50.5 and cost["estimated"]


@pytest.mark.parametrize("fn,bad", [(parse_trivy, []), (parse_checkov, [{"nothing": 1}]),
                                    (parse_kyverno, ""), (parse_cfn_guard, "not json"),
                                    (parse_infracost, {"currency": "EUR", "totalMonthlyCost": "1"}),
                                    (parse_infracost, {})])
def test_unreadable_output_fails_closed(fn, bad):
    with pytest.raises(EngineError):
        fn(bad)


def _fake(tmp_path, name, script):
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_text("#!/bin/sh\n" + script)
    f.chmod(f.stat().st_mode | stat.S_IEXEC)
    return d


def _ctx(tmp_path, platform="terraform", artifacts=None):
    env = parse_config(config_doc({"dev": aws_env()})).environment("dev")
    plan = Plan(platform=platform, environment="dev", artifacts=artifacts or {},
                changes=(ResourceChange(address="a.b", type="aws_instance", action=Action.UPDATE, cloud="aws"),))
    return PolicyContext(plan=plan, env=env, request=ChangeRequest(kind="iac_pr", environment="dev",
                                                                   summary="t", requester="me"))


def _with_path(monkeypatch, d):
    monkeypatch.setenv("PATH", f"{d}{os.pathsep}{os.environ['PATH']}")


@pytest.mark.posix_only
def test_trivy_adapter_runs_with_pin_and_no_cloud_creds(tmp_path, monkeypatch):
    out = tmp_path / "trivy.json"
    out.write_text(json.dumps(TRIVY))
    log = tmp_path / "argv"
    d = _fake(tmp_path, "trivy", f"""
if [ "$1" = "--version" ]; then echo "Version: 0.76.2"; exit 0; fi
echo "$@ KEY=${{AWS_SECRET_ACCESS_KEY:-none}}" > {log}
cat {out}
""")
    _with_path(monkeypatch, d)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak")
    root = tmp_path / "iac"
    root.mkdir()
    eng = TrivyEngine.from_params({"version": "0.76.2", "skip_check_update": True})
    ctx = _ctx(tmp_path, artifacts={"iac_root": str(root)})
    assert eng.applies_to(ctx)
    got = eng.evaluate(ctx)
    assert got[0].rule_id == "AVD-AWS-0107"
    argv = log.read_text()
    assert "config --format json --quiet --exit-code 0 --skip-check-update" in argv and "KEY=none" in argv
    with pytest.raises(EngineError, match="version mismatch"):
        TrivyEngine.from_params({"version": "0.50.0"}).evaluate(ctx)


@pytest.mark.posix_only
def test_checkov_adapter_scans_the_plan_json(tmp_path, monkeypatch):
    out = tmp_path / "ck.json"
    out.write_text(json.dumps(CHECKOV))
    log = tmp_path / "argv"
    d = _fake(tmp_path, "checkov", f"""
if [ "$1" = "--version" ]; then echo "3.4.6"; exit 0; fi
echo "$@ MAP=$BC_SKIP_MAPPING" > {log}
cat {out}
""")
    _with_path(monkeypatch, d)
    plan_json = tmp_path / "plan.json"
    plan_json.write_text("{}")
    eng = CheckovEngine.from_params({"version": "3.4.6", "severity_map": {"CKV_AWS_24": "HIGH"}})
    got = eng.evaluate(_ctx(tmp_path, artifacts={"terraform_plan_json": str(plan_json)}))
    assert {f.rule_id for f in got} == {"CKV_AWS_24", "CKV_AWS_18"}
    argv = log.read_text()
    assert f"-f {plan_json} --framework terraform_plan -o json" in argv
    assert "--skip-download" in argv and "MAP=TRUE" in argv


@pytest.mark.posix_only
def test_cfn_guard_adapter_exit_codes(tmp_path, monkeypatch):
    out = tmp_path / "g.json"
    out.write_text(json.dumps(GUARD))
    d = _fake(tmp_path, "cfn-guard", f"cat {out}; exit 19\n")
    _with_path(monkeypatch, d)
    rules = tmp_path / "rules.guard"
    rules.write_text("")
    tpl = tmp_path / "t.json"
    tpl.write_text("{}")
    eng = CfnGuardEngine.from_params({"rules": str(rules)})
    ctx = _ctx(tmp_path, platform="cloudformation", artifacts={"template:app": str(tpl)})
    assert eng.applies_to(ctx)
    assert eng.evaluate(ctx)[0].rule_id == "S3_BUCKET_SSL_REQUESTS_ONLY"
    _fake(tmp_path, "cfn-guard", "echo boom >&2; exit 5\n")
    with pytest.raises(EngineError, match="exited 5|exit"):
        eng.evaluate(ctx)


@pytest.mark.posix_only
def test_kyverno_adapter(tmp_path, monkeypatch):
    out = tmp_path / "k.yaml"
    out.write_text(KYVERNO)
    d = _fake(tmp_path, "kyverno", f"cat {out}; exit 1\n")
    _with_path(monkeypatch, d)
    pol = tmp_path / "policies"
    pol.mkdir()
    man = tmp_path / "manifests"
    man.mkdir()
    eng = KyvernoEngine.from_params({"policies": str(pol)})
    got = eng.evaluate(_ctx(tmp_path, platform="kubernetes", artifacts={"k8s_manifests": str(man)}))
    assert got[0].severity == Severity.HIGH


@pytest.mark.posix_only
def test_infracost_needs_a_key_and_sets_cost_facts(tmp_path, monkeypatch):
    out = tmp_path / "i.json"
    out.write_text(json.dumps(INFRACOST))
    d = _fake(tmp_path, "infracost", f"cat {out}\n")
    _with_path(monkeypatch, d)
    plan_json = tmp_path / "plan.json"
    plan_json.write_text("{}")
    ctx = _ctx(tmp_path, artifacts={"terraform_plan_json": str(plan_json)})
    enr = InfracostEnricher.from_params({})
    monkeypatch.delenv("INFRACOST_API_KEY", raising=False)
    with pytest.raises(EngineError, match="INFRACOST_API_KEY"):
        enr.enrich(ctx)
    monkeypatch.setenv("INFRACOST_API_KEY", "ico-test")
    enr.enrich(ctx)
    assert ctx.facts["cost"]["monthly_delta_usd"] == 50.5


def test_missing_binary_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    plan_json = tmp_path / "plan.json"
    plan_json.write_text("{}")
    with pytest.raises(EngineError, match="not installed"):
        CheckovEngine.from_params({}).evaluate(_ctx(tmp_path, artifacts={"terraform_plan_json": str(plan_json)}))


def test_scanner_config_errors():
    with pytest.raises(EngineError):
        CfnGuardEngine.from_params({})
    with pytest.raises(EngineError):
        KyvernoEngine.from_params({})
    with pytest.raises(EngineError):
        CheckovEngine.from_params({"severity_map": {"X": "BAD"}})
    with pytest.raises(EngineError):
        TrivyEngine.from_params({"extra_args": "--oops"})


@pytest.mark.posix_only
def test_opa_binary_backend_restricts_capabilities(tmp_path, monkeypatch):
    from cloudctl.gate.policy.rego import OpaBinaryBackend
    caps = {"builtins": [{"name": "http.send"}, {"name": "concat"}, {"name": "time.now_ns"}], "allow_net": ["*"]}
    capsf = tmp_path / "caps.json"
    capsf.write_text(json.dumps(caps))
    log = tmp_path / "argv"
    d = _fake(tmp_path, "opa", f"""
case "$1" in
  version) echo "Version: 1.22.4";;
  capabilities) /bin/cat {capsf};;
  eval) for a in "$@"; do case "$a" in */caps.json) /bin/cp "$a" {tmp_path}/used_caps.json;; esac; done
        echo "$@" > {log}
        echo '{{"result":[{{"expressions":[{{"value":{{"rules":{{}}}}}}]}}]}}';;
esac
""")
    b = OpaBinaryBackend(binary_path=str(d / "opa"), pinned_version="1.22.4")
    assert b.evaluate({"m": "package cloudctl.x"}, {"a": 1}, "data.cloudctl") == {"rules": {}}
    used = json.loads((tmp_path / "used_caps.json").read_text())
    assert [x["name"] for x in used["builtins"]] == ["concat"] and used["allow_net"] == []
    assert "--strict-builtin-errors" in log.read_text()
    with pytest.raises(EngineError, match="version mismatch"):
        OpaBinaryBackend(binary_path=str(d / "opa"), pinned_version="0.60.0")

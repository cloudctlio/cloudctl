"""Rego core engine (regopy, in process): built-in rules on AWS, Azure and
GCP plans, custom YAML rules and Conftest-style packs, fail-closed errors."""
import json

import pytest

pytest.importorskip("regopy")

from cloudctl.gate.config import parse_config  # noqa: E402
from cloudctl.gate.models import Action, ChangeRequest, EngineError, Plan, ResourceChange, Severity  # noqa: E402
from cloudctl.gate.policy.engine import PolicyContext, evaluate_policy  # noqa: E402
from cloudctl.gate.policy.rego import RegoEngine, make_backend  # noqa: E402
from tests.gate.conftest import AWS_ACCT, SUB, aws_env, azure_env, config_doc, gcp_env  # noqa: E402

PUB = "MCowBQYDK2VwAyEAplaceholderplaceholderplaceholderxx="


@pytest.fixture(scope="module")
def cfg():
    return parse_config(config_doc(
        {"dev": aws_env(cost={"max_monthly_increase_usd": 100}),
         "az": azure_env(), "gp": gcp_env(),
         "prod": aws_env("prod", approval={"approvers": ["alice"]},
                         cost={"max_model_cost_usd": 1.0})},
        approvers={"alice": {"public_key": PUB}},
        sink={"type": "s3", "bucket": "b", "region": "us-east-1", "retain_days": 1},
        policy={"engines": {"checkov": {"enabled": True, "version": "3.4.6"}}}))


@pytest.fixture(scope="module")
def engine():
    return RegoEngine.from_config(builtin=True, rule_paths=[], rego_paths=[], params={})


def run(cfg, engine, env_name, changes, *, context=None, cost=None, platform="terraform"):
    env = cfg.environment(env_name)
    plan = Plan(platform=platform, environment=env_name, changes=tuple(changes))
    req = ChangeRequest(kind="iac_apply", environment=env_name, summary="t", requester="me",
                        context=context or {})
    ctx = PolicyContext(plan=plan, env=env, request=req)
    if cost is not None:
        ctx.facts["cost"] = cost
    return {(f.rule_id, f.resource): f for f in evaluate_policy(ctx, enrichers=[], engines=[engine]).findings}


def rc(address, type_, cloud, action=Action.CREATE, after=None, before=None):
    return ResourceChange(address=address, type=type_, action=action, cloud=cloud, after=after, before=before)


ADMIN = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})


def test_aws_rules(cfg, engine):
    got = run(cfg, engine, "dev", [
        rc("aws_security_group.ssh", "aws_security_group", "aws",
           after={"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}),
        rc("aws_security_group.web", "aws_security_group", "aws",
           after={"ingress": [{"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}]}),
        rc("aws_iam_policy.admin", "aws_iam_policy", "aws", after={"policy": ADMIN}),
        rc("aws_db_instance.db", "aws_db_instance", "aws", Action.DELETE, before={}),
        rc("aws_s3_bucket.eu", "aws_s3_bucket", "aws", after={"region": "eu-west-1"}),
        rc("google_storage_bucket.g", "google_storage_bucket", "gcp", after={}),
    ], context={"model_cost_usd": 3})
    assert ("CCTL-NET-001", "aws_security_group.ssh") in got
    assert ("CCTL-NET-001", "aws_security_group.web") not in got          # 443 to the world is allowed
    assert got[("CCTL-IAM-001", "aws_iam_policy.admin")].severity == Severity.HIGH
    assert got[("CCTL-DEL-002", "aws_db_instance.db")].severity == Severity.MEDIUM   # non-prod delete
    assert got[("CCTL-SCOPE-001", "aws_s3_bucket.eu")].severity == Severity.CRITICAL  # other region
    assert got[("CCTL-SCOPE-002", "google_storage_bucket.g")].severity == Severity.CRITICAL
    assert ("CCTL-COST-002", "") in got                                  # limit set, cost unknown


def test_prod_delete_of_stateful_resource_is_critical(cfg, engine):
    got = run(cfg, engine, "prod", [rc("aws_db_instance.db", "aws_db_instance", "aws", Action.DELETE, before={})],
              context={"model_cost_usd": 0.1})
    assert got[("CCTL-DEL-001", "aws_db_instance.db")].severity == Severity.CRITICAL


def test_azure_rules(cfg, engine):
    got = run(cfg, engine, "az", [
        rc("azurerm_network_security_rule.rdp", "azurerm_network_security_rule", "azure",
           after={"direction": "Inbound", "access": "Allow", "source_address_prefix": "*",
                  "destination_port_range": "3389", "resource_group_name": "rg-app"}),
        rc("azurerm_role_assignment.owner", "azurerm_role_assignment", "azure",
           after={"role_definition_name": "Owner", "scope": f"/subscriptions/{SUB}"}),
        rc("azurerm_storage_account.sa", "azurerm_storage_account", "azure",
           after={"resource_group_name": "other-rg", "allow_nested_items_to_be_public": True,
                  "min_tls_version": "TLS1_0"}),
    ])
    assert ("CCTL-NET-001", "azurerm_network_security_rule.rdp") in got
    assert ("CCTL-IAM-001", "azurerm_role_assignment.owner") in got
    assert ("CCTL-STG-001", "azurerm_storage_account.sa") in got
    assert ("CCTL-ENC-001", "azurerm_storage_account.sa") in got
    assert ("CCTL-SCOPE-001", "azurerm_storage_account.sa") in got        # another resource group


def test_azure_what_if_unsupported_is_flagged(cfg, engine):
    rid = f"/subscriptions/{SUB}/resourceGroups/rg-app/providers/Microsoft.Web/sites/app"
    got = run(cfg, engine, "az", [rc(rid, "Microsoft.Web/sites", "azure", Action.UPDATE,
                                     after={"_whatif_change_type": "Unsupported"})], platform="bicep")
    assert got[("CCTL-PLAN-001", rid)].severity == Severity.HIGH


def test_gcp_rules(cfg, engine):
    got = run(cfg, engine, "gp", [
        rc("google_compute_firewall.ssh", "google_compute_firewall", "gcp",
           after={"source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["22"]}],
                  "project": "proj-app"}),
        rc("google_project_iam_member.owner", "google_project_iam_member", "gcp",
           after={"role": "roles/owner", "member": "user:a@example.com", "project": "other-proj"}),
        rc("google_storage_bucket_iam_member.pub", "google_storage_bucket_iam_member", "gcp",
           after={"role": "roles/storage.objectViewer", "member": "allUsers"}),
    ])
    assert ("CCTL-NET-001", "google_compute_firewall.ssh") in got
    assert ("CCTL-IAM-001", "google_project_iam_member.owner") in got
    assert ("CCTL-SCOPE-001", "google_project_iam_member.owner") in got
    assert ("CCTL-IAM-002", "google_storage_bucket_iam_member.pub") in got


def test_cost_rules(cfg, engine):
    over = run(cfg, engine, "dev", [rc("aws_instance.big", "aws_instance", "aws", after={"region": "us-east-1"})],
               cost={"estimated": True, "monthly_delta_usd": 250.0, "currency": "USD", "source": "infracost"})
    assert ("CCTL-COST-001", "") in over and ("CCTL-COST-002", "") not in over
    under = run(cfg, engine, "dev", [rc("aws_instance.s", "aws_instance", "aws", after={"region": "us-east-1"})],
                cost={"estimated": True, "monthly_delta_usd": 5.0, "currency": "USD", "source": "infracost"})
    assert not any(k[0].startswith("CCTL-COST") for k in under)


def test_model_spend_rules(cfg, engine):
    ch = [rc("aws_instance.s", "aws_instance", "aws", Action.UPDATE, after={"region": "us-east-1"})]
    assert ("CCTL-COST-003", "") in run(cfg, engine, "prod", ch, context={"model_cost_usd": 2.5})
    assert ("CCTL-COST-004", "") in run(cfg, engine, "prod", ch, context={})
    ok = run(cfg, engine, "prod", ch, context={"model_cost_usd": 0.2})
    assert not any(k[0] in ("CCTL-COST-003", "CCTL-COST-004") for k in ok)


def test_custom_yaml_rule_and_rego_pack(cfg, tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("""rules:
  - id: ACME-TAG-001
    title: Team tag required
    severity: MEDIUM
    clouds: [aws]
    condition: |
      lib.mutating(change)
      not object.get(lib.attrs(change), "tags", {}).team
    message: "{resource} has no team tag."
    fix_hint: Add a team tag.
""")
    pack = tmp_path / "pack.rego"
    pack.write_text("""package cloudctl.packs.acme
import rego.v1
deny contains {"id": "ACME-NO-T2", "msg": "t2 instances are retired", "resource": c.address, "severity": "HIGH"} if {
  some c in input.plan.changes
  startswith(object.get(object.get(c, "after", {}), "instance_type", ""), "t2.")
}
warn contains "plan touches instances" if { some c in input.plan.changes; c.type == "aws_instance" }
""")
    eng = RegoEngine.from_config(builtin=False, rule_paths=[rules], rego_paths=[pack], params={})
    got = run(cfg, eng, "dev", [rc("aws_instance.a", "aws_instance", "aws",
                                   after={"instance_type": "t2.micro", "tags": {}})])
    assert got[("ACME-TAG-001", "aws_instance.a")].severity == Severity.MEDIUM
    assert got[("ACME-NO-T2", "aws_instance.a")].severity == Severity.HIGH
    assert got[("cloudctl.packs.acme", "")].severity == Severity.LOW


def test_rules_may_not_reach_the_network(tmp_path):
    pack = tmp_path / "evil.rego"
    pack.write_text('package cloudctl.packs.evil\nimport rego.v1\ndeny contains "x" if { http.send({"url": "https://x"}) }\n')
    with pytest.raises(EngineError, match="forbidden"):
        RegoEngine.from_config(builtin=False, rule_paths=[], rego_paths=[pack], params={})


def test_pack_package_must_be_namespaced(tmp_path):
    pack = tmp_path / "p.rego"
    pack.write_text("package other\nimport rego.v1\ndeny contains 1 if { true }\n")
    with pytest.raises(EngineError, match="cloudctl.packs"):
        RegoEngine.from_config(builtin=False, rule_paths=[], rego_paths=[pack], params={})


def test_bad_rule_files_fail_closed(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - id: lower-case\n    severity: HIGH\n    condition: 'true'\n    message: m\n    title: t\n")
    with pytest.raises(EngineError):
        RegoEngine.from_config(builtin=False, rule_paths=[bad], rego_paths=[], params={})


def test_regopy_version_pin_and_opa_backend_missing():
    with pytest.raises(EngineError, match="version mismatch"):
        make_backend({"version": "0.0.1"}).evaluate({}, {}, "data.cloudctl")
    with pytest.raises(EngineError):
        b = make_backend({"backend": "opa", "binary": "/nonexistent/opa"})
        b.evaluate({}, {}, "data.cloudctl")
    with pytest.raises(EngineError, match="unknown rego backend"):
        make_backend({"backend": "magic"})


def test_disabled_rules_and_severity_overrides(cfg, engine):
    env = cfg.environment("dev")
    plan = Plan(platform="terraform", environment="dev",
                changes=(rc("aws_iam_policy.admin", "aws_iam_policy", "aws", after={"policy": ADMIN}),))
    ctx = PolicyContext(plan=plan, env=env, request=ChangeRequest(kind="iac_apply", environment="dev",
                                                                  summary="t", requester="me"))
    r = evaluate_policy(ctx, enrichers=[], engines=[engine], disabled_rules=["CCTL-COST-002"],
                        severity_overrides={"CCTL-IAM-001": Severity.CRITICAL})
    ids = {f.rule_id: f.severity for f in r.findings}
    assert "CCTL-COST-002" not in ids and ids["CCTL-IAM-001"] == Severity.CRITICAL
    assert AWS_ACCT

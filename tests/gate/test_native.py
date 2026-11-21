"""Cloud-native policy checks (AWS Access Analyzer + SCP simulation, Azure
Policy checkPolicyRestrictions, GCP Organization Policy).

These run against mocked SDK clients only. They prove the requests we send
and how the answers map into findings, not the clouds' live behaviour.
"""
from unittest.mock import MagicMock

import pytest

from cloudctl.gate.config import parse_config
from cloudctl.gate.models import Action, ChangeRequest, EngineError, Plan, ResourceChange, Severity
from cloudctl.gate.policy.engine import PolicyContext
from cloudctl.gate.policy.native import (
    AwsNativeEngine, AzureNativeEngine, GcpNativeEngine, _location_allowed, azure_resource_content,
)
from tests.gate.conftest import AWS_ROLE, aws_env, azure_env, config_doc, gcp_env


def _ctx(env_doc, changes, creds=None):
    env = parse_config(config_doc({"dev": env_doc})).environment("dev")
    plan = Plan(platform="terraform", environment="dev", changes=tuple(changes))
    return PolicyContext(plan=plan, env=env, creds=creds,
                         request=ChangeRequest(kind="iac_pr", environment="dev", summary="t", requester="me"))


class _Paginator:
    def __init__(self, pages):
        self.pages = pages
        self.kwargs = None

    def paginate(self, **kw):
        self.kwargs = kw
        return iter(self.pages)


class _Creds:
    def __init__(self, obj, kind):
        self.obj, self.kind = obj, kind

    def client(self, kind):
        assert kind == self.kind
        return self.obj


def _aws_session(aa_pages=None, sim_pages=None):
    aa_pag, sim_pag = _Paginator(aa_pages or []), _Paginator(sim_pages or [])
    aa, iam = MagicMock(), MagicMock()
    aa.get_paginator.side_effect = lambda n: aa_pag if n == "validate_policy" else None
    iam.get_paginator.side_effect = lambda n: sim_pag if n == "simulate_principal_policy" else None
    session = MagicMock()
    session.client.side_effect = lambda svc: {"accessanalyzer": aa, "iam": iam}[svc]
    return session, aa_pag, sim_pag


# ── AWS ──────────────────────────────────────────────────────────────────────

def test_aws_needs_scoped_creds():
    ctx = _ctx(aws_env(), [ResourceChange(address="aws_instance.a", type="aws_instance", action=Action.CREATE,
                                          cloud="aws")])
    with pytest.raises(EngineError, match="scoped credentials"):
        AwsNativeEngine().evaluate(ctx)


def test_aws_access_analyzer_findings_mapped():
    session, aa_pag, _ = _aws_session(aa_pages=[{"findings": [
        {"findingType": "SECURITY_WARNING", "issueCode": "PASS_ROLE_WITH_STAR_IN_RESOURCE",
         "findingDetails": "iam:PassRole with *", "learnMoreLink": "https://docs.aws.amazon.com/x"},
        {"findingType": "SUGGESTION", "issueCode": "EMPTY_ARRAY_ACTION", "findingDetails": "empty"}]}])
    pol = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]}
    ch = ResourceChange(address="aws_iam_policy.p", type="aws_iam_policy", action=Action.CREATE, cloud="aws",
                        after={"policy": pol})
    eng = AwsNativeEngine()
    out = eng.evaluate(_ctx(aws_env(), [ch], _Creds(session, "session")))
    assert aa_pag.kwargs["policyType"] == "IDENTITY_POLICY"
    ids = {f.rule_id: f for f in out}
    assert ids["AWS-AA-PASS_ROLE_WITH_STAR_IN_RESOURCE"].severity == Severity.HIGH
    assert ids["AWS-AA-PASS_ROLE_WITH_STAR_IN_RESOURCE"].references == ("https://docs.aws.amazon.com/x",)
    assert ids["AWS-AA-EMPTY_ARRAY_ACTION"].severity == Severity.LOW
    assert "SCP simulation skipped" in eng.last_detail  # profile mode, no role


def test_aws_resource_policy_sets_resource_type():
    session, aa_pag, _ = _aws_session(aa_pages=[{"findings": []}])
    ch = ResourceChange(address="aws_s3_bucket_policy.b", type="aws_s3_bucket_policy", action=Action.UPDATE,
                        cloud="aws", after={"policy": '{"Version":"2012-10-17","Statement":[]}'})
    AwsNativeEngine(simulate_scps=False).evaluate(_ctx(aws_env(), [ch], _Creds(session, "session")))
    assert aa_pag.kwargs == {"policyDocument": '{"Version":"2012-10-17","Statement":[]}',
                             "policyType": "RESOURCE_POLICY", "validatePolicyResourceType": "AWS::S3::Bucket"}


def test_aws_scp_deny_is_critical_and_iam_deny_high():
    session, _, sim_pag = _aws_session(sim_pages=[{"EvaluationResults": [
        {"EvalActionName": "ec2:RunInstances", "EvalDecision": "explicitDeny",
         "OrganizationsDecisionDetail": {"AllowedByOrganizations": False}},
        {"EvalActionName": "ec2:CreateVpc", "EvalDecision": "implicitDeny",
         "OrganizationsDecisionDetail": {"AllowedByOrganizations": True}}]}])
    env = aws_env(credentials={"mode": "assume_role", "role_arn": AWS_ROLE})
    changes = [ResourceChange(address="aws_instance.a", type="aws_instance", action=Action.CREATE, cloud="aws",
                              location="eu-west-1"),
               ResourceChange(address="aws_vpc.v", type="aws_vpc", action=Action.CREATE, cloud="aws",
                              location="eu-west-1"),
               ResourceChange(address="aws_widget.w", type="aws_widget", action=Action.CREATE, cloud="aws")]
    eng = AwsNativeEngine(validate_policies=False)
    out = eng.evaluate(_ctx(env, changes, _Creds(session, "session")))
    assert sim_pag.kwargs["PolicySourceArn"] == AWS_ROLE
    assert sim_pag.kwargs["ActionNames"] == ["ec2:CreateVpc", "ec2:RunInstances"]
    assert sim_pag.kwargs["ContextEntries"][0]["ContextKeyValues"] == ["eu-west-1"]
    by = {f.resource: f for f in out}
    assert by["aws_instance.a"].rule_id == "AWS-SCP-DENY" and by["aws_instance.a"].severity == Severity.CRITICAL
    assert by["aws_vpc.v"].rule_id == "AWS-IAM-NOT-ALLOWED" and by["aws_vpc.v"].severity == Severity.HIGH
    assert "no SCP mapping for aws_widget" in eng.last_detail


def test_aws_api_errors_fail_closed():
    session = MagicMock()
    iam = MagicMock()
    iam.get_paginator.return_value.paginate.side_effect = RuntimeError("AccessDenied")
    session.client.return_value = iam
    env = aws_env(credentials={"mode": "assume_role", "role_arn": AWS_ROLE})
    ch = ResourceChange(address="aws_instance.a", type="aws_instance", action=Action.CREATE, cloud="aws")
    with pytest.raises(EngineError, match="SimulatePrincipalPolicy failed"):
        AwsNativeEngine(validate_policies=False).evaluate(_ctx(env, [ch], _Creds(session, "session")))


# ── Azure ────────────────────────────────────────────────────────────────────

def test_azure_resource_content_mapping():
    ch = ResourceChange(address="azurerm_storage_account.s", type="azurerm_storage_account", action=Action.CREATE,
                        cloud="azure", after={"location": "westeurope", "tags": {"team": "a"}})
    assert azure_resource_content(ch) == {"type": "Microsoft.Storage/storageAccounts", "location": "westeurope",
                                          "tags": {"team": "a"}}
    unknown = ResourceChange(address="azurerm_foo.f", type="azurerm_foo", action=Action.CREATE, cloud="azure")
    assert azure_resource_content(unknown) is None


def test_azure_noncompliant_and_field_restrictions():
    client = MagicMock()
    client.policy_restrictions.check_at_resource_group_scope.return_value = {
        "contentEvaluationResult": {"policyEvaluations": [
            {"evaluationResult": "NonCompliant", "policyInfo": {
                "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/allowed-locations",
                "policyAssignmentId": "/subscriptions/x/providers/Microsoft.Authorization/policyAssignments/loc"}},
            {"evaluationResult": "Compliant", "policyInfo": {"policyDefinitionId": "ok"}}]},
        "fieldRestrictions": [{"field": "location", "restrictions": [
            {"result": "Deny", "values": ["eastus", "westus"]}]}]}
    seen = {}

    def factory(ctx):
        seen["ctx"] = ctx
        return client

    ch = ResourceChange(address="azurerm_storage_account.s", type="azurerm_storage_account", action=Action.CREATE,
                        cloud="azure", after={"location": "westeurope"})
    skip = ResourceChange(address="azurerm_foo.f", type="azurerm_foo", action=Action.CREATE, cloud="azure")
    eng = AzureNativeEngine(client_factory=factory)
    out = eng.evaluate(_ctx(azure_env(), [ch, skip], creds=object()))
    rg, body = client.policy_restrictions.check_at_resource_group_scope.call_args.args
    assert rg == "rg-app"
    assert body["resourceDetails"]["resourceContent"]["type"] == "Microsoft.Storage/storageAccounts"
    ids = sorted(f.rule_id for f in out)
    assert ids == ["AZURE-POLICY-FIELD", "AZURE-POLICY:allowed-locations"]
    assert all(f.severity == Severity.HIGH for f in out)
    assert "no ARM mapping for azurerm_foo" in eng.last_detail


def test_azure_api_failure_fails_closed():
    client = MagicMock()
    client.policy_restrictions.check_at_resource_group_scope.side_effect = RuntimeError("403")
    ch = ResourceChange(address="azurerm_key_vault.k", type="azurerm_key_vault", action=Action.CREATE,
                        cloud="azure")
    with pytest.raises(EngineError, match="checkPolicyRestrictions failed"):
        AzureNativeEngine(client_factory=lambda c: client).evaluate(_ctx(azure_env(), [ch], creds=object()))


def test_azure_skips_deletes():
    ctx = _ctx(azure_env(), [ResourceChange(address="azurerm_key_vault.k", type="azurerm_key_vault",
                                            action=Action.DELETE, cloud="azure")], creds=object())
    assert not AzureNativeEngine().applies_to(ctx)


# ── GCP ──────────────────────────────────────────────────────────────────────

class _NotFound(Exception):
    def __init__(self):
        super().__init__("404")
        self.resp = type("R", (), {"status": 404})()


def _gcp_service(policies):
    """policies: constraint -> dict, or an Exception instance to raise."""
    svc = MagicMock()
    names = []

    def get(name):
        names.append(name)
        c = name.rsplit("/", 1)[-1]
        req = MagicMock()
        val = policies.get(c, _NotFound())
        if isinstance(val, Exception):
            req.execute.side_effect = val
        else:
            req.execute.return_value = val
        return req

    svc.projects.return_value.policies.return_value.getEffectivePolicy.side_effect = get
    return svc, names


def _rule(**kw):
    return {"spec": {"rules": [kw]}}


def test_gcp_location_and_external_ip_and_public_member():
    svc, names = _gcp_service({
        "gcp.resourceLocations": _rule(values={"allowedValues": ["in:us-locations"]}),
        "compute.vmExternalIpAccess": _rule(denyAll=True),
        "storage.publicAccessPrevention": _rule(enforce=True),
        "iam.allowedPolicyMemberDomains": _rule(values={"allowedValues": ["C0abc"]}),
    })
    vm = ResourceChange(address="google_compute_instance.vm", type="google_compute_instance", action=Action.CREATE,
                        cloud="gcp", location="europe-west1-b",
                        after={"network_interface": [{"access_config": [{}]}]})
    grant = ResourceChange(address="google_storage_bucket_iam_member.pub", type="google_storage_bucket_iam_member",
                           action=Action.CREATE, cloud="gcp", after={"member": "allUsers"})
    out = GcpNativeEngine(service_factory=lambda c: svc).evaluate(_ctx(gcp_env(), [vm, grant], creds=object()))
    assert names[0] == "projects/proj-app/policies/gcp.resourceLocations"
    ids = sorted((f.resource, f.rule_id) for f in out)
    assert ids == [("google_compute_instance.vm", "GCP-ORG-resourceLocations"),
                   ("google_compute_instance.vm", "GCP-ORG-vmExternalIpAccess"),
                   ("google_storage_bucket_iam_member.pub", "GCP-ORG-allowedPolicyMemberDomains"),
                   ("google_storage_bucket_iam_member.pub", "GCP-ORG-publicAccessPrevention")]
    assert all(f.severity == Severity.CRITICAL for f in out)


def test_gcp_404_means_no_policy_and_allowed():
    svc, _ = _gcp_service({})
    vm = ResourceChange(address="google_compute_instance.vm", type="google_compute_instance", action=Action.CREATE,
                        cloud="gcp", location="europe-west1-b",
                        after={"network_interface": [{"access_config": [{}]}]})
    assert GcpNativeEngine(service_factory=lambda c: svc).evaluate(_ctx(gcp_env(), [vm], creds=object())) == []


def test_gcp_unknown_value_group_is_medium_unverified():
    svc, _ = _gcp_service({"gcp.resourceLocations": _rule(values={"allowedValues": ["in:mystery-locations"]})})
    ch = ResourceChange(address="google_storage_bucket.b", type="google_storage_bucket", action=Action.CREATE,
                        cloud="gcp", after={"location": "us-central1"})
    eng = GcpNativeEngine(service_factory=lambda c: svc)
    out = eng.evaluate(_ctx(gcp_env(), [ch], creds=object()))
    assert [(f.rule_id, f.severity) for f in out] == [("GCP-ORG-resourceLocations-UNVERIFIED", Severity.MEDIUM)]
    assert "unknown value group" in eng.last_detail


def test_gcp_other_errors_fail_closed():
    svc, _ = _gcp_service({"gcp.resourceLocations": RuntimeError("PERMISSION_DENIED")})
    ch = ResourceChange(address="google_storage_bucket.b", type="google_storage_bucket", action=Action.CREATE,
                        cloud="gcp", after={"location": "us-central1"})
    with pytest.raises(EngineError, match="getEffectivePolicy"):
        GcpNativeEngine(service_factory=lambda c: svc).evaluate(_ctx(gcp_env(), [ch], creds=object()))


@pytest.mark.parametrize("loc,policy,expected", [
    ("us-central1", {}, True),
    ("us-central1", _rule(allowAll=True), True),
    ("us-central1", _rule(denyAll=True), False),
    ("us-east1", _rule(values={"allowedValues": ["in:us-locations"]}), True),
    ("europe-west1", _rule(values={"allowedValues": ["in:us-locations"]}), False),
    ("europe-west1", _rule(values={"deniedValues": ["in:europe-locations"]}), False),
    ("us-east1", _rule(values={"allowedValues": ["us-east1"]}), True),
    ("us-east1-b", _rule(values={"allowedValues": ["us-east1"]}), True),
    ("us-east1", _rule(values={"allowedValues": ["in:odd-locations"]}), None),
])
def test_gcp_location_matching(loc, policy, expected):
    assert _location_allowed(loc, policy) is expected

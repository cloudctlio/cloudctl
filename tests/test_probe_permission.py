"""probe_permission must not report a missing permission that isn't missing.

Live regression (small app, Lambda -> DynamoDB): the agent claimed the Lambda
role "lacks dynamodb:PutItem (implicitDeny)" while `aws iam
simulate-principal-policy` with the table ARN returned allowed and the table
held 1,642 items. The role's grant was an inline policy scoped to the table
ARN. A probe without the exact ARN makes the simulator test the literal "*",
which never matches a resource-scoped statement, and the bare implicitDeny was
read as proof. These tests drive probe_permission against a fake IAM whose
simulator follows the same matching rules.
"""
from __future__ import annotations

import json
import re

import pytest

from cloudctl.mcp.tools import debug as dbg
from cloudctl.mcp.tools import recorder

ACCT = "111122223333"
ROLE = "app-role"
ROLE_ARN = f"arn:aws:iam::{ACCT}:role/{ROLE}"
TABLE = f"arn:aws:dynamodb:us-east-1:{ACCT}:table/orders"

INLINE_PUT_ON_TABLE = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
                   "Resource": TABLE}],
}


def _glob(p, v, ic=False):
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in p)
    return re.fullmatch(rx, v, re.I if ic else 0) is not None


class FakeIAM:
    def __init__(self, inline=None, managed=None, *, rp_mode="error",
                 missing_context=None):
        self.inline = inline or {}
        self.managed = managed or {}
        self.rp_mode = rp_mode
        self.missing_context = missing_context or []
        self.calls = []

    def get_role(self, RoleName):
        assert RoleName == ROLE, RoleName
        return {"Role": {"Arn": ROLE_ARN}}

    def _docs(self):
        return [*self.inline.values(), *self.managed.values()]

    def simulate_principal_policy(self, PolicySourceArn, ActionNames,
                                  ResourceArns=None, ResourcePolicy=None,
                                  CallerArn=None):
        self.calls.append({"ResourceArns": ResourceArns,
                           "ResourcePolicy": ResourcePolicy})
        assert PolicySourceArn == ROLE_ARN
        if ResourcePolicy is not None and self.rp_mode == "error":
            raise RuntimeError("InvalidInput: CallerArn must be an IAM user")
        res = (ResourceArns or ["*"])[0]
        action = ActionNames[0]
        decision, matched = "implicitDeny", []
        for d in self._docs():
            for st in d["Statement"]:
                acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
                rs = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
                if any(_glob(a, action, True) for a in acts) and any(_glob(r, res) for r in rs):
                    if st["Effect"] == "Deny":
                        decision = "explicitDeny"
                    elif decision != "explicitDeny":
                        decision = "allowed"
                    matched.append({"SourcePolicyId": "p", "SourcePolicyType": "IAM Policy"})
        if ResourcePolicy is not None:
            rp = json.loads(ResourcePolicy)
            if any(s["Effect"] == "Deny" for s in rp["Statement"]):
                decision = "explicitDeny"
            elif self.rp_mode == "implicit":
                decision = "implicitDeny"   # simulator mishandling a role caller
        if self.missing_context:
            decision = "implicitDeny"
        return {"EvaluationResults": [{
            "EvalActionName": action, "EvalResourceName": res,
            "EvalDecision": decision, "MatchedStatements": matched,
            "MissingContextValues": list(self.missing_context),
        }]}

    def list_role_policies(self, RoleName, Marker=None):
        return {"PolicyNames": list(self.inline), "IsTruncated": False}

    def get_role_policy(self, RoleName, PolicyName):
        return {"PolicyDocument": self.inline[PolicyName]}

    def list_attached_role_policies(self, RoleName, Marker=None):
        return {"AttachedPolicies": [{"PolicyName": n, "PolicyArn": f"arn:aws:iam::{ACCT}:policy/{n}"}
                                     for n in self.managed], "IsTruncated": False}

    def get_policy(self, PolicyArn):
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):
        return {"PolicyVersion": {"Document": self.managed[PolicyArn.rsplit("/", 1)[-1]]}}


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.delenv("CLOUDCTL_REPLAY", raising=False)
    holder = {}

    class _Session:
        def client(self, name):
            assert name == "iam"
            return holder["iam"]

    monkeypatch.setattr(dbg, "_make_session", lambda p, r: _Session())
    recorder._SESSION_CACHE.clear()

    def run(iam, **kw):
        holder["iam"] = iam
        recorder._SESSION_CACHE.clear()
        args = {"role": ROLE, "action": "dynamodb:PutItem", "resource_arn": "",
                "profile": None, "region": "us-east-1"}
        args.update(kw)
        return json.loads(dbg.probe_permission(**args))
    return run


def test_probe_without_resource_arn_is_not_proof_of_missing_permission(fake):
    out = fake(FakeIAM(inline={"app-policy": INLINE_PUT_ON_TABLE}))
    r = out["results"][0]
    assert r["decision"] == "implicitDeny"          # what the simulator says
    assert r["conclusive"] is False                  # ...but it proves nothing
    why = " ".join(r["inconclusive_because"])
    assert "'*'" in why and TABLE in why             # names the fix: the real ARN
    assert "conclusive=false is NOT evidence" in out["note"]
    assert out["identity_statements_for_action"][0]["type"] == "inline"


def test_exact_table_arn_with_inline_policy_is_allowed(fake):
    out = fake(FakeIAM(inline={"app-policy": INLINE_PUT_ON_TABLE}), resource_arn=TABLE)
    r = out["results"][0]
    assert r["decision"] == "allowed" and r["conclusive"] is True


def test_grant_in_managed_policy_is_found_too(fake):
    out = fake(FakeIAM(managed={"app-managed": INLINE_PUT_ON_TABLE}))
    r = out["results"][0]
    assert r["conclusive"] is False
    assert out["identity_statements_for_action"][0]["type"] == "managed"


def test_wrong_account_in_arn_is_flagged(fake):
    bad = "arn:aws:dynamodb:us-east-1:123456789012:table/orders"
    out = fake(FakeIAM(inline={"app-policy": INLINE_PUT_ON_TABLE}), resource_arn=bad)
    r = out["results"][0]
    assert r["decision"] == "implicitDeny" and r["conclusive"] is False
    assert any("account 123456789012" in x for x in r["inconclusive_because"])


def test_genuinely_missing_permission_stays_conclusive(fake):
    read_only = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": TABLE}]}
    out = fake(FakeIAM(inline={"ro": read_only}), resource_arn=TABLE)
    r = out["results"][0]
    assert r["decision"] == "implicitDeny"
    assert r["conclusive"] is True
    assert "inconclusive_because" not in r
    assert "NOT evidence" not in out["note"]


def test_explicit_deny_is_reported(fake):
    doc = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"},
        {"Effect": "Deny", "Action": "dynamodb:PutItem", "Resource": TABLE}]}
    out = fake(FakeIAM(inline={"p": doc}), resource_arn=TABLE)
    assert out["results"][0]["decision"] == "explicitDeny"
    assert out["results"][0]["conclusive"] is True


def test_resource_policy_artifact_does_not_hide_same_account_identity_allow(fake):
    rp = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": ACCT}, "Action": "dynamodb:GetItem",
         "Resource": TABLE}]})
    iam = FakeIAM(inline={"app-policy": INLINE_PUT_ON_TABLE}, rp_mode="implicit")
    out = fake(iam, resource_arn=TABLE, resource_policy=rp)
    r = out["results"][0]
    assert r["identity_decision"] == "allowed"
    assert r["combined_decision"] == "implicitDeny"
    assert r["decision"] == "allowed"
    assert out["resource_policy_evaluated"] is True


def test_resource_policy_explicit_deny_wins(fake):
    rp = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Deny", "Principal": "*", "Action": "dynamodb:PutItem", "Resource": TABLE}]})
    iam = FakeIAM(inline={"app-policy": INLINE_PUT_ON_TABLE}, rp_mode="ok")
    out = fake(iam, resource_arn=TABLE, resource_policy=rp)
    assert out["results"][0]["decision"] == "explicitDeny"


def test_resource_policy_the_simulator_refuses_falls_back_to_identity(fake):
    rp = json.dumps({"Version": "2012-10-17", "Statement": []})
    iam = FakeIAM(inline={"app-policy": INLINE_PUT_ON_TABLE}, rp_mode="error")
    out = fake(iam, resource_arn=TABLE, resource_policy=rp)
    assert out["results"][0]["decision"] == "allowed"
    assert out["resource_policy_evaluated"] is False
    assert "could not be simulated" in out["note"]


def test_missing_context_values_make_a_deny_inconclusive(fake):
    iam = FakeIAM(inline={"app-policy": INLINE_PUT_ON_TABLE},
                  missing_context=["aws:SourceVpce"])
    out = fake(iam, resource_arn=TABLE)
    r = out["results"][0]
    assert r["decision"] == "implicitDeny" and r["conclusive"] is False
    assert r["missing_context_values"] == ["aws:SourceVpce"]


def test_assumed_role_arn_from_logs_is_resolved_to_the_role(fake):
    sts = f"arn:aws:sts::{ACCT}:assumed-role/{ROLE}/my-function"
    out = fake(FakeIAM(inline={"app-policy": INLINE_PUT_ON_TABLE}),
               role=sts, resource_arn=TABLE)
    assert out["role_arn"] == ROLE_ARN
    assert out["results"][0]["decision"] == "allowed"


def test_dynamodb_item_count_is_labelled_as_stale():
    from cloudctl.debug.notes import DDB_ITEM_COUNT_NOTE

    class _DDB:
        def list_tables(self):
            return {"TableNames": ["orders"]}

        def describe_table(self, TableName):
            return {"Table": {"TableName": "orders", "TableStatus": "ACTIVE",
                              "ItemCount": 0, "TableSizeBytes": 0,
                              "ProvisionedThroughput": {"ReadCapacityUnits": 1,
                                                        "WriteCapacityUnits": 1}}}

        def __getattr__(self, name):
            def _none(**kw):
                raise RuntimeError("not needed")
            return _none

    class _Sess:
        region_name = "us-east-1"

        def client(self, name, **kw):
            return _DDB()

    from cloudctl.debug.fetcher import DebugFetcher
    f = DebugFetcher(_Sess())
    method = next(getattr(f, m) for m in dir(f) if "dynamodb" in m and "config" in m)
    cfg = method("orders")
    assert cfg["item_count"] == 0
    assert cfg["item_count_note"] == DDB_ITEM_COUNT_NOTE
    assert "six hours" in DDB_ITEM_COUNT_NOTE and "not evidence" in DDB_ITEM_COUNT_NOTE

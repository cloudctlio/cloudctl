"""Executors apply exactly the approved plan, or nothing."""
import json
from pathlib import Path

import pytest

import cloudctl.controlplane.executors as X
from cloudctl.controlplane.graph import Node
from cloudctl.gate.canonical import sha256_hex
from cloudctl.gate.config import parse_config
from cloudctl.gate.models import Plan
from cloudctl.gate.plan.base import ToolResult
from tests.controlplane.conftest import ENVF, iac_root, tag
from tests.gate.conftest import config_doc


class Creds:
    """Stands in for ScopedCredentials: a scoped env and SDK clients."""

    def __init__(self, session=None, credential=None):
        self._session, self._credential = session, credential
        self.remaining_seconds = 600

    def subprocess_env(self, base=None):
        return {"PATH": "/usr/bin", "SCOPED": "1"}

    def client(self, kind, *a, **k):
        return {"session": self._session, "credential": self._credential}[kind]


def _env(cloud, **extra):
    return parse_config(config_doc({"dev": ENVF[cloud]("dev", **extra)})).environment("dev")


@pytest.fixture
def tools(monkeypatch):
    calls = []

    def fake_run(argv, *, cwd, env, timeout=0, ok_codes=(0,), what=""):
        calls.append({"argv": list(argv), "cwd": str(cwd), "env": dict(env), "what": what})
        return ToolResult(0, "done\n", "")
    monkeypatch.setattr(X, "run_tool", fake_run)
    monkeypatch.setattr(X, "find_binary", lambda name, explicit=None: f"/bin/{name}")
    return calls


# ── Terraform ───────────────────────────────────────────────────────────────

def _tf(tmp_path, content=b"PLAN"):
    from cloudctl.gate.plan.terraform import TerraformPlanner
    root = iac_root(tmp_path, "tf")
    pf = tmp_path / "plan.tfplan"
    pf.write_bytes(content)
    plan = Plan(platform="terraform", environment="dev", changes=(tag("aws"),), source=str(root),
                artifacts={"terraform_plan_binary": str(pf)}, metadata={"plan_binary_sha256": sha256_hex(content)})
    return X.TerraformExecutor(TerraformPlanner(root)), plan, pf, root


def test_terraform_applies_the_saved_plan_file_with_scoped_env(tmp_path, tools):
    ex, plan, pf, root = _tf(tmp_path)
    out = ex.apply(Creds(), plan, _env("aws"))
    [call] = tools
    assert call["argv"] == ["/bin/terraform", "apply", "-input=false", "-no-color", "-lock-timeout=120s", str(pf)]
    assert call["cwd"] == str(root) and call["env"]["SCOPED"] == "1" and call["env"]["TF_INPUT"] == "0"
    assert out["applied_plan_sha256"] == plan.metadata["plan_binary_sha256"]


def test_terraform_refuses_a_changed_or_missing_plan_file(tmp_path, tools):
    ex, plan, pf, _ = _tf(tmp_path)
    pf.write_bytes(b"TAMPERED")
    with pytest.raises(X.ExecutionError, match="changed after approval"):
        ex.apply(Creds(), plan, _env("aws"))
    pf.unlink()
    with pytest.raises(X.ExecutionError, match="missing"):
        ex.apply(Creds(), plan, _env("aws"))
    assert tools == []


def test_tool_failure_becomes_execution_error(tmp_path, monkeypatch):
    from cloudctl.gate.models import PlanError
    ex, plan, _, _ = _tf(tmp_path)
    monkeypatch.setattr(X, "find_binary", lambda n, e=None: "/bin/terraform")

    def fail(*a, **k):
        raise PlanError("exited 1: Error acquiring the state lock")
    monkeypatch.setattr(X, "run_tool", fail)
    with pytest.raises(X.ExecutionError, match="state lock"):
        ex.apply(Creds(), plan, _env("aws"))


# ── CloudFormation / CDK ────────────────────────────────────────────────────

class FakeCfn:
    def __init__(self, changes, end_status="UPDATE_COMPLETE", cs_status="CREATE_COMPLETE"):
        self.changes, self.end_status, self.cs_status = changes, end_status, cs_status
        self.created, self.deleted, self.executed = [], [], []

    def describe_stacks(self, StackName):
        return {"Stacks": [{"StackStatus": self.end_status if self.executed else "UPDATE_COMPLETE"}]}

    def create_change_set(self, **kw):
        self.created.append(kw)
        return {"Id": f"cs-{len(self.created)}"}

    def describe_change_set(self, ChangeSetName):
        return {"Status": self.cs_status, "ExecutionStatus": "AVAILABLE"}

    def get_paginator(self, name):
        cfn = self

        class P:
            def paginate(self, ChangeSetName):
                return [{"Status": "CREATE_COMPLETE", "Changes": cfn.changes}]
        return P()

    def delete_change_set(self, ChangeSetName):
        self.deleted.append(ChangeSetName)

    def execute_change_set(self, ChangeSetName):
        self.executed.append(ChangeSetName)


class Session:
    def __init__(self, cfn):
        self.cfn = cfn

    def client(self, name, region_name=None):
        assert name == "cloudformation" and region_name == "us-east-1"
        return self.cfn


def _change(logical="Bucket", action="Modify"):
    return {"ResourceChange": {"LogicalResourceId": logical, "ResourceType": "AWS::S3::Bucket", "Action": action,
                               "Replacement": "False", "Details": []}}


def _cfn_setup(tmp_path, cfn):
    from cloudctl.gate.plan.cloudformation import CloudFormationPlanner
    t = tmp_path / "t.json"
    t.write_text(json.dumps({"Resources": {}}))
    planner = CloudFormationPlanner({"app": t}, poll_seconds=0)
    env, creds = _env("aws"), Creds(session=Session(cfn))
    approved = planner.plan(env=env, creds=creds, workdir=tmp_path)
    return X.CloudFormationExecutor(planner, poll_seconds=0), approved, env, creds


def test_cloudformation_replans_with_kept_change_sets_and_executes_them(tmp_path):
    cfn = FakeCfn([_change()])
    ex, approved, env, creds = _cfn_setup(tmp_path, cfn)
    assert cfn.deleted == ["cs-1"]                         # the gate's own plan cleans up its change set
    out = ex.apply(creds, approved, env)
    assert cfn.executed == ["cs-2"] and out == {"stacks": {"app": "UPDATE_COMPLETE"}}


def test_cloudformation_refuses_when_live_state_moved_and_deletes_the_new_change_set(tmp_path):
    cfn = FakeCfn([_change()])
    ex, approved, env, creds = _cfn_setup(tmp_path, cfn)
    cfn.changes = [_change(), _change("Queue", "Add")]
    with pytest.raises(X.ExecutionError, match="digest mismatch"):
        ex.apply(creds, approved, env)
    assert cfn.executed == [] and "cs-2" in cfn.deleted


def test_cloudformation_rollback_is_a_failure(tmp_path):
    cfn = FakeCfn([_change()], end_status="UPDATE_ROLLBACK_COMPLETE")
    ex, approved, env, creds = _cfn_setup(tmp_path, cfn)
    with pytest.raises(X.ExecutionError, match="UPDATE_ROLLBACK_COMPLETE"):
        ex.apply(creds, approved, env)


def test_cdk_executor_replans_with_keep(tmp_path):
    from cloudctl.gate.plan.cloudformation import CdkPlanner
    root = iac_root(tmp_path, "cdk", "cdk.json")
    ex = X.executor_for_planner(CdkPlanner(root, pinned_version="2.1"))
    fresh = ex._fresh_planner()
    assert isinstance(fresh, CdkPlanner) and fresh.keep and fresh.pinned_version == "2.1"


# ── ARM / Bicep ─────────────────────────────────────────────────────────────

class Poller:
    def __init__(self, result):
        self._r = result

    def result(self, timeout=None):
        return self._r


class Deployments:
    def __init__(self, changes, state="Succeeded"):
        self.changes, self.state, self.deployed = changes, state, []

    def begin_what_if(self, rg, name, body):
        return Poller({"status": "Succeeded", "properties": {"changes": self.changes}})

    def begin_create_or_update(self, rg, name, body):
        self.deployed.append((rg, body))
        return Poller({"properties": {"provisioningState": self.state}})


def _arm(tmp_path, deps):
    from cloudctl.gate.plan.arm import ArmWhatIfPlanner

    class RM:
        def __init__(self, cred, sub):
            self.deployments = deps
    t = tmp_path / "azuredeploy.json"
    t.write_text(json.dumps({"resources": [{"type": "Microsoft.Storage/storageAccounts"}]}))
    planner = ArmWhatIfPlanner(t, rm_client_factory=RM)
    env, creds = _env("azure"), Creds(credential=object())
    approved = planner.plan(env=env, creds=creds, workdir=tmp_path)
    return X.executor_for_planner(planner), approved, env, creds


def _whatif(name="st1"):
    rid = f"/subscriptions/x/resourceGroups/rg-app/providers/Microsoft.Storage/storageAccounts/{name}"
    return {"changeType": "Modify", "resourceId": rid, "before": {"location": "eastus"},
            "after": {"location": "eastus"}}


def test_arm_deploys_the_same_template_after_a_matching_what_if(tmp_path):
    deps = Deployments([_whatif()])
    ex, approved, env, creds = _arm(tmp_path, deps)
    out = ex.apply(creds, approved, env)
    [(rg, body)] = deps.deployed
    assert rg == "rg-app" and body["properties"]["mode"] == "Incremental"
    assert body["properties"]["template"]["resources"][0]["type"] == "Microsoft.Storage/storageAccounts"
    assert out["state"] == "Succeeded"


def test_arm_refuses_on_digest_mismatch_and_reports_failed_deploys(tmp_path):
    deps = Deployments([_whatif()])
    ex, approved, env, creds = _arm(tmp_path, deps)
    deps.changes = [_whatif(), _whatif("st2")]
    with pytest.raises(X.ExecutionError, match="digest mismatch"):
        ex.apply(creds, approved, env)
    assert deps.deployed == []
    deps.changes, deps.state = [_whatif()], "Failed"
    with pytest.raises(X.ExecutionError, match="ended in Failed"):
        ex.apply(creds, approved, env)


# ── Pulumi and Kubernetes (re-plan, compare, deploy) ────────────────────────

class StubPlanner:
    def __init__(self, plan, **attrs):
        self._plan = plan
        self.__dict__.update(attrs)

    def plan(self, *, env, creds, workdir):
        if getattr(self, "kubeconfig", False):
            (workdir / "kubeconfig").write_text("apiVersion: v1\n")
        return self._plan


def test_pulumi_up_runs_only_after_a_matching_preview(tmp_path, tools):
    p = Plan(platform="pulumi", environment="dev", changes=(tag("gcp"),), source="x")
    ex = X.PulumiExecutor(StubPlanner(p, root=tmp_path, stack="dev", binary_path=None, timeout=60))
    ex.apply(Creds(), p, _env("gcp"))
    assert tools[0]["argv"] == ["/bin/pulumi", "up", "--yes", "--skip-preview", "--non-interactive", "--stack", "dev"]
    other = Plan(platform="pulumi", environment="dev", changes=(tag("gcp", 2),), source="x")
    with pytest.raises(X.ExecutionError, match="digest mismatch"):
        ex.apply(Creds(), other, _env("gcp"))
    assert len(tools) == 1


@pytest.mark.parametrize("cloud,prov", [("aws", "eks"), ("azure", "aks"), ("gcp", "gke")])
def test_kubectl_apply_server_side_on_every_managed_cluster(tmp_path, tools, cloud, prov):
    k8s = {"provider": prov, "cluster": "c1", "namespace": "app"}
    if prov == "gke":
        k8s["location"] = "us-central1"
    env = _env(cloud, kubernetes=k8s)
    p = Plan(platform="kubernetes", environment="dev", changes=(tag(cloud),), source="m")
    ex = X.KubernetesExecutor(StubPlanner(p, kubeconfig=True, manifests=tmp_path, binary_path=None,
                                          server_side=True, prune_selector=None, timeout=60))
    out = ex.apply(Creds(), p, env)
    argv = tools[0]["argv"]
    assert argv[:2] == ["/bin/kubectl", "apply"] and "--server-side" in argv and argv[-2:] == ["-n", "app"]
    assert tools[0]["env"]["KUBECONFIG"].endswith("kubeconfig") and out["cluster"] == "c1"
    assert not Path(tools[0]["env"]["KUBECONFIG"]).exists()       # private workdir removed afterwards


# ── factory ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("marker,cls", [("main.tf", "TerraformExecutor"), ("cdk.json", "CloudFormationExecutor"),
                                        ("Pulumi.yaml", "PulumiExecutor"), ("main.bicep", "ArmExecutor")])
def test_factory_picks_the_executor_for_the_iac_tool(tmp_path, marker, cls):
    root = iac_root(tmp_path, "r", marker)
    n = Node(id="a", kind="iac_apply", environment="dev", summary="s", iac_root=str(root))
    assert type(X.default_executor_factory(n, _env("aws"))).__name__ == cls


@pytest.mark.parametrize("cloud,issue,fixer", [
    ("aws", {"resource": "sg/sg-1 (web)", "issue": "allows 0.0.0.0/0 inbound"}, "AWSOpenSecurityGroupFixer"),
    ("azure", {"resource": "nsg/web/rules/ssh", "issue": "open to the internet"}, "AzureNSGOpenRuleFixer"),
    ("gcp", {"resource": "firewalls/allow-all", "issue": "0.0.0.0/0 open"}, "GCPOpenFirewallFixer"),
])
def test_factory_api_fix_uses_the_environments_cloud(cloud, issue, fixer):
    n = Node(id="a", kind="api_action", environment="dev", summary="s", issue=issue)
    ex = X.default_executor_factory(n, _env(cloud))
    assert type(ex.fixer).__name__ == fixer and ex.planner.platform == "api"


def test_factory_errors(tmp_path):
    with pytest.raises(X.ExecutionError, match="no fixer"):
        X.default_executor_factory(Node(id="a", kind="api_action", environment="dev", summary="s",
                                        issue={"resource": "x", "issue": "y"}), _env("aws"))
    with pytest.raises(X.ExecutionError, match="cannot tell"):
        X.default_executor_factory(Node(id="a", kind="iac_apply", environment="dev", summary="s",
                                        iac_root=str(tmp_path)), _env("aws"))


def test_api_fix_executor_calls_fixer_apply_with_scoped_creds():
    seen = {}

    class Fixer:
        cloud = "aws"

        def plan(self, *a, **k):
            return [tag("aws")]

        def apply(self, issue, fix, creds=None):
            seen.update(issue=issue, fix=fix, creds=creds)
    c = Creds()
    out = X.ApiFixExecutor(Fixer(), {"resource": "r", "issue": "i"}, {"x": 1}).apply(c, None, None)
    assert seen == {"issue": {"resource": "r", "issue": "i"}, "fix": {"x": 1}, "creds": c}
    assert out == {"applied": "Fixer", "resource": "r"}

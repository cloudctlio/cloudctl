"""Plan stage: each platform's own plan output normalised to one Plan."""
import json
import os
from unittest.mock import MagicMock

import pytest

from cloudctl.gate.config import parse_config
from cloudctl.gate.models import Action, PlanError
from cloudctl.gate.plan import detect_iac_planner
from cloudctl.gate.plan.api import ApiActionPlanner
from cloudctl.gate.plan.arm import arm_type, parse_what_if
from cloudctl.gate.plan.base import tool_version_matches
from cloudctl.gate.plan.cloudformation import parse_change_set
from cloudctl.gate.plan.kubernetes import parse_kubectl_diff
from cloudctl.gate.plan.pulumi import parse_preview
from cloudctl.gate.plan.terraform import TerraformPlanner, parse_show_json
from tests.gate.conftest import SUB, FakeCredsBroker, aws_env, config_doc

TF_SHOW = {
    "format_version": "1.2", "terraform_version": "1.10.5",
    "resource_changes": [
        {"address": "aws_s3_bucket.logs", "mode": "managed", "type": "aws_s3_bucket", "name": "logs",
         "provider_name": "registry.terraform.io/hashicorp/aws",
         "change": {"actions": ["create"], "before": None, "after": {"bucket": "logs", "region": "us-east-1"},
                    "after_unknown": {"arn": True}}},
        {"address": "aws_instance.old", "mode": "managed", "type": "aws_instance", "name": "old",
         "provider_name": "registry.terraform.io/hashicorp/aws",
         "change": {"actions": ["delete", "create"], "before": {"ami": "a"}, "after": {"ami": "b"}}},
        {"address": "google_storage_bucket.b", "mode": "managed", "type": "google_storage_bucket", "name": "b",
         "provider_name": "registry.terraform.io/hashicorp/google",
         "change": {"actions": ["delete"], "before": {"project": "p"}, "after": None}},
        {"address": "data.aws_caller_identity.me", "mode": "data", "type": "aws_caller_identity", "name": "me",
         "provider_name": "registry.terraform.io/hashicorp/aws", "change": {"actions": ["read"]}},
    ],
}


def _env():
    return parse_config(config_doc({"dev": aws_env()})).environment("dev")


def test_terraform_show_json_is_normalised():
    plan = parse_show_json(TF_SHOW, environment="dev")
    by = {c.address: c for c in plan.changes}
    assert by["aws_s3_bucket.logs"].action == Action.CREATE and by["aws_s3_bucket.logs"].cloud == "aws"
    assert by["aws_s3_bucket.logs"].location == "us-east-1"
    assert by["aws_instance.old"].action == Action.REPLACE
    assert by["google_storage_bucket.b"].action == Action.DELETE and by["google_storage_bucket.b"].cloud == "gcp"
    assert by["data.aws_caller_identity.me"].action == Action.READ
    assert (plan.add_count, plan.modify_count, plan.destroy_count) == (2, 0, 2)
    assert plan.changed_resource_count == 3


def test_plan_digest_is_stable_and_change_sensitive():
    a = parse_show_json(TF_SHOW, environment="dev").digest()
    assert a == parse_show_json(json.loads(json.dumps(TF_SHOW)), environment="dev").digest()
    changed = json.loads(json.dumps(TF_SHOW))
    changed["resource_changes"][0]["change"]["after"]["bucket"] = "other"
    assert parse_show_json(changed, environment="dev").digest() != a


@pytest.mark.parametrize("doc,msg", [({"format_version": "0.1"}, "format_version"),
                                     ({"format_version": "1.2", "errored": True}, "errored")])
def test_bad_terraform_plans_are_refused(doc, msg):
    with pytest.raises(PlanError, match=msg):
        parse_show_json(doc, environment="dev")


def test_terraform_planner_runs_the_tool_with_scoped_env_only(tmp_path, monkeypatch):
    root = tmp_path / "iac"
    root.mkdir()
    (root / "main.tf").write_text("")
    log = tmp_path / "calls.log"
    show = tmp_path / "show.json"
    show.write_text(json.dumps(TF_SHOW))
    fake = tmp_path / "terraform"
    fake.write_text(f"""#!/bin/sh
echo "$@ AWS_PROFILE=${{AWS_PROFILE:-unset}} FAKE_TOKEN=$FAKE_TOKEN" >> {log}
case "$1" in
  version) echo "Terraform v1.10.5";;
  plan) for a in "$@"; do case "$a" in -out=*) : > "${{a#-out=}}";; esac; done; exit 2;;
  show) cat {show};;
esac
""")
    fake.chmod(0o755)
    monkeypatch.setenv("AWS_PROFILE", "admin")
    env = _env()
    creds = FakeCredsBroker("aws").acquire(env, request_id="r", requester="a")
    wd = tmp_path / "wd"
    wd.mkdir()
    plan = TerraformPlanner(root, binary_path=str(fake), pinned_version="1.10.5").plan(env=env, creds=creds,
                                                                                    workdir=wd)
    assert plan.platform == "terraform" and plan.changed_resource_count == 3
    assert os.path.exists(plan.artifacts["terraform_plan_json"])
    calls = log.read_text()
    assert "AWS_PROFILE=unset" in calls and "FAKE_TOKEN=tok-r" in calls
    with pytest.raises(PlanError, match="version mismatch"):
        TerraformPlanner(root, binary_path=str(fake), pinned_version="1.9.0").plan(env=env, creds=creds, workdir=wd)


def test_tool_version_pin_matches_whole_versions_only():
    assert tool_version_matches("Terraform v1.10.5\non linux", "1.10.5")
    assert not tool_version_matches("Terraform v1.10.50", "1.10.5")
    assert tool_version_matches("anything", None)


def test_arm_what_if_is_normalised():
    rid = f"/subscriptions/{SUB}/resourceGroups/rg-app/providers/Microsoft.Network/networkSecurityGroups/n/securityRules/r"
    assert arm_type(rid) == "Microsoft.Network/networkSecurityGroups/securityRules"
    out = parse_what_if([{"resourceId": rid, "changeType": "Modify", "after": {"location": "eastus"}},
                         {"resourceId": rid + "2", "changeType": "Unsupported", "unsupportedReason": "nested"}])
    assert out[0].action == Action.UPDATE and out[0].location == "eastus" and out[0].cloud == "azure"
    assert out[1].after["_whatif_change_type"] == "Unsupported"
    with pytest.raises(PlanError):
        parse_what_if([{"resourceId": rid, "changeType": "Bogus"}])


def test_cloudformation_change_set_is_normalised():
    pages = [{"Status": "CREATE_COMPLETE", "Changes": [
        {"ResourceChange": {"Action": "Modify", "LogicalResourceId": "Db", "ResourceType": "AWS::RDS::DBInstance",
                            "Replacement": "Conditional"}},
        {"ResourceChange": {"Action": "Add", "LogicalResourceId": "Q", "ResourceType": "AWS::SQS::Queue"}}]}]
    out = parse_change_set(pages, environment="dev", stack="app", region="us-east-1")
    assert [c.action for c in out] == [Action.REPLACE, Action.CREATE]
    assert parse_change_set([{"Status": "FAILED", "StatusReason": "The submitted information didn't contain changes."}],
                            environment="dev", stack="app", region="r") == []
    with pytest.raises(PlanError):
        parse_change_set([{"Status": "FAILED", "StatusReason": "boom"}], environment="dev", stack="app", region="r")


def test_pulumi_preview_is_normalised_and_skips_stack_resources():
    doc = {"steps": [
        {"op": "same", "urn": "urn:pulumi:dev::app::pulumi:pulumi:Stack::app-dev"},
        {"op": "create", "urn": "urn:pulumi:dev::app::gcp:storage/bucket:Bucket::b",
         "newState": {"type": "gcp:storage/bucket:Bucket", "inputs": {"location": "US"}}},
        {"op": "create-replacement", "urn": "urn:pulumi:dev::app::azure-native:storage:StorageAccount::s",
         "newState": {"type": "azure-native:storage:StorageAccount", "inputs": {}}},
        {"op": "delete-replaced", "urn": "urn:pulumi:dev::app::azure-native:storage:StorageAccount::s",
         "oldState": {"type": "azure-native:storage:StorageAccount"}},
    ]}
    plan = parse_preview(doc, environment="dev")
    by = {c.name: c for c in plan.changes}
    assert set(by) == {"b", "s"}
    assert by["b"].cloud == "gcp" and by["s"].action == Action.REPLACE and by["s"].cloud == "azure"
    with pytest.raises(PlanError):
        parse_preview({"steps": [{"op": "teleport"}]}, environment="dev")


def test_kubectl_diff_is_normalised():
    text = """diff -u -N /tmp/LIVE-1/apps.v1.Deployment.shop.web /tmp/MERGED-1/apps.v1.Deployment.shop.web
--- /tmp/LIVE-1/apps.v1.Deployment.shop.web
+++ /tmp/MERGED-1/apps.v1.Deployment.shop.web
@@ -10,7 +10,7 @@
-  replicas: 2
+  replicas: 3
diff -u -N /tmp/LIVE-2/v1.ConfigMap.shop.cfg /tmp/MERGED-2/v1.ConfigMap.shop.cfg
--- /tmp/LIVE-2/v1.ConfigMap.shop.cfg
+++ /tmp/MERGED-2/v1.ConfigMap.shop.cfg
@@ -0,0 +1,5 @@
+kind: ConfigMap
"""
    out = parse_kubectl_diff(text, environment="dev", cluster="eks1")
    assert [(c.type, c.action) for c in out] == [("apps/v1/Deployment", Action.UPDATE),
                                                 ("core/v1/ConfigMap", Action.CREATE)]
    assert out[0].address == "eks1/shop/Deployment/web"


def test_detect_iac_planner(tmp_path):
    env = _env()
    (tmp_path / "main.tf").write_text("")
    assert isinstance(detect_iac_planner(tmp_path, env=env), TerraformPlanner)
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(PlanError, match="cannot tell"):
        detect_iac_planner(empty, env=env)


def test_api_action_planner_uses_the_fixer_declaration():
    from tests.gate.conftest import sg_change
    fixer = MagicMock()
    fixer.plan.return_value = [sg_change()]
    env = _env()
    plan = ApiActionPlanner(fixer, {"resource": "x"}, {}).plan(env=env, creds="c", workdir=None)
    assert plan.platform == "api" and len(plan.changes) == 1
    assert fixer.plan.call_args.kwargs == {"creds": "c", "env": env}
    fixer.plan.return_value = []
    with pytest.raises(PlanError, match="declared no change"):
        ApiActionPlanner(fixer, {"resource": "x"}, {}).plan(env=env, creds="c", workdir=None)
    fixer.plan.side_effect = RuntimeError("describe failed")
    with pytest.raises(PlanError, match="describe failed"):
        ApiActionPlanner(fixer, {"resource": "x"}, {}).plan(env=env, creds="c", workdir=None)

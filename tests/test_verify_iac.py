"""Declared layer: Terraform state/plan, CloudFormation and CDK synth."""
from __future__ import annotations

import json
import os

import pytest

from cloudctl.verify.iac import (
    load_cdk_out,
    load_cfn_template,
    load_iac_path,
    load_terraform_plan,
    load_terraform_state,
    read_template_file,
)
from cloudctl.verify.model import SystemModel
from tests.verify_support import FIXTURES, FN, ROLE, TABLE, orders_model


def test_terraform_state_nodes_edges_and_modules():
    m = orders_model()
    fn = m.node(FN)
    assert fn.iac_address == "module.orders.aws_lambda_function.orders"
    assert fn.iac_module == "module.orders"
    assert fn.declared["timeout"] == 30
    assert fn.iac_file == "orders.tfstate.json"
    # data sources are not part of the system
    assert not any("aws_iam_policy_document" in n.type for n in m.nodes.values())
    deps = {(e.dst, e.via) for e in m.edges if e.src == FN and e.source == "declared"}
    assert (ROLE, "tf_dependency") in deps
    assert (TABLE, "tf_value_ref") in deps       # table name in env var
    assert m.resolve("module.orders.aws_iam_role.orders") == ROLE


def test_terraform_state_index_keys_and_bad_version():
    m = SystemModel()
    state = {"version": 4, "resources": [
        {"mode": "managed", "type": "aws_sqs_queue", "name": "q", "instances": [
            {"index_key": 0, "attributes": {"arn": "arn:aws:sqs:us-east-1:1:q-zero", "name": "q-zero"}},
            {"index_key": "blue", "attributes": {"name": "q-blue-xx"}}]}]}
    res = load_terraform_state(m, state)
    assert res["resources"] == 2
    assert m.resolve("aws_sqs_queue.q[0]") == "arn:aws:sqs:us-east-1:1:q-zero"
    assert m.resolve('aws_sqs_queue.q["blue"]') == 'aws_sqs_queue.q["blue"]'
    with pytest.raises(ValueError):
        load_terraform_state(SystemModel(), {"version": 3, "modules": []})


def _plan():
    return {
        "format_version": "1.2",
        "planned_values": {"root_module": {
            "resources": [{"address": "aws_iam_role.r", "mode": "managed", "type": "aws_iam_role",
                           "name": "r", "values": {"name": "svc-role-1"}}],
            "child_modules": [{"address": "module.app", "resources": [
                {"address": "module.app.aws_lambda_function.f", "mode": "managed",
                 "type": "aws_lambda_function", "name": "f",
                 "values": {"function_name": "svc-fn-1", "timeout": 10}},
                {"address": "module.app.aws_sqs_queue.q", "mode": "managed",
                 "type": "aws_sqs_queue", "name": "q", "values": {"name": "svc-q-1"}}]}]}},
        "configuration": {"root_module": {
            "resources": [{"address": "aws_iam_role.r", "mode": "managed", "type": "aws_iam_role",
                           "name": "r", "expressions": {"name": {"constant_value": "svc-role-1"}}}],
            "module_calls": {"app": {"module": {"resources": [
                {"address": "aws_lambda_function.f", "mode": "managed", "type": "aws_lambda_function",
                 "name": "f", "expressions": {
                     "role": {"references": ["var.role_arn"]},
                     "environment": [{"variables": {"references": ["aws_sqs_queue.q.url", "aws_sqs_queue.q"]}}],
                     "kms": {"references": ["data.aws_kms_key.k.arn"]}}}]}}}}},
    }


def test_terraform_plan_nodes_and_reference_edges():
    m = SystemModel()
    res = load_terraform_plan(m, _plan(), "plan.json")
    assert res["resources"] == 3
    f = m.node("module.app.aws_lambda_function.f")
    assert f.declared["timeout"] == 10 and f.iac_module == "module.app"
    edges = [(e.src, e.dst, e.via) for e in m.edges]
    assert edges == [("module.app.aws_lambda_function.f", "module.app.aws_sqs_queue.q", "tf_ref")]
    assert "environment" in m.edges[0].detail
    with pytest.raises(ValueError):
        load_terraform_plan(SystemModel(), {"resources": []})


def _template():
    return {
        "Parameters": {"Env": {"Type": "String"}},
        "Resources": {
            "Fn": {"Type": "AWS::Lambda::Function",
                   "Metadata": {"aws:cdk:path": "App/Api/Fn/Resource"},
                   "Properties": {"FunctionName": "api-fn-xyz",
                                  "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                                  "Environment": {"Variables": {
                                      "T": {"Ref": "Table"}, "E": {"Ref": "Env"},
                                      "R": {"Ref": "AWS::Region"},
                                      "U": {"Fn::Sub": "https://${Api}.execute-api/${AWS::Region}"}}}},
                   "DependsOn": "Bucket"},
            "Role": {"Type": "AWS::IAM::Role", "Properties": {}},
            "Table": {"Type": "AWS::DynamoDB::Table", "Properties": {"TableName": "api-table-xyz"}},
            "Api": {"Type": "AWS::ApiGateway::RestApi", "Properties": {}},
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
        }}


def test_cfn_refs_getatt_sub_dependson_and_naming():
    m = SystemModel()
    res = load_cfn_template(m, _template(), "ApiStack", "t.json",
                            physical_ids={"Role": "arn:aws:iam::1:role/ApiStack-Role-abc"})
    assert res["resources"] == 5
    vias = {(e.dst, e.via) for e in m.edges}
    assert vias == {("arn:aws:iam::1:role/ApiStack-Role-abc", "cfn_GetAtt"),
                    ("ApiStack/Table", "cfn_Ref"), ("ApiStack/Api", "cfn_Sub"),
                    ("ApiStack/Bucket", "cfn_DependsOn")}
    fn = m.node("ApiStack/Fn")
    assert fn.name == "api-fn-xyz" and fn.iac_module == "App/Api/Fn/Resource"
    assert m.node("ApiStack/Table").name == "api-table-xyz"
    assert m.resolve("ApiStack/Role") == "arn:aws:iam::1:role/ApiStack-Role-abc"


def test_cfn_yaml_short_tags(tmp_path):
    p = tmp_path / "stack.yaml"
    p.write_text("Resources:\n"
                 "  Fn:\n    Type: AWS::Lambda::Function\n    Properties:\n"
                 "      Role: !GetAtt Role.Arn\n      Q: !Ref Queue\n"
                 "      U: !Sub 'x-${Queue.Arn}'\n"
                 "  Role:\n    Type: AWS::IAM::Role\n"
                 "  Queue:\n    Type: AWS::SQS::Queue\n")
    doc = read_template_file(str(p))
    assert doc["Resources"]["Fn"]["Properties"]["Role"] == {"Fn::GetAtt": ["Role", "Arn"]}
    m = SystemModel()
    res = load_iac_path(m, str(p))
    assert res["kind"] == "cloudformation"
    assert {(e.dst, e.via) for e in m.edges} == {("stack/Role", "cfn_GetAtt"),
                                                 ("stack/Queue", "cfn_Ref"),
                                                 ("stack/Queue", "cfn_Sub")}


def test_cdk_out_manifest(tmp_path):
    (tmp_path / "ApiStack.template.json").write_text(json.dumps(_template()))
    (tmp_path / "manifest.json").write_text(json.dumps({"artifacts": {
        "ApiStack": {"type": "aws:cloudformation:stack",
                     "properties": {"templateFile": "ApiStack.template.json"}},
        "Tree": {"type": "cdk:tree"}}}))
    m = SystemModel()
    res = load_cdk_out(m, str(tmp_path))
    assert res == {"stacks": 1, "resources": 5, "edges": 4}
    assert load_iac_path(SystemModel(), str(tmp_path))["kind"] == "cdk"


def test_load_iac_path_detection(tmp_path):
    m = SystemModel()
    assert load_iac_path(m, os.path.join(FIXTURES, "orders.tfstate.json"))["kind"] == "terraform_state"
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(_plan()))
    assert load_iac_path(SystemModel(), str(plan))["kind"] == "terraform_plan"
    junk = tmp_path / "junk.json"
    junk.write_text("{}")
    with pytest.raises(ValueError):
        load_iac_path(SystemModel(), str(junk))
    with pytest.raises(ValueError):
        load_iac_path(SystemModel(), str(tmp_path))  # dir without manifest


def test_dependency_on_counted_resource_reaches_every_instance():
    m = SystemModel()
    state = {"version": 4, "resources": [
        {"mode": "managed", "type": "aws_sqs_queue", "name": "q", "instances": [
            {"index_key": 0, "attributes": {"name": "q-zero-x"}},
            {"index_key": 1, "attributes": {"name": "q-one-xx"}}]},
        {"mode": "managed", "type": "aws_lambda_function", "name": "f", "instances": [
            {"attributes": {"function_name": "fn-abcdef"}, "dependencies": ["aws_sqs_queue.q"]}]}]}
    load_terraform_state(m, state)
    assert sorted(e.dst for e in m.edges if e.via == "tf_dependency") == [
        "aws_sqs_queue.q[0]", "aws_sqs_queue.q[1]"]

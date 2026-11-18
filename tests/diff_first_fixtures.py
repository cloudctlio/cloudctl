"""Synthetic recordings of the complex orders app (e2e/complex-app) for the
diff-first replay tests.

The app: HTTP API -> api Lambda -> SQS orders queue (DLQ after 3 tries) ->
event-source mapping -> worker Lambda -> S3 receipts + DynamoDB + EventBridge
bus -> rule -> notifier Lambda. Names and wiring match app/*.tf.

Each scenario returns (iac_root files, RecordedLive data). Metrics are one-minute
buckets over three hours ending at NOW; the fault lands about 15 minutes ago.
"""

from __future__ import annotations

import copy
import json
import math
from datetime import datetime, timedelta, timezone

ACCT = "111122223333"
REGION = "us-east-1"
P = "cctl-complexapp"
NOW = datetime(2026, 11, 18, 22, 0, tzinfo=timezone.utc)
START = NOW - timedelta(minutes=180)


def t(minutes_ago: float) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def arn(svc: str, rest: str) -> str:
    return f"arn:aws:{svc}:{REGION}:{ACCT}:{rest}"


Q_URL = f"https://sqs.{REGION}.amazonaws.com/{ACCT}/{P}-orders"
DLQ_URL = f"https://sqs.{REGION}.amazonaws.com/{ACCT}/{P}-orders-dlq"
ESM_ID = "3f2c1b9e-7a44-4b51-9a6e-0c1d2e3f4a5b"
API_ID = "a1b2c3d4e5"


def _policy(stmts: list[dict]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": stmts})


def worker_policy(prefix: str = "receipts") -> str:
    return _policy([
        {"Sid": "Logs", "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": f"arn:aws:logs:{REGION}:{ACCT}:log-group:/aws/lambda/{P}-worker:*"},
        {"Sid": "Consume", "Effect": "Allow",
         "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
         "Resource": arn("sqs", f"{P}-orders")},
        {"Sid": "Orders", "Effect": "Allow", "Action": ["dynamodb:UpdateItem"],
         "Resource": arn("dynamodb", f"table/{P}-orders")},
        {"Sid": "WriteReceipts", "Effect": "Allow", "Action": ["s3:PutObject"],
         "Resource": f"arn:aws:s3:::{P}-receipts-{ACCT}/{prefix}/*"},
        {"Sid": "Publish", "Effect": "Allow", "Action": ["events:PutEvents"],
         "Resource": arn("events", f"event-bus/{P}-bus")},
    ])


API_POLICY = _policy([
    {"Sid": "Orders", "Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:GetItem"],
     "Resource": arn("dynamodb", f"table/{P}-orders")},
    {"Sid": "Enqueue", "Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": arn("sqs", f"{P}-orders")},
])
NOTIFIER_POLICY = _policy([
    {"Sid": "Orders", "Effect": "Allow", "Action": ["dynamodb:UpdateItem"],
     "Resource": arn("dynamodb", f"table/{P}-orders")},
])
PATTERN_OK = json.dumps({"source": ["cctl.orders"], "detail-type": ["OrderProcessed"]})
PATTERN_BAD = json.dumps({"source": ["cctl.orders"], "detail-type": ["OrderCompleted"]})


# ── Terraform state (what `terraform apply` left behind) ─────────────────────

def tf_attrs(api_env: dict | None = None, worker_timeout: int = 10, worker_prefix: str = "receipts",
             rule_pattern: str = PATTERN_OK, esm_enabled: bool = True) -> dict[tuple[str, str], dict]:
    api_env = api_env or {"TABLE_NAME": f"{P}-orders", "QUEUE_URL": Q_URL}

    def fn(name, role, env, timeout=10, mem=256):
        return {"id": f"{P}-{name}", "arn": arn("lambda", f"function:{P}-{name}"),
                "function_name": f"{P}-{name}", "role": f"arn:aws:iam::{ACCT}:role/{P}-{name}-role",
                "runtime": "python3.12", "handler": f"{name}.handler", "timeout": timeout,
                "memory_size": mem, "reserved_concurrent_executions": -1,
                "environment": [{"variables": env}], "last_modified": "2026-11-18T12:00:00.000+0000",
                "source_code_hash": "abc=", "tags_all": {}}

    return {
        ("aws_lambda_function", "api"): fn("api", "api", api_env),
        ("aws_lambda_function", "worker"): fn("worker", "worker", {
            "TABLE_NAME": f"{P}-orders", "RECEIPT_BUCKET": f"{P}-receipts-{ACCT}",
            "BUS_NAME": f"{P}-bus", "BASE_MS": "200", "ITEM_MS": "300"}, timeout=worker_timeout),
        ("aws_lambda_function", "notifier"): fn("notifier", "notifier", {"TABLE_NAME": f"{P}-orders"}, mem=128),
        ("aws_lambda_event_source_mapping", "worker"): {
            "id": ESM_ID, "uuid": ESM_ID, "event_source_arn": arn("sqs", f"{P}-orders"),
            "function_name": arn("lambda", f"function:{P}-worker"),
            "function_arn": arn("lambda", f"function:{P}-worker"), "batch_size": 1,
            "enabled": esm_enabled, "state": "Enabled" if esm_enabled else "Disabled"},
        ("aws_lambda_permission", "notifier_events"): {
            "id": "AllowEventBridge", "statement_id": "AllowEventBridge", "action": "lambda:InvokeFunction",
            "function_name": f"{P}-notifier", "principal": "events.amazonaws.com",
            "source_arn": arn("events", f"rule/{P}-bus/{P}-order-processed")},
        ("aws_sqs_queue", "orders"): {
            "id": Q_URL, "url": Q_URL, "arn": arn("sqs", f"{P}-orders"), "name": f"{P}-orders",
            "visibility_timeout_seconds": 30, "message_retention_seconds": 86400,
            "redrive_policy": json.dumps({"deadLetterTargetArn": arn("sqs", f"{P}-orders-dlq"),
                                          "maxReceiveCount": 3})},
        ("aws_sqs_queue", "orders_dlq"): {
            "id": DLQ_URL, "url": DLQ_URL, "arn": arn("sqs", f"{P}-orders-dlq"),
            "name": f"{P}-orders-dlq", "message_retention_seconds": 86400, "visibility_timeout_seconds": 30},
        ("aws_cloudwatch_event_bus", "orders"): {
            "id": f"{P}-bus", "name": f"{P}-bus", "arn": arn("events", f"event-bus/{P}-bus")},
        ("aws_cloudwatch_event_rule", "order_processed"): {
            "id": f"{P}-bus/{P}-order-processed", "name": f"{P}-order-processed",
            "arn": arn("events", f"rule/{P}-bus/{P}-order-processed"), "event_bus_name": f"{P}-bus",
            "event_pattern": rule_pattern, "state": "ENABLED"},
        ("aws_cloudwatch_event_target", "notifier"): {
            "id": f"{P}-bus-{P}-order-processed-terraform-1", "rule": f"{P}-order-processed",
            "event_bus_name": f"{P}-bus", "arn": arn("lambda", f"function:{P}-notifier"),
            "target_id": "terraform-1"},
        ("aws_iam_role", "api"): {"id": f"{P}-api-role", "name": f"{P}-api-role",
                                  "arn": f"arn:aws:iam::{ACCT}:role/{P}-api-role"},
        ("aws_iam_role", "worker"): {"id": f"{P}-worker-role", "name": f"{P}-worker-role",
                                     "arn": f"arn:aws:iam::{ACCT}:role/{P}-worker-role"},
        ("aws_iam_role", "notifier"): {"id": f"{P}-notifier-role", "name": f"{P}-notifier-role",
                                       "arn": f"arn:aws:iam::{ACCT}:role/{P}-notifier-role"},
        ("aws_iam_role_policy", "api"): {"id": f"{P}-api-role:{P}-api-policy", "name": f"{P}-api-policy",
                                         "role": f"{P}-api-role", "policy": API_POLICY},
        ("aws_iam_role_policy", "worker"): {"id": f"{P}-worker-role:{P}-worker-policy",
                                            "name": f"{P}-worker-policy", "role": f"{P}-worker-role",
                                            "policy": worker_policy(worker_prefix)},
        ("aws_iam_role_policy", "notifier"): {"id": f"{P}-notifier-role:{P}-notifier-policy",
                                              "name": f"{P}-notifier-policy", "role": f"{P}-notifier-role",
                                              "policy": NOTIFIER_POLICY},
        ("aws_dynamodb_table", "orders"): {"id": f"{P}-orders", "name": f"{P}-orders",
                                           "arn": arn("dynamodb", f"table/{P}-orders"),
                                           "billing_mode": "PAY_PER_REQUEST", "hash_key": "order_id"},
        ("aws_s3_bucket", "receipts"): {"id": f"{P}-receipts-{ACCT}", "bucket": f"{P}-receipts-{ACCT}",
                                        "arn": f"arn:aws:s3:::{P}-receipts-{ACCT}"},
        ("aws_apigatewayv2_api", "http"): {"id": API_ID, "name": f"{P}-http", "protocol_type": "HTTP",
                                           "api_endpoint": f"https://{API_ID}.execute-api.{REGION}.amazonaws.com"},
        ("aws_apigatewayv2_integration", "api"): {
            "id": "int123", "api_id": API_ID, "integration_type": "AWS_PROXY",
            "integration_uri": arn("lambda", f"function:{P}-api")},
        ("aws_cloudwatch_log_group", "worker"): {"id": f"/aws/lambda/{P}-worker",
                                                 "name": f"/aws/lambda/{P}-worker", "retention_in_days": 1},
        ("aws_cloudwatch_metric_alarm", "dlq"): {
            "id": f"{P}-dlq-not-empty", "alarm_name": f"{P}-dlq-not-empty",
            "dimensions": {"QueueName": f"{P}-orders-dlq"}},
    }


def tf_state(attrs: dict) -> dict:
    res = []
    for (typ, name), a in attrs.items():
        res.append({"mode": "managed", "type": typ, "name": name,
                    "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                    "instances": [{"schema_version": 0, "attributes": a}]})
    return {"version": 4, "terraform_version": "1.9.8", "serial": 12, "lineage": "x", "resources": res}


# ── Live config, as Cloud Control returns it (CloudFormation property names) ──

def live_configs(api_env: dict | None = None, worker_timeout: int = 10, worker_prefix: str = "receipts",
                 rule_pattern: str = PATTERN_OK, esm_enabled: bool = True, key_style: str = "tf") -> dict:
    api_env = api_env or {"TABLE_NAME": f"{P}-orders", "QUEUE_URL": Q_URL}

    def fn(name, env, timeout=10, mem=256):
        return {"FunctionName": f"{P}-{name}", "Arn": arn("lambda", f"function:{P}-{name}"),
                "Role": f"arn:aws:iam::{ACCT}:role/{P}-{name}-role", "Runtime": "python3.12",
                "Handler": f"{name}.handler", "Timeout": timeout, "MemorySize": mem,
                "Environment": {"Variables": env}}

    out = {
        "aws_lambda_function.api": fn("api", api_env),
        "aws_lambda_function.worker": fn("worker", {
            "TABLE_NAME": f"{P}-orders", "RECEIPT_BUCKET": f"{P}-receipts-{ACCT}",
            "BUS_NAME": f"{P}-bus", "BASE_MS": "200", "ITEM_MS": "300"}, timeout=worker_timeout),
        "aws_lambda_function.notifier": fn("notifier", {"TABLE_NAME": f"{P}-orders"}, mem=128),
        "aws_lambda_event_source_mapping.worker": {
            "Id": ESM_ID, "EventSourceArn": arn("sqs", f"{P}-orders"),
            "FunctionName": arn("lambda", f"function:{P}-worker"), "BatchSize": 1, "Enabled": esm_enabled},
        "aws_sqs_queue.orders": {"QueueUrl": Q_URL, "QueueName": f"{P}-orders", "VisibilityTimeout": 30,
                                 "MessageRetentionPeriod": 86400,
                                 "RedrivePolicy": {"deadLetterTargetArn": arn("sqs", f"{P}-orders-dlq"),
                                                   "maxReceiveCount": 3}},
        "aws_sqs_queue.orders_dlq": {"QueueUrl": DLQ_URL, "QueueName": f"{P}-orders-dlq",
                                     "MessageRetentionPeriod": 86400},
        "aws_cloudwatch_event_rule.order_processed": {
            "Name": f"{P}-order-processed", "EventBusName": f"{P}-bus",
            "EventPattern": json.loads(rule_pattern), "State": "ENABLED"},
        "aws_iam_role_policy.worker": {"PolicyName": f"{P}-worker-policy", "RoleName": f"{P}-worker-role",
                                       "PolicyDocument": json.loads(worker_policy(worker_prefix))},
        "aws_iam_role_policy.api": {"PolicyName": f"{P}-api-policy", "RoleName": f"{P}-api-role",
                                    "PolicyDocument": json.loads(API_POLICY)},
    }
    return out


# ── Metrics ──────────────────────────────────────────────────────────────────

def _series(base: float, segments: list[tuple[float, float, float]] | None = None,
            noise: float = 0.05, phase: int = 0) -> list[list]:
    """One-minute buckets. segments: (from_minutes_ago, to_minutes_ago, value)
    where value replaces the baseline in that span (exact)."""
    out = []
    for i in range(181):
        ago = 180 - i
        v = base * (1 + noise * math.sin((i + phase) * 0.7)) if base else 0.0
        for frm, to, val in segments or []:
            if to <= ago <= frm:
                v = val(ago) if callable(val) else val
        out.append([t(ago), round(max(v, 0.0), 3)])
    return out


def metrics(api_count=360.0, api_5xx=None, q_sent=None, q_deleted=None, q_visible=None,
            dlq_visible=None, w_inv=None, w_err=None, rule_matched=None, n_inv=None) -> dict:
    """Healthy series unless a segment list is given for a metric."""
    def m(typ, name, metric):
        return f"{typ}|{name}|{metric}"
    L, S, E = "AWS::Lambda::Function", "AWS::SQS::Queue", "AWS::Events::Rule"
    return {
        m("AWS::ApiGatewayV2::Api", API_ID, "Count"): _series(api_count),
        m("AWS::ApiGatewayV2::Api", API_ID, "5xx"): _series(0.0, api_5xx),
        m(L, f"{P}-api", "Invocations"): _series(api_count),
        m(L, f"{P}-api", "Errors"): _series(0.0, api_5xx),
        m(S, f"{P}-orders", "NumberOfMessagesSent"): _series(288.0, q_sent, phase=1),
        m(S, f"{P}-orders", "NumberOfMessagesDeleted"): _series(288.0, q_deleted, phase=2),
        m(S, f"{P}-orders", "ApproximateNumberOfMessagesVisible"): _series(2.0, q_visible, noise=0.5),
        m(S, f"{P}-orders-dlq", "NumberOfMessagesSent"): _series(0.0),
        m(S, f"{P}-orders-dlq", "ApproximateNumberOfMessagesVisible"): _series(0.0, dlq_visible, noise=0),
        m(L, f"{P}-worker", "Invocations"): _series(288.0, w_inv, phase=3),
        m(L, f"{P}-worker", "Errors"): _series(0.0, w_err),
        m(L, f"{P}-worker", "Throttles"): _series(0.0),
        m(E, f"{P}-order-processed", "MatchedEvents"): _series(288.0, rule_matched, phase=4),
        m(E, f"{P}-order-processed", "FailedInvocations"): _series(0.0),
        m(L, f"{P}-notifier", "Invocations"): _series(288.0, n_inv, phase=5),
        m(L, f"{P}-notifier", "Errors"): _series(0.0),
        m("AWS::DynamoDB::Table", f"{P}-orders", "ConsumedWriteCapacityUnits"): _series(864.0),
    }


def ev(ago: float, name: str, source: str, params: dict, resources: list[str] | None = None,
       actor: str = "terraform", error: str = "") -> dict:
    return {"time": t(ago), "event_name": name, "event_source": source, "actor": actor,
            "resources": resources or [], "params": params, "error_code": error}


def background_events() -> list[dict]:
    """Unrelated writes in the account (other apps) — must be ignored."""
    return [
        ev(170, "PutObject", "s3.amazonaws.com", {"bucketName": "some-other-bucket", "key": "x"}),
        ev(120, "UpdateFunctionConfiguration20150331v2", "lambda.amazonaws.com",
           {"functionName": "billing-export", "timeout": 30}, actor="ci-deployer"),
        ev(60, "CreateLogStream", "logs.amazonaws.com", {"logGroupName": "/aws/lambda/other"}),
        ev(8, "PutRolePolicy", "iam.amazonaws.com",
           {"roleName": "unrelated-role", "policyName": "p", "policyDocument": "{}"}, actor="admin"),
    ]


def ramp(rate_per_min: float, from_ago: float, start: float = 0.0):
    return lambda ago: start + rate_per_min * (from_ago - ago)


# ── Scenarios ────────────────────────────────────────────────────────────────

def scenario(sid: str) -> tuple[dict, dict]:
    """(terraform state, RecordedLive data) for s1, s3, s4, s5."""
    if sid == "s1":
        attrs = tf_attrs(worker_prefix="invoices")
        live = live_configs(worker_prefix="invoices")
        mets = metrics(w_err=[(15, 0, 100.0)], q_deleted=[(15, 0, 190.0)],
                       dlq_visible=[(15, 0, ramp(30.0, 15))], rule_matched=[(15, 0, 188.0)],
                       n_inv=[(15, 0, 188.0)])
        events = background_events() + [
            ev(17, "PutRolePolicy", "iam.amazonaws.com",
               {"roleName": f"{P}-worker-role", "policyName": f"{P}-worker-policy",
                "policyDocument": worker_policy("invoices")}),
        ]
    elif sid == "s3":
        bad_env = {"TABLE_NAME": f"{P}-orders",
                   "QUEUE_URL": f"https://sqs.{REGION}.amazonaws.com/{ACCT}/{P}-orders-v2",
                   "CACHE_ENDPOINT": "redis://127.0.0.1:6379"}
        attrs = tf_attrs(api_env=bad_env)
        live = live_configs(api_env=bad_env)
        mets = metrics(api_5xx=[(15, 0, 90.0)], q_sent=[(15, 0, 0.0)], q_deleted=[(15, 0, 0.0)],
                       w_inv=[(15, 0, 0.0)], rule_matched=[(15, 0, 0.0)], n_inv=[(15, 0, 0.0)])
        events = background_events() + [
            ev(16, "UpdateFunctionConfiguration20150331v2", "lambda.amazonaws.com",
               {"functionName": f"{P}-api", "environment": {"variables": bad_env}}),
        ]
    elif sid == "s4":
        attrs = tf_attrs(worker_timeout=2, rule_pattern=PATTERN_BAD)
        live = live_configs(worker_timeout=2, rule_pattern=PATTERN_BAD)
        mets = metrics(w_err=[(15, 0, 110.0)], q_deleted=[(15, 0, 180.0)],
                       dlq_visible=[(15, 0, ramp(20.0, 15))], rule_matched=[(15, 0, 0.0)],
                       n_inv=[(15, 0, 0.0)])
        events = background_events() + [
            ev(18, "UpdateFunctionConfiguration20150331v2", "lambda.amazonaws.com",
               {"functionName": f"{P}-worker", "timeout": 2}),
            ev(17, "PutRule", "events.amazonaws.com",
               {"name": f"{P}-order-processed", "eventBusName": f"{P}-bus", "eventPattern": PATTERN_BAD}),
        ]
    elif sid == "s5":
        # IaC is correct; the mapping was disabled by hand. s1 ran ~45 minutes
        # ago in the same account and was reverted ~40 minutes ago; its DLQ
        # leftovers are still there (flat), its IAM edits are in CloudTrail.
        attrs = tf_attrs()
        live = live_configs(esm_enabled=False)
        mets = metrics(w_err=[(45, 39, 100.0)], dlq_visible=[(45, 39, ramp(30.0, 45)), (38, 0, 180.0)],
                       w_inv=[(15, 0, 0.0)], q_deleted=[(15, 0, 0.0)],
                       q_visible=[(15, 0, ramp(288.0, 15, 2.0))],
                       rule_matched=[(15, 0, 0.0)], n_inv=[(15, 0, 0.0)])
        events = background_events() + [
            ev(47, "PutRolePolicy", "iam.amazonaws.com",
               {"roleName": f"{P}-worker-role", "policyName": f"{P}-worker-policy",
                "policyDocument": worker_policy("invoices")}),
            ev(40, "PutRolePolicy", "iam.amazonaws.com",
               {"roleName": f"{P}-worker-role", "policyName": f"{P}-worker-policy",
                "policyDocument": worker_policy("receipts")}),
            ev(16, "UpdateEventSourceMapping20150331", "lambda.amazonaws.com",
               {"uUID": ESM_ID, "enabled": False}, actor="console-admin"),
        ]
    else:
        raise KeyError(sid)
    return tf_state(attrs), {"now": t(0), "configs": live, "events": events, "metrics": mets}


# ── CloudFormation / CDK variant of s5 ───────────────────────────────────────

CFN_STACK = "OrdersStack"


def cdk_s5() -> tuple[dict, dict, dict]:
    """(cdk.out manifest, template, RecordedLive data) for s5 deployed with CDK."""
    template = {"Resources": {
        "OrdersQueue": {"Type": "AWS::SQS::Queue", "Properties": {
            "QueueName": f"{P}-orders", "VisibilityTimeout": 30,
            "RedrivePolicy": {"deadLetterTargetArn": {"Fn::GetAtt": ["OrdersDlq", "Arn"]}, "maxReceiveCount": 3}}},
        "OrdersDlq": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": f"{P}-orders-dlq"}},
        "WorkerRole": {"Type": "AWS::IAM::Role", "Properties": {"RoleName": f"{P}-worker-role"}},
        "WorkerFn": {"Type": "AWS::Lambda::Function", "Properties": {
            "FunctionName": f"{P}-worker", "Timeout": 10, "Role": {"Fn::GetAtt": ["WorkerRole", "Arn"]},
            "Environment": {"Variables": {"BUS_NAME": {"Ref": "OrdersBus"}}}}},
        "WorkerMapping": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
            "EventSourceArn": {"Fn::GetAtt": ["OrdersQueue", "Arn"]}, "FunctionName": {"Ref": "WorkerFn"},
            "BatchSize": 1, "Enabled": True}},
        "ApiFn": {"Type": "AWS::Lambda::Function", "Properties": {
            "FunctionName": f"{P}-api", "Environment": {"Variables": {"QUEUE_URL": {"Ref": "OrdersQueue"}}}}},
        "OrdersBus": {"Type": "AWS::Events::EventBus", "Properties": {"Name": f"{P}-bus"}},
        "OrderProcessedRule": {"Type": "AWS::Events::Rule", "Properties": {
            "Name": f"{P}-order-processed", "EventBusName": {"Ref": "OrdersBus"},
            "EventPattern": json.loads(PATTERN_OK),
            "Targets": [{"Id": "t1", "Arn": {"Fn::GetAtt": ["NotifierFn", "Arn"]}}]}},
        "NotifierFn": {"Type": "AWS::Lambda::Function", "Properties": {"FunctionName": f"{P}-notifier"}},
        "CDKMetadata": {"Type": "AWS::CDK::Metadata", "Properties": {}},
    }}
    manifest = {"version": "36.0.0", "artifacts": {CFN_STACK: {
        "type": "aws:cloudformation:stack", "environment": f"aws://{ACCT}/{REGION}",
        "properties": {"templateFile": f"{CFN_STACK}.template.json"}}}}
    phys = {"OrdersQueue": Q_URL, "OrdersDlq": DLQ_URL, "WorkerRole": f"{P}-worker-role",
            "WorkerFn": f"{P}-worker", "WorkerMapping": ESM_ID, "ApiFn": f"{P}-api",
            "OrdersBus": f"{P}-bus", "OrderProcessedRule": f"{P}-bus|{P}-order-processed",
            "NotifierFn": f"{P}-notifier"}
    _, data = scenario("s5")
    data = copy.deepcopy(data)
    data["configs"] = {}     # CloudFormation's own drift detection is the comparison here
    data["stacks"] = {CFN_STACK: {
        "resources": [{"LogicalResourceId": k, "PhysicalResourceId": v} for k, v in phys.items()],
        "drifts": [
            {"LogicalResourceId": "WorkerMapping", "ResourceType": "AWS::Lambda::EventSourceMapping",
             "StackResourceDriftStatus": "MODIFIED",
             "PropertyDifferences": [{"PropertyPath": "/Enabled", "ExpectedValue": "true",
                                      "ActualValue": "false", "DifferenceType": "NOT_EQUAL"}]},
            {"LogicalResourceId": "WorkerFn", "ResourceType": "AWS::Lambda::Function",
             "StackResourceDriftStatus": "IN_SYNC"},
        ]}}
    return manifest, template, data


# ── No IaC: discovered resources + AWS Config history ────────────────────────

def no_iac_s5() -> dict:
    _, data = scenario("s5")
    data = copy.deepcopy(data)
    lc = live_configs(esm_enabled=False)
    disc = [
        {"key": f"lambda:{P}-api", "type": "AWS::Lambda::Function", "name": f"{P}-api",
         "physical_id": f"{P}-api", "arn": arn("lambda", f"function:{P}-api"),
         "config": lc["aws_lambda_function.api"]},
        {"key": f"lambda:{P}-worker", "type": "AWS::Lambda::Function", "name": f"{P}-worker",
         "physical_id": f"{P}-worker", "arn": arn("lambda", f"function:{P}-worker"),
         "config": lc["aws_lambda_function.worker"]},
        {"key": f"lambda:{P}-notifier", "type": "AWS::Lambda::Function", "name": f"{P}-notifier",
         "physical_id": f"{P}-notifier", "arn": arn("lambda", f"function:{P}-notifier"),
         "config": lc["aws_lambda_function.notifier"]},
        {"key": f"esm:{ESM_ID}", "type": "AWS::Lambda::EventSourceMapping", "name": ESM_ID,
         "physical_id": ESM_ID, "arn": "", "config": {**lc["aws_lambda_event_source_mapping.worker"],
                                                      "State": "Disabled", "UUID": ESM_ID}},
        {"key": f"sqs:{P}-orders", "type": "AWS::SQS::Queue", "name": f"{P}-orders",
         "physical_id": Q_URL, "arn": arn("sqs", f"{P}-orders"), "config": {"QueueUrl": Q_URL}},
        {"key": f"sqs:{P}-orders-dlq", "type": "AWS::SQS::Queue", "name": f"{P}-orders-dlq",
         "physical_id": DLQ_URL, "arn": arn("sqs", f"{P}-orders-dlq"), "config": {"QueueUrl": DLQ_URL}},
        {"key": f"bus:{P}-bus", "type": "AWS::Events::EventBus", "name": f"{P}-bus",
         "physical_id": f"{P}-bus", "arn": arn("events", f"event-bus/{P}-bus"), "config": {"Name": f"{P}-bus"}},
        {"key": f"rule:{P}-bus/{P}-order-processed", "type": "AWS::Events::Rule",
         "name": f"{P}-order-processed", "physical_id": arn("events", f"rule/{P}-bus/{P}-order-processed"),
         "arn": arn("events", f"rule/{P}-bus/{P}-order-processed"),
         "config": {"Name": f"{P}-order-processed", "EventBusName": f"{P}-bus",
                    "Targets": [{"Id": "t1", "Arn": arn("lambda", f"function:{P}-notifier")}]}},
        {"key": f"api:{API_ID}", "type": "AWS::ApiGatewayV2::Api", "name": f"{P}-http",
         "physical_id": API_ID, "arn": "", "config": {"ApiId": API_ID}},
    ]
    data["discovered"] = disc
    live_by_key = {d["key"]: d["config"] for d in disc}
    data["configs"] = live_by_key
    hist = copy.deepcopy(live_by_key)
    hist[f"esm:{ESM_ID}"] = {**hist[f"esm:{ESM_ID}"], "Enabled": True, "State": "Enabled"}
    data["config_history"] = hist
    return data

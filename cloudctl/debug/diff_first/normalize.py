"""Shared vocabulary so Terraform, CloudFormation/CDK, Pulumi and live AWS can be
compared field by field.

Nothing here knows about failures. It only knows how resource TYPES are named
in each tool (a naming table, not a knowledge base) and how to compare two
config dicts whose keys are spelled differently (``reserved_concurrent_executions``
vs ``ReservedConcurrentExecutions`` vs ``reservedConcurrentExecutions``).
"""

from __future__ import annotations

import json
import re
from typing import Any

# ── Type names ───────────────────────────────────────────────────────────────
# Canonical vocabulary = CloudFormation type names: the Cloud Control API reads
# any of them live, and CDK synthesises to them. Terraform names map here;
# Pulumi's AWS provider is bridged from Terraform, so its names map through the
# Terraform name (aws:lambda/eventSourceMapping:EventSourceMapping ->
# aws_lambda_event_source_mapping).
TF_TO_CFN: dict[str, str] = {
    "aws_lambda_function": "AWS::Lambda::Function",
    "aws_lambda_event_source_mapping": "AWS::Lambda::EventSourceMapping",
    "aws_lambda_permission": "AWS::Lambda::Permission",
    "aws_lambda_function_url": "AWS::Lambda::Url",
    "aws_lambda_alias": "AWS::Lambda::Alias",
    "aws_sqs_queue": "AWS::SQS::Queue",
    "aws_sqs_queue_policy": "AWS::SQS::QueuePolicy",
    "aws_sns_topic": "AWS::SNS::Topic",
    "aws_sns_topic_subscription": "AWS::SNS::Subscription",
    "aws_dynamodb_table": "AWS::DynamoDB::Table",
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_s3_bucket_notification": "AWS::S3::BucketNotification",
    "aws_iam_role": "AWS::IAM::Role",
    "aws_iam_role_policy": "AWS::IAM::RolePolicy",
    "aws_iam_policy": "AWS::IAM::ManagedPolicy",
    "aws_iam_role_policy_attachment": "AWS::IAM::RolePolicyAttachment",
    "aws_cloudwatch_event_bus": "AWS::Events::EventBus",
    "aws_cloudwatch_event_rule": "AWS::Events::Rule",
    "aws_cloudwatch_event_target": "AWS::Events::Target",
    "aws_cloudwatch_metric_alarm": "AWS::CloudWatch::Alarm",
    "aws_cloudwatch_log_group": "AWS::Logs::LogGroup",
    "aws_apigatewayv2_api": "AWS::ApiGatewayV2::Api",
    "aws_apigatewayv2_integration": "AWS::ApiGatewayV2::Integration",
    "aws_apigatewayv2_route": "AWS::ApiGatewayV2::Route",
    "aws_apigatewayv2_stage": "AWS::ApiGatewayV2::Stage",
    "aws_kinesis_stream": "AWS::Kinesis::Stream",
    "aws_sfn_state_machine": "AWS::StepFunctions::StateMachine",
    "aws_ecs_service": "AWS::ECS::Service",
    "aws_ecs_task_definition": "AWS::ECS::TaskDefinition",
    "aws_pipes_pipe": "AWS::Pipes::Pipe",
    "aws_kms_key": "AWS::KMS::Key",
}

# Types that only watch or describe the system; a change on them cannot stop
# work flowing, so they are never part of a cause's scope.
OBSERVER_TYPES = {
    "AWS::CloudWatch::Alarm", "AWS::CloudWatch::Dashboard", "AWS::Logs::LogGroup",
    "AWS::Logs::MetricFilter", "AWS::Logs::SubscriptionFilter",
}

# Attachment types: they exist to grant/attach something to another resource
# (an IAM policy to a role, an invoke permission to a function). A resource's
# own scope includes the attachments of the things it references.
ATTACHMENT_TYPES = {
    "AWS::IAM::RolePolicy", "AWS::IAM::ManagedPolicy", "AWS::IAM::RolePolicyAttachment",
    "AWS::IAM::Policy", "AWS::Lambda::Permission", "AWS::SQS::QueuePolicy",
    "AWS::SNS::TopicPolicy", "AWS::S3::BucketPolicy",
}


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def pulumi_to_tf(pulumi_type: str) -> str:
    """aws:lambda/eventSourceMapping:EventSourceMapping -> aws_lambda_event_source_mapping."""
    m = re.match(r"^aws:([a-zA-Z0-9]+)/([a-zA-Z0-9]+):[A-Za-z0-9]+$", pulumi_type or "")
    if not m:
        return ""
    module, member = m.group(1).lower(), _snake(m.group(2))
    return f"aws_{module}_{member}"


def canonical_type(source_type: str) -> str:
    """Map any tool's type name to the CloudFormation name (unknown -> source name)."""
    t = source_type or ""
    if t.startswith("AWS::"):
        return t
    if t.startswith("aws:"):
        tf = pulumi_to_tf(t)
        return TF_TO_CFN.get(tf, tf or t)
    return TF_TO_CFN.get(t, t)


# ── Keys and values ──────────────────────────────────────────────────────────

def norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


# Metadata that changes on every deploy or read and says nothing about behaviour.
VOLATILE_KEYS = {
    "arn", "id", "lastmodified", "lastmodifiedtime", "version", "revisionid",
    "qualifiedarn", "invokearn", "sourcecodehash", "codesha256", "codesize",
    "tagsall", "tags", "statereasonmessage", "lastupdatestatus",
    "lastupdatestatusreason", "lastupdatestatusreasoncode", "laststatechange",
    "lastprocessingresult", "statetransitionreason", "createdtimestamp",
    "creationdate", "createdate", "lastmodifieddate", "uuid", "filename",
    "s3key", "s3bucket", "s3objectversion", "imageuri", "signingjobarn",
    "signingprofileversionarn", "statereason", "statereasoncode",
    "approximatenumberofmessages", "approximatenumberofmessagesnotvisible",
    "approximatenumberofmessagesdelayed", "itemcount", "tablesizebytes",
    "physicalresourceid", "logicalresourceid", "timestamp", "url",
}

# Two spellings of the same switch: Terraform/CloudFormation say Enabled=true,
# some live APIs say State="Enabled"/"Disabled". Generic, not service-specific.
_STATE_WORDS = {"enabled": True, "enabling": True, "disabled": False, "disabling": False}


def _maybe_json(value: Any) -> Any:
    if isinstance(value, str):
        s = value.strip()
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                return json.loads(s)
            except ValueError:
                return value
        # URL-encoded IAM documents (GetRolePolicy returns them this way)
        if s.startswith("%7B"):
            from urllib.parse import unquote
            return _maybe_json(unquote(s))
    return value


def _is_intrinsic(value: Any) -> bool:
    return isinstance(value, dict) and len(value) == 1 and (
        next(iter(value)) in ("Ref", "Condition") or str(next(iter(value))).startswith("Fn::")
    )


def canon_value(value: Any) -> Any:
    """Comparable form of a value: JSON strings parsed, numbers and booleans
    unified with their string spellings, lists of scalars order-free."""
    value = _maybe_json(value)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "false"):
            return low == "true"
        try:
            return float(low)
        except ValueError:
            return value.strip()
    if isinstance(value, dict):
        return {norm_key(k): canon_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        items = [canon_value(v) for v in value]
        if len(items) == 1 and not isinstance(items[0], (dict, list)):
            # Single-element list wrapping a scalar (IAM "Action": ["s3:GetObject"])
            # equals the bare scalar.
            return items[0]
        return sorted(items, key=lambda x: json.dumps(x, sort_keys=True, default=str))
    return value


def flatten(config: Any, prefix: str = "", out: dict | None = None,
            depth: int = 0) -> dict[str, Any]:
    """Flatten a config into {normalised.path: canonical leaf}. Terraform's
    single-element block lists (``environment = [{variables = {...}}]``) collapse
    so they line up with CloudFormation's ``Environment.Variables``. IAM-style
    documents and lists of objects stay as one canonical leaf."""
    if out is None:
        out = {}
    if depth > 6:
        out[prefix] = canon_value(config)
        return out
    config = _maybe_json(config)
    if isinstance(config, list) and len(config) == 1 and isinstance(config[0], dict):
        config = config[0]
    if isinstance(config, dict):
        if _is_intrinsic(config):
            return out            # unresolved CloudFormation intrinsic: not comparable
        # A policy document compares as a whole.
        keys = {norm_key(k) for k in config}
        if "statement" in keys and ("version" in keys or len(keys) == 1):
            out[prefix] = canon_value(config)
            return out
        for k, v in config.items():
            nk = norm_key(k)
            if not prefix and nk in VOLATILE_KEYS:
                continue
            flatten(v, f"{prefix}.{nk}" if prefix else nk, out, depth + 1)
        return out
    if prefix:
        out[prefix] = canon_value(config)
    return out


def _alias(flat: dict[str, Any]) -> dict[str, Any]:
    """Add the Enabled spelling when only a State word is present (and back)."""
    out = dict(flat)
    st = out.get("state")
    if "enabled" not in out and isinstance(st, str) and st.lower() in _STATE_WORDS:
        out["enabled"] = _STATE_WORDS[st.lower()]
    return out


def _empty(v: Any) -> bool:
    return v in (None, "", [], {}) or (isinstance(v, float) and v != v)


def diff_configs(expected: dict, live: dict, max_fields: int = 20) -> list[dict]:
    """Field-level differences on keys BOTH sides know. Keys only one side has
    are skipped: Terraform state carries computed attributes and live APIs
    return defaults, and neither is a sign of drift on its own."""
    e = _alias(flatten(expected))
    lv = _alias(flatten(live))
    # Compare enabled once; the State word only stands in for it.
    if "enabled" in e and "enabled" in lv:
        e.pop("state", None)
        lv.pop("state", None)
    out: list[dict] = []
    for k in sorted(set(e) & set(lv)):
        ev, lv_ = e[k], lv[k]
        if _empty(ev) and _empty(lv_):
            continue
        if ev != lv_:
            out.append({"field": k, "expected": ev, "live": lv_})
            if len(out) >= max_fields:
                break
    return out


# ── Identifier helpers ───────────────────────────────────────────────────────

_ARN_RE = re.compile(r"arn:aws[a-z\-]*:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s\"',]+")
_URL_RE = re.compile(r"https://sqs\.[a-z0-9\-]+\.amazonaws\.com/\d{12}/[A-Za-z0-9_\-.]+")


def identifiers_in(value: Any, limit: int = 200) -> set[str]:
    """Every string leaf (and ARN / queue URL inside it) of a value, lower-cased."""
    found: set[str] = set()

    def walk(v: Any, depth: int = 0) -> None:
        if len(found) >= limit or depth > 8:
            return
        v = _maybe_json(v)
        if isinstance(v, dict):
            for x in v.values():
                walk(x, depth + 1)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x, depth + 1)
        elif isinstance(v, str) and len(v) >= 3:
            low = v.lower()
            found.add(low)
            for m in _ARN_RE.findall(low):
                found.add(m)
                found.add(m.replace(":", "/").rstrip("/").split("/")[-1])
            for m in _URL_RE.findall(v):
                found.add(m.lower())
                found.add(m.lower().rsplit("/", 1)[-1])
    walk(value)
    return found


def get_field(config: dict, *names: str) -> Any:
    """First top-level field whose normalised name matches one of ``names``."""
    if not isinstance(config, dict):
        return None
    wanted = {norm_key(n) for n in names}
    for k, v in config.items():
        if norm_key(k) in wanted:
            v = _maybe_json(v)
            if isinstance(v, list) and len(v) == 1 and not isinstance(v[0], (list,)):
                return v[0] if isinstance(v[0], dict) else v
            return v
    return None

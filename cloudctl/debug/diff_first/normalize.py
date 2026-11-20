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
    "aws_cloudwatch_composite_alarm": "AWS::CloudWatch::CompositeAlarm",
    "aws_cloudwatch_dashboard": "AWS::CloudWatch::Dashboard",
    "aws_cloudwatch_log_metric_filter": "AWS::Logs::MetricFilter",
    "aws_cloudwatch_log_subscription_filter": "AWS::Logs::SubscriptionFilter",
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

# Azure and Google Cloud resources keep their own clouds' type names: the ARM
# resource type (``Microsoft.Insights/metricAlerts``) and the Cloud Asset
# Inventory type (``monitoring.googleapis.com/AlertPolicy``). Kept apart from
# TF_TO_CFN, whose words also name AWS references inside configs.
TF_TO_NATIVE: dict[str, str] = {
    # Azure
    "azurerm_monitor_metric_alert": "Microsoft.Insights/metricAlerts",
    "azurerm_monitor_scheduled_query_rules_alert": "Microsoft.Insights/scheduledQueryRules",
    "azurerm_monitor_scheduled_query_rules_alert_v2": "Microsoft.Insights/scheduledQueryRules",
    "azurerm_monitor_activity_log_alert": "Microsoft.Insights/activityLogAlerts",
    "azurerm_monitor_smart_detector_alert_rule": "Microsoft.AlertsManagement/smartDetectorAlertRules",
    "azurerm_monitor_action_group": "Microsoft.Insights/actionGroups",
    "azurerm_monitor_diagnostic_setting": "Microsoft.Insights/diagnosticSettings",
    "azurerm_application_insights": "Microsoft.Insights/components",
    "azurerm_log_analytics_workspace": "Microsoft.OperationalInsights/workspaces",
    "azurerm_portal_dashboard": "Microsoft.Portal/dashboards",
    "azurerm_dashboard": "Microsoft.Portal/dashboards",
    "azurerm_monitor_autoscale_setting": "Microsoft.Insights/autoscaleSettings",
    "azurerm_linux_function_app": "Microsoft.Web/sites",
    "azurerm_windows_function_app": "Microsoft.Web/sites",
    "azurerm_function_app": "Microsoft.Web/sites",
    "azurerm_linux_web_app": "Microsoft.Web/sites",
    "azurerm_windows_web_app": "Microsoft.Web/sites",
    "azurerm_service_plan": "Microsoft.Web/serverfarms",
    "azurerm_storage_account": "Microsoft.Storage/storageAccounts",
    "azurerm_servicebus_namespace": "Microsoft.ServiceBus/namespaces",
    "azurerm_servicebus_queue": "Microsoft.ServiceBus/namespaces/queues",
    "azurerm_servicebus_topic": "Microsoft.ServiceBus/namespaces/topics",
    "azurerm_eventhub_namespace": "Microsoft.EventHub/namespaces",
    "azurerm_eventhub": "Microsoft.EventHub/namespaces/eventhubs",
    "azurerm_key_vault": "Microsoft.KeyVault/vaults",
    "azurerm_cosmosdb_account": "Microsoft.DocumentDB/databaseAccounts",
    "azurerm_container_app": "Microsoft.App/containerApps",
    "azurerm_kubernetes_cluster": "Microsoft.ContainerService/managedClusters",
    # Google Cloud
    "google_monitoring_alert_policy": "monitoring.googleapis.com/AlertPolicy",
    "google_monitoring_notification_channel": "monitoring.googleapis.com/NotificationChannel",
    "google_monitoring_dashboard": "monitoring.googleapis.com/Dashboard",
    "google_monitoring_uptime_check_config": "monitoring.googleapis.com/UptimeCheckConfig",
    "google_logging_metric": "logging.googleapis.com/LogMetric",
    "google_logging_project_sink": "logging.googleapis.com/LogSink",
    "google_cloudfunctions2_function": "cloudfunctions.googleapis.com/Function",
    "google_cloudfunctions_function": "cloudfunctions.googleapis.com/CloudFunction",
    "google_cloud_run_v2_service": "run.googleapis.com/Service",
    "google_cloud_run_service": "run.googleapis.com/Service",
    "google_pubsub_topic": "pubsub.googleapis.com/Topic",
    "google_pubsub_subscription": "pubsub.googleapis.com/Subscription",
    "google_storage_bucket": "storage.googleapis.com/Bucket",
    "google_sql_database_instance": "sqladmin.googleapis.com/Instance",
    "google_service_account": "iam.googleapis.com/ServiceAccount",
    "google_container_cluster": "container.googleapis.com/Cluster",
}

# Types that only watch or describe the system (alarms, alert rules,
# dashboards, log pipelines, notification targets). A change on them cannot
# stop work flowing, so they are never part of a cause's scope; their drift is
# still reported, because a silenced alarm hides the next outage.
OBSERVER_TYPES = {
    "AWS::CloudWatch::Alarm", "AWS::CloudWatch::CompositeAlarm", "AWS::CloudWatch::Dashboard",
    "AWS::CloudWatch::AnomalyDetector", "AWS::Logs::LogGroup",
    "AWS::Logs::MetricFilter", "AWS::Logs::SubscriptionFilter",
    "Microsoft.Insights/metricAlerts", "Microsoft.Insights/scheduledQueryRules",
    "Microsoft.Insights/activityLogAlerts", "Microsoft.AlertsManagement/smartDetectorAlertRules",
    "Microsoft.Insights/actionGroups", "Microsoft.Insights/diagnosticSettings",
    "Microsoft.Insights/components", "Microsoft.OperationalInsights/workspaces",
    "Microsoft.Portal/dashboards",
    "monitoring.googleapis.com/AlertPolicy", "monitoring.googleapis.com/NotificationChannel",
    "monitoring.googleapis.com/Dashboard", "monitoring.googleapis.com/UptimeCheckConfig",
    "logging.googleapis.com/LogMetric", "logging.googleapis.com/LogSink",
}
_OBSERVER_LOWER = {t.lower() for t in OBSERVER_TYPES}


def is_observer(cfn_type: str) -> bool:
    """Case-insensitive: ARM type names are case-insensitive."""
    return (cfn_type or "").lower() in _OBSERVER_LOWER


def cloud_of_type(cfn_type: str, source_type: str = "") -> str:
    """aws | azure | gcp, from either the canonical or the IaC's own type name."""
    t, s = (cfn_type or ""), (source_type or "")
    if t.startswith("AWS::") or s.startswith(("aws_", "aws:")):
        return "aws"
    if t.lower().startswith("microsoft.") or s.startswith(("azurerm_", "azapi_", "azure-native:", "azure:")):
        return "azure"
    if ".googleapis.com/" in t or s.startswith(("google_", "gcp:")):
        return "gcp"
    return "aws"

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
    """aws:lambda/eventSourceMapping:EventSourceMapping -> aws_lambda_event_source_mapping.
    Pulumi's GCP provider is bridged the same way (gcp:monitoring/alertPolicy:AlertPolicy
    -> google_monitoring_alert_policy)."""
    m = re.match(r"^(aws|gcp):([a-zA-Z0-9]+)/([a-zA-Z0-9]+):[A-Za-z0-9]+$", pulumi_type or "")
    if not m:
        return ""
    prefix = {"aws": "aws", "gcp": "google"}[m.group(1)]
    module, member = m.group(2).lower(), _snake(m.group(3))
    return f"{prefix}_{module}_{member}"


def _azure_native_type(pulumi_type: str) -> str:
    """azure-native:insights:MetricAlert -> Microsoft.insights/metricAlerts (ARM
    type names compare case-insensitively)."""
    m = re.match(r"^azure-native:([a-zA-Z0-9]+)(?:/[^:]+)?:([A-Za-z0-9]+)$", pulumi_type or "")
    if not m:
        return ""
    member = m.group(2)
    return f"Microsoft.{m.group(1)}/{member[0].lower()}{member[1:]}s"


def canonical_type(source_type: str) -> str:
    """Map any tool's type name to the canonical name: CloudFormation's for AWS,
    the ARM type for Azure, the Cloud Asset type for Google Cloud (unknown ->
    the source name)."""
    t = source_type or ""
    if t.startswith("AWS::") or t.lower().startswith("microsoft.") or ".googleapis.com/" in t:
        return t
    if t.startswith("azure-native:"):
        return _azure_native_type(t) or t
    if t.startswith(("aws:", "gcp:")):
        tf = pulumi_to_tf(t)
        return TF_TO_CFN.get(tf) or TF_TO_NATIVE.get(tf) or tf or t
    return TF_TO_CFN.get(t) or TF_TO_NATIVE.get(t) or t


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
    config = _pairs_to_dict(config)
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


def _pairs_to_dict(value: Any) -> Any:
    """[{"Name": "QueueName", "Value": "q"}] -> {"QueueName": "q"}. CloudFormation
    and most cloud APIs spell maps as name/value (or key/value) pair lists,
    Terraform as plain maps; both mean the same thing."""
    if not isinstance(value, list) or not value or not all(isinstance(x, dict) for x in value):
        return value
    out: dict = {}
    for x in value:
        keys = {norm_key(k): k for k in x}
        if set(keys) not in ({"name", "value"}, {"key", "value"}):
            return value
        name = x[keys.get("name") or keys["key"]]
        if not isinstance(name, str) or name in out:
            return value
        out[name] = x[keys["value"]]
    return out


def _is_policy(v: Any) -> bool:
    return isinstance(v, dict) and "statement" in v


def loose_equal(a: Any, b: Any, depth: int = 0) -> bool:
    """Equality that tolerates what one side leaves out. Terraform state lists
    every attribute of a nested block (most null or empty) and wraps blocks in
    one-element lists; cloud APIs omit defaults and return plain objects. Keys
    only one side has, or that are empty on either side, are skipped, the same
    rule ``diff_configs`` applies at the top level. Policy documents still
    compare whole: a statement or condition missing on one side is a change."""
    if depth > 8 or _is_policy(a) or _is_policy(b):
        return a == b
    if isinstance(a, list) and len(a) == 1 and isinstance(b, dict):
        a = a[0]
    if isinstance(b, list) and len(b) == 1 and isinstance(a, dict):
        b = b[0]
    if isinstance(a, dict) and isinstance(b, dict):
        for k in set(a) & set(b):
            if _empty(a[k]) or _empty(b[k]):
                continue
            if not loose_equal(a[k], b[k], depth + 1):
                return False
        return True
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return a == b
        if all(isinstance(x, dict) for x in a + b):
            # canon_value sorted both lists, but extra keys on one side can sort
            # the same items differently: match each item to any unused one.
            unused = list(b)
            for x in a:
                hit = next((i for i, y in enumerate(unused) if loose_equal(x, y, depth + 1)), None)
                if hit is None:
                    return False
                unused.pop(hit)
            return True
        return a == b
    return a == b


def _alias(flat: dict[str, Any]) -> dict[str, Any]:
    """Add the Enabled spelling when only a State word is present (and back)."""
    out = dict(flat)
    st = out.get("state")
    if "enabled" not in out and isinstance(st, str) and st.lower() in _STATE_WORDS:
        out["enabled"] = _STATE_WORDS[st.lower()]
    return out


def _empty(v: Any) -> bool:
    return v in (None, "", [], {}) or (isinstance(v, float) and v != v)


def _same_name(key: str, a: Any, b: Any) -> bool:
    """A name field where one side is the short name and the other the full
    resource path: Terraform keeps ``orders-api``, Cloud Run returns
    ``projects/p/locations/l/services/orders-api``."""
    if key.split(".")[-1] not in ("name", "id") or not (isinstance(a, str) and isinstance(b, str)):
        return False
    short, long_ = sorted((a.strip("/").lower(), b.strip("/").lower()), key=len)
    return bool(short) and "/" not in short and long_.endswith("/" + short)


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
        if ev != lv_ and not loose_equal(ev, lv_) and not _same_name(k, ev, lv_):
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

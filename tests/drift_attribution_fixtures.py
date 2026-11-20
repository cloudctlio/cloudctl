"""Recordings for monitor drift and who-made-each-change, on AWS, Azure and
Google Cloud.

The AWS cases reuse the complex orders app (diff_first_fixtures) and mirror the
research drift eval: D3 changes the api function's QUEUE_URL by hand with
boto3; C2 makes the same change through ``terraform apply``; S3 raises the
dead-letter alarm's threshold by hand. Audit records are raw, in each cloud's
own format, so the replays exercise the same parsing as a live run.
"""

from __future__ import annotations

import copy
import json

import diff_first_fixtures as fx

P, ACCT, REGION = fx.P, fx.ACCT, fx.REGION
SSO_ROLE = "AWSReservedSSO_AdministratorAccess_0123456789abcdef"
SSO_ARN = f"arn:aws:sts::{ACCT}:assumed-role/{SSO_ROLE}/dev@example.com"
BOTO3_UA = ("Boto3/1.35.60 md/Botocore#1.35.60 ua/2.0 os/windows#11 md/arch#amd64 "
            "lang/python#3.13.1 md/pyimpl#CPython cfg/retry-mode#legacy Botocore/1.35.60")
TF_AWS_UA = ("APN/1.0 HashiCorp/1.0 Terraform/1.10.5 (+https://www.terraform.io) "
             "terraform-provider-aws/5.80.0 (+https://registry.terraform.io/providers/hashicorp/aws) "
             "aws-sdk-go-v2/1.32.6 ua/2.1 os/windows lang/go#1.23.3 md/GOOS#windows m/E,g")
CLI_UA = "aws-cli/2.22.1 md/awscrt#0.22.0 ua/2.0 os/windows#11 md/arch#amd64 lang/python#3.12.6"
BAD_URL = f"https://sqs.{REGION}.amazonaws.com/{ACCT}/{P}-orders-v2"
BAD_ENV = {"TABLE_NAME": f"{P}-orders", "QUEUE_URL": BAD_URL}
ALARM = f"{P}-orders-dlq-not-empty"
ALARM_ARN = f"arn:aws:cloudwatch:{REGION}:{ACCT}:alarm:{ALARM}"


def cloudtrail(ago: float, name: str, source: str, params: dict, *, ua: str = BOTO3_UA,
               arn: str = SSO_ARN, console: bool = False, invoked_by: str = "",
               src_ip: str = "203.0.113.10", resources: list[str] | None = None,
               ptype: str = "AssumedRole") -> dict:
    """A LookupEvents record, the way boto3 returns it."""
    uid: dict = {"type": ptype, "arn": arn, "accountId": ACCT,
                 "sessionContext": {"sessionIssuer": {"type": "Role", "userName": arn.split("/")[1]
                                                      if "/" in arn else arn}}}
    if invoked_by:
        uid["invokedBy"] = invoked_by
    detail = {"eventVersion": "1.10", "userIdentity": uid, "eventTime": fx.t(ago),
              "eventSource": source, "eventName": name, "awsRegion": REGION,
              "sourceIPAddress": src_ip, "userAgent": ua, "requestParameters": params,
              "readOnly": False}
    if console:
        detail["sessionCredentialFromConsole"] = "true"
    return {"EventId": f"e-{name}-{ago}", "EventName": name, "EventSource": source,
            "EventTime": fx.t(ago), "Username": arn.split("/")[-1],
            "Resources": [{"ResourceName": r} for r in resources or []],
            "CloudTrailEvent": json.dumps(detail)}


def _api_change(ago: float = 16, **kw) -> dict:
    return cloudtrail(ago, "UpdateFunctionConfiguration20150331v2", "lambda.amazonaws.com",
                      {"functionName": f"{P}-api", "environment": {"variables": BAD_ENV}}, **kw)


def _symptom_metrics() -> dict:
    """POST /orders fails and nothing reaches the queue from ~15 minutes ago."""
    return fx.metrics(api_5xx=[(15, 0, 90.0)], q_sent=[(15, 0, 0.0)], q_deleted=[(15, 0, 0.0)],
                      w_inv=[(15, 0, 0.0)], rule_matched=[(15, 0, 0.0)], n_inv=[(15, 0, 0.0)])


def aws_case(case: str) -> tuple[dict, dict]:
    """(terraform state, RecordedLive data).

    d3            QUEUE_URL changed by hand with boto3 (state still has the good URL)
    c2            the same change made by ``terraform apply`` (state has it too)
    console       the same hand change, made in the console
    cfn           the change made by the CloudFormation service
    tf_other      Terraform's user agent, but this state doesn't hold the change
    s3            the alarm's threshold raised by hand; nothing is broken
    s3_symptom    alarm silenced by hand while the D3 fault is live
    alarm_actions alarm actions switched off by hand (DisableAlarmActions)
    """
    good_attrs = fx.tf_attrs()
    alarm_attrs = {"id": ALARM, "alarm_name": ALARM, "arn": ALARM_ARN,
                   "namespace": "AWS/SQS", "metric_name": "ApproximateNumberOfMessagesVisible",
                   "dimensions": {"QueueName": f"{P}-orders-dlq"}, "statistic": "Maximum",
                   "period": 60, "evaluation_periods": 1, "threshold": 0.0,
                   "comparison_operator": "GreaterThanThreshold", "actions_enabled": True,
                   "alarm_actions": [], "treat_missing_data": "notBreaching", "tags_all": {}}
    good_attrs[("aws_cloudwatch_metric_alarm", "dlq")] = alarm_attrs
    live_alarm = {"AlarmName": ALARM, "Namespace": "AWS/SQS",
                  "MetricName": "ApproximateNumberOfMessagesVisible",
                  "Dimensions": [{"Name": "QueueName", "Value": f"{P}-orders-dlq"}],
                  "Statistic": "Maximum", "Period": 60, "EvaluationPeriods": 1, "Threshold": 0.0,
                  "ComparisonOperator": "GreaterThanThreshold", "ActionsEnabled": True,
                  "AlarmActions": [], "TreatMissingData": "notBreaching"}
    configs = fx.live_configs()
    configs["aws_cloudwatch_metric_alarm.dlq"] = live_alarm
    attrs = good_attrs
    audit: list[dict] = []
    mets = fx.metrics()
    if case in ("d3", "console", "tf_other", "s3_symptom", "cfn"):
        configs["aws_lambda_function.api"] = fx.live_configs(api_env=BAD_ENV)["aws_lambda_function.api"]
        mets = _symptom_metrics()
        kw = {"d3": {}, "s3_symptom": {}, "console": {"console": True, "ua": "AWS Internal"},
              "tf_other": {"ua": TF_AWS_UA},
              "cfn": {"ua": "cloudformation.amazonaws.com", "invoked_by": "cloudformation.amazonaws.com",
                      "src_ip": "cloudformation.amazonaws.com",
                      "arn": f"arn:aws:sts::{ACCT}:assumed-role/cdk-hnb659fds-cfn-exec-role-{ACCT}-{REGION}/AWSCloudFormation"}}[case]
        audit.append(_api_change(**kw))
        if case == "cfn":
            # CloudFormation's own record holds the new value, so there is no drift.
            attrs = copy.deepcopy(good_attrs)
            attrs[("aws_lambda_function", "api")] = fx.tf_attrs(api_env=BAD_ENV)[("aws_lambda_function", "api")]
    elif case == "c2":
        attrs = copy.deepcopy(good_attrs)
        attrs[("aws_lambda_function", "api")] = fx.tf_attrs(api_env=BAD_ENV)[("aws_lambda_function", "api")]
        configs["aws_lambda_function.api"] = fx.live_configs(api_env=BAD_ENV)["aws_lambda_function.api"]
        mets = _symptom_metrics()
        audit.append(_api_change(ua=TF_AWS_UA))
    if case in ("s3", "s3_symptom"):
        live_alarm["Threshold"] = 100.0
        put = {k[0].lower() + k[1:]: v for k, v in live_alarm.items()}
        audit.append(cloudtrail(20, "PutMetricAlarm", "monitoring.amazonaws.com", put, ua=CLI_UA))
    if case == "alarm_actions":
        live_alarm["ActionsEnabled"] = False
        audit.append(cloudtrail(12, "DisableAlarmActions", "monitoring.amazonaws.com",
                                {"alarmNames": [ALARM]}, ua="AWS Internal", console=True,
                                resources=[ALARM_ARN]))
    data = {"now": fx.t(0), "configs": configs, "events": fx.background_events(),
            "metrics": mets, "audit": {"aws": audit}}
    return fx.tf_state(attrs), data


# ── Azure ────────────────────────────────────────────────────────────────────

SUB = "00000000-1111-2222-3333-444444444444"
RG = f"/subscriptions/{SUB}/resourceGroups/orders-rg/providers"
ALERT_ID = f"{RG}/Microsoft.Insights/metricAlerts/orders-5xx"
APP_ID = f"{RG}/Microsoft.Web/sites/orders-func"
PORTAL_APP = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
CLI_APP = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
DEPLOY_SP = "9f0c1d2e-3b4a-5c6d-7e8f-90a1b2c3d4e5"


def azure_activity(ago: float, op: str, rid: str, *, caller: str, appid: str, idtyp: str,
                   status: str = "Succeeded", correlation: str = "corr-1") -> dict:
    """An Activity Log record as the REST API returns it."""
    return {"caller": caller, "correlationId": correlation, "eventTimestamp": fx.t(ago),
            "operationName": {"value": op, "localizedValue": op},
            "resourceId": rid, "status": {"value": status}, "subStatus": {"value": ""},
            "claims": {"appid": appid, "idtyp": idtyp},
            "httpRequest": {"clientIpAddress": "198.51.100.7", "method": "PUT"},
            "category": {"value": "Administrative"}}


def azure_case(case: str) -> tuple[dict, dict]:
    """portal_alert   metric alert switched off in the Azure portal (monitor drift, by hand)
    tf_sp          app setting changed by the deploy service principal; state holds it
    cli_hand       app setting changed with `az`, live differs from state
    cli_tf         app setting changed with Azure CLI credentials, state holds it
                   (Terraform signed in with `az login` looks like this)
    arm            app setting changed by an ARM/Bicep deployment"""
    from cloudctl.debug.diff_first.live_clouds import _arm_shape
    alert = {"id": ALERT_ID, "name": "orders-5xx", "resource_group_name": "orders-rg",
             "enabled": True, "severity": 2, "window_size": "PT5M", "frequency": "PT1M",
             "criteria": [{"metric_namespace": "Microsoft.Web/sites", "metric_name": "Http5xx",
                           "aggregation": "Total", "operator": "GreaterThan", "threshold": 10,
                           "dimension": [], "skip_metric_validation": False}],
             "scopes": [APP_ID], "tags": {}}
    app_good = {"id": APP_ID, "name": "orders-func", "location": "eastus",
                "app_settings": {"QUEUE_NAME": "orders"}, "enabled": True, "https_only": True}
    app_new = {**app_good, "app_settings": {"QUEUE_NAME": "orders-v2"}}

    def live_alert(enabled=True, threshold=10):
        return _arm_shape({"id": ALERT_ID, "name": "orders-5xx", "type": "Microsoft.Insights/metricAlerts",
                           "location": "global", "properties": {
                               "enabled": enabled, "severity": 2, "windowSize": "PT5M",
                               "evaluationFrequency": "PT1M", "scopes": [APP_ID],
                               "criteria": {"odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                                            "allOf": [{"name": "c1", "metricName": "Http5xx",
                                                       "metricNamespace": "Microsoft.Web/sites",
                                                       "operator": "GreaterThan", "threshold": threshold,
                                                       "timeAggregation": "Total"}]}}})

    def live_app(settings):
        return _arm_shape({"id": APP_ID, "name": "orders-func", "type": "Microsoft.Web/sites",
                           "location": "eastus", "properties": {"enabled": True, "httpsOnly": True},
                           "app_settings": settings})

    state_app, live_app_cfg, audit = app_good, live_app({"QUEUE_NAME": "orders"}), []
    alert_live = live_alert()
    user = "dev@contoso.example"
    if case == "portal_alert":
        alert_live = live_alert(enabled=False)
        audit += [azure_activity(13, "Microsoft.Insights/metricAlerts/write", ALERT_ID, caller=user,
                                 appid=PORTAL_APP, idtyp="user", status="Started"),
                  azure_activity(13, "Microsoft.Insights/metricAlerts/write", ALERT_ID, caller=user,
                                 appid=PORTAL_APP, idtyp="user")]
    elif case in ("tf_sp", "cli_tf", "arm"):
        state_app, live_app_cfg = app_new, live_app({"QUEUE_NAME": "orders-v2"})
        if case == "tf_sp":
            audit.append(azure_activity(14, "Microsoft.Web/sites/config/write", APP_ID + "/config/appsettings",
                                        caller=DEPLOY_SP, appid=DEPLOY_SP, idtyp="app"))
        elif case == "cli_tf":
            audit.append(azure_activity(14, "Microsoft.Web/sites/config/write", APP_ID + "/config/appsettings",
                                        caller=user, appid=CLI_APP, idtyp="user"))
        else:
            audit += [azure_activity(15, "Microsoft.Resources/deployments/write",
                                     f"/subscriptions/{SUB}/resourceGroups/orders-rg/providers/"
                                     "Microsoft.Resources/deployments/main", caller=user, appid=CLI_APP,
                                     idtyp="user", correlation="corr-deploy"),
                      azure_activity(14, "Microsoft.Web/sites/config/write", APP_ID + "/config/appsettings",
                                     caller=user, appid=CLI_APP, idtyp="user", correlation="corr-deploy")]
    elif case == "cli_hand":
        live_app_cfg = live_app({"QUEUE_NAME": "orders-v2"})
        audit.append(azure_activity(14, "Microsoft.Web/sites/config/write", APP_ID + "/config/appsettings",
                                    caller=user, appid=CLI_APP, idtyp="user"))
    state = {"version": 4, "terraform_version": "1.10.5", "resources": [
        {"mode": "managed", "type": "azurerm_monitor_metric_alert", "name": "http5xx",
         "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": alert}]},
        {"mode": "managed", "type": "azurerm_linux_function_app", "name": "orders",
         "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": state_app}]},
    ]}
    data = {"now": fx.t(0), "configs": {"azurerm_monitor_metric_alert.http5xx": alert_live,
                                        "azurerm_linux_function_app.orders": live_app_cfg},
            "events": [], "metrics": {}, "audit": {"azure": audit}}
    return state, data


# ── Google Cloud ─────────────────────────────────────────────────────────────

PROJECT = "orders-prod"
POLICY = f"projects/{PROJECT}/alertPolicies/1234567890"
RUN_SVC = f"projects/{PROJECT}/locations/us-central1/services/orders-api"
TF_GCP_UA = ("Terraform/1.10.5 (+https://www.terraform.io) Terraform-Plugin-SDK/2.33.0 "
             "terraform-provider-google/6.12.0")
GCLOUD_UA = ("google-cloud-sdk gcloud/502.0.0 command/gcloud.run.services.update "
             "invocation-id/0a1b2c environment/None environment-version/None")
CONSOLE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0,gzip(gfe)"


def gcp_audit(ago: float, method: str, service: str, resource: str, *, ua: str,
              email: str = "dev@example.com", code: int = 0) -> dict:
    """An Admin Activity audit LogEntry as entries.list returns it."""
    return {"logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
            "timestamp": fx.t(ago), "severity": "NOTICE",
            "protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                             "serviceName": service, "methodName": method, "resourceName": resource,
                             "authenticationInfo": {"principalEmail": email},
                             "requestMetadata": {"callerIp": "198.51.100.9", "callerSuppliedUserAgent": ua},
                             "status": {"code": code} if code else {}}}


def gcp_case(case: str) -> tuple[dict, dict]:
    """console_policy  alert policy threshold raised in the console (monitor drift, by hand)
    tf_run          Cloud Run env var changed by Terraform; state holds it
    gcloud_run      the same change made with gcloud; live differs from state"""
    policy = {"id": POLICY, "name": POLICY, "project": PROJECT, "display_name": "API 5xx",
              "enabled": True, "combiner": "OR", "notification_channels": [],
              "conditions": [{"display_name": "5xx rate", "name": f"{POLICY}/conditions/1",
                              "condition_absent": [], "condition_matched_log": [],
                              "condition_threshold": [{"comparison": "COMPARISON_GT", "duration": "60s",
                                                       "threshold_value": 0.5, "filter": "metric.type=x",
                                                       "trigger": [], "aggregations": []}]}]}

    def live_policy(threshold=0.5, enabled=True):
        return {"name": POLICY, "displayName": "API 5xx", "enabled": enabled, "combiner": "OR",
                "conditions": [{"displayName": "5xx rate", "name": f"{POLICY}/conditions/1",
                                "conditionThreshold": {"comparison": "COMPARISON_GT", "duration": "60s",
                                                       "thresholdValue": threshold, "filter": "metric.type=x"}}]}

    def svc(topic):
        return {"id": RUN_SVC, "name": "orders-api", "project": PROJECT, "location": "us-central1",
                "template": [{"containers": [{"image": "gcr.io/x/api:1",
                                              "env": [{"name": "TOPIC", "value": topic}]}]}]}

    def live_svc(topic):
        return {"name": RUN_SVC, "template": {"containers": [{"image": "gcr.io/x/api:1",
                                                              "env": [{"name": "TOPIC", "value": topic}]}]}}

    state_svc, live_svc_cfg, pol_live, audit = svc("orders"), live_svc("orders"), live_policy(), []
    if case == "console_policy":
        pol_live = live_policy(threshold=5.0)
        audit.append(gcp_audit(11, "google.monitoring.v3.AlertPolicyService.UpdateAlertPolicy",
                               "monitoring.googleapis.com", POLICY, ua=CONSOLE_UA))
        audit.append(gcp_audit(10, "google.monitoring.v3.AlertPolicyService.GetAlertPolicy",
                               "monitoring.googleapis.com", POLICY, ua=CONSOLE_UA))
    elif case == "tf_run":
        state_svc, live_svc_cfg = svc("orders-v2"), live_svc("orders-v2")
        audit.append(gcp_audit(14, "google.cloud.run.v2.Services.UpdateService", "run.googleapis.com",
                               RUN_SVC, ua=TF_GCP_UA, email=f"deployer@{PROJECT}.iam.gserviceaccount.com"))
    elif case == "gcloud_run":
        live_svc_cfg = live_svc("orders-v2")
        audit.append(gcp_audit(14, "google.cloud.run.v2.Services.UpdateService", "run.googleapis.com",
                               RUN_SVC, ua=GCLOUD_UA))
    state = {"version": 4, "terraform_version": "1.10.5", "resources": [
        {"mode": "managed", "type": "google_monitoring_alert_policy", "name": "api_5xx",
         "provider": 'provider["registry.terraform.io/hashicorp/google"]',
         "instances": [{"attributes": policy}]},
        {"mode": "managed", "type": "google_cloud_run_v2_service", "name": "api",
         "provider": 'provider["registry.terraform.io/hashicorp/google"]',
         "instances": [{"attributes": state_svc}]},
    ]}
    data = {"now": fx.t(0), "configs": {"google_monitoring_alert_policy.api_5xx": pol_live,
                                        "google_cloud_run_v2_service.api": live_svc_cfg},
            "events": [], "metrics": {}, "audit": {"gcp": audit}}
    return state, data

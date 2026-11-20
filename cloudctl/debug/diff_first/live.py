"""Read-only access to the live account, behind one small interface.

``AwsLive`` talks to AWS (Describe/Get/List/Lookup calls only). ``RecordedLive``
serves the same calls from a dict, for replay tests and recorded incidents.
The checks only ever see the ``LiveSource`` methods, so a recording and a live
account behave the same.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Protocol

from cloudctl.debug.diff_first.model import Resource, iso, to_dt
from cloudctl.debug.diff_first.normalize import get_field

NOT_FOUND = {"__not_found__": True}


class LiveSource(Protocol):
    def read(self, resource: Resource) -> dict | None: ...
    def discover(self) -> list[Resource]: ...
    def write_events(self, start: datetime, end: datetime) -> list[dict]: ...
    def metrics(self, queries: list[dict], start: datetime, end: datetime, period: int) -> dict: ...
    def stack_resources(self, stack: str) -> list[dict]: ...
    def stack_drifts(self, stack: str, detect: bool = False) -> list[dict]: ...
    def config_history(self, resource: Resource, at: str | None) -> dict | None: ...


# ── Recorded (replay) ────────────────────────────────────────────────────────

class RecordedLive:
    """Serve a recorded incident. Shape:

    {"now": iso, "configs": {key-or-name: {...} | {"__not_found__": true}},
     "discovered": [resource dicts], "events": [cloudtrail rows],
     "metrics": {"<type>|<name>|<metric>": [[iso, value], ...]},
     "stacks": {stack: {"resources": [...], "drifts": [...]}},
     "config_history": {key-or-name: {...}}}
    """

    def __init__(self, data: dict):
        self.data = data
        self.calls: list[str] = []

    def _lookup(self, table: str, r: Resource) -> Any:
        t = self.data.get(table) or {}
        for k in (r.key, r.name, r.physical_id, r.arn):
            if k and k in t:
                return t[k]
        return None

    def read(self, resource: Resource) -> dict | None:
        self.calls.append(f"read:{resource.key}")
        return self._lookup("configs", resource)

    def discover(self) -> list[Resource]:
        self.calls.append("discover")
        return [Resource(**{**r, "source": "live"}) for r in self.data.get("discovered") or []]

    def write_events(self, start: datetime, end: datetime) -> list[dict]:
        """Rows from ``events`` (already in row shape), plus raw audit records
        under ``audit`` ({"aws": [LookupEvents records], "azure": [Activity Log
        records], "gcp": [audit LogEntry]}), normalised the way the live
        sources do it, so a replay exercises the same parsing."""
        from cloudctl.debug.diff_first.attribution import is_write, normalize_audit
        self.calls.append("write_events")
        rows = list(self.data.get("events") or [])
        for cloud, records in (self.data.get("audit") or {}).items():
            rows += [r for r in (normalize_audit(x, cloud) for x in records or []) if is_write(r)]
        out = []
        for e in rows:
            t = to_dt(e.get("time"))
            if t and start <= t <= end:
                out.append(e)
        return out

    def metrics(self, queries: list[dict], start: datetime, end: datetime, period: int) -> dict:
        self.calls.append("metrics")
        src = self.data.get("metrics") or {}
        out: dict = {}
        for q in queries:
            series = src.get(q["key"])
            if series is None:
                continue
            out[q["id"]] = [(t, float(v)) for t, v in series
                            if (dt := to_dt(t)) and start <= dt <= end]
        return out

    def stack_resources(self, stack: str) -> list[dict]:
        return ((self.data.get("stacks") or {}).get(stack) or {}).get("resources") or []

    def stack_drifts(self, stack: str, detect: bool = False) -> list[dict]:
        return ((self.data.get("stacks") or {}).get(stack) or {}).get("drifts") or []

    def config_history(self, resource: Resource, at: str | None) -> dict | None:
        return self._lookup("config_history", resource)

    def now(self) -> datetime:
        return to_dt(self.data.get("now")) or datetime.now(timezone.utc)


# ── AWS ──────────────────────────────────────────────────────────────────────

def _cc_identifier(r: Resource) -> str:
    """Cloud Control primary identifier for the common types; physical id otherwise."""
    t, cfg = r.type, r.config or {}
    if t == "AWS::IAM::RolePolicy":
        pol = get_field(cfg, "name", "policy_name", "PolicyName") or ""
        role = get_field(cfg, "role", "role_name", "RoleName") or ""
        if not (pol and role) and ":" in r.physical_id:          # terraform id role:policy
            role, pol = r.physical_id.split(":", 1)
        role = str(role).split("/")[-1]
        return f"{pol}|{role}" if pol and role else r.physical_id
    if t == "AWS::SQS::Queue":
        url = r.physical_id if r.physical_id.startswith("https://") else (get_field(cfg, "url", "QueueUrl") or "")
        return url or r.physical_id
    if t in ("AWS::Events::Rule", "AWS::SNS::Topic"):
        return r.arn or r.physical_id
    if t in ("AWS::Lambda::Function", "AWS::IAM::Role", "AWS::DynamoDB::Table",
             "AWS::S3::Bucket", "AWS::Events::EventBus"):
        return r.name or r.physical_id
    if t in ("AWS::CloudWatch::Alarm", "AWS::CloudWatch::CompositeAlarm"):
        return str(get_field(cfg, "alarm_name", "AlarmName") or r.name or r.physical_id)
    if t == "AWS::CloudWatch::Dashboard":
        return str(get_field(cfg, "dashboard_name", "DashboardName") or r.name or r.physical_id)
    if t in ("AWS::Logs::MetricFilter", "AWS::Logs::SubscriptionFilter"):
        name = get_field(cfg, "name", "filter_name", "FilterName") or r.name
        group = get_field(cfg, "log_group_name", "LogGroupName") or ""
        if name and group:     # Cloud Control's compound primary identifiers
            return f"{group}|{name}" if t == "AWS::Logs::MetricFilter" else f"{name}|{group}"
    return r.physical_id or r.name


class AwsLive:
    """Read-only AWS access. Every call here is a Describe/Get/List/Lookup."""

    def __init__(self, session: Any, region: str):
        self.session = session
        self.region = region
        self._clients: dict[str, Any] = {}

    def _c(self, svc: str):
        if svc not in self._clients:
            from botocore.config import Config
            self._clients[svc] = self.session.client(
                svc, region_name=self.region,
                config=Config(retries={"max_attempts": 3, "mode": "standard"},
                              read_timeout=20, connect_timeout=5))
        return self._clients[svc]

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    # config ---------------------------------------------------------------
    def read(self, resource: Resource) -> dict | None:
        from botocore.exceptions import ClientError
        ident = _cc_identifier(resource)
        if not ident or not resource.type.startswith("AWS::"):
            return None
        try:
            resp = self._c("cloudcontrol").get_resource(TypeName=resource.type, Identifier=ident)
            return json.loads((resp.get("ResourceDescription") or {}).get("Properties") or "{}")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("ResourceNotFoundException", "NotFound"):
                return NOT_FOUND
            return self._native_read(resource)
        except Exception:  # noqa: BLE001
            return self._native_read(resource)

    def _native_read(self, r: Resource) -> dict | None:
        """Fallback for types/identifiers Cloud Control can't read."""
        from botocore.exceptions import ClientError
        try:
            if r.type == "AWS::Lambda::Function":
                return self._c("lambda").get_function_configuration(FunctionName=r.name or r.physical_id)
            if r.type == "AWS::Lambda::EventSourceMapping":
                return self._c("lambda").get_event_source_mapping(UUID=r.physical_id)
            if r.type == "AWS::SQS::Queue":
                return self._c("sqs").get_queue_attributes(QueueUrl=_cc_identifier(r),
                                                           AttributeNames=["All"]).get("Attributes")
            if r.type == "AWS::Events::Rule":
                bus = get_field(r.config, "event_bus_name", "EventBusName") or "default"
                return self._c("events").describe_rule(Name=r.name, EventBusName=bus)
            if r.type == "AWS::IAM::RolePolicy":
                pol, _, role = _cc_identifier(r).partition("|")
                return self._c("iam").get_role_policy(RoleName=role, PolicyName=pol)
            if r.type in ("AWS::CloudWatch::Alarm", "AWS::CloudWatch::CompositeAlarm"):
                name = _cc_identifier(r)
                resp = self._c("cloudwatch").describe_metric_alarms(AlarmNames=[name]) \
                    if r.type == "AWS::CloudWatch::Alarm" else \
                    self._c("cloudwatch").describe_alarms(AlarmNames=[name], AlarmTypes=["CompositeAlarm"])
                found = resp.get("MetricAlarms") or resp.get("CompositeAlarms") or []
                return found[0] if found else NOT_FOUND
            if r.type == "AWS::Logs::LogGroup":
                name = r.name or r.physical_id
                groups = self._c("logs").describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
                hit = [g for g in groups if g.get("logGroupName") == name]
                return hit[0] if hit else NOT_FOUND
            if r.type == "AWS::Logs::MetricFilter":
                group, _, name = _cc_identifier(r).partition("|")
                fs = self._c("logs").describe_metric_filters(logGroupName=group, filterNamePrefix=name)
                hit = [f for f in fs.get("metricFilters", []) if f.get("filterName") == name]
                return hit[0] if hit else NOT_FOUND
            if r.type == "AWS::Logs::SubscriptionFilter":
                name, _, group = _cc_identifier(r).partition("|")
                fs = self._c("logs").describe_subscription_filters(logGroupName=group, filterNamePrefix=name)
                hit = [f for f in fs.get("subscriptionFilters", []) if f.get("filterName") == name]
                return hit[0] if hit else NOT_FOUND
        except ClientError as exc:
            if "NotFound" in exc.response.get("Error", {}).get("Code", ""):
                return NOT_FOUND
        except Exception:  # noqa: BLE001
            return None
        return None

    # changes --------------------------------------------------------------
    def write_events(self, start: datetime, end: datetime, max_pages: int = 10) -> list[dict]:
        ct = self._c("cloudtrail")
        rows: list[dict] = []
        token = None
        for _ in range(max_pages):
            kw = dict(LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
                      StartTime=start, EndTime=end, MaxResults=50)
            if token:
                kw["NextToken"] = token
            resp = ct.lookup_events(**kw)
            for e in resp.get("Events", []):
                rows.append(cloudtrail_row(e))
            token = resp.get("NextToken")
            if not token:
                break
        return rows

    # metrics --------------------------------------------------------------
    def metrics(self, queries: list[dict], start: datetime, end: datetime, period: int) -> dict:
        cw = self._c("cloudwatch")
        out: dict = {}
        for i in range(0, len(queries), 400):
            chunk = queries[i:i + 400]
            mdq = [{"Id": q["id"], "ReturnData": True, "MetricStat": {
                "Metric": {"Namespace": q["namespace"], "MetricName": q["metric"],
                           "Dimensions": [{"Name": k, "Value": v} for k, v in q["dims"].items()]},
                "Period": period, "Stat": q.get("stat", "Sum")}} for q in chunk]
            token = None
            for _ in range(5):
                kw = dict(MetricDataQueries=mdq, StartTime=start, EndTime=end, ScanBy="TimestampAscending")
                if token:
                    kw["NextToken"] = token
                resp = cw.get_metric_data(**kw)
                for res in resp.get("MetricDataResults", []):
                    out.setdefault(res["Id"], []).extend(
                        (iso(t), float(v)) for t, v in zip(res.get("Timestamps", []), res.get("Values", [])))
                token = resp.get("NextToken")
                if not token:
                    break
        return out

    # CloudFormation -------------------------------------------------------
    def stack_resources(self, stack: str) -> list[dict]:
        return self._c("cloudformation").describe_stack_resources(StackName=stack).get("StackResources", [])

    def stack_drifts(self, stack: str, detect: bool = False) -> list[dict]:
        cfn = self._c("cloudformation")
        if detect:
            import time
            did = cfn.detect_stack_drift(StackName=stack)["StackDriftDetectionId"]
            for _ in range(20):
                st = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=did)
                if st.get("DetectionStatus") != "DETECTION_IN_PROGRESS":
                    break
                time.sleep(3)
        return cfn.describe_stack_resource_drifts(StackName=stack).get("StackResourceDrifts", [])

    # AWS Config -----------------------------------------------------------
    def config_history(self, resource: Resource, at: str | None) -> dict | None:
        from botocore.exceptions import ClientError
        kw = dict(resourceType=resource.type, resourceId=resource.physical_id or resource.name, limit=1)
        if at:
            kw["laterTime"] = to_dt(at)
        try:
            items = self._c("config").get_resource_config_history(**kw).get("configurationItems", [])
        except ClientError:
            return None
        if not items or not items[0].get("configuration"):
            return None
        cfg = items[0]["configuration"]
        return json.loads(cfg) if isinstance(cfg, str) else cfg

    # discovery (no IaC) ---------------------------------------------------
    def discover(self, limit: int = 200) -> list[Resource]:
        """Resources that carry work, with the config needed to wire them up."""
        out: list[Resource] = []
        lam = self._c("lambda")
        try:
            for page in lam.get_paginator("list_functions").paginate(PaginationConfig={"MaxItems": limit}):
                for f in page.get("Functions", []):
                    out.append(Resource(key=f"lambda:{f['FunctionName']}", type="AWS::Lambda::Function",
                                        name=f["FunctionName"], physical_id=f["FunctionName"],
                                        arn=f.get("FunctionArn", ""), config=f, source="live"))
            for page in lam.get_paginator("list_event_source_mappings").paginate(PaginationConfig={"MaxItems": limit}):
                for m in page.get("EventSourceMappings", []):
                    out.append(Resource(key=f"esm:{m['UUID']}", type="AWS::Lambda::EventSourceMapping",
                                        name=m["UUID"], physical_id=m["UUID"],
                                        arn=m.get("EventSourceMappingArn", ""), config=m, source="live"))
        except Exception:  # noqa: BLE001
            pass
        try:
            sqs = self._c("sqs")
            for url in (sqs.list_queues(MaxResults=1000).get("QueueUrls") or [])[:limit]:
                name = url.rsplit("/", 1)[-1]
                out.append(Resource(key=f"sqs:{name}", type="AWS::SQS::Queue", name=name,
                                    physical_id=url, config={"QueueUrl": url}, source="live"))
        except Exception:  # noqa: BLE001
            pass
        try:
            ev = self._c("events")
            buses = [b["Name"] for b in ev.list_event_buses().get("EventBuses", [])]
            for bus in buses[:20]:
                if bus != "default":
                    out.append(Resource(key=f"bus:{bus}", type="AWS::Events::EventBus", name=bus,
                                        physical_id=bus, config={"Name": bus}, source="live"))
                for rule in ev.list_rules(EventBusName=bus).get("Rules", [])[:limit]:
                    targets = ev.list_targets_by_rule(Rule=rule["Name"], EventBusName=bus).get("Targets", [])
                    cfg = {**rule, "Targets": targets}
                    out.append(Resource(key=f"rule:{bus}/{rule['Name']}", type="AWS::Events::Rule",
                                        name=rule["Name"], physical_id=rule.get("Arn", ""),
                                        arn=rule.get("Arn", ""), config=cfg, source="live"))
        except Exception:  # noqa: BLE001
            pass
        try:
            ddb = self._c("dynamodb")
            for t in ddb.list_tables(Limit=100).get("TableNames", []):
                out.append(Resource(key=f"ddb:{t}", type="AWS::DynamoDB::Table", name=t,
                                    physical_id=t, config={"TableName": t}, source="live"))
        except Exception:  # noqa: BLE001
            pass
        try:
            apis = self._c("apigatewayv2").get_apis().get("Items", [])
            for a in apis[:50]:
                out.append(Resource(key=f"api:{a['ApiId']}", type="AWS::ApiGatewayV2::Api",
                                    name=a.get("Name", ""), physical_id=a["ApiId"], config=a, source="live"))
                for integ in self._c("apigatewayv2").get_integrations(ApiId=a["ApiId"]).get("Items", []):
                    out.append(Resource(key=f"integ:{a['ApiId']}/{integ['IntegrationId']}",
                                        type="AWS::ApiGatewayV2::Integration", name="",
                                        physical_id=integ["IntegrationId"],
                                        config={**integ, "ApiId": a["ApiId"]}, source="live"))
        except Exception:  # noqa: BLE001
            pass
        return out


def cloudtrail_row(e: dict) -> dict:
    """One LookupEvents record -> the row shape the checks use, with the caller
    evidence (user agent, principal, console flag, invoking service) that tells
    a hand change from an IaC deploy."""
    from cloudctl.debug.diff_first.attribution import normalize_cloudtrail
    return normalize_cloudtrail(e)

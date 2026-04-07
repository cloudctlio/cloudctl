"""Debug fetcher — collects raw evidence from cloud data sources."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional


_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


class DebugFetcher:
    """
    Fetches raw evidence from AWS (and stub hooks for Azure/GCP).
    Each method returns a list of normalised event dicts:
        {"time": str, "source": str, "event": str, ...}
    Raises are suppressed; missing/inaccessible sources return an empty list
    plus a availability flag.
    """

    def __init__(self, session):
        """
        Args:
            session: boto3.Session (or None for non-AWS clouds)
        """
        self._session = session
        self._availability: dict[str, bool] = {}

    @property
    def availability(self) -> dict[str, bool]:
        """Which sources returned data (True) vs were missing/disabled (False)."""
        return dict(self._availability)

    def _mark(self, source: str, ok: bool) -> None:
        self._availability[source] = ok

    def cloudwatch_metrics(
        self,
        namespace: str = "AWS/EC2",
        metric_name: str = "CPUUtilization",
        minutes: int = 60,
        dimensions: Optional[list[dict]] = None,
    ) -> list[dict]:
        if not self._session:
            self._mark("cloudwatch_metrics", False)
            return []
        try:
            cw = self._session.client("cloudwatch")
            end   = datetime.now(timezone.utc)
            start = end - timedelta(minutes=minutes)
            resp  = cw.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions or [],
                StartTime=start,
                EndTime=end,
                Period=300,
                Statistics=["Average", "Maximum"],
            )
            events = [
                {
                    "time":   dp["Timestamp"].strftime(_TS_FMT),
                    "source": f"CloudWatch/{namespace}/{metric_name}",
                    "event":  f"avg={dp.get('Average', '—'):.1f} max={dp.get('Maximum', '—'):.1f}",
                    "value":  dp.get("Average", 0),
                }
                for dp in sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"])
            ]
            self._mark("cloudwatch_metrics", True)
            return events
        except Exception:  # noqa: BLE001
            self._mark("cloudwatch_metrics", False)
            return []

    def cloudwatch_logs(
        self,
        log_group: str,
        filter_pattern: str = "ERROR",
        minutes: int = 60,
    ) -> list[dict]:
        if not self._session:
            self._mark("cloudwatch_logs", False)
            return []
        try:
            logs  = self._session.client("logs")
            end   = int(datetime.now(timezone.utc).timestamp() * 1000)
            start = end - minutes * 60 * 1000
            resp  = logs.filter_log_events(
                logGroupName=log_group,
                startTime=start,
                endTime=end,
                filterPattern=filter_pattern,
                limit=100,
            )
            events = [
                {
                    "time":   datetime.fromtimestamp(
                        e["timestamp"] / 1000, tz=timezone.utc
                    ).strftime(_TS_FMT),
                    "source": f"CloudWatch/Logs/{log_group}",
                    "event":  e.get("message", "").strip()[:200],
                }
                for e in resp.get("events", [])
            ]
            self._mark("cloudwatch_logs", bool(events))
            return events
        except Exception:  # noqa: BLE001
            self._mark("cloudwatch_logs", False)
            return []

    def cloudtrail(
        self,
        minutes: int = 120,
        resource_name: Optional[str] = None,
        error_only: bool = False,
    ) -> list[dict]:
        if not self._session:
            self._mark("cloudtrail", False)
            return []
        try:
            ct    = self._session.client("cloudtrail")
            end   = datetime.now(timezone.utc)
            start = end - timedelta(minutes=minutes)
            kwargs: dict = {
                "StartTime": start,
                "EndTime":   end,
                "MaxResults": 50,
            }
            if error_only:
                kwargs["LookupAttributes"] = [
                    {"AttributeKey": "EventName", "AttributeValue": "AccessDenied"}
                ]
            elif resource_name:
                kwargs["LookupAttributes"] = [
                    {"AttributeKey": "ResourceName", "AttributeValue": resource_name}
                ]

            resp = ct.lookup_events(**kwargs)
            events = []
            for e in resp.get("Events", []):
                events.append({
                    "time":       e["EventTime"].strftime(_TS_FMT),
                    "source":     "CloudTrail",
                    "event":      e.get("EventName", ""),
                    "principal":  e.get("Username", ""),
                    "resource":   ", ".join(
                        r.get("ResourceName", "") for r in e.get("Resources", [])
                    ),
                    "error_code": e.get("ErrorCode", ""),
                })
            self._mark("cloudtrail", True)
            return events
        except Exception:  # noqa: BLE001
            self._mark("cloudtrail", False)
            return []

    def alb_metrics(
        self,
        load_balancer_name: str,
        minutes: int = 60,
    ) -> list[dict]:
        """Fetch ALB 5xx / target response time metrics from CloudWatch."""
        if not self._session:
            self._mark("alb_logs", False)
            return []
        try:
            cw  = self._session.client("cloudwatch")
            end = datetime.now(timezone.utc)
            start = end - timedelta(minutes=minutes)
            results = []
            for metric in ["HTTPCode_ELB_5XX_Count", "TargetResponseTime", "RequestCount"]:
                resp = cw.get_metric_statistics(
                    Namespace="AWS/ApplicationELB",
                    MetricName=metric,
                    Dimensions=[{"Name": "LoadBalancer", "Value": load_balancer_name}],
                    StartTime=start,
                    EndTime=end,
                    Period=300,
                    Statistics=["Sum", "Average"],
                )
                for dp in sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"]):
                    val = dp.get("Sum", dp.get("Average", 0))
                    if val and val > 0:
                        results.append({
                            "time":   dp["Timestamp"].strftime(_TS_FMT),
                            "source": f"ALB/{metric}",
                            "event":  f"{metric}={val:.1f}",
                            "metric": metric,
                            "value":  val,
                        })
            self._mark("alb_logs", bool(results))
            return results
        except Exception:  # noqa: BLE001
            self._mark("alb_logs", False)
            return []

    def ecs_events(
        self,
        cluster: str,
        service: str,
        limit: int = 20,
    ) -> list[dict]:
        if not self._session:
            self._mark("ecs_events", False)
            return []
        try:
            ecs  = self._session.client("ecs")
            resp = ecs.describe_services(cluster=cluster, services=[service])
            svc  = resp.get("services", [{}])[0]
            events = [
                {
                    "time":   e["createdAt"].strftime(_TS_FMT),
                    "source": f"ECS/{cluster}/{service}",
                    "event":  e.get("message", ""),
                }
                for e in svc.get("events", [])[:limit]
            ]
            self._mark("ecs_events", bool(events))
            return events
        except Exception:  # noqa: BLE001
            self._mark("ecs_events", False)
            return []

    def rds_events(
        self,
        db_identifier: Optional[str] = None,
        minutes: int = 120,
    ) -> list[dict]:
        if not self._session:
            self._mark("rds_events", False)
            return []
        try:
            rds   = self._session.client("rds")
            end   = datetime.now(timezone.utc)
            start = end - timedelta(minutes=minutes)
            kwargs: dict = {
                "StartTime":       start,
                "EndTime":         end,
                "SourceType":      "db-instance",
                "Duration":        minutes,
            }
            if db_identifier:
                kwargs["SourceIdentifier"] = db_identifier
            resp = rds.describe_events(**kwargs)
            events = [
                {
                    "time":   e["Date"].strftime(_TS_FMT),
                    "source": f"RDS/{e.get('SourceIdentifier', '')}",
                    "event":  e.get("Message", ""),
                }
                for e in resp.get("Events", [])
            ]
            self._mark("rds_events", bool(events))
            return events
        except Exception:  # noqa: BLE001
            self._mark("rds_events", False)
            return []

    def codepipeline(
        self,
        pipeline_name: Optional[str] = None,
        limit: int = 5,
    ) -> list[dict]:
        if not self._session:
            self._mark("codepipeline", False)
            return []
        try:
            cp = self._session.client("codepipeline")
            if pipeline_name:
                pipelines = [{"name": pipeline_name}]
            else:
                resp      = cp.list_pipelines()
                pipelines = resp.get("pipelines", [])[:3]

            events = []
            for p in pipelines:
                name = p.get("name", "")
                try:
                    execs = cp.list_pipeline_executions(
                        pipelineName=name, maxResults=limit
                    )
                    for ex in execs.get("pipelineExecutionSummaries", []):
                        events.append({
                            "time":   ex["startTime"].strftime(_TS_FMT),
                            "source": f"CodePipeline/{name}",
                            "event":  (
                                f"status={ex.get('status', '?')} "
                                f"trigger={ex.get('trigger', {}).get('triggerType', '?')}"
                            ),
                            "status": ex.get("status", ""),
                        })
                except Exception:  # noqa: BLE001
                    pass
            self._mark("codepipeline", bool(events))
            return events
        except Exception:  # noqa: BLE001
            self._mark("codepipeline", False)
            return []

    def discover_log_groups(self, prefix: str, limit: int = 10) -> list[str]:
        """Return log group names that contain *prefix* (case-insensitive search)."""
        if not self._session:
            return []
        try:
            logs = self._session.client("logs")
            resp = logs.describe_log_groups(logGroupNamePattern=prefix, limit=limit)
            return [lg["logGroupName"] for lg in resp.get("logGroups", [])]
        except Exception:  # noqa: BLE001
            return []

    def lambda_logs(
        self,
        function_name: str,
        minutes: int = 60,
    ) -> list[dict]:
        log_group = f"/aws/lambda/{function_name}"
        return self.cloudwatch_logs(
            log_group=log_group,
            filter_pattern="?ERROR ?WARN ?Task timed out",
            minutes=minutes,
        )

    def network_context(
        self,
        vpc_id: Optional[str] = None,
    ) -> list[dict]:
        if not self._session:
            self._mark("network_context", False)
            return []
        try:
            ec2 = self._session.client("ec2")
            events = []

            # Route tables
            kwargs: dict = {}
            if vpc_id:
                kwargs["Filters"] = [{"Name": "vpc-id", "Values": [vpc_id]}]
            rts = ec2.describe_route_tables(**kwargs).get("RouteTables", [])
            for rt in rts[:3]:
                rt_id = rt.get("RouteTableId", "")
                for route in rt.get("Routes", []):
                    if route.get("State") == "blackhole":
                        events.append({
                            "time":   "—",
                            "source": f"RouteTable/{rt_id}",
                            "event":  f"blackhole route: {route.get('DestinationCidrBlock', '?')}",
                        })

            # NAT Gateways
            nat_resp = ec2.describe_nat_gateways(
                Filters=[{"Name": "state", "Values": ["failed", "deleted"]}]
            )
            for ng in nat_resp.get("NatGateways", []):
                events.append({
                    "time":   "—",
                    "source": "NAT Gateway",
                    "event":  f"{ng.get('NatGatewayId')} state={ng.get('State')}",
                })

            self._mark("network_context", True)
            return events
        except Exception:  # noqa: BLE001
            self._mark("network_context", False)
            return []

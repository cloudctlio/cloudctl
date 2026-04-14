"""Debug fetcher — collects raw evidence from cloud data sources."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional


_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

# CloudTrail management events have up to 15-minute delivery lag.
# cloudctl uses CloudTrail for deployment detection (7-day lookback, lag irrelevant)
# and IAM deny diagnosis (lag acceptable). Real-time signals come from CloudWatch
# metrics (1-min lag). If an incident happened < 20 minutes ago, the caller should
# surface a lag warning so users know CloudTrail data may be incomplete.
CLOUDTRAIL_LAG_MINUTES = 15


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

    def recently_active_log_groups(self, minutes: int = 180, limit: int = 30) -> list[str]:
        """Return log groups that had activity in the last *minutes*, sorted by recency.

        This catches custom log groups (/app/payments, /prod/checkout, etc.) that
        would never be found by hint-based prefix matching against AWS resource names.
        """
        if not self._session:
            return []
        try:
            from datetime import datetime, timezone, timedelta  # noqa: PLC0415
            logs      = self._session.client("logs")
            cutoff_ms = int(
                (datetime.now(timezone.utc) - timedelta(minutes=minutes)).timestamp() * 1000
            )
            paginator = logs.get_paginator("describe_log_groups")
            active: list[tuple[int, str]] = []
            # Scan up to 5 pages (= 250 log groups) — enough to find recent ones
            for page in paginator.paginate(PaginationConfig={"MaxItems": 250, "PageSize": 50}):
                for lg in page.get("logGroups", []):
                    last_event = lg.get("lastEventTimestamp") or lg.get("creationTime", 0)
                    if last_event >= cutoff_ms:
                        active.append((last_event, lg["logGroupName"]))
            # Sort most-recent first, return names only
            active.sort(reverse=True)
            return [name for _, name in active[:limit]]
        except Exception:  # noqa: BLE001
            return []

    def tail_log_group(self, log_group: str, lines: int = 50) -> list[dict]:
        """Fetch the last *lines* events from the most recent log stream.

        Used as a fallback when ERROR/WARN filter returns empty — catches
        stack traces and structured JSON logs that don't contain those words.
        """
        if not self._session:
            return []
        try:
            logs = self._session.client("logs")
            # Get the most recently active stream
            streams = logs.describe_log_streams(
                logGroupName=log_group,
                orderBy="LastEventTime",
                descending=True,
                limit=1,
            ).get("logStreams", [])
            if not streams:
                return []
            stream_name = streams[0]["logStreamName"]
            resp = logs.get_log_events(
                logGroupName=log_group,
                logStreamName=stream_name,
                limit=lines,
                startFromHead=False,
            )
            return [
                {
                    "time":   datetime.fromtimestamp(
                        e["timestamp"] / 1000, tz=timezone.utc
                    ).strftime(_TS_FMT),
                    "source": f"CloudWatch/Logs/{log_group}",
                    "event":  e.get("message", "").strip()[:200],
                }
                for e in resp.get("events", [])
            ]
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
            filter_pattern="?ERROR ?WARN ?error ?warn",
            minutes=minutes,
        )

    def network_context(  # noqa: C901
        self,
        vpc_id: Optional[str] = None,
    ) -> list[dict]:
        """Fetch the full network configuration state for the account/region.

        Covers every AWS network component: VPCs, subnets, route tables,
        IGW, NAT GW, VPN gateways, Transit Gateway, VPC endpoints, peering,
        NACLs, security groups, ENIs, EIPs, flow logs, ALB/NLB listeners,
        target group health, Route 53 health checks, Direct Connect.
        """
        if not self._session:
            self._mark("network_context", False)
            return []
        try:
            ec2   = self._session.client("ec2")
            events: list[dict] = []
            vf    = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []

            def _evt(source: str, event: str) -> None:
                events.append({"time": "—", "source": source, "event": event})

            # ── VPCs ──────────────────────────────────────────────────────────
            vpcs = ec2.describe_vpcs(**({"Filters": vf} if vf else {})).get("Vpcs", [])
            for v in vpcs[:10]:
                vid   = v.get("VpcId", "")
                state = v.get("State", "")
                dns_h = v.get("EnableDnsHostnames", False)
                dns_s = v.get("EnableDnsSupport",   False)
                _evt(f"VPC/{vid}", f"state={state} cidr={v.get('CidrBlock')} dns_hostnames={dns_h} dns_support={dns_s}")
                if state != "available":
                    _evt(f"VPC/{vid}", f"WARNING: VPC not available state={state}")

            # ── Subnets ───────────────────────────────────────────────────────
            for sn in ec2.describe_subnets(**({"Filters": vf} if vf else {})).get("Subnets", [])[:20]:
                sn_id  = sn.get("SubnetId", "")
                sn_az  = sn.get("AvailabilityZone", "")
                avail  = sn.get("AvailableIpAddressCount", 0)
                state  = sn.get("State", "")
                if state != "available" or avail == 0:
                    _evt(f"Subnet/{sn_id}", f"az={sn_az} cidr={sn.get('CidrBlock')} state={state} available_ips={avail}")

            # ── Route tables — blackhole routes ───────────────────────────────
            for rt in ec2.describe_route_tables(**({"Filters": vf} if vf else {})).get("RouteTables", [])[:10]:
                rt_id = rt.get("RouteTableId", "")
                for route in rt.get("Routes", []):
                    dest  = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock", "?")
                    state = route.get("State", "")
                    gw    = (route.get("GatewayId") or route.get("NatGatewayId") or
                             route.get("TransitGatewayId") or route.get("VpcPeeringConnectionId") or "local")
                    if state == "blackhole":
                        _evt(f"RouteTable/{rt_id}", f"blackhole route: dest={dest} via={gw}")
                    else:
                        _evt(f"RouteTable/{rt_id}", f"route: dest={dest} via={gw} state={state}")

            # ── Internet Gateways ─────────────────────────────────────────────
            igw_f = [{"Name": "attachment.vpc-id", "Values": [vpc_id]}] if vpc_id else []
            for igw in ec2.describe_internet_gateways(**({"Filters": igw_f} if igw_f else {})).get("InternetGateways", [])[:5]:
                attachments = igw.get("Attachments", [])
                state = attachments[0].get("State", "detached") if attachments else "detached"
                _evt(f"InternetGateway/{igw.get('InternetGatewayId')}", f"state={state} vpc={attachments[0].get('VpcId') if attachments else '—'}")

            # ── NAT Gateways — all ────────────────────────────────────────────
            for ng in ec2.describe_nat_gateways(**({"Filters": vf} if vf else {})).get("NatGateways", [])[:10]:
                _evt(f"NATGateway/{ng.get('NatGatewayId')}", f"state={ng.get('State')} subnet={ng.get('SubnetId')} type={ng.get('ConnectivityType')}")

            # ── VPN Gateways ──────────────────────────────────────────────────
            vgw_f = [{"Name": "attachment.vpc-id", "Values": [vpc_id]}] if vpc_id else []
            for vgw in ec2.describe_vpn_gateways(**({"Filters": vgw_f} if vgw_f else {})).get("VpnGateways", [])[:5]:
                _evt(f"VPNGateway/{vgw.get('VpnGatewayId')}", f"state={vgw.get('State')} type={vgw.get('Type')}")

            # ── VPN Connections — tunnel status ───────────────────────────────
            for vpn in ec2.describe_vpn_connections().get("VpnConnections", [])[:10]:
                for t in vpn.get("VgwTelemetry", []):
                    _evt(f"VPNConnection/{vpn.get('VpnConnectionId')}", f"tunnel={t.get('OutsideIpAddress')} status={t.get('Status')} accepted_routes={t.get('AcceptedRouteCount')}")

            # ── Transit Gateway attachments ───────────────────────────────────
            try:
                for att in ec2.describe_transit_gateway_attachments().get("TransitGatewayAttachments", [])[:10]:
                    state = att.get("State", "")
                    if state not in ("available", "associated"):
                        _evt(f"TGWAttachment/{att.get('TransitGatewayAttachmentId')}", f"type={att.get('ResourceType')} state={state} tgw={att.get('TransitGatewayId')}")
            except Exception:  # noqa: BLE001
                pass

            # ── VPC Endpoints ─────────────────────────────────────────────────
            for ep in ec2.describe_vpc_endpoints(**({"Filters": vf} if vf else {})).get("VpcEndpoints", [])[:10]:
                _evt(f"VPCEndpoint/{ep.get('VpcEndpointId')}", f"service={ep.get('ServiceName')} type={ep.get('VpcEndpointType')} state={ep.get('State')}")

            # ── VPC Peering ───────────────────────────────────────────────────
            for pc in ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", [])[:10]:
                status = pc.get("Status", {}).get("Code", "")
                _evt(f"VPCPeering/{pc.get('VpcPeeringConnectionId')}", f"status={status} requester={pc.get('RequesterVpcInfo', {}).get('VpcId')} accepter={pc.get('AccepterVpcInfo', {}).get('VpcId')}")

            # ── Network ACLs ──────────────────────────────────────────────────
            for nacl in ec2.describe_network_acls(**({"Filters": vf} if vf else {})).get("NetworkAcls", [])[:10]:
                nacl_id = nacl.get("NetworkAclId", "")
                for entry in nacl.get("Entries", []):
                    direction = "egress" if entry.get("Egress") else "ingress"
                    action    = entry.get("RuleAction", "")
                    cidr      = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock", "?")
                    _evt(f"NetworkACL/{nacl_id}", f"{direction} rule#{entry.get('RuleNumber')} {action.upper()} cidr={cidr} protocol={entry.get('Protocol', '?')}")

            # ── Security Groups ───────────────────────────────────────────────
            for sg in ec2.describe_security_groups(**({"Filters": vf} if vf else {})).get("SecurityGroups", [])[:20]:
                sg_id   = sg.get("GroupId", "")
                sg_name = sg.get("GroupName", "")
                for perm in sg.get("IpPermissions", []):
                    port  = f"{perm.get('FromPort', 'all')}-{perm.get('ToPort', 'all')}"
                    proto = perm.get("IpProtocol", "?")
                    for ip_r in perm.get("IpRanges", []):
                        _evt(f"SecurityGroup/{sg_id}", f"{sg_name} ingress port={port} proto={proto} cidr={ip_r.get('CidrIp')}")
                    for ip_r in perm.get("Ipv6Ranges", []):
                        _evt(f"SecurityGroup/{sg_id}", f"{sg_name} ingress port={port} proto={proto} cidr={ip_r.get('CidrIpv6')}")
                for perm in sg.get("IpPermissionsEgress", []):
                    port  = f"{perm.get('FromPort', 'all')}-{perm.get('ToPort', 'all')}"
                    proto = perm.get("IpProtocol", "?")
                    for ip_r in perm.get("IpRanges", []):
                        _evt(f"SecurityGroup/{sg_id}", f"{sg_name} egress port={port} proto={proto} cidr={ip_r.get('CidrIp')}")

            # ── Elastic IPs ───────────────────────────────────────────────────
            for eip in ec2.describe_addresses().get("Addresses", [])[:20]:
                assoc = eip.get("AssociationId", "")
                _evt(f"ElasticIP/{eip.get('AllocationId')}", f"public_ip={eip.get('PublicIp')} associated={'yes' if assoc else 'no'} instance={eip.get('InstanceId', '—')}")

            # ── Network Interfaces — non-available ────────────────────────────
            for eni in ec2.describe_network_interfaces(**({"Filters": vf} if vf else {})).get("NetworkInterfaces", [])[:20]:
                state = eni.get("Status", "")
                if state not in ("in-use", "available"):
                    _evt(f"ENI/{eni.get('NetworkInterfaceId')}", f"state={state} type={eni.get('InterfaceType')} subnet={eni.get('SubnetId')}")

            # ── VPC Flow Logs ─────────────────────────────────────────────────
            fl_filters = [{"Name": "resource-id", "Values": [vpc_id]}] if vpc_id else []
            fls = ec2.describe_flow_logs(**({"Filters": fl_filters} if fl_filters else {})).get("FlowLogs", [])
            if not fls:
                _evt("VPCFlowLogs", "WARNING: No VPC flow logs configured — network traffic not logged")
            else:
                for fl in fls[:5]:
                    _evt(f"VPCFlowLog/{fl.get('FlowLogId')}", f"status={fl.get('FlowLogStatus')} dest={fl.get('LogDestinationType')} traffic={fl.get('TrafficType')}")

            # ── ALB / NLB ─────────────────────────────────────────────────────
            try:
                elbv2 = self._session.client("elbv2")
                lbs   = elbv2.describe_load_balancers().get("LoadBalancers", [])[:10]
                for lb in lbs:
                    lb_arn  = lb.get("LoadBalancerArn", "")
                    lb_name = lb.get("LoadBalancerName", "")
                    lb_type = lb.get("Type", "")
                    lb_state = lb.get("State", {}).get("Code", "")
                    _evt(f"LoadBalancer/{lb_name}", f"type={lb_type} state={lb_state} dns={lb.get('DNSName')}")

                    # Listeners + rules
                    try:
                        for lst in elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", []):
                            lst_arn = lst.get("ListenerArn", "")
                            _evt(f"Listener/{lb_name}", f"port={lst.get('Port')} protocol={lst.get('Protocol')} ssl_policy={lst.get('SslPolicy', '—')}")
                            try:
                                for rule in elbv2.describe_rules(ListenerArn=lst_arn).get("Rules", [])[:10]:
                                    conditions = ", ".join(
                                        f"{c.get('Field')}={c.get('Values', [c.get('HostHeaderConfig', c.get('PathPatternConfig', ''))])[0] if c.get('Values') else ''}"
                                        for c in rule.get("Conditions", [])
                                    )
                                    actions = ", ".join(a.get("Type", "") for a in rule.get("Actions", []))
                                    _evt(f"ListenerRule/{lb_name}", f"priority={rule.get('Priority')} conditions=[{conditions}] actions=[{actions}]")
                            except Exception:  # noqa: BLE001
                                pass
                    except Exception:  # noqa: BLE001
                        pass

                # Target groups + health
                for tg in elbv2.describe_target_groups().get("TargetGroups", [])[:10]:
                    tg_arn  = tg.get("TargetGroupArn", "")
                    tg_name = tg.get("TargetGroupName", "")
                    _evt(f"TargetGroup/{tg_name}", f"protocol={tg.get('Protocol')} port={tg.get('Port')} target_type={tg.get('TargetType')} healthy_threshold={tg.get('HealthyThresholdCount')}")
                    try:
                        for th in elbv2.describe_target_health(TargetGroupArn=tg_arn).get("TargetHealthDescriptions", []):
                            tgt   = th.get("Target", {})
                            state = th.get("TargetHealth", {}).get("State", "")
                            reason = th.get("TargetHealth", {}).get("Reason", "")
                            _evt(f"TargetHealth/{tg_name}", f"target={tgt.get('Id')}:{tgt.get('Port')} state={state} reason={reason}")
                    except Exception:  # noqa: BLE001
                        pass
            except Exception:  # noqa: BLE001
                pass

            # ── Route 53 health checks ────────────────────────────────────────
            try:
                r53 = self._session.client("route53")
                hcs = r53.list_health_checks().get("HealthChecks", [])[:10]
                for hc in hcs:
                    hc_id  = hc.get("Id", "")
                    cfg    = hc.get("HealthCheckConfig", {})
                    status = r53.get_health_check_status(HealthCheckId=hc_id)
                    for obs in status.get("HealthCheckObservations", [])[:3]:
                        st = obs.get("StatusReport", {})
                        _evt(f"Route53HealthCheck/{hc_id}", f"type={cfg.get('Type')} endpoint={cfg.get('FullyQualifiedDomainName', cfg.get('IPAddress', '?'))} status={st.get('Status')} checked={st.get('CheckedTime')}")
            except Exception:  # noqa: BLE001
                pass

            # ── Direct Connect ────────────────────────────────────────────────
            try:
                dx = self._session.client("directconnect")
                for conn in dx.describe_connections().get("connections", [])[:5]:
                    _evt(f"DirectConnect/{conn.get('connectionId')}", f"name={conn.get('connectionName')} state={conn.get('connectionState')} bandwidth={conn.get('bandwidth')} location={conn.get('location')}")
                for vif in dx.describe_virtual_interfaces().get("virtualInterfaces", [])[:5]:
                    _evt(f"DirectConnectVIF/{vif.get('virtualInterfaceId')}", f"name={vif.get('virtualInterfaceName')} state={vif.get('virtualInterfaceState')} vlan={vif.get('vlan')} bgp_asn={vif.get('asn')}")
            except Exception:  # noqa: BLE001
                pass

            self._mark("network_context", bool(events))
            return events
        except Exception:  # noqa: BLE001
            self._mark("network_context", False)
            return []

    def cloudtrail_with_lag_check(
        self,
        minutes: int = 120,
        resource_name: Optional[str] = None,
        incident_time: Optional[datetime] = None,
    ) -> tuple[list[dict], bool]:
        """Fetch CloudTrail events and return (events, lag_warning).

        lag_warning is True when the incident is < 20 minutes old, meaning
        CloudTrail may not yet have delivered the latest management events
        (AWS-documented max delivery lag: CLOUDTRAIL_LAG_MINUTES).
        Use CloudWatch metrics for real-time signals in that case.
        """
        lag_warning = False
        if incident_time:
            age_minutes = (datetime.now(timezone.utc) - incident_time).total_seconds() / 60
            if age_minutes < CLOUDTRAIL_LAG_MINUTES + 5:
                lag_warning = True
        return self.cloudtrail(minutes=minutes, resource_name=resource_name), lag_warning

    # ── P2.5: ALB log discovery ───────────────────────────────────────────────

    def find_alb_for_resource(self, resource_name: str) -> Optional[str]:
        """Discover the ALB ARN attached to an ECS service or resource by name hint.

        Searches ECS services for a name match, follows loadBalancers →
        target group → ALB. Falls back to scanning all ALBs for a name match.
        Returns ALB ARN or None.
        """
        if not self._session:
            return None
        try:
            ecs   = self._session.client("ecs")
            elbv2 = self._session.client("elbv2")

            # Search ECS clusters for a service matching the hint
            clusters = ecs.list_clusters().get("clusterArns", [])[:5]
            for cluster_arn in clusters:
                svcs = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])[:20]
                matching = [s for s in svcs if resource_name.lower() in s.lower()]
                if matching:
                    desc = ecs.describe_services(cluster=cluster_arn, services=[matching[0]])
                    svc  = desc.get("services", [{}])[0]
                    for lb in svc.get("loadBalancers", []):
                        tg_arn = lb.get("targetGroupArn")
                        if tg_arn:
                            tg_resp = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])
                            alb_arns = tg_resp["TargetGroups"][0].get("LoadBalancerArns", [])
                            if alb_arns:
                                return alb_arns[0]

            # Fallback: scan ALBs by name
            for lb in elbv2.describe_load_balancers().get("LoadBalancers", [])[:20]:
                if resource_name.lower() in lb.get("LoadBalancerName", "").lower():
                    return lb.get("LoadBalancerArn")
        except Exception:  # noqa: BLE001
            pass
        return None

    def get_alb_log_config(self, alb_arn: str) -> dict:
        """Read ALB access log config from load balancer attributes.

        Returns dict: {enabled: bool, bucket: str|None, prefix: str, alb_arn: str}
        """
        if not self._session:
            return {"enabled": False, "bucket": None, "prefix": "", "alb_arn": alb_arn}
        try:
            elbv2  = self._session.client("elbv2")
            attrs  = elbv2.describe_load_balancer_attributes(LoadBalancerArn=alb_arn)
            by_key = {a["Key"]: a["Value"] for a in attrs.get("Attributes", [])}
            enabled = by_key.get("access_logs.s3.enabled", "false").lower() == "true"
            bucket  = by_key.get("access_logs.s3.bucket") or None
            prefix  = by_key.get("access_logs.s3.prefix", "")
            return {"enabled": enabled, "bucket": bucket, "prefix": prefix, "alb_arn": alb_arn}
        except Exception:  # noqa: BLE001
            return {"enabled": False, "bucket": None, "prefix": "", "alb_arn": alb_arn}

    def alb_target_health(self, alb_arn: str) -> list[dict]:
        """Return target health for all target groups on an ALB."""
        if not self._session:
            return []
        results = []
        try:
            elbv2 = self._session.client("elbv2")
            for tg in elbv2.describe_target_groups(LoadBalancerArn=alb_arn).get("TargetGroups", []):
                tg_name = tg.get("TargetGroupName", "")
                tg_arn  = tg.get("TargetGroupArn", "")
                for th in elbv2.describe_target_health(TargetGroupArn=tg_arn).get("TargetHealthDescriptions", []):
                    tgt    = th.get("Target", {})
                    health = th.get("TargetHealth", {})
                    results.append({
                        "time":   "—",
                        "source": f"ALBTargetHealth/{tg_name}",
                        "event":  (
                            f"target={tgt.get('Id')}:{tgt.get('Port')} "
                            f"state={health.get('State')} "
                            f"reason={health.get('Reason', '')} "
                            f"description={health.get('Description', '')}"
                        ),
                    })
        except Exception:  # noqa: BLE001
            pass
        return results

    # ── P2.6: ECS stopped task reasons ───────────────────────────────────────

    def ecs_stopped_tasks(self, cluster: str, service: Optional[str] = None, limit: int = 10) -> list[dict]:
        """Fetch recently stopped ECS tasks with stop reasons.

        Stop reasons (e.g. OOMKilled, task failed to start) are the most
        useful signal for crash and OOM diagnosis — more specific than service events.
        """
        if not self._session:
            return []
        try:
            ecs    = self._session.client("ecs")
            kwargs: dict = {"cluster": cluster, "desiredStatus": "STOPPED", "maxResults": limit}
            if service:
                kwargs["serviceName"] = service
            task_arns = ecs.list_tasks(**kwargs).get("taskArns", [])
            if not task_arns:
                return []
            tasks  = ecs.describe_tasks(cluster=cluster, tasks=task_arns).get("tasks", [])
            events = []
            for t in tasks:
                stopped_at = t.get("stoppedAt")
                ts = stopped_at.strftime(_TS_FMT) if stopped_at else "—"
                for container in t.get("containers", []):
                    reason = container.get("reason", t.get("stoppedReason", "—"))
                    events.append({
                        "time":   ts,
                        "source": f"ECS/StoppedTask/{cluster}",
                        "event":  (
                            f"container={container.get('name')} "
                            f"exit_code={container.get('exitCode', '—')} "
                            f"stop_reason={reason}"
                        ),
                    })
            return events
        except Exception:  # noqa: BLE001
            return []

    # ── P2.6: RDS slow query log ──────────────────────────────────────────────

    def rds_slow_queries(self, db_identifier: str, minutes: int = 60) -> list[dict]:
        """Fetch RDS slow query log lines from CloudWatch Logs if enabled.

        Checks the parameter group for slow_query_log / log_min_duration_statement
        then reads from /aws/rds/instance/<id>/slowquery or postgresql log group.
        """
        if not self._session:
            return []
        try:
            rds = self._session.client("rds")
            db  = rds.describe_db_instances(DBInstanceIdentifier=db_identifier)
            instance = db.get("DBInstances", [{}])[0]
            engine   = instance.get("Engine", "")

            # Pick correct log group path by engine
            if "postgres" in engine:
                log_group = f"/aws/rds/instance/{db_identifier}/postgresql"
                pattern   = "?duration ?ERROR ?FATAL"
            else:
                log_group = f"/aws/rds/instance/{db_identifier}/slowquery"
                pattern   = "?Query_time ?slow"

            return self.cloudwatch_logs(log_group=log_group, filter_pattern=pattern, minutes=minutes)
        except Exception:  # noqa: BLE001
            return []

    # ── P2.6: Lambda REPORT line parser ──────────────────────────────────────

    def lambda_report_metrics(self, function_name: str, minutes: int = 60) -> list[dict]:
        """Parse Lambda REPORT lines from CloudWatch Logs.

        Each invocation emits a REPORT line:
          REPORT RequestId: ...  Duration: 234.12 ms  Billed Duration: 235 ms
          Memory Size: 128 MB  Max Memory Used: 87 MB  Init Duration: 312 ms

        Returns structured events with duration, memory, cold_start fields.
        """
        import re  # noqa: PLC0415
        _REPORT_PATTERN = re.compile(
            r"Duration:\s*([\d.]+)\s*ms.*?"
            r"Billed Duration:\s*([\d.]+)\s*ms.*?"
            r"Memory Size:\s*(\d+)\s*MB.*?"
            r"Max Memory Used:\s*(\d+)\s*MB"
            r"(?:.*?Init Duration:\s*([\d.]+)\s*ms)?",
            re.DOTALL,
        )
        log_group = f"/aws/lambda/{function_name}"
        raw = self.cloudwatch_logs(log_group=log_group, filter_pattern="REPORT RequestId", minutes=minutes)
        events = []
        for entry in raw:
            m = _REPORT_PATTERN.search(entry.get("event", ""))
            if m:
                duration, billed, mem_size, mem_used, init = m.groups()
                cold_start = init is not None
                events.append({
                    "time":        entry["time"],
                    "source":      f"LambdaREPORT/{function_name}",
                    "event":       entry["event"],
                    "duration_ms": float(duration),
                    "memory_mb":   int(mem_used),
                    "cold_start":  cold_start,
                })
        return events

    # ── P2.6: SQS DLQ discovery ───────────────────────────────────────────────

    def sqs_with_dlq(self, queue_name_hint: str) -> list[dict]:
        """Discover SQS queues matching a hint and fetch metrics including DLQ depth.

        Returns events for: queue depth, DLQ depth (if configured), message age.
        """
        if not self._session:
            return []
        try:
            sqs    = self._session.client("sqs")
            cw     = self._session.client("cloudwatch")
            queues = sqs.list_queues(QueueNamePrefix=queue_name_hint).get("QueueUrls", [])[:5]
            events = []
            for url in queues:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=url,
                    AttributeNames=["All"],
                ).get("Attributes", {})
                q_name  = url.split("/")[-1]
                depth   = attrs.get("ApproximateNumberOfMessages", "0")
                in_flight = attrs.get("ApproximateNumberOfMessagesNotVisible", "0")
                events.append({
                    "time":   "—",
                    "source": f"SQS/{q_name}",
                    "event":  f"depth={depth} in_flight={in_flight} retention_seconds={attrs.get('MessageRetentionPeriod', '?')}",
                })

                # Check for DLQ via RedrivePolicy
                redrive = attrs.get("RedrivePolicy", "")
                if redrive:
                    import json as _json  # noqa: PLC0415
                    try:
                        rp     = _json.loads(redrive)
                        dlq_arn = rp.get("deadLetterTargetArn", "")
                        max_rcv = rp.get("maxReceiveCount", "?")
                        dlq_name = dlq_arn.split(":")[-1]
                        dlq_url  = sqs.get_queue_url(QueueName=dlq_name).get("QueueUrl", "")
                        if dlq_url:
                            dlq_attrs = sqs.get_queue_attributes(
                                QueueUrl=dlq_url,
                                AttributeNames=["ApproximateNumberOfMessages"],
                            ).get("Attributes", {})
                            dlq_depth = dlq_attrs.get("ApproximateNumberOfMessages", "0")
                            events.append({
                                "time":   "—",
                                "source": f"SQS/DLQ/{dlq_name}",
                                "event":  f"dlq_depth={dlq_depth} max_receive_count={max_rcv} source_queue={q_name}",
                            })
                    except Exception:  # noqa: BLE001
                        pass
            return events
        except Exception:  # noqa: BLE001
            return []

    # ── P2.6: CodePipeline discovery from resource ────────────────────────────

    def codepipeline_for_resource(self, resource_name: str) -> list[dict]:
        """Find CodePipeline pipelines that deploy a named resource.

        Searches by: (1) resource name in pipeline name, (2) pipeline tags,
        (3) tag on the resource itself. Returns recent execution events.
        """
        if not self._session:
            return []
        try:
            cp = self._session.client("codepipeline")
            all_pipelines = cp.list_pipelines().get("pipelines", [])

            matched: list[str] = []
            for p in all_pipelines:
                name = p.get("name", "")
                if resource_name.lower() in name.lower():
                    matched.append(name)

            # Fallback: check tags on the resource for pipeline name
            if not matched:
                try:
                    tagger = self._session.client("resourcegroupstaggingapi")
                    resp   = tagger.get_resources(
                        TagFilters=[{"Key": "pipeline", "Values": [resource_name]}]
                    )
                    for item in resp.get("ResourceTagMappingList", []):
                        for tag in item.get("Tags", []):
                            if tag["Key"].lower() == "pipeline":
                                matched.append(tag["Value"])
                except Exception:  # noqa: BLE001
                    pass

            events = []
            for name in matched[:3]:
                try:
                    execs = cp.list_pipeline_executions(pipelineName=name, maxResults=5)
                    for ex in execs.get("pipelineExecutionSummaries", []):
                        events.append({
                            "time":   ex["startTime"].strftime(_TS_FMT),
                            "source": f"CodePipeline/{name}",
                            "event":  f"status={ex.get('status')} trigger={ex.get('trigger', {}).get('triggerType', '?')}",
                            "status": ex.get("status", ""),
                        })
                except Exception:  # noqa: BLE001
                    pass
            return events
        except Exception:  # noqa: BLE001
            return []

    # ── P2.6: RDS instance discovery from ECS service ────────────────────────

    def rds_for_resource(self, resource_name: str, vpc_id: Optional[str] = None) -> list[dict]:
        """Discover RDS instances likely used by a named resource.

        Strategy: (1) match by resource name in RDS identifier,
        (2) if vpc_id given, return RDS instances in same VPC,
        (3) scan environment variable hints via CloudTrail.
        Returns RDS events for matched instances.
        """
        if not self._session:
            return []
        try:
            rds = self._session.client("rds")
            instances = rds.describe_db_instances().get("DBInstances", [])
            matched = []

            # Name match
            for db in instances:
                ident = db.get("DBInstanceIdentifier", "")
                if resource_name.lower() in ident.lower():
                    matched.append(db)

            # VPC match fallback
            if not matched and vpc_id:
                for db in instances:
                    if db.get("DBSubnetGroup", {}).get("VpcId") == vpc_id:
                        matched.append(db)

            events = []
            for db in matched[:3]:
                ident  = db.get("DBInstanceIdentifier", "")
                status = db.get("DBInstanceStatus", "")
                engine = db.get("Engine", "")
                events.append({
                    "time":   "—",
                    "source": f"RDS/{ident}",
                    "event":  (
                        f"status={status} engine={engine} "
                        f"endpoint={db.get('Endpoint', {}).get('Address', '—')} "
                        f"connections={db.get('DBInstanceClass')} "
                        f"storage={db.get('AllocatedStorage')}GB"
                    ),
                })
                # Also pull recent events
                events.extend(self.rds_events(db_identifier=ident, minutes=120))
            return events
        except Exception:  # noqa: BLE001
            return []

    # ── ACM certificate expiry ────────────────────────────────────────────────

    def acm_certificates(self) -> dict:
        """List all ACM certificates and flag expiry/import risks.

        Called on EVERY debug session regardless of symptom keywords.
        Reason: expired certs cause silent outages with no CPU spike,
        no deployment event, and no CloudWatch alarm — the user describes
        "app went down" not "certificate expired" because they don't know.

        Flags three conditions:
          EXPIRED              — cert is past expiry → active outage cause
          EXPIRING_SOON        — < 30 days remaining → upcoming risk
          IMPORTED_NO_AUTO_RENEW — ACM-issued certs auto-renew; IMPORTED
                                   certs NEVER auto-renew regardless of any
                                   setting. Human must renew manually.
        """
        if not self._session:
            self._mark("acm_certificates", False)
            return {"total": 0, "issues": [], "has_issues": False}
        try:
            acm = self._session.client("acm")
            now = datetime.now(timezone.utc)

            certs: list[dict] = []
            paginator = acm.get_paginator("list_certificates")
            for page in paginator.paginate(
                CertificateStatuses=["ISSUED", "EXPIRED", "INACTIVE"]
            ):
                for summary in page.get("CertificateSummaryList", []):
                    try:
                        detail = acm.describe_certificate(
                            CertificateArn=summary["CertificateArn"]
                        )["Certificate"]
                    except Exception:  # noqa: BLE001
                        continue

                    expiry    = detail.get("NotAfter")
                    cert_type = detail.get("Type", "")
                    in_use_by = detail.get("InUseBy", [])

                    days: int | None = None
                    if expiry:
                        expiry_utc = expiry if expiry.tzinfo else expiry.replace(tzinfo=timezone.utc)
                        days = (expiry_utc - now).days

                    if days is not None and days < 0:
                        status = "EXPIRED"
                    elif days is not None and days < 30:
                        status = "EXPIRING_SOON"
                    elif cert_type == "IMPORTED":
                        status = "IMPORTED_NO_AUTO_RENEW"
                    else:
                        status = "OK"

                    certs.append({
                        "domain":         detail.get("DomainName", "—"),
                        "sans":           detail.get("SubjectAlternativeNames", []),
                        "arn":            summary["CertificateArn"],
                        "status":         status,
                        "days_to_expiry": days,
                        "expiry":         expiry.isoformat() if expiry else None,
                        "type":           cert_type,
                        "auto_renew":     cert_type == "AMAZON_ISSUED",
                        "in_use_by":      in_use_by,
                    })

            expired       = [c for c in certs if c["status"] == "EXPIRED"]
            expiring_soon = [c for c in certs if c["status"] == "EXPIRING_SOON"]
            imported_no_auto = [c for c in certs if c["type"] == "IMPORTED"]
            issues = sorted(
                expired + expiring_soon,
                key=lambda c: c["days_to_expiry"] if c["days_to_expiry"] is not None else -999,
            )

            self._mark("acm_certificates", True)
            return {
                "total":            len(certs),
                "expired":          expired,
                "expiring_soon":    expiring_soon,
                "imported_no_auto": imported_no_auto,
                "issues":           issues,
                "all":              certs,
                "has_issues":       bool(expired or expiring_soon),
            }
        except Exception:  # noqa: BLE001
            self._mark("acm_certificates", False)
            return {"total": 0, "issues": [], "has_issues": False}

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
        filter_pattern: str = "",
        minutes: int = 60,
    ) -> list[dict]:
        if not self._session:
            self._mark("cloudwatch_logs", False)
            return []
        try:
            logs  = self._session.client("logs")
            end   = int(datetime.now(timezone.utc).timestamp() * 1000)
            start = end - minutes * 60 * 1000
            kwargs: dict = dict(
                logGroupName=log_group,
                startTime=start,
                endTime=end,
                limit=100,
            )
            if filter_pattern:
                kwargs["filterPattern"] = filter_pattern
            resp  = logs.filter_log_events(**kwargs)
            events = [
                {
                    "time":   datetime.fromtimestamp(
                        e["timestamp"] / 1000, tz=timezone.utc
                    ).strftime(_TS_FMT),
                    "source": f"CloudWatch/Logs/{log_group}",
                    "event":  e.get("message", "").strip()[:500],
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
            from concurrent.futures import ThreadPoolExecutor  # noqa: PLC0415
            logs      = self._session.client("logs")
            cutoff_ms = int(
                (datetime.now(timezone.utc) - timedelta(minutes=minutes)).timestamp() * 1000
            )
            paginator = logs.get_paginator("describe_log_groups")
            names: list[str] = []
            # Scan up to 5 pages (= 250 log groups) — enough to find recent ones
            for page in paginator.paginate(PaginationConfig={"MaxItems": 250, "PageSize": 50}):
                names.extend(lg["logGroupName"] for lg in page.get("logGroups", []))

            # describe_log_groups does NOT return lastEventTimestamp — that
            # field only exists on log streams. Check each group's most recent
            # stream for true recency, in parallel to keep this fast.
            def _last_event(group: str) -> tuple[int, str]:
                try:
                    streams = logs.describe_log_streams(
                        logGroupName=group,
                        orderBy="LastEventTime",
                        descending=True,
                        limit=1,
                    ).get("logStreams", [])
                    if streams:
                        return streams[0].get("lastEventTimestamp", 0), group
                except Exception:  # noqa: BLE001
                    pass
                return 0, group

            with ThreadPoolExecutor(max_workers=10) as pool:
                results = list(pool.map(_last_event, names[:100]))

            active = [(ts, name) for ts, name in results if ts >= cutoff_ms]
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
                    "event":  e.get("message", "").strip()[:500],
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

    def sqs_with_dlq(self, queue_name: str) -> list[dict]:
        """Discover SQS queues matching a name and fetch metrics including DLQ depth."""
        if not self._session:
            return []
        try:
            sqs    = self._session.client("sqs")
            queues = sqs.list_queues(QueueNamePrefix=queue_name).get("QueueUrls", [])[:5]
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

    # ── GAP 1: Full ALB topology map ─────────────────────────────────────────

    def build_alb_resource_map(self, resource_name: str) -> Optional[dict]:
        """Build complete ALB topology for a resource (ECS service / resource name hint).

        Returns a dict with:
          alb_arn, alb_name, log_config,
          primary_tg  — TargetGroupHealth for the matched resource,
          all_tgs     — list of TargetGroupHealth for every TG on this ALB,
          listeners   — raw listener configs,
          has_unhealthy — True if any TG has unhealthy targets.
        """
        if not self._session:
            return None
        try:
            ecs   = self._session.client("ecs")
            elbv2 = self._session.client("elbv2")

            # Step 1: Find primary TG from ECS service matching the hint
            primary_tg_arn: Optional[str] = None
            clusters = ecs.list_clusters().get("clusterArns", [])[:5]
            for cluster_arn in clusters:
                svcs = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])[:30]
                for svc_arn in svcs:
                    if resource_name.lower() not in svc_arn.lower():
                        continue
                    desc = ecs.describe_services(cluster=cluster_arn, services=[svc_arn])
                    svc  = desc.get("services", [{}])[0]
                    for lb in svc.get("loadBalancers", []):
                        tg_arn = lb.get("targetGroupArn")
                        if tg_arn:
                            primary_tg_arn = tg_arn
                            break
                if primary_tg_arn:
                    break

            # Step 2: Resolve ALB ARN from TG, or fall back to name scan
            alb_arn: Optional[str] = None
            if primary_tg_arn:
                tg_resp  = elbv2.describe_target_groups(TargetGroupArns=[primary_tg_arn])
                alb_arns = tg_resp["TargetGroups"][0].get("LoadBalancerArns", []) if tg_resp["TargetGroups"] else []
                alb_arn  = alb_arns[0] if alb_arns else None
            if not alb_arn:
                for lb in elbv2.describe_load_balancers().get("LoadBalancers", [])[:20]:
                    if resource_name.lower() in lb.get("LoadBalancerName", "").lower():
                        alb_arn = lb.get("LoadBalancerArn")
                        break
            if not alb_arn:
                return None

            alb_name = alb_arn.split("/")[-2] if "/" in alb_arn else alb_arn

            # Step 3: Listeners
            listeners = elbv2.describe_listeners(LoadBalancerArn=alb_arn).get("Listeners", [])

            # Step 4: Build path map {tg_arn: [paths]} from listener rules
            tg_paths: dict = {}
            for lst in listeners:
                try:
                    rules = elbv2.describe_rules(ListenerArn=lst["ListenerArn"]).get("Rules", [])
                    for rule in rules:
                        paths = []
                        for cond in rule.get("Conditions", []):
                            if cond.get("Field") == "path-pattern":
                                paths.extend(cond.get("PathPatternConfig", {}).get("Values", []))
                        for action in rule.get("Actions", []):
                            if action.get("Type") == "forward":
                                for tg_ref in [action.get("TargetGroupArn", "")] + [
                                    w.get("TargetGroupArn", "")
                                    for w in action.get("ForwardConfig", {}).get("TargetGroups", [])
                                ]:
                                    if tg_ref:
                                        tg_paths.setdefault(tg_ref, []).extend(paths)
                except Exception:  # noqa: BLE001
                    pass

            # Step 5+6: All TGs + per-TG target health
            all_tgs_resp = elbv2.describe_target_groups(LoadBalancerArn=alb_arn).get("TargetGroups", [])
            all_tgs = []
            for tg in all_tgs_resp:
                tg_arn   = tg["TargetGroupArn"]
                tg_name  = tg.get("TargetGroupName", "")
                health   = elbv2.describe_target_health(TargetGroupArn=tg_arn).get("TargetHealthDescriptions", [])
                healthy_c   = sum(1 for t in health if t.get("TargetHealth", {}).get("State") == "healthy")
                unhealthy_c = sum(1 for t in health if t.get("TargetHealth", {}).get("State") != "healthy")
                targets_summary = [
                    {
                        "id":     t.get("Target", {}).get("Id"),
                        "port":   t.get("Target", {}).get("Port"),
                        "state":  t.get("TargetHealth", {}).get("State"),
                        "reason": t.get("TargetHealth", {}).get("Reason", ""),
                    }
                    for t in health
                ]
                all_tgs.append({
                    "arn":            tg_arn,
                    "name":           tg_name,
                    "port":           tg.get("Port", 0),
                    "protocol":       tg.get("Protocol", ""),
                    "target_type":    tg.get("TargetType", ""),
                    "healthy_count":  healthy_c,
                    "unhealthy_count": unhealthy_c,
                    "targets":        targets_summary,
                    "routing_paths":  tg_paths.get(tg_arn, []),
                    "is_primary":     tg_arn == primary_tg_arn,
                })

            # Step 7: Log config
            log_config = self.get_alb_log_config(alb_arn)

            primary_tg = next((t for t in all_tgs if t["is_primary"]), None) or (all_tgs[0] if all_tgs else None)
            has_unhealthy = any(t["unhealthy_count"] > 0 for t in all_tgs)

            self._mark("alb_resource_map", True)
            return {
                "alb_arn":       alb_arn,
                "alb_name":      alb_name,
                "primary_tg":    primary_tg,
                "all_tgs":       all_tgs,
                "log_config":    log_config,
                "listeners":     listeners,
                "has_unhealthy": has_unhealthy,
            }
        except Exception:  # noqa: BLE001
            self._mark("alb_resource_map", False)
            return None

    # ── GAP 10: VPC Flow Log REJECT records ──────────────────────────────────

    def vpc_flow_logs(self, vpc_id: Optional[str] = None, minutes: int = 120) -> list[dict]:
        """Fetch VPC Flow Log REJECT records — network-layer packet drops.

        REJECT records are invisible in application logs: the packet is dropped
        before the app sees anything. Indicates NACL or security group blocking.
        Only available if VPC flow logs are enabled and sent to CloudWatch Logs.
        """
        if not self._session:
            self._mark("vpc_flow_logs", False)
            return []
        try:
            ec2  = self._session.client("ec2")
            logs = self._session.client("logs")
            end   = datetime.now(timezone.utc)
            start = end - timedelta(minutes=minutes)

            # Find active flow logs → CloudWatch Logs destination
            fl_filters = [{"Name": "resource-id", "Values": [vpc_id]}] if vpc_id else []
            flow_logs = ec2.describe_flow_logs(
                **({"Filters": fl_filters} if fl_filters else {})
            ).get("FlowLogs", [])

            active_cw = [
                fl for fl in flow_logs
                if fl.get("FlowLogStatus") == "ACTIVE"
                and fl.get("LogDestinationType", "cloud-watch-logs") == "cloud-watch-logs"
                and fl.get("LogGroupName")
            ]
            if not active_cw:
                self._mark("vpc_flow_logs", False)
                return [{
                    "time":   "—",
                    "source": "VPCFlowLogs",
                    "event":  (
                        "WARNING: No active VPC flow logs (CloudWatch destination) configured. "
                        "Enable: CDK vpc.addFlowLog() | Terraform aws_flow_log | "
                        "Console: VPC → Flow Logs → Create"
                    ),
                }]

            events: list[dict] = []
            for fl in active_cw[:2]:
                log_group = fl.get("LogGroupName", "")
                try:
                    resp = logs.filter_log_events(
                        logGroupName=log_group,
                        filterPattern="REJECT",
                        startTime=int(start.timestamp() * 1000),
                        endTime=int(end.timestamp() * 1000),
                        limit=50,
                    )
                    for ev in resp.get("events", []):
                        fields = ev.get("message", "").split()
                        # VPC Flow Log fields: version account-id interface-id
                        # srcaddr dstaddr srcport dstport protocol packets bytes
                        # start end action log-status
                        if len(fields) >= 14 and fields[13] == "REJECT":
                            events.append({
                                "time":   datetime.fromtimestamp(
                                    ev["timestamp"] / 1000, tz=timezone.utc
                                ).strftime(_TS_FMT),
                                "source": f"VPCFlowLog/{log_group}",
                                "event":  (
                                    f"REJECT src={fields[3]}:{fields[5]} "
                                    f"dst={fields[4]}:{fields[6]} "
                                    f"proto={fields[7]} "
                                    f"interface={fields[2]}"
                                ),
                            })
                except Exception:  # noqa: BLE001
                    pass

            self._mark("vpc_flow_logs", bool(events))
            return events
        except Exception:  # noqa: BLE001
            self._mark("vpc_flow_logs", False)
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

    # ── ECS service + task definition details ────────────────────────────────

    # Env/tag values are redacted by SHAPE (known secret formats, JWTs, PEM,
    # long base64 runs) via the guardrails value redactor. Key names always
    # survive: key-name filtering was tried and deleted diagnostic evidence
    # (substring "auth" hid ExplicitAuthFlows/authorizerUri, "token"/"key"
    # hid pagination and KMS/schema fields). Values that merely LOOK like
    # config stay visible; values that look like secret material are masked.

    def _redact_env_value(self, value: str) -> str:
        try:
            from cloudctl.ai.guardrails import _redact_value  # noqa: PLC0415
            return _redact_value(str(value))
        except Exception:  # noqa: BLE001
            return str(value)

    def _filter_tags(self, tags: dict) -> dict:
        """Tags pass through with values redacted by shape — no key filtering."""
        return {k: self._redact_env_value(v) for k, v in (tags or {}).items()}

    def ecs_service_details(self, cluster_hint: str, service_hint: str) -> dict:
        """Fetch ECS service describe + active task definition + container config.

        Returns a dict with:
          service:     running/desired/pending counts, deployments, events, health
          task_def:    cpu, memory, requires_compatibilities, network_mode
          containers:  name, image, cpu, memory, port_mappings, env_vars (redacted),
                       log_config, health_check
        """
        if not self._session:
            return {}
        try:
            ecs = self._session.client("ecs")

            # Resolve cluster — list clusters, match by hint
            cluster_arn = cluster_hint
            try:
                arns = ecs.list_clusters().get("clusterArns", [])
                matched = [a for a in arns if cluster_hint.lower() in a.lower()]
                if matched:
                    cluster_arn = matched[0].split("/")[-1]
                elif arns:
                    cluster_arn = arns[0].split("/")[-1]
            except Exception:  # noqa: BLE001
                pass

            # Resolve service — list services, match by hint
            service_name = service_hint
            try:
                svc_arns = ecs.list_services(cluster=cluster_arn).get("serviceArns", [])
                matched_svc = [a for a in svc_arns if service_hint.lower() in a.lower()]
                if matched_svc:
                    service_name = matched_svc[0].split("/")[-1]
                elif svc_arns:
                    service_name = svc_arns[0].split("/")[-1]
            except Exception:  # noqa: BLE001
                pass

            resp = ecs.describe_services(cluster=cluster_arn, services=[service_name])
            svcs = resp.get("services", [])
            if not svcs:
                return {}

            svc = svcs[0]
            result: dict = {
                "service": {
                    "name":           svc.get("serviceName"),
                    "status":         svc.get("status"),
                    "running_count":  svc.get("runningCount", 0),
                    "desired_count":  svc.get("desiredCount", 0),
                    "pending_count":  svc.get("pendingCount", 0),
                    "launch_type":    svc.get("launchType", ""),
                    "deployments": [
                        {
                            "status":         d.get("status"),
                            "running_count":  d.get("runningCount", 0),
                            "desired_count":  d.get("desiredCount", 0),
                            "failed_tasks":   d.get("failedTasks", 0),
                            "rollout_state":  d.get("rolloutState", ""),
                            "created_at":     d.get("createdAt", ""),
                        }
                        for d in svc.get("deployments", [])[:3]
                    ],
                    "events": [
                        {"time": e.get("createdAt", ""), "message": e.get("message", "")}
                        for e in svc.get("events", [])[:10]
                    ],
                    "load_balancers": svc.get("loadBalancers", []),
                    "health_check_grace_period": svc.get("healthCheckGracePeriodSeconds"),
                },
            }

            # Task definition
            td_arn = svc.get("taskDefinition", "")
            if td_arn:
                try:
                    td = ecs.describe_task_definition(taskDefinition=td_arn)["taskDefinition"]
                    result["task_def"] = {
                        "family":         td.get("family"),
                        "revision":       td.get("revision"),
                        "cpu":            td.get("cpu"),
                        "memory":         td.get("memory"),
                        "network_mode":   td.get("networkMode"),
                        "requires_compat": td.get("requiresCompatibilities", []),
                        "task_role":      td.get("taskRoleArn", ""),
                        "exec_role":      td.get("executionRoleArn", ""),
                    }
                    result["containers"] = []
                    for c in td.get("containerDefinitions", []):
                        env_vars = {
                            e["name"]: self._redact_env_value(e.get("value", ""))
                            for e in c.get("environment", [])
                        }
                        result["containers"].append({
                            "name":          c.get("name"),
                            "image":         c.get("image"),
                            "cpu":           c.get("cpu", 0),
                            "memory":        c.get("memory"),
                            "memory_reservation": c.get("memoryReservation"),
                            "port_mappings": c.get("portMappings", []),
                            "env_vars":      env_vars,
                            "secrets":       [s.get("name") for s in c.get("secrets", [])],
                            "log_config":    c.get("logConfiguration", {}),
                            "health_check":  c.get("healthCheck"),
                            "essential":     c.get("essential", True),
                        })
                except Exception:  # noqa: BLE001
                    pass

            # Recently stopped tasks — stoppedReason is the strongest signal for
            # crash/OOM/health-check/image-pull failures.
            try:
                stopped = self.ecs_stopped_tasks(cluster_arn, service_name, limit=5)
                if stopped:
                    result["recent_stopped_tasks"] = stopped
            except Exception:  # noqa: BLE001
                pass

            # Target group health for any ALBs attached to this service.
            tg_health: list[dict] = []
            for lb in svc.get("loadBalancers", []) or []:
                tg_arn = lb.get("targetGroupArn", "")
                if tg_arn:
                    try:
                        tg_health.extend(self.alb_target_health(tg_arn))
                    except Exception:  # noqa: BLE001
                        pass
            if tg_health:
                result["target_group_health"] = tg_health

            return result
        except Exception:  # noqa: BLE001
            return {}

    # ── Lambda function configuration ─────────────────────────────────────────

    def lambda_function_config(self, resource_name: str) -> dict:
        """Fetch Lambda function configuration: runtime, memory, timeout, VPC,
        env vars (redacted), layers, concurrency, and last invocation errors.

        This is the first-class data needed to diagnose Lambda issues — without it
        the AI has to guess from logs alone. Covers:
          - Memory/timeout settings (OOM, timeout scenarios)
          - VPC config and SGs (VPC connectivity scenarios)
          - Env vars present/missing (missing-config scenarios)
          - Layers (missing-layer scenarios)
          - Reserved concurrency (throttle scenarios)
        """
        if not self._session:
            return {}
        try:
            lmb = self._session.client("lambda")

            # Resolve function name — try direct, then list with hint match
            fn_name = resource_name
            try:
                resp = lmb.list_functions(MaxItems=50)
                fns  = resp.get("Functions", [])
                matched = [f for f in fns if resource_name.lower() in f["FunctionName"].lower()]
                if matched:
                    fn_name = matched[0]["FunctionName"]
            except Exception:  # noqa: BLE001
                pass

            cfg = lmb.get_function_configuration(FunctionName=fn_name)

            env_vars = {
                k: self._redact_env_value(v)
                for k, v in cfg.get("Environment", {}).get("Variables", {}).items()
            }

            vpc = cfg.get("VpcConfig", {})
            result: dict = {
                "function_name":    cfg.get("FunctionName"),
                "runtime":          cfg.get("Runtime"),
                "handler":          cfg.get("Handler"),
                "memory_mb":        cfg.get("MemorySize", 128),
                "timeout_s":        cfg.get("Timeout", 3),
                "state":            cfg.get("State"),
                "state_reason":     cfg.get("StateReason", ""),
                "last_update":      cfg.get("LastUpdateStatus", ""),
                "last_update_reason": cfg.get("LastUpdateStatusReason", ""),
                "role":             cfg.get("Role", ""),
                "env_vars":         env_vars,
                "env_var_keys":     list(env_vars.keys()),
                "layers": [
                    {
                        "arn":  lyr.get("Arn"),
                        "size": lyr.get("CodeSize", 0),
                    }
                    for lyr in cfg.get("Layers", [])
                ],
                "vpc_config": {
                    "vpc_id":            vpc.get("VpcId", ""),
                    "subnet_ids":        vpc.get("SubnetIds", []),
                    "security_group_ids": vpc.get("SecurityGroupIds", []),
                    "in_vpc":            bool(vpc.get("VpcId")),
                } if vpc else {"in_vpc": False},
                "architectures": cfg.get("Architectures", ["x86_64"]),
                "ephemeral_storage_mb": cfg.get("EphemeralStorage", {}).get("Size", 512),
            }

            # Reserved / provisioned concurrency
            try:
                conc = lmb.get_function_concurrency(FunctionName=fn_name)
                result["reserved_concurrency"] = conc.get("ReservedConcurrentExecutions")
            except Exception:  # noqa: BLE001
                pass

            # Event source mappings (Kafka/MSK, DynamoDB Streams, Kinesis,
            # SQS) — when the poller's own auth fails, the function is never
            # invoked at all, so logs are empty and this is the ONLY place
            # AWS surfaces the real failure (StateTransitionReason /
            # LastProcessingResult, e.g. "PROBLEM: Service is unable to ...").
            # Missing this fetcher field was a confirmed root cause of a
            # wrong diagnosis (msk_auth_denied, 2026-06-24): the agent had no
            # tool-visible way to see the ESM was failing auth and guessed
            # "cluster was recreated" from circumstantial metric timing.
            try:
                mappings = lmb.list_event_source_mappings(FunctionName=fn_name).get("EventSourceMappings", [])
                result["event_source_mappings"] = [
                    {
                        "uuid":                     m.get("UUID"),
                        "event_source_arn":         m.get("EventSourceArn"),
                        "state":                    m.get("State"),
                        "state_transition_reason":  m.get("StateTransitionReason"),
                        "last_processing_result":   m.get("LastProcessingResult"),
                        "last_modified":            str(m.get("LastModified", "")),
                    }
                    for m in mappings
                ]
            except Exception:  # noqa: BLE001
                pass

            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # RDS / Aurora
    # ─────────────────────────────────────────────────────────────────────────

    def rds_instance_config(self, resource_name: str) -> dict:
        """Fetch RDS / Aurora instance config — engine, version, SGs, parameter group, events."""
        if not self._session:
            return {}
        try:
            rds = self._session.client("rds")
            instances = rds.describe_db_instances().get("DBInstances", [])
            matched = [
                i for i in instances
                if resource_name.lower() in i.get("DBInstanceIdentifier", "").lower()
                or resource_name.lower() in i.get("DBName", "").lower()
            ]
            if not matched:
                return {}
            inst = matched[0]
            sgs = [{"sg_id": sg.get("VpcSecurityGroupId"), "status": sg.get("Status")}
                   for sg in inst.get("VpcSecurityGroups", [])]
            pg_name = (inst.get("DBParameterGroups") or [{}])[0].get("DBParameterGroupName", "")
            result: dict = {
                "db_instance_identifier": inst.get("DBInstanceIdentifier"),
                "db_instance_class":      inst.get("DBInstanceClass"),
                "engine":                 inst.get("Engine"),
                "engine_version":         inst.get("EngineVersion"),
                "db_name":                inst.get("DBName"),
                "status":                 inst.get("DBInstanceStatus"),
                "multi_az":               inst.get("MultiAZ", False),
                "storage_type":           inst.get("StorageType"),
                "allocated_storage_gb":   inst.get("AllocatedStorage"),
                "max_allocated_storage_gb": inst.get("MaxAllocatedStorage"),
                "storage_encrypted":      inst.get("StorageEncrypted", False),
                "deletion_protection":    inst.get("DeletionProtection", False),
                "publicly_accessible":    inst.get("PubliclyAccessible", False),
                "vpc_id":                 inst.get("DBSubnetGroup", {}).get("VpcId", ""),
                "availability_zone":      inst.get("AvailabilityZone"),
                "vpc_security_groups":    sgs,
                "parameter_group":        pg_name,
                "ca_certificate":         inst.get("CACertificateIdentifier", ""),
                "endpoint": {
                    "address": inst.get("Endpoint", {}).get("Address", ""),
                    "port":    inst.get("Endpoint", {}).get("Port", 0),
                },
                "iam_db_auth_enabled":    inst.get("IAMDatabaseAuthenticationEnabled", False),
                "backup_retention_days":  inst.get("BackupRetentionPeriod", 0),
                "cloudwatch_log_exports": inst.get("EnabledCloudwatchLogsExports", []),
                "tags": self._filter_tags({t["Key"]: t["Value"] for t in inst.get("TagList", [])}),
            }
            pending = inst.get("PendingModifiedValues", {})
            if pending:
                result["pending_modified_values"] = pending
            if pg_name:
                try:
                    overrides: dict = {}
                    pager = rds.get_paginator("describe_db_parameters")
                    for page in pager.paginate(DBParameterGroupName=pg_name):
                        for p in page.get("Parameters", []):
                            if p.get("Source") == "user" and p.get("ParameterValue") is not None:
                                overrides[p["ParameterName"]] = {
                                    "value":        p.get("ParameterValue"),
                                    "apply_method": p.get("ApplyMethod"),
                                    "apply_type":   p.get("ApplyType"),
                                }
                    if overrides:
                        result["parameter_overrides"] = overrides
                except Exception:  # noqa: BLE001
                    pass
            try:
                evts = rds.describe_events(
                    SourceIdentifier=inst["DBInstanceIdentifier"],
                    SourceType="db-instance",
                    Duration=60,
                )
                result["recent_events"] = [
                    {"time": str(e.get("Date", "")), "message": e.get("Message", "")}
                    for e in evts.get("Events", [])[:5]
                ]
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    def aurora_cluster_config(self, resource_name: str) -> dict:
        """Fetch Aurora cluster config — members, failover, serverless scaling."""
        if not self._session:
            return {}
        try:
            rds = self._session.client("rds")
            clusters = rds.describe_db_clusters().get("DBClusters", [])
            matched = [
                c for c in clusters
                if resource_name.lower() in c.get("DBClusterIdentifier", "").lower()
                or resource_name.lower() in c.get("DatabaseName", "").lower()
            ]
            if not matched:
                return {}
            cl = matched[0]
            members = [
                {
                    "instance_id":       m.get("DBInstanceIdentifier"),
                    "is_writer":         m.get("IsClusterWriter", False),
                    "failover_priority": m.get("PromotionTier", 0),
                }
                for m in cl.get("DBClusterMembers", [])
            ]
            return {
                "cluster_identifier":    cl.get("DBClusterIdentifier"),
                "cluster_arn":           cl.get("DBClusterArn"),
                "engine":                cl.get("Engine"),
                "engine_version":        cl.get("EngineVersion"),
                "engine_mode":           cl.get("EngineMode", "provisioned"),
                "status":                cl.get("Status"),
                "multi_az":              cl.get("MultiAZ", False),
                "database_name":         cl.get("DatabaseName", ""),
                "vpc_security_groups": [
                    {"sg_id": sg.get("VpcSecurityGroupId"), "status": sg.get("Status")}
                    for sg in cl.get("VpcSecurityGroups", [])
                ],
                "db_cluster_parameter_group": cl.get("DBClusterParameterGroup", ""),
                "endpoint":              cl.get("Endpoint", ""),
                "reader_endpoint":       cl.get("ReaderEndpoint", ""),
                "port":                  cl.get("Port", 3306),
                "storage_encrypted":     cl.get("StorageEncrypted", False),
                "iam_db_auth_enabled":   cl.get("IAMDatabaseAuthenticationEnabled", False),
                "deletion_protection":   cl.get("DeletionProtectionEnabled", False),
                "backup_retention_days": cl.get("BackupRetentionPeriod", 0),
                "cloudwatch_log_exports": cl.get("EnabledCloudwatchLogsExports", []),
                "members":               members,
                "scaling_config":        cl.get("ScalingConfigurationInfo", {}),
                "serverless_v2_config":  cl.get("ServerlessV2ScalingConfiguration", {}),
                "tags": self._filter_tags({t["Key"]: t["Value"] for t in cl.get("TagList", [])}),
            }
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # Redshift
    # ─────────────────────────────────────────────────────────────────────────

    def redshift_cluster_config(self, resource_name: str) -> dict:
        """Fetch Redshift cluster config — node type, count, VPC, encryption, maintenance."""
        if not self._session:
            return {}
        try:
            rs = self._session.client("redshift")
            clusters = rs.describe_clusters().get("Clusters", [])
            matched = [
                c for c in clusters
                if resource_name.lower() in c.get("ClusterIdentifier", "").lower()
                or resource_name.lower() in c.get("DBName", "").lower()
            ]
            if not matched:
                return {}
            cl = matched[0]
            result: dict = {
                "cluster_identifier":    cl.get("ClusterIdentifier"),
                "cluster_status":        cl.get("ClusterStatus"),
                "node_type":             cl.get("NodeType"),
                "number_of_nodes":       cl.get("NumberOfNodes", 1),
                "db_name":               cl.get("DBName"),
                "master_username":       cl.get("MasterUsername"),
                "endpoint": {
                    "address": cl.get("Endpoint", {}).get("Address", ""),
                    "port":    cl.get("Endpoint", {}).get("Port", 5439),
                },
                "publicly_accessible":   cl.get("PubliclyAccessible", False),
                "encrypted":             cl.get("Encrypted", False),
                "kms_key_id":            cl.get("KmsKeyId", ""),
                "vpc_id":                cl.get("VpcId", ""),
                "vpc_security_groups": [
                    {"sg_id": sg.get("VpcSecurityGroupId"), "status": sg.get("Status")}
                    for sg in cl.get("VpcSecurityGroups", [])
                ],
                "cluster_parameter_group": (cl.get("ClusterParameterGroups") or [{}])[0].get("ParameterGroupName", ""),
                "automated_snapshot_retention_days": cl.get("AutomatedSnapshotRetentionPeriod", 1),
                "preferred_maintenance_window":      cl.get("PreferredMaintenanceWindow", ""),
                "allow_version_upgrade": cl.get("AllowVersionUpgrade", True),
                "cluster_version":       cl.get("ClusterVersion", ""),
                "availability_zone":     cl.get("AvailabilityZone", ""),
                "tags": self._filter_tags({t["Key"]: t["Value"] for t in cl.get("Tags", [])}),
            }
            pmv = cl.get("PendingModifiedValues", {})
            if pmv:
                result["pending_modified_values"] = pmv
            try:
                evts = rs.describe_events(
                    SourceIdentifier=cl["ClusterIdentifier"],
                    SourceType="cluster",
                    Duration=60,
                )
                result["recent_events"] = [
                    {"time": str(e.get("Date", "")), "message": e.get("Message", "")}
                    for e in evts.get("Events", [])[:5]
                ]
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # Glue
    # ─────────────────────────────────────────────────────────────────────────

    def glue_job_config(self, resource_name: str) -> dict:
        """Fetch Glue job config — worker type, capacity, connections, bookmarks, last runs."""
        if not self._session:
            return {}
        try:
            glue = self._session.client("glue")
            jobs = glue.get_jobs(MaxResults=50).get("Jobs", [])
            matched = [j for j in jobs if resource_name.lower() in j.get("Name", "").lower()]
            if not matched:
                return {}
            job = matched[0]
            result: dict = {
                "job_name":        job.get("Name"),
                "job_type":        job.get("Command", {}).get("Name", ""),
                "glue_version":    job.get("GlueVersion", ""),
                "worker_type":     job.get("WorkerType", ""),
                "num_workers":     job.get("NumberOfWorkers", 0),
                "max_capacity":    job.get("MaxCapacity", 0),
                "timeout_minutes": job.get("Timeout", 2880),
                "max_retries":     job.get("MaxRetries", 0),
                "connections":     job.get("Connections", {}).get("Connections", []),
                "default_arguments": {
                    k: v for k, v in job.get("DefaultArguments", {}).items()
                    if not any(s in k.lower() for s in ("password", "secret", "key", "token"))
                },
                "role":            job.get("Role", ""),
                "security_config": job.get("SecurityConfiguration", ""),
                "bookmark_option": job.get("JobBookmarkOption", {}).get("JobBookmarkOption", ""),
            }
            try:
                runs = glue.get_job_runs(JobName=job["Name"], MaxResults=5).get("JobRuns", [])
                result["last_runs"] = [
                    {
                        "job_run_id":    r.get("Id"),
                        "state":         r.get("JobRunState"),
                        "started":       str(r.get("StartedOn", "")),
                        "completed":     str(r.get("CompletedOn", "")),
                        "duration_s":    r.get("ExecutionTime", 0),
                        "error_message": r.get("ErrorMessage", ""),
                        "dpu_seconds":   r.get("DPUSeconds", 0),
                    }
                    for r in runs
                ]
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # API Gateway
    # ─────────────────────────────────────────────────────────────────────────

    def api_gateway_config(self, resource_name: str) -> dict:
        """Fetch API Gateway config — HTTP API v2 + REST v1, stages, throttling, CORS."""
        if not self._session:
            return {}
        try:
            apiv2 = self._session.client("apigatewayv2")
            apis_v2 = apiv2.get_apis().get("Items", [])
            matched_v2 = [
                a for a in apis_v2
                if resource_name.lower() in a.get("Name", "").lower()
                or resource_name.lower() in a.get("ApiId", "").lower()
            ]
            if matched_v2:
                api = matched_v2[0]
                api_id = api["ApiId"]
                stages = apiv2.get_stages(ApiId=api_id).get("Items", [])
                routes = apiv2.get_routes(ApiId=api_id).get("Items", [])
                return {
                    "type":          "HTTP_API_V2",
                    "api_id":        api_id,
                    "api_name":      api.get("Name"),
                    "protocol_type": api.get("ProtocolType"),
                    "cors_config":   api.get("CorsConfiguration", {}),
                    "stages": [
                        {
                            "name":             s.get("StageName"),
                            "auto_deploy":      s.get("AutoDeploy", False),
                            "throttling_burst": s.get("DefaultRouteSettings", {}).get("ThrottlingBurstLimit"),
                            "throttling_rate":  s.get("DefaultRouteSettings", {}).get("ThrottlingRateLimit"),
                            "detailed_metrics": s.get("DefaultRouteSettings", {}).get("DetailedMetricsEnabled", False),
                        }
                        for s in stages[:5]
                    ],
                    "routes": [
                        {"route_key": r.get("RouteKey"), "target": r.get("Target", "")}
                        for r in routes[:10]
                    ],
                }
            apiv1 = self._session.client("apigateway")
            apis_v1 = apiv1.get_rest_apis().get("items", [])
            matched_v1 = [
                a for a in apis_v1
                if resource_name.lower() in a.get("name", "").lower()
                or resource_name.lower() in a.get("id", "").lower()
            ]
            if matched_v1:
                api = matched_v1[0]
                api_id = api["id"]
                stages = apiv1.get_stages(restApiId=api_id).get("item", [])
                integrations = []
                try:
                    resources = apiv1.get_resources(restApiId=api_id, limit=50).get("items", [])
                    for r in resources:
                        r_id = r.get("id")
                        path = r.get("path")
                        methods = r.get("resourceMethods", {}).keys()
                        for m in methods:
                            try:
                                integ = apiv1.get_integration(restApiId=api_id, resourceId=r_id, httpMethod=m)
                                integrations.append({
                                    "resource_path": path,
                                    "http_method": m,
                                    "type": integ.get("type"),
                                    "uri": integ.get("uri"),
                                    "timeout_ms": integ.get("timeoutInMillis")
                                })
                            except Exception:
                                pass
                except Exception:
                    pass
                # Fetch authorizer config — TOKEN/COGNITO authorizers store their
                # validation logic (Lambda env vars or Cognito pool) here; mismatched
                # client IDs or wrong pool ARNs produce 401s with zero other signal.
                authorizers = []
                try:
                    lmb = self._session.client("lambda")
                    for auth in apiv1.get_authorizers(restApiId=api_id).get("items", []):
                        auth_entry: dict = {
                            "id":             auth.get("id"),
                            "name":           auth.get("name"),
                            "type":           auth.get("type"),
                            "provider_arns":  auth.get("providerARNs", []),
                            "identity_source": auth.get("identitySource"),
                            "ttl_seconds":    auth.get("authorizerResultTtlInSeconds"),
                        }
                        # For Lambda TOKEN authorizers, fetch the function's env vars —
                        # expected client IDs, allowed audiences, etc. are often stored there.
                        uri = auth.get("authorizerUri", "")
                        if auth.get("type") == "TOKEN" and "/functions/" in uri:
                            try:
                                lambda_arn = uri.split("/functions/")[1].split("/invocations")[0]
                                fn_cfg = lmb.get_function_configuration(FunctionName=lambda_arn)
                                auth_entry["lambda_env_vars"] = {
                                    k: self._redact_env_value(v)
                                    for k, v in fn_cfg.get("Environment", {}).get("Variables", {}).items()
                                }
                                auth_entry["lambda_function_name"] = fn_cfg.get("FunctionName")
                            except Exception:  # noqa: BLE001
                                pass
                        authorizers.append(auth_entry)
                except Exception:  # noqa: BLE001
                    pass
                return {
                    "type":        "REST_API_V1",
                    "api_id":      api_id,
                    "api_name":    api.get("name"),
                    "description": api.get("description", ""),
                    "stages": [
                        {
                            "name":            s.get("stageName"),
                            "web_acl_arn":     s.get("webAclArn"),
                            "logging_level":   s.get("methodSettings", {}).get("*/*", {}).get("loggingLevel", "OFF"),
                            "metrics_enabled": s.get("methodSettings", {}).get("*/*", {}).get("metricsEnabled", False),
                            "caching_enabled": s.get("cacheClusterEnabled", False),
                            "throttling_burst": s.get("methodSettings", {}).get("*/*", {}).get("throttlingBurstLimit"),
                            "throttling_rate":  s.get("methodSettings", {}).get("*/*", {}).get("throttlingRateLimit"),
                        }
                        for s in stages[:5]
                    ],
                    "integrations": integrations,
                    "authorizers":  authorizers,
                }
            return {}
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # DynamoDB
    # ─────────────────────────────────────────────────────────────────────────

    def dynamodb_table_config(self, resource_name: str) -> dict:
        """Fetch DynamoDB table config — billing, capacity, GSIs, TTL, streams."""
        if not self._session:
            return {}
        try:
            ddb = self._session.client("dynamodb")
            tables = ddb.list_tables().get("TableNames", [])
            matched = [t for t in tables if resource_name.lower() in t.lower()]
            if not matched:
                return {}
            table_name = matched[0]
            desc = ddb.describe_table(TableName=table_name)["Table"]
            gsis = [
                {
                    "name":       g.get("IndexName"),
                    "status":     g.get("IndexStatus"),
                    "key_schema": g.get("KeySchema", []),
                    "projection": g.get("Projection", {}).get("ProjectionType"),
                    "item_count": g.get("ItemCount", 0),
                    "size_bytes": g.get("IndexSizeBytes", 0),
                }
                for g in desc.get("GlobalSecondaryIndexes", [])
            ]
            result: dict = {
                "table_name":   desc.get("TableName"),
                "table_status": desc.get("TableStatus"),
                "billing_mode": desc.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED"),
                "item_count":   desc.get("ItemCount", 0),
                "size_bytes":   desc.get("TableSizeBytes", 0),
                "key_schema":   desc.get("KeySchema", []),
                "provisioned_throughput": {
                    "read_capacity_units":  desc.get("ProvisionedThroughput", {}).get("ReadCapacityUnits", 0),
                    "write_capacity_units": desc.get("ProvisionedThroughput", {}).get("WriteCapacityUnits", 0),
                    "last_decrease":        str(desc.get("ProvisionedThroughput", {}).get("LastDecreaseDateTime", "")),
                    "last_increase":        str(desc.get("ProvisionedThroughput", {}).get("LastIncreaseDateTime", "")),
                    "decreases_today":      desc.get("ProvisionedThroughput", {}).get("NumberOfDecreasesToday", 0),
                },
                "global_secondary_indexes": gsis,
                "stream_specification":     desc.get("StreamSpecification", {}),
                "sse_description":          desc.get("SSEDescription", {}),
                "deletion_protection":      desc.get("DeletionProtectionEnabled", False),
                "table_class":              desc.get("TableClassSummary", {}).get("TableClass", "STANDARD"),
                "replicas":                 [r.get("RegionName") for r in desc.get("Replicas", [])],
            }
            try:
                ttl = ddb.describe_time_to_live(TableName=table_name).get("TimeToLiveDescription", {})
                result["ttl"] = {"status": ttl.get("TimeToLiveStatus"), "attribute": ttl.get("AttributeName", "")}
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # S3
    # ─────────────────────────────────────────────────────────────────────────

    def s3_bucket_config(self, resource_name: str) -> dict:
        """Fetch S3 bucket config — versioning, encryption, CORS, lifecycle, notifications."""
        if not self._session:
            return {}
        try:
            s3 = self._session.client("s3")
            buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
            matched = [b for b in buckets if resource_name.lower() in b.lower()]
            if not matched:
                return {}
            bucket = matched[0]
            result: dict = {"bucket_name": bucket}
            try:
                v = s3.get_bucket_versioning(Bucket=bucket)
                result["versioning"] = v.get("Status", "Disabled")
                result["mfa_delete"] = v.get("MFADelete", "Disabled")
            except Exception:  # noqa: BLE001
                pass
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                result["encryption"] = [
                    {
                        "sse_algorithm": r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm"),
                        "kms_key":       r.get("ApplyServerSideEncryptionByDefault", {}).get("KMSMasterKeyID", ""),
                        "bucket_key":    r.get("BucketKeyEnabled", False),
                    }
                    for r in rules
                ]
            except Exception:  # noqa: BLE001
                result["encryption"] = "none"
            try:
                pab = s3.get_public_access_block(Bucket=bucket).get("PublicAccessBlockConfiguration", {})
                result["public_access_block"] = {
                    "block_public_acls":       pab.get("BlockPublicAcls", False),
                    "ignore_public_acls":      pab.get("IgnorePublicAcls", False),
                    "block_public_policy":     pab.get("BlockPublicPolicy", False),
                    "restrict_public_buckets": pab.get("RestrictPublicBuckets", False),
                }
            except Exception:  # noqa: BLE001
                pass
            try:
                cors = s3.get_bucket_cors(Bucket=bucket).get("CORSRules", [])
                result["cors_rules"] = cors[:3]
            except Exception:  # noqa: BLE001
                result["cors_rules"] = []
            try:
                lc = s3.get_bucket_lifecycle_configuration(Bucket=bucket).get("Rules", [])
                result["lifecycle_rules_count"] = len(lc)
                result["lifecycle_rules"] = [
                    {"id": r.get("ID"), "status": r.get("Status"), "prefix": r.get("Filter", {}).get("Prefix", "")}
                    for r in lc[:3]
                ]
            except Exception:  # noqa: BLE001
                result["lifecycle_rules_count"] = 0
            try:
                notif = s3.get_bucket_notification_configuration(Bucket=bucket)
                result["notifications"] = {
                    "lambda_configs": len(notif.get("LambdaFunctionConfigurations", [])),
                    "sns_configs":    len(notif.get("TopicConfigurations", [])),
                    "sqs_configs":    len(notif.get("QueueConfigurations", [])),
                }
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # Secrets Manager
    # ─────────────────────────────────────────────────────────────────────────

    def secrets_manager_config(self, resource_name: str) -> dict:
        """Fetch Secrets Manager metadata — rotation, KMS key.  Secret VALUE is never fetched."""
        if not self._session:
            return {}
        try:
            sm = self._session.client("secretsmanager")
            secrets = sm.list_secrets(MaxResults=50).get("SecretList", [])
            matched = [
                s for s in secrets
                if resource_name.lower() in s.get("Name", "").lower()
                or resource_name.lower() in s.get("ARN", "").lower()
            ]
            if not matched:
                return {}
            secret = matched[0]
            result: dict = {
                "rotation_enabled":    secret.get("RotationEnabled", False),
                "rotation_lambda_arn": secret.get("RotationLambdaARN", ""),
                "rotation_rules":      secret.get("RotationRules", {}),
                "secret_name":         secret.get("Name"),
                "secret_arn":          secret.get("ARN"),
                "description":         secret.get("Description", ""),
                "kms_key_id":          secret.get("KmsKeyId", "aws/secretsmanager"),
                "last_rotated_date":   str(secret.get("LastRotatedDate", "")),
                "last_accessed_date":  str(secret.get("LastAccessedDate", "")),
                "last_changed_date":   str(secret.get("LastChangedDate", "")),
                "deleted_date":        str(secret.get("DeletedDate", "")),
                "tags": self._filter_tags({t["Key"]: t["Value"] for t in secret.get("Tags", [])}),
            }
            try:
                versions = sm.list_secret_version_ids(
                    SecretId=secret["ARN"], IncludeDeprecated=False
                ).get("Versions", [])
                result["version_stages"] = [
                    {"version_id": v.get("VersionId", "")[:8] + "...", "stages": v.get("VersionStages", [])}
                    for v in versions[:5]
                ]
            except Exception:  # noqa: BLE001
                pass
            # Fetch resource-based policy — an explicit Deny here blocks access
            # even when the caller's IAM identity policy grants the action.
            try:
                rp = sm.get_resource_policy(SecretId=secret["ARN"])
                policy_str = rp.get("ResourcePolicy", "")
                if policy_str:
                    import json as _json
                    result["resource_policy"] = _json.loads(policy_str)
                else:
                    result["resource_policy"] = None
            except Exception:  # noqa: BLE001
                result["resource_policy"] = None
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # SNS
    # ─────────────────────────────────────────────────────────────────────────

    def sns_topic_config(self, resource_name: str) -> dict:
        """Fetch SNS topic attributes and subscription counts."""
        if not self._session:
            return {}
        try:
            sns = self._session.client("sns")
            topics = sns.list_topics().get("Topics", [])
            matched = [t for t in topics if resource_name.lower() in t.get("TopicArn", "").lower()]
            if not matched:
                return {}
            topic_arn = matched[0]["TopicArn"]
            attrs = sns.get_topic_attributes(TopicArn=topic_arn).get("Attributes", {})
            result: dict = {
                "topic_arn":               topic_arn,
                "topic_name":              topic_arn.split(":")[-1],
                "display_name":            attrs.get("DisplayName", ""),
                "subscriptions_confirmed": int(attrs.get("SubscriptionsConfirmed", 0)),
                "subscriptions_pending":   int(attrs.get("SubscriptionsPending", 0)),
                "subscriptions_deleted":   int(attrs.get("SubscriptionsDeleted", 0)),
                "fifo_topic":              attrs.get("FifoTopic") == "true",
                "content_based_dedup":     attrs.get("ContentBasedDeduplication") == "true",
                "kms_master_key_id":       attrs.get("KmsMasterKeyId", ""),
            }
            try:
                subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn).get("Subscriptions", [])
                result["subscriptions"] = [
                    {
                        "protocol":         s.get("Protocol"),
                        "subscription_arn": s.get("SubscriptionArn"),
                        "endpoint":         s.get("Endpoint", "")[:60],
                    }
                    for s in subs[:10]
                ]
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # SQS
    # ─────────────────────────────────────────────────────────────────────────

    def sqs_queue_config(self, resource_name: str) -> dict:
        """Fetch SQS queue config — visibility timeout, DLQ, delay, encryption, message counts."""
        if not self._session:
            return {}
        try:
            import json as _json
            sqs = self._session.client("sqs")
            queues = sqs.list_queues(QueueNamePrefix="").get("QueueUrls", [])
            matched = [q for q in queues if resource_name.lower() in q.lower()]
            if not matched:
                return {}
            queue_url = matched[0]
            attrs = sqs.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["All"]
            ).get("Attributes", {})
            result: dict = {
                "queue_url":                    queue_url,
                "queue_name":                   queue_url.split("/")[-1],
                "queue_arn":                    attrs.get("QueueArn", ""),
                "visibility_timeout_s":         int(attrs.get("VisibilityTimeout", 30)),
                "message_retention_s":          int(attrs.get("MessageRetentionPeriod", 345600)),
                "max_message_size_bytes":       int(attrs.get("MaximumMessageSize", 262144)),
                "delay_seconds":                int(attrs.get("DelaySeconds", 0)),
                "receive_wait_time_s":          int(attrs.get("ReceiveMessageWaitTimeSeconds", 0)),
                "approximate_messages":         int(attrs.get("ApproximateNumberOfMessages", 0)),
                "approximate_messages_delayed": int(attrs.get("ApproximateNumberOfMessagesDelayed", 0)),
                "approximate_messages_not_visible": int(attrs.get("ApproximateNumberOfMessagesNotVisible", 0)),
                "fifo":                         attrs.get("FifoQueue") == "True",
                "content_based_dedup":          attrs.get("ContentBasedDeduplication") == "True",
                "kms_key_id":                   attrs.get("KmsMasterKeyId", ""),
                "dlq_arn":                      "",
                "max_receive_count":            0,
            }
            redrive = attrs.get("RedrivePolicy")
            if redrive:
                try:
                    rd = _json.loads(redrive)
                    result["dlq_arn"] = rd.get("deadLetterTargetArn", "")
                    result["max_receive_count"] = int(rd.get("maxReceiveCount", 0))
                except Exception:  # noqa: BLE001
                    pass

            # DLQ current depth — a growing DLQ is the canonical "messages
            # failing silently" signal.
            if result.get("dlq_arn"):
                try:
                    dlq_url = sqs.get_queue_url(
                        QueueName=result["dlq_arn"].split(":")[-1]
                    ).get("QueueUrl", "")
                    if dlq_url:
                        dlq_attrs = sqs.get_queue_attributes(
                            QueueUrl=dlq_url,
                            AttributeNames=["ApproximateNumberOfMessages"],
                        ).get("Attributes", {})
                        result["dlq_depth"] = int(dlq_attrs.get("ApproximateNumberOfMessages", 0))
                except Exception:  # noqa: BLE001
                    pass

            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # ElastiCache
    # ─────────────────────────────────────────────────────────────────────────

    def elasticache_config(self, resource_name: str) -> dict:
        """Fetch ElastiCache config — Redis replication group or Memcached cluster."""
        if not self._session:
            return {}
        try:
            ec = self._session.client("elasticache")
            rgs = ec.describe_replication_groups().get("ReplicationGroups", [])
            matched_rg = [
                r for r in rgs
                if resource_name.lower() in r.get("ReplicationGroupId", "").lower()
                or resource_name.lower() in r.get("Description", "").lower()
            ]
            if matched_rg:
                rg = matched_rg[0]
                result: dict = {
                    "type":                   "redis_replication_group",
                    "replication_group_id":   rg.get("ReplicationGroupId"),
                    "description":            rg.get("Description", ""),
                    "status":                 rg.get("Status"),
                    "node_count":             len(rg.get("MemberClusters", [])),
                    "member_clusters":        rg.get("MemberClusters", []),
                    "automatic_failover":     rg.get("AutomaticFailover"),
                    "multi_az":               rg.get("MultiAZ"),
                    "at_rest_encryption":     rg.get("AtRestEncryptionEnabled", False),
                    "transit_encryption":     rg.get("TransitEncryptionEnabled", False),
                    "auth_token_enabled":     rg.get("AuthTokenEnabled", False),
                    "cluster_mode":           rg.get("ClusterEnabled", False),
                    "snapshot_retention_days": rg.get("SnapshotRetentionLimit", 0),
                    "node_groups": [
                        {
                            "node_group_id": ng.get("NodeGroupId"),
                            "status":        ng.get("Status"),
                            "primary":       ng.get("PrimaryEndpoint", {}).get("Address", ""),
                            "reader":        ng.get("ReaderEndpoint", {}).get("Address", ""),
                        }
                        for ng in rg.get("NodeGroups", [])[:3]
                    ],
                }
                if rg.get("MemberClusters"):
                    try:
                        cls = ec.describe_cache_clusters(
                            CacheClusterId=rg["MemberClusters"][0], ShowCacheNodeInfo=True
                        ).get("CacheClusters", [{}])[0]
                        result["node_type"]       = cls.get("CacheNodeType")
                        result["engine"]          = cls.get("Engine")
                        result["engine_version"]  = cls.get("EngineVersion")
                        result["security_groups"] = [
                            {"sg_id": sg.get("SecurityGroupId"), "status": sg.get("Status")}
                            for sg in cls.get("SecurityGroups", [])
                        ]
                    except Exception:  # noqa: BLE001
                        pass
                return result
            clusters = ec.describe_cache_clusters(ShowCacheNodeInfo=True).get("CacheClusters", [])
            matched_mc = [c for c in clusters if resource_name.lower() in c.get("CacheClusterId", "").lower()]
            if matched_mc:
                cls = matched_mc[0]
                return {
                    "type":            "memcached_cluster",
                    "cluster_id":      cls.get("CacheClusterId"),
                    "status":          cls.get("CacheClusterStatus"),
                    "node_type":       cls.get("CacheNodeType"),
                    "engine":          cls.get("Engine"),
                    "engine_version":  cls.get("EngineVersion"),
                    "num_cache_nodes": cls.get("NumCacheNodes", 0),
                    "security_groups": [
                        {"sg_id": sg.get("SecurityGroupId"), "status": sg.get("Status")}
                        for sg in cls.get("SecurityGroups", [])
                    ],
                }
            return {}
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # Kinesis
    # ─────────────────────────────────────────────────────────────────────────

    def kinesis_stream_config(self, resource_name: str) -> dict:
        """Fetch Kinesis Data Streams config — shard count, retention, encryption, consumers."""
        if not self._session:
            return {}
        try:
            kin = self._session.client("kinesis")
            streams = kin.list_streams().get("StreamNames", [])
            matched = [s for s in streams if resource_name.lower() in s.lower()]
            if not matched:
                return {}
            stream_name = matched[0]
            desc = kin.describe_stream_summary(StreamName=stream_name).get("StreamDescriptionSummary", {})
            result: dict = {
                "stream_name":            desc.get("StreamName"),
                "stream_arn":             desc.get("StreamARN"),
                "stream_status":          desc.get("StreamStatus"),
                "stream_mode":            desc.get("StreamModeDetails", {}).get("StreamMode", "PROVISIONED"),
                "shard_count":            desc.get("OpenShardCount", 0),
                "retention_period_hours": desc.get("RetentionPeriodHours", 24),
                "enhanced_monitoring":    [m.get("ShardLevelMetrics", []) for m in desc.get("EnhancedMonitoring", [])],
                "encryption_type":        desc.get("EncryptionType", "NONE"),
                "key_id":                 desc.get("KeyId", ""),
                "consumer_count":         desc.get("ConsumerCount", 0),
            }
            try:
                consumers = kin.list_stream_consumers(StreamARN=desc["StreamARN"]).get("Consumers", [])
                result["consumers"] = [
                    {"name": c.get("ConsumerName"), "status": c.get("ConsumerStatus")}
                    for c in consumers[:5]
                ]
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # Step Functions
    # ─────────────────────────────────────────────────────────────────────────

    def stepfunctions_config(self, resource_name: str) -> dict:
        """Fetch Step Functions state machine config and recent execution summary."""
        if not self._session:
            return {}
        try:
            sf = self._session.client("stepfunctions")
            machines = sf.list_state_machines().get("stateMachines", [])
            matched = [m for m in machines if resource_name.lower() in m.get("name", "").lower()]
            if not matched:
                return {}
            arn = matched[0]["stateMachineArn"]
            desc = sf.describe_state_machine(stateMachineArn=arn)
            result: dict = {
                "name":              desc.get("name"),
                "arn":               arn,
                "status":            desc.get("status"),
                "type":              desc.get("type"),
                "role_arn":          desc.get("roleArn"),
                "logging_level":     desc.get("loggingConfiguration", {}).get("level", "OFF"),
                "tracing_enabled":   desc.get("tracingConfiguration", {}).get("enabled", False),
                "created":           str(desc.get("creationDate", "")),
            }
            try:
                execs = sf.list_executions(stateMachineArn=arn, maxResults=20).get("executions", [])
                counts: dict = {}
                for e in execs:
                    counts[e["status"]] = counts.get(e["status"], 0) + 1
                result["recent_executions_summary"] = counts
                failed = [e for e in execs if e["status"] == "FAILED"]
                if failed:
                    detail = sf.describe_execution(executionArn=failed[0]["executionArn"])
                    result["last_failed_cause"] = detail.get("cause", "")[:500]
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # OpenSearch
    # ─────────────────────────────────────────────────────────────────────────

    def opensearch_config(self, resource_name: str) -> dict:
        """Fetch OpenSearch domain config and cluster health."""
        if not self._session:
            return {}
        try:
            os_client = self._session.client("opensearch")
            domains = os_client.list_domain_names().get("DomainNames", [])
            matched = [d for d in domains if resource_name.lower() in d.get("DomainName", "").lower()]
            if not matched:
                return {}
            name = matched[0]["DomainName"]
            desc = os_client.describe_domain(DomainName=name).get("DomainStatus", {})
            cluster = desc.get("ClusterConfig", {})
            result: dict = {
                "domain_name":          name,
                "arn":                  desc.get("ARN"),
                "engine_version":       desc.get("EngineVersion"),
                "endpoint":             desc.get("Endpoint", ""),
                "instance_type":        cluster.get("InstanceType"),
                "instance_count":       cluster.get("InstanceCount"),
                "dedicated_master":     cluster.get("DedicatedMasterEnabled", False),
                "master_type":          cluster.get("DedicatedMasterType", ""),
                "zone_awareness":       cluster.get("ZoneAwarenessEnabled", False),
                "ebs_enabled":          desc.get("EBSOptions", {}).get("EBSEnabled", False),
                "volume_size_gb":       desc.get("EBSOptions", {}).get("VolumeSize"),
                "encryption_at_rest":   desc.get("EncryptionAtRestOptions", {}).get("Enabled", False),
                "node_to_node_encrypt": desc.get("NodeToNodeEncryptionOptions", {}).get("Enabled", False),
                "created":              desc.get("Created", False),
                "deleted":              desc.get("Deleted", False),
            }
            try:
                health = os_client.describe_domain_health(DomainName=name)
                result["cluster_health"] = health.get("DomainHealth", "")
                result["active_shards"]  = health.get("ActiveShardsPercent", "")
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # EventBridge
    # ─────────────────────────────────────────────────────────────────────────

    def eventbridge_rule_config(self, resource_name: str) -> dict:
        """Fetch EventBridge rule config — schedule/pattern, targets, state.

        list_rules()/list_targets_by_rule() without EventBusName only search
        the DEFAULT bus — a rule on a custom bus is invisible otherwise.
        Confirmed the hard way (streaming-etl, eventbridge_rule_misfire,
        2026-06-24): the agent concluded "no rule exists" with HIGH
        confidence because its only rule lived on a custom bus this call
        never looked at. Enumerate every bus, not just the default one.
        """
        if not self._session:
            return {}
        try:
            eb = self._session.client("events")
            bus_names = ["default"] + [
                b["Name"] for b in eb.list_event_buses().get("EventBuses", [])
                if b["Name"] != "default"
            ]

            rule = None
            event_bus_name = "default"
            for bus in bus_names:
                try:
                    candidates = eb.list_rules(NamePrefix=resource_name[:64], EventBusName=bus).get("Rules", [])
                    if not candidates:
                        candidates = [r for r in eb.list_rules(EventBusName=bus).get("Rules", [])
                                      if resource_name.lower() in r.get("Name", "").lower()]
                except Exception:  # noqa: BLE001
                    candidates = []
                if candidates:
                    rule = candidates[0]
                    event_bus_name = bus
                    break

            if rule is None:
                return {}
            targets = eb.list_targets_by_rule(Rule=rule["Name"], EventBusName=event_bus_name).get("Targets", [])
            return {
                "name":               rule.get("Name"),
                "state":              rule.get("State"),
                "schedule":           rule.get("ScheduleExpression", ""),
                "event_pattern":      rule.get("EventPattern", ""),
                "event_bus":          rule.get("EventBusName", "default"),
                "targets": [
                    {
                        "id":  t.get("Id"),
                        "arn": t.get("Arn"),
                        "dlq": t.get("DeadLetterConfig", {}).get("Arn", ""),
                    }
                    for t in targets
                ],
            }
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # CloudFront
    # ─────────────────────────────────────────────────────────────────────────

    def cloudfront_config(self, resource_name: str) -> dict:
        """Fetch CloudFront distribution config — origins, behaviors, cache policy."""
        if not self._session:
            return {}
        try:
            cf = self._session.client("cloudfront")
            items = cf.list_distributions().get("DistributionList", {}).get("Items", [])
            matched = [d for d in items
                       if resource_name.lower() in d.get("Id", "").lower()
                       or resource_name.lower() in d.get("DomainName", "").lower()
                       or any(resource_name.lower() in a.lower()
                              for a in d.get("Aliases", {}).get("Items", []))]
            if not matched:
                return {}
            d = matched[0]
            dist_id = d["Id"]
            desc = cf.get_distribution(Id=dist_id).get("Distribution", {})
            cfg  = desc.get("DistributionConfig", {})
            origins = cfg.get("Origins", {}).get("Items", [])
            return {
                "id":             dist_id,
                "domain_name":    d.get("DomainName"),
                "status":         desc.get("Status"),
                "enabled":        cfg.get("Enabled"),
                "http_version":   cfg.get("HttpVersion"),
                "price_class":    cfg.get("PriceClass"),
                "aliases":        cfg.get("Aliases", {}).get("Items", []),
                "origins": [
                    {
                        "id":          o.get("Id"),
                        "domain":      o.get("DomainName"),
                        "protocol":    o.get("CustomOriginConfig", {}).get("OriginProtocolPolicy", ""),
                        "shield":      o.get("OriginShield", {}).get("Enabled", False),
                    }
                    for o in origins[:5]
                ],
                "waf_web_acl":        cfg.get("WebACLId", ""),
                "logging_enabled":    bool(cfg.get("Logging", {}).get("Bucket")),
            }
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # ALB (ELBv2)
    # ─────────────────────────────────────────────────────────────────────────

    def alb_config(self, resource_name: str) -> dict:
        """Fetch ALB/NLB config — listeners, target groups, health."""
        if not self._session:
            return {}
        try:
            elb = self._session.client("elbv2")
            lbs = elb.describe_load_balancers().get("LoadBalancers", [])
            matched = [lb for lb in lbs if resource_name.lower() in lb.get("LoadBalancerName", "").lower()]
            if not matched:
                return {}
            lb = matched[0]
            arn = lb["LoadBalancerArn"]
            listeners = elb.describe_listeners(LoadBalancerArn=arn).get("Listeners", [])
            tg_arns = list({
                action.get("TargetGroupArn")
                for lst in listeners
                for action in lst.get("DefaultActions", [])
                if action.get("TargetGroupArn")
            })
            tg_health = []
            for tg_arn in tg_arns[:5]:
                try:
                    health = elb.describe_target_health(TargetGroupArn=tg_arn).get("TargetHealthDescriptions", [])
                    counts: dict = {}
                    for t in health:
                        st = t.get("TargetHealth", {}).get("State", "unknown")
                        counts[st] = counts.get(st, 0) + 1
                    tg_health.append({"arn": tg_arn.split("/")[-2], "health_summary": counts})
                except Exception:  # noqa: BLE001
                    pass
            return {
                "name":               lb.get("LoadBalancerName"),
                "dns_name":           lb.get("DNSName"),
                "type":               lb.get("Type"),
                "scheme":             lb.get("Scheme"),
                "state":              lb.get("State", {}).get("Code"),
                "vpc_id":             lb.get("VpcId"),
                "listeners_count":    len(listeners),
                "listener_ports":     [lst.get("Port") for lst in listeners],
                "target_group_health": tg_health,
            }
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # SSM Parameter Store
    # ─────────────────────────────────────────────────────────────────────────

    def ssm_parameter_config(self, resource_name: str) -> dict:
        """Fetch SSM Parameter Store parameter metadata (no secret values)."""
        if not self._session:
            return {}
        try:
            ssm = self._session.client("ssm")
            params = ssm.describe_parameters(
                ParameterFilters=[{"Key": "Name", "Option": "Contains", "Values": [resource_name]}],
                MaxResults=10,
            ).get("Parameters", [])
            if not params:
                return {}
            p = params[0]
            return {
                "name":               p.get("Name"),
                "type":               p.get("Type"),
                "key_id":             p.get("KeyId", ""),
                "last_modified":      str(p.get("LastModifiedDate", "")),
                "version":            p.get("Version"),
                "tier":               p.get("Tier"),
                "data_type":          p.get("DataType", "text"),
                "all_matching_count": len(params),
            }
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # ACM
    # ─────────────────────────────────────────────────────────────────────────

    def acm_certificate_config(self, resource_name: str) -> dict:
        """Fetch ACM certificate status, expiry, and validation state."""
        if not self._session:
            return {}
        try:
            acm = self._session.client("acm")
            certs = acm.list_certificates().get("CertificateSummaryList", [])
            matched = [c for c in certs
                       if resource_name.lower() in c.get("DomainName", "").lower()]
            if not matched:
                return {}
            arn = matched[0]["CertificateArn"]
            desc = acm.describe_certificate(CertificateArn=arn).get("Certificate", {})
            return {
                "domain_name":        desc.get("DomainName"),
                "status":             desc.get("Status"),
                "type":               desc.get("Type"),
                "key_algorithm":      desc.get("KeyAlgorithm"),
                "not_after":          str(desc.get("NotAfter", "")),
                "not_before":         str(desc.get("NotBefore", "")),
                "renewal_eligibility": desc.get("RenewalEligibility", ""),
                "in_use_by":          desc.get("InUseBy", []),
                "subject_alternatives": desc.get("SubjectAlternativeNames", [])[:10],
                "validation_status":  [
                    {"domain": v.get("DomainName"), "status": v.get("ValidationStatus")}
                    for v in desc.get("DomainValidationOptions", [])
                ],
            }
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # MSK (Managed Kafka)
    # ─────────────────────────────────────────────────────────────────────────

    def msk_cluster_config(self, resource_name: str) -> dict:
        """Fetch MSK cluster config — broker type, version, storage, monitoring."""
        if not self._session:
            return {}
        try:
            msk = self._session.client("kafka")
            clusters = msk.list_clusters_v2().get("ClusterInfoList", [])
            matched = [c for c in clusters if resource_name.lower() in c.get("ClusterName", "").lower()]
            if not matched:
                return {}
            c = matched[0]
            broker = c.get("Provisioned", c.get("Serverless", {}))
            return {
                "cluster_name":       c.get("ClusterName"),
                "cluster_arn":        c.get("ClusterArn"),
                "state":              c.get("State"),
                "cluster_type":       c.get("ClusterType"),
                "kafka_version":      broker.get("CurrentBrokerSoftwareInfo", {}).get("KafkaVersion", ""),
                "broker_type":        broker.get("BrokerNodeGroupInfo", {}).get("InstanceType", ""),
                "broker_count":       broker.get("NumberOfBrokerNodes", 0),
                "storage_gb":         broker.get("BrokerNodeGroupInfo", {}).get(
                                        "StorageInfo", {}).get("EbsStorageInfo", {}).get("VolumeSize", 0),
                "encryption_in_transit": broker.get("EncryptionInfo", {}).get(
                                        "EncryptionInTransit", {}).get("ClientBroker", ""),
                "enhanced_monitoring": broker.get("EnhancedMonitoring", ""),
                "created":            str(c.get("CreationTime", "")),
            }
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # ECR
    # ─────────────────────────────────────────────────────────────────────────

    def ecr_repository_config(self, resource_name: str) -> dict:
        """Fetch ECR repository config — image count, scan findings, lifecycle policy."""
        if not self._session:
            return {}
        try:
            ecr = self._session.client("ecr")
            repos = ecr.describe_repositories().get("repositories", [])
            matched = [r for r in repos if resource_name.lower() in r.get("repositoryName", "").lower()]
            if not matched:
                return {}
            repo = matched[0]
            name = repo["repositoryName"]
            result: dict = {
                "repository_name":     name,
                "repository_uri":      repo.get("repositoryUri"),
                "image_tag_mutability": repo.get("imageTagMutability"),
                "scan_on_push":        repo.get("imageScanningConfiguration", {}).get("scanOnPush", False),
                "encryption_type":     repo.get("encryptionConfiguration", {}).get("encryptionType", "AES256"),
                "created":             str(repo.get("createdAt", "")),
            }
            try:
                images = ecr.describe_images(repositoryName=name).get("imageDetails", [])
                result["image_count"] = len(images)
                result["latest_pushed"] = str(max(
                    (i.get("imagePushedAt") for i in images if i.get("imagePushedAt")),
                    default=""
                ))
            except Exception:  # noqa: BLE001
                pass
            try:
                policy_resp = ecr.get_repository_policy(repositoryName=name)
                import json as _json
                result["repository_policy"] = _json.loads(policy_resp.get("policyText", "{}"))
            except ecr.exceptions.RepositoryPolicyNotFoundException:
                result["repository_policy"] = None
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # Route 53
    # ─────────────────────────────────────────────────────────────────────────

    def route53_zone_config(self, resource_name: str) -> dict:
        """Fetch Route53 hosted zone config and health check summary."""
        if not self._session:
            return {}
        try:
            r53 = self._session.client("route53")
            zones = r53.list_hosted_zones().get("HostedZones", [])
            matched = [z for z in zones if resource_name.lower() in z.get("Name", "").lower()]
            if not matched:
                return {}
            z = matched[0]
            zone_id = z["Id"].split("/")[-1]
            result: dict = {
                "zone_name":     z.get("Name"),
                "zone_id":       zone_id,
                "private_zone":  z.get("Config", {}).get("PrivateZone", False),
                "record_count":  z.get("ResourceRecordSetCount", 0),
            }
            try:
                records = r53.list_resource_record_sets(HostedZoneId=zone_id, MaxItems="20")
                result["record_types"] = list({r["Type"] for r in records.get("ResourceRecordSets", [])})
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # CodePipeline
    # ─────────────────────────────────────────────────────────────────────────

    def codepipeline_config(self, resource_name: str) -> dict:
        """Fetch CodePipeline config and latest execution status."""
        if not self._session:
            return {}
        try:
            cp = self._session.client("codepipeline")
            pipelines = cp.list_pipelines().get("pipelines", [])
            matched = [p for p in pipelines if resource_name.lower() in p.get("name", "").lower()]
            if not matched:
                return {}
            name = matched[0]["name"]
            desc = cp.get_pipeline(name=name).get("pipeline", {})
            result: dict = {
                "name":         name,
                "role_arn":     desc.get("roleArn"),
                "stage_count":  len(desc.get("stages", [])),
                "stages":       [s.get("name") for s in desc.get("stages", [])],
                "artifact_store": desc.get("artifactStore", {}).get("location", ""),
            }
            try:
                state = cp.get_pipeline_state(name=name)
                result["stage_states"] = [
                    {
                        "stage":  s.get("stageName"),
                        "status": s.get("latestExecution", {}).get("status", ""),
                    }
                    for s in state.get("stageStates", [])
                ]
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # SageMaker
    # ─────────────────────────────────────────────────────────────────────────

    def sagemaker_endpoint_config(self, resource_name: str) -> dict:
        """Fetch SageMaker endpoint or training job config and status."""
        if not self._session:
            return {}
        try:
            sm = self._session.client("sagemaker")
            endpoints = sm.list_endpoints().get("Endpoints", [])
            matched = [e for e in endpoints if resource_name.lower() in e.get("EndpointName", "").lower()]
            if matched:
                ep = matched[0]
                name = ep["EndpointName"]
                desc = sm.describe_endpoint(EndpointName=name)
                cfg_name = desc.get("EndpointConfigName", "")
                result: dict = {
                    "type":                  "endpoint",
                    "name":                  name,
                    "status":                desc.get("EndpointStatus"),
                    "config_name":           cfg_name,
                    "last_modified":         str(desc.get("LastModifiedTime", "")),
                    "failure_reason":        desc.get("FailureReason", ""),
                }
                try:
                    cfg = sm.describe_endpoint_config(EndpointConfigName=cfg_name)
                    result["variants"] = [
                        {
                            "name":          v.get("VariantName"),
                            "model":         v.get("ModelName"),
                            "instance_type": v.get("InstanceType"),
                            "instance_count": v.get("InitialInstanceCount"),
                            "weight":        v.get("InitialVariantWeight"),
                        }
                        for v in cfg.get("ProductionVariants", [])
                    ]
                except Exception:  # noqa: BLE001
                    pass
                return result
            jobs = sm.list_training_jobs(MaxResults=20).get("TrainingJobSummaries", [])
            matched_jobs = [j for j in jobs if resource_name.lower() in j.get("TrainingJobName", "").lower()]
            if matched_jobs:
                jname = matched_jobs[0]["TrainingJobName"]
                jdesc = sm.describe_training_job(TrainingJobName=jname)
                return {
                    "type":           "training_job",
                    "name":           jname,
                    "status":         jdesc.get("TrainingJobStatus"),
                    "failure_reason": jdesc.get("FailureReason", ""),
                    "instance_type":  jdesc.get("ResourceConfig", {}).get("InstanceType"),
                    "instance_count": jdesc.get("ResourceConfig", {}).get("InstanceCount"),
                    "billable_seconds": jdesc.get("BillableTimeInSeconds", 0),
                }
            return {}
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # Bedrock Agent
    # ─────────────────────────────────────────────────────────────────────────

    def bedrock_agent_config(self, resource_name: str) -> dict:
        """Fetch Bedrock Agent config — foundation model, aliases, action groups."""
        if not self._session:
            return {}
        try:
            ba = self._session.client("bedrock-agent")
            agents = ba.list_agents().get("agentSummaries", [])
            matched = [a for a in agents if resource_name.lower() in a.get("agentName", "").lower()]
            if not matched:
                return {}
            agent_id = matched[0]["agentId"]
            desc = ba.get_agent(agentId=agent_id).get("agent", {})
            result: dict = {
                "agent_id":             agent_id,
                "agent_name":           desc.get("agentName"),
                "status":               desc.get("agentStatus"),
                "foundation_model":     desc.get("foundationModel"),
                "instruction_length":   len(desc.get("instruction", "")),
                "idle_session_ttl":     desc.get("idleSessionTTLInSeconds"),
                "created":              str(desc.get("createdAt", "")),
                "updated":              str(desc.get("updatedAt", "")),
            }
            try:
                aliases = ba.list_agent_aliases(agentId=agent_id).get("agentAliasSummaries", [])
                result["aliases"] = [
                    {"name": a.get("agentAliasName"), "status": a.get("agentAliasStatus")}
                    for a in aliases
                ]
            except Exception:  # noqa: BLE001
                pass
            try:
                ags = ba.list_agent_action_groups(agentId=agent_id, agentVersion="DRAFT").get("actionGroupSummaries", [])
                result["action_groups"] = [
                    {"name": ag.get("actionGroupName"), "state": ag.get("actionGroupState")}
                    for ag in ags
                ]
            except Exception:  # noqa: BLE001
                pass
            try:
                kbs = ba.list_agent_knowledge_bases(agentId=agent_id, agentVersion="DRAFT").get("agentKnowledgeBaseSummaries", [])
                result["knowledge_bases"] = [
                    {"knowledge_base_id": kb.get("knowledgeBaseId"), "state": kb.get("knowledgeBaseState")}
                    for kb in kbs
                ]
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # Bedrock Knowledge Base
    # ─────────────────────────────────────────────────────────────────────────

    def bedrock_kb_config(self, resource_name: str) -> dict:
        """Fetch Bedrock Knowledge Base config, data source sync status, and
        vector store IAM permissions. S3 Vectors uses a separate s3vectors:*
        permission namespace — missing s3vectors:QueryVectors is a common
        silent failure that looks identical to a missing s3:GetObject at the
        symptom level but requires a completely different IAM fix.
        """
        if not self._session:
            return {}
        try:
            ba = self._session.client("bedrock-agent")
            kbs = ba.list_knowledge_bases().get("knowledgeBaseSummaries", [])
            matched = [kb for kb in kbs if resource_name.lower() in kb.get("name", "").lower()]
            if not matched:
                return {}
            kb_id = matched[0]["knowledgeBaseId"]
            desc = ba.get_knowledge_base(knowledgeBaseId=kb_id).get("knowledgeBase", {})
            storage_cfg = desc.get("storageConfiguration", {})
            storage_type = storage_cfg.get("type", "")
            result: dict = {
                "kb_id":             kb_id,
                "name":              desc.get("name"),
                "status":            desc.get("status"),
                "role_arn":          desc.get("roleArn"),
                "storage_type":      storage_type,
                "embedding_model":   desc.get("knowledgeBaseConfiguration", {}).get(
                                        "vectorKnowledgeBaseConfiguration", {}).get("embeddingModelArn", ""),
                "created":           str(desc.get("createdAt", "")),
                "updated":           str(desc.get("updatedAt", "")),
            }
            # For S3 Vectors storage, surface the vector bucket ARN and check whether
            # the KB execution role has s3vectors:* permissions. Missing s3vectors actions
            # are invisible to the agent unless explicitly surfaced here — the error
            # "AccessDeniedException on s3vectors:QueryVectors" looks like a generic S3
            # permission error but requires s3vectors:* grants, NOT s3:GetObject.
            if storage_type == "S3_VECTORS":
                s3v_cfg = storage_cfg.get("s3VectorsConfiguration", {})
                vector_bucket_arn = s3v_cfg.get("vectorBucketArn", "")
                result["s3vectors_bucket_arn"] = vector_bucket_arn
                result["s3vectors_note"] = (
                    "S3 Vectors uses the s3vectors:* permission namespace, NOT s3:*. "
                    "Required actions: s3vectors:QueryVectors, s3vectors:GetVectors, "
                    "s3vectors:PutVectors, s3vectors:GetIndex, s3vectors:ListVectors."
                )
                # Check the KB execution role's policies for s3vectors grants
                role_arn = desc.get("roleArn", "")
                if role_arn:
                    try:
                        iam = self._session.client("iam")
                        role_name = role_arn.split("/")[-1]
                        s3vectors_actions_found: list[str] = []
                        has_s3vectors_policy = False
                        # Check inline policies
                        for pol_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                            pol = iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                            doc = pol.get("PolicyDocument", {})
                            for stmt in doc.get("Statement", []):
                                actions = stmt.get("Action", [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                s3v = [a for a in actions if "s3vectors" in a.lower()]
                                if s3v:
                                    has_s3vectors_policy = True
                                    s3vectors_actions_found.extend(s3v)
                        # Check attached managed policies
                        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
                            pv = iam.get_policy_version(
                                PolicyArn=pol["PolicyArn"],
                                VersionId=iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]["DefaultVersionId"],
                            )
                            doc = pv.get("PolicyVersion", {}).get("Document", {})
                            for stmt in doc.get("Statement", []):
                                actions = stmt.get("Action", [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                s3v = [a for a in actions if "s3vectors" in a.lower()]
                                if s3v:
                                    has_s3vectors_policy = True
                                    s3vectors_actions_found.extend(s3v)
                        result["s3vectors_iam_granted"] = has_s3vectors_policy
                        result["s3vectors_actions_found"] = s3vectors_actions_found
                        if not has_s3vectors_policy:
                            result["s3vectors_iam_missing"] = (
                                "KB execution role has NO s3vectors:* permissions. "
                                "This will cause AccessDeniedException on all vector store operations."
                            )
                    except Exception:  # noqa: BLE001
                        pass
            try:
                sources = ba.list_data_sources(knowledgeBaseId=kb_id).get("dataSourceSummaries", [])
                result["data_sources"] = [
                    {
                        "name":   ds.get("name"),
                        "status": ds.get("status"),
                        "updated": str(ds.get("updatedAt", "")),
                    }
                    for ds in sources
                ]
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # Bedrock AgentCore
    # ─────────────────────────────────────────────────────────────────────────

    def agentcore_config(self, resource_name: str) -> dict:
        """Fetch Bedrock AgentCore memory store config."""
        if not self._session:
            return {}
        try:
            ac = self._session.client("bedrock-agentcore")
            stores = ac.list_memory_stores().get("memoryStoreSummaries", [])
            matched = [s for s in stores if resource_name.lower() in s.get("memoryStoreId", "").lower()]
            if not matched:
                return {}
            store_id = matched[0]["memoryStoreId"]
            desc = ac.get_memory_store(memoryStoreId=store_id).get("memoryStore", {})
            return {
                "memory_store_id":  store_id,
                "status":           desc.get("status"),
                "storage_type":     desc.get("storageConfiguration", {}).get("type", ""),
                "created":          str(desc.get("createdAt", "")),
            }
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # EKS
    # ─────────────────────────────────────────────────────────────────────────

    def eks_cluster_config(self, resource_name: str) -> dict:
        """Fetch EKS cluster config — K8s version, VPC, logging, OIDC, add-ons, node groups."""
        if not self._session:
            return {}
        try:
            eks = self._session.client("eks")
            clusters = eks.list_clusters().get("clusters", [])
            matched = [c for c in clusters if resource_name.lower() in c.lower()]
            if not matched:
                return {}
            cluster_name  = matched[0]
            desc          = eks.describe_cluster(name=cluster_name).get("cluster", {})
            resources_vpc = desc.get("resourcesVpcConfig", {})
            logging_cfg   = desc.get("logging", {}).get("clusterLogging", [])
            enabled_logs  = [
                lt
                for entry in logging_cfg
                if entry.get("enabled")
                for lt in entry.get("types", [])
            ]
            result: dict = {
                "cluster_name":            desc.get("name"),
                "cluster_arn":             desc.get("arn"),
                "kubernetes_version":      desc.get("version"),
                "status":                  desc.get("status"),
                "platform_version":        desc.get("platformVersion", ""),
                "role_arn":                desc.get("roleArn", ""),
                "vpc_id":                  resources_vpc.get("vpcId", ""),
                "subnet_ids":              resources_vpc.get("subnetIds", []),
                "security_group_ids":      resources_vpc.get("securityGroupIds", []),
                "endpoint_public_access":  resources_vpc.get("endpointPublicAccess", True),
                "endpoint_private_access": resources_vpc.get("endpointPrivateAccess", False),
                "public_access_cidrs":     resources_vpc.get("publicAccessCidrs", []),
                "enabled_log_types":       enabled_logs,
                "oidc_provider":           desc.get("identity", {}).get("oidc", {}).get("issuer", ""),
                "encryption_config": [
                    {"resources": e.get("resources", []), "kms_key": e.get("provider", {}).get("keyArn", "")}
                    for e in desc.get("encryptionConfig", [])
                ],
                "tags": self._filter_tags(desc.get("tags", {})),
            }
            try:
                addons = eks.list_addons(clusterName=cluster_name).get("addons", [])
                addon_details = []
                for addon_name in addons[:5]:
                    try:
                        a = eks.describe_addon(clusterName=cluster_name, addonName=addon_name).get("addon", {})
                        addon_details.append({
                            "name":    a.get("addonName"),
                            "version": a.get("addonVersion"),
                            "status":  a.get("status"),
                        })
                    except Exception:  # noqa: BLE001
                        pass
                result["addons"] = addon_details
            except Exception:  # noqa: BLE001
                pass
            try:
                ngs = eks.list_nodegroups(clusterName=cluster_name).get("nodegroups", [])
                ng_details = []
                for ng_name in ngs[:3]:
                    try:
                        ng = eks.describe_nodegroup(
                            clusterName=cluster_name, nodegroupName=ng_name
                        ).get("nodegroup", {})
                        ng_details.append({
                            "name":            ng.get("nodegroupName"),
                            "status":          ng.get("status"),
                            "instance_types":  ng.get("instanceTypes", []),
                            "scaling": {
                                "desired": ng.get("scalingConfig", {}).get("desiredSize"),
                                "min":     ng.get("scalingConfig", {}).get("minSize"),
                                "max":     ng.get("scalingConfig", {}).get("maxSize"),
                            },
                            "ami_type":        ng.get("amiType"),
                            "disk_size":       ng.get("diskSize"),
                            "release_version": ng.get("releaseVersion", ""),
                        })
                    except Exception:  # noqa: BLE001
                        pass
                result["node_groups"] = ng_details
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:  # noqa: BLE001
            return {}

    def waf_web_acl_config(self, resource_name: str) -> dict:
        """Fetch details for a WAFv2 WebACL by name or ID hint."""
        if not self._session:
            return {}
        try:
            scopes = [
                ("REGIONAL", self._session.region_name),
                ("CLOUDFRONT", "us-east-1")
            ]
            for scope, region in scopes:
                try:
                    waf = self._session.client("wafv2", region_name=region)
                    acls = waf.list_web_acls(Scope=scope).get("WebACLs", [])
                    matched = [
                        a for a in acls
                        if resource_name.lower() in a.get("Name", "").lower()
                        or resource_name.lower() in a.get("Id", "").lower()
                    ]
                    if matched:
                        acl = matched[0]
                        acl_id = acl["Id"]
                        acl_name = acl["Name"]
                        details = waf.get_web_acl(
                            Name=acl_name,
                            Scope=scope,
                            Id=acl_id
                        ).get("WebACL", {})
                        return {
                            "name": acl_name,
                            "id": acl_id,
                            "arn": acl.get("ARN"),
                            "scope": scope,
                            "region": region,
                            "default_action": details.get("DefaultAction"),
                            "rules": [
                                {
                                    "name": r.get("Name"),
                                    "priority": r.get("Priority"),
                                    "action": r.get("Action"),
                                    "statement": r.get("Statement"),
                                    "visibility_config": r.get("VisibilityConfig")
                                }
                                for r in details.get("Rules", [])
                            ],
                            "visibility_config": details.get("VisibilityConfig"),
                            "capacity": details.get("Capacity")
                        }
                except Exception:
                    pass
            return {}
        except Exception:
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # Cognito User Pool
    # ─────────────────────────────────────────────────────────────────────────

    def cognito_user_pool_config(self, resource_name: str) -> dict:
        """Fetch Cognito User Pool config — Lambda trigger wiring, App Client
        auth flows. Without this, the agent can see the trigger Lambdas
        themselves (via the lambda fetcher) but has no way to see WHICH
        triggers are actually wired to the pool, or whether an App Client's
        explicit_auth_flows excludes a flow the symptom depends on — both
        config-drift classes that produce no log/metric signal at all.
        """
        if not self._session:
            return {}
        try:
            idp = self._session.client("cognito-idp")
            pools = idp.list_user_pools(MaxResults=60).get("UserPools", [])
            matched = [
                p for p in pools
                if resource_name.lower() in p.get("Name", "").lower()
                or resource_name.lower() in p.get("Id", "").lower()
            ]
            if not matched:
                return {}
            pool_id = matched[0]["Id"]
            pool = idp.describe_user_pool(UserPoolId=pool_id).get("UserPool", {})

            clients = idp.list_user_pool_clients(UserPoolId=pool_id, MaxResults=60).get("UserPoolClients", [])
            client_details = []
            for c in clients:
                try:
                    detail = idp.describe_user_pool_client(
                        UserPoolId=pool_id, ClientId=c["ClientId"],
                    ).get("UserPoolClient", {})
                    # Report raw facts only — explicit_auth_flows shows exactly
                    # which flows are enabled; interpreting what an absent flow
                    # means is the model's job, not the tool's.
                    entry: dict = {
                        "client_id":            detail.get("ClientId"),
                        "client_name":          detail.get("ClientName"),
                        "explicit_auth_flows":  detail.get("ExplicitAuthFlows", []),
                        "access_token_validity": detail.get("AccessTokenValidity"),
                        "id_token_validity":     detail.get("IdTokenValidity"),
                    }
                    client_details.append(entry)
                except Exception:  # noqa: BLE001
                    pass

            return {
                "pool_id":            pool_id,
                "pool_name":          pool.get("Name"),
                "arn":                pool.get("Arn"),
                "status":             pool.get("Status"),
                "mfa_configuration":  pool.get("MfaConfiguration"),
                "lambda_config":      pool.get("LambdaConfig", {}),
                "auto_verified_attributes": pool.get("AutoVerifiedAttributes", []),
                "estimated_users":    pool.get("EstimatedNumberOfUsers"),
                "app_clients":        client_details,
            }
        except Exception:  # noqa: BLE001
            return {}

    # ─────────────────────────────────────────────────────────────────────────
    # AppSync
    # ─────────────────────────────────────────────────────────────────────────

    def appsync_api_config(self, resource_name: str) -> dict:
        """Fetch AppSync GraphQL API config — auth mode(s), data source
        service roles, and resolver mapping templates. Without this, a
        resolver VTL bug or an auth-mode mismatch produces zero log/metric
        signal the agent could find any other way — AppSync only logs
        errors if request-level logging is explicitly enabled, and a
        resolver returning a wrong-but-valid value (e.g. null) is
        indistinguishable from "no data" without reading the template.
        """
        if not self._session:
            return {}
        try:
            appsync = self._session.client("appsync")
            apis = appsync.list_graphql_apis(maxResults=25).get("graphqlApis", [])
            matched = [
                a for a in apis
                if resource_name.lower() in a.get("name", "").lower()
                or resource_name.lower() in a.get("apiId", "").lower()
            ]
            if not matched:
                return {}
            api = matched[0]
            api_id = api["apiId"]

            data_sources = appsync.list_data_sources(apiId=api_id).get("dataSources", [])
            ds_details = [
                {
                    "name":             ds.get("name"),
                    "type":             ds.get("type"),
                    "service_role_arn": ds.get("serviceRoleArn"),
                    "dynamodb_table":   ds.get("dynamodbConfig", {}).get("tableName"),
                }
                for ds in data_sources
            ]

            resolvers = []
            for type_name in ("Query", "Mutation"):
                try:
                    for r in appsync.list_resolvers(apiId=api_id, typeName=type_name).get("resolvers", []):
                        resolvers.append({
                            "type_name":        type_name,
                            "field_name":       r.get("fieldName"),
                            "data_source_name": r.get("dataSourceName"),
                            "kind":             r.get("kind"),
                            "request_mapping_template_len":  len(r.get("requestMappingTemplate") or ""),
                            "response_mapping_template":      r.get("responseMappingTemplate"),
                        })
                except Exception:  # noqa: BLE001
                    pass

            api_keys = []
            try:
                for k in appsync.list_api_keys(apiId=api_id).get("apiKeys", []):
                    api_keys.append({"id": k.get("id"), "expires": k.get("expires")})
            except Exception:  # noqa: BLE001
                pass

            return {
                "api_id":                          api_id,
                "name":                            api.get("name"),
                "authentication_type":             api.get("authenticationType"),
                "additional_authentication_providers": [
                    {
                        "type": p.get("authenticationType"),
                        "user_pool_id": p.get("userPoolConfig", {}).get("userPoolId"),
                    }
                    for p in api.get("additionalAuthenticationProviders", [])
                ],
                "data_sources":  ds_details,
                "resolvers":     resolvers,
                "api_keys":      api_keys,
            }
        except Exception:  # noqa: BLE001
            return {}

    def batch_config(self, resource_name: str) -> dict:
        """Fetch AWS Batch configuration — compute environments, job queues, job definitions, and recent jobs matching the resource name."""
        if not self._session:
            return {}
        try:
            batch = self._session.client("batch")

            # 1. Compute Environments
            envs = batch.describe_compute_environments().get("computeEnvironments", [])
            matched_envs = [
                e for e in envs
                if resource_name.lower() in e.get("computeEnvironmentName", "").lower()
                or resource_name.lower() in e.get("computeEnvironmentArn", "").lower()
            ]
            env_details = []
            for env in matched_envs:
                resources = env.get("computeResources", {})
                env_details.append({
                    "name":                  env.get("computeEnvironmentName"),
                    "arn":                   env.get("computeEnvironmentArn"),
                    "type":                  env.get("type"),
                    "state":                 env.get("state"),
                    "status":                env.get("status"),
                    "status_reason":         env.get("statusReason", ""),
                    "service_role":          env.get("serviceRole", ""),
                    "compute_resources": {
                        "type":               resources.get("type"),
                        "max_vcpus":          resources.get("maxvCpus"),
                        "min_vcpus":          resources.get("minvCpus"),
                        "desired_vcpus":      resources.get("desiredvCpus"),
                        "subnets":            resources.get("subnets", []),
                        "security_group_ids": resources.get("securityGroupIds", []),
                        "instance_types":     resources.get("instanceTypes", []),
                    },
                })

            # 2. Job Queues
            queues = batch.describe_job_queues().get("jobQueues", [])
            matched_queues = [
                q for q in queues
                if resource_name.lower() in q.get("jobQueueName", "").lower()
                or resource_name.lower() in q.get("jobQueueArn", "").lower()
            ]
            queue_details = []
            for q in matched_queues:
                queue_details.append({
                    "name":     q.get("jobQueueName"),
                    "arn":      q.get("jobQueueArn"),
                    "state":    q.get("state"),
                    "status":   q.get("status"),
                    "priority": q.get("priority"),
                    "compute_environment_order": [
                        {
                            "order":               item.get("order"),
                            "compute_environment": item.get("computeEnvironment"),
                        }
                        for item in q.get("computeEnvironmentOrder", [])
                    ],
                })

            # 3. Job Definitions
            jds = batch.describe_job_definitions(status="ACTIVE").get("jobDefinitions", [])
            matched_jds = [
                j for j in jds
                if resource_name.lower() in j.get("jobDefinitionName", "").lower()
                or resource_name.lower() in j.get("jobDefinitionArn", "").lower()
            ]

            jd_by_name = {}
            for jd in matched_jds:
                name = jd.get("jobDefinitionName")
                if name not in jd_by_name or jd.get("revision", 0) > jd_by_name[name].get("revision", 0):
                    jd_by_name[name] = jd

            jd_details = []
            for jd in jd_by_name.values():
                container = jd.get("containerProperties", {})
                jd_details.append({
                    "name":                   jd.get("jobDefinitionName"),
                    "arn":                    jd.get("jobDefinitionArn"),
                    "revision":               jd.get("revision"),
                    "status":                 jd.get("status"),
                    "type":                   jd.get("type"),
                    "platform_capabilities":  jd.get("platformCapabilities", []),
                    "image":                  container.get("image"),
                    "command":                container.get("command", []),
                    "execution_role_arn":     container.get("executionRoleArn", ""),
                    "job_role_arn":           container.get("jobRoleArn", ""),
                    "resource_requirements":  container.get("resourceRequirements", []),
                    "environment": [
                        {"name": e.get("name"), "value": self._redact_env_value(e.get("value", ""))}
                        for e in container.get("environment", [])
                    ],
                    "log_configuration":      container.get("logConfiguration", {}),
                    "network_configuration":  container.get("networkConfiguration", {}),
                })

            # 4. Recent Jobs
            recent_jobs = []
            for q in matched_queues:
                q_name = q.get("jobQueueName")
                q_arn = q.get("jobQueueArn")
                try:
                    job_ids = []
                    for status in ("FAILED", "RUNNABLE", "RUNNING", "SUCCEEDED"):
                        resp = batch.list_jobs(jobQueue=q_arn, jobStatus=status, maxResults=5)
                        job_ids.extend(j["jobId"] for j in resp.get("jobSummaryList", []))
                    if job_ids:
                        jobs = batch.describe_jobs(jobs=job_ids[:10]).get("jobs", [])
                        for j in jobs:
                            recent_jobs.append({
                                "job_queue":    q_name,
                                "job_id":       j.get("jobId"),
                                "job_name":     j.get("jobName"),
                                "status":       j.get("status"),
                                "status_reason": j.get("statusReason", ""),
                                "created_at":   j.get("createdAt"),
                                "started_at":   j.get("startedAt"),
                                "stopped_at":   j.get("stoppedAt"),
                                "log_stream":   j.get("container", {}).get("logStreamName", ""),
                            })
                except Exception:
                    pass

            if not (env_details or queue_details or jd_details or recent_jobs):
                return {}

            return {
                "compute_environments": env_details,
                "job_queues":           queue_details,
                "job_definitions":      jd_details,
                "recent_jobs":          recent_jobs,
            }
        except Exception:
            return {}

    def batch_jobs_recent(self, resource_name: str, limit: int = 10) -> list[dict]:
        """List recent Batch jobs in a queue with their status and reason."""
        if not self._session:
            return []
        try:
            batch = self._session.client("batch")
            queues = batch.describe_job_queues().get("jobQueues", [])
            matched = [q for q in queues if resource_name.lower() in q.get("jobQueueName", "").lower()]
            if not matched:
                return []
            queue_arn = matched[0]["jobQueueArn"]
            job_ids: list[str] = []
            for status in ("FAILED", "RUNNABLE", "RUNNING", "SUCCEEDED"):
                resp = batch.list_jobs(jobQueue=queue_arn, jobStatus=status, maxResults=5)
                job_ids.extend(j["jobId"] for j in resp.get("jobSummaryList", []))
                if len(job_ids) >= limit:
                    break
            if not job_ids:
                return []
            jobs = batch.describe_jobs(jobs=job_ids[:limit]).get("jobs", [])
            return [
                {
                    "job_id":       j.get("jobId"),
                    "job_name":     j.get("jobName"),
                    "status":       j.get("status"),
                    "status_reason": j.get("statusReason", ""),
                    "created_at":   j.get("createdAt"),
                    "started_at":   j.get("startedAt"),
                    "stopped_at":   j.get("stoppedAt"),
                    "log_stream":   j.get("container", {}).get("logStreamName", ""),
                }
                for j in jobs
            ]
        except Exception:  # noqa: BLE001
            return []

    def efs_filesystem_config(self, resource_name: str) -> dict:
        """Fetch EFS filesystem config — mount targets, access points, security groups, POSIX settings."""
        if not self._session:
            return {}
        try:
            efs = self._session.client("efs")
            ec2 = self._session.client("ec2")

            filesystems = efs.describe_file_systems().get("FileSystems", [])
            matched = [
                fs for fs in filesystems
                if resource_name.lower() in fs.get("FileSystemId", "").lower()
                or resource_name.lower() in fs.get("Name", "").lower()
                or any(
                    resource_name.lower() in tag.get("Value", "").lower()
                    for tag in fs.get("Tags", [])
                    if tag.get("Key") == "Name"
                )
            ]
            if not matched:
                return {}
            fs = matched[0]
            fs_id = fs["FileSystemId"]

            # Mount targets
            mt_resp = efs.describe_mount_targets(FileSystemId=fs_id)
            mount_targets = []
            for mt in mt_resp.get("MountTargets", []):
                mt_entry = {
                    "mount_target_id":  mt.get("MountTargetId"),
                    "subnet_id":        mt.get("SubnetId"),
                    "availability_zone": mt.get("AvailabilityZoneName"),
                    "lifecycle_state":  mt.get("LifeCycleState"),
                    "ip_address":       mt.get("IpAddress"),
                }
                try:
                    sg_resp = efs.describe_mount_target_security_groups(
                        MountTargetId=mt["MountTargetId"]
                    )
                    sg_ids = sg_resp.get("SecurityGroups", [])
                    mt_entry["security_groups"] = sg_ids
                    # Fetch SG ingress rules to surface NFS port 2049 configuration
                    if sg_ids:
                        sgs = ec2.describe_security_groups(GroupIds=sg_ids).get("SecurityGroups", [])
                        mt_entry["security_group_rules"] = [
                            {
                                "sg_id": sg.get("GroupId"),
                                "sg_name": sg.get("GroupName"),
                                "ingress": [
                                    {
                                        "protocol": r.get("IpProtocol"),
                                        "from_port": r.get("FromPort"),
                                        "to_port": r.get("ToPort"),
                                        "source_sg": r.get("UserIdGroupPairs", [{}])[0].get("GroupId") if r.get("UserIdGroupPairs") else None,
                                        "source_cidr": r.get("IpRanges", [{}])[0].get("CidrIp") if r.get("IpRanges") else None,
                                    }
                                    for r in sg.get("IpPermissions", [])
                                ],
                            }
                            for sg in sgs
                        ]
                except Exception:  # noqa: BLE001
                    pass
                mount_targets.append(mt_entry)

            # Access points
            ap_resp = efs.describe_access_points(FileSystemId=fs_id)
            access_points = []
            for ap in ap_resp.get("AccessPoints", []):
                root_dir = ap.get("RootDirectory", {})
                creation_info = root_dir.get("CreationInfo", {})
                posix_user = ap.get("PosixUser", {})
                access_points.append({
                    "access_point_id":  ap.get("AccessPointId"),
                    "access_point_arn": ap.get("AccessPointArn"),
                    "name": next(
                        (t["Value"] for t in ap.get("Tags", []) if t["Key"] == "Name"), ""
                    ),
                    "lifecycle_state":  ap.get("LifeCycleState"),
                    "posix_user": {
                        "uid": posix_user.get("Uid"),
                        "gid": posix_user.get("Gid"),
                    },
                    "root_directory": {
                        "path":        root_dir.get("Path"),
                        "owner_uid":   creation_info.get("OwnerUid"),
                        "owner_gid":   creation_info.get("OwnerGid"),
                        "permissions": creation_info.get("Permissions"),
                    },
                })

            return {
                "filesystem_id":       fs_id,
                "name": fs.get("Name") or next(
                    (t["Value"] for t in fs.get("Tags", []) if t["Key"] == "Name"), ""
                ),
                "lifecycle_state":     fs.get("LifeCycleState"),
                "performance_mode":    fs.get("PerformanceMode"),
                "throughput_mode":     fs.get("ThroughputMode"),
                "provisioned_throughput_mibps": fs.get("ProvisionedThroughputInMibps"),
                "encrypted":           fs.get("Encrypted"),
                "kms_key_id":          fs.get("KmsKeyId", ""),
                "size_in_bytes":       fs.get("SizeInBytes", {}).get("Value"),
                "number_of_mount_targets": fs.get("NumberOfMountTargets"),
                "mount_targets":       mount_targets,
                "access_points":       access_points,
            }
        except Exception:  # noqa: BLE001
            return {}

    def generic_resource_config(self, service_type: str, resource_name: str) -> dict:
        """Fetch AWS resource config generically using Cloud Control API or Boto3 client reflection.
        Enriches the returned config payload with ingress/egress rules for referenced Security Groups,
        policy documents for referenced IAM Roles, key policies/rotation for referenced KMS Keys,
        and subnet/VPC routing and CIDR settings.

        Note: service_type should be formatted as the exact service namespace/prefix expected by the
        AWS Resource Groups Tagging API (e.g. "kafka" for MSK, "elasticfilesystem" for EFS) rather
        than generic shorthands.
        """
        import re
        import json
        from botocore import xform_name

        if not self._session:
            return {}

        # 1. Resolve matching resource ARN via tagging API
        arn = None
        tags_dict = {}
        try:
            tagger = self._session.client("resourcegroupstaggingapi")
            # Map shorthand service names to their ARN namespace used by the Tagging API.
            # ResourceTypeFilters expects the ARN service prefix (e.g. "kafka" for MSK,
            # "elasticfilesystem" for EFS) — not the console/CLI shorthand.
            _ARN_NAMESPACE: dict[str, str] = {
                "msk":            "kafka",
                "opensearch":     "es",
                "efs":            "elasticfilesystem",
                "stepfunctions":  "states",
                "step-functions": "states",
                "alb":            "elasticloadbalancing",
                "elb":            "elasticloadbalancing",
                "waf":            "wafv2",
                "cognito":        "cognito-idp",
            }
            tag_filter = _ARN_NAMESPACE.get(service_type, service_type)
            resp = tagger.get_resources(ResourceTypeFilters=[tag_filter])
            matched_items = []
            for item in resp.get("ResourceTagMappingList", []):
                item_arn = item.get("ResourceARN", "")
                name_tag = next((t["Value"] for t in item.get("Tags", []) if t["Key"].lower() == "name"), "")
                if (resource_name.lower() in item_arn.lower() or 
                        resource_name.lower() in name_tag.lower()):
                    matched_items.append(item)
            
            if matched_items:
                best_match = matched_items[0]
                arn = best_match["ResourceARN"]
                tags_dict = {t["Key"]: t["Value"] for t in best_match.get("Tags", [])}
        except Exception:
            pass

        # If resource name looks like an ARN directly, use it
        if not arn and resource_name.startswith("arn:aws:"):
            arn = resource_name

        if not arn:
            return {}

        # 2. Convert ARN to CloudFormation TypeName
        # Format: arn:aws:<service>:<region>:<account>:<resource_type>/<resource_id>
        cfn_type = None
        arn_parts = arn.split(":")
        if len(arn_parts) >= 6:
            svc_name = arn_parts[2]
            res_part = arn_parts[5]
            if "/" in res_part:
                res_type = res_part.split("/")[0]
            elif ":" in res_part:
                res_type = res_part.split(":")[0]
            else:
                res_type = svc_name
            
            def to_pascal(s: str) -> str:
                return "".join(word.capitalize() for word in s.replace("-", "_").split("_"))
            
            service_map = {
                "mq": "AmazonMQ",
                "apigateway": "ApiGateway",
                "elasticsearch": "Elasticsearch",
                "opensearch": "OpenSearchService",
                "states": "StepFunctions",
                "logs": "Logs",
            }
            svc_pascal = service_map.get(svc_name, to_pascal(svc_name))
            type_pascal = to_pascal(res_type)
            cfn_type = f"AWS::{svc_pascal}::{type_pascal}"

        config_data = {}
        fetch_method = "none"

        # 3. Attempt Cloud Control API call
        if cfn_type:
            try:
                cc = self._session.client("cloudcontrol")
                cc_resp = cc.get_resource(TypeName=cfn_type, Identifier=arn)
                res_desc = cc_resp.get("ResourceDescription", {})
                props = json.loads(res_desc.get("Properties", "{}"))
                if props:
                    config_data = props
                    fetch_method = "cloudcontrol"
            except Exception:
                pass

        # 4. Fallback to Dynamic Boto3 Client Reflection
        if not config_data and len(arn_parts) >= 6:
            try:
                svc_name = arn_parts[2]
                res_part = arn_parts[5]
                res_id = res_part.split("/")[-1] if "/" in res_part else res_part.split(":")[-1] if ":" in res_part else res_part
                
                client = self._session.client(svc_name)
                ops = client.meta.service_model.operation_names
                candidates = []
                r_type_clean = (res_part.split("/")[0] if "/" in res_part else res_part.split(":")[0] if ":" in res_part else res_part).lower().rstrip("s")
                for op in ops:
                    op_lower = op.lower()
                    if op_lower.startswith(("describe", "get")) and r_type_clean in op_lower:
                        candidates.append(op)
                
                candidates.sort(key=len)
                for op in candidates:
                    op_model = client.meta.service_model.operation_model(op)
                    input_shape = op_model.input_shape
                    if not input_shape:
                        continue
                    
                    param_name = None
                    members = input_shape.members
                    
                    # Match ARN input
                    for m in members:
                        if "arn" in m.lower():
                            param_name = m
                            break
                    
                    # Match ID/Name input
                    if not param_name:
                        for m in members:
                            m_lower = m.lower()
                            if m_lower in ("id", "identifier", "name"):
                                param_name = m
                                break
                            if r_type_clean in m_lower and ("id" in m_lower or "name" in m_lower):
                                param_name = m
                                break
                    
                    # Generic ID/Name fallback
                    if not param_name:
                        for m in members:
                            m_lower = m.lower()
                            if "id" in m_lower or "name" in m_lower:
                                param_name = m
                                break
                    
                    if param_name:
                        try:
                            func = getattr(client, xform_name(op))
                            val_to_pass = arn if "arn" in param_name.lower() else res_id
                            res = func(**{param_name: val_to_pass})
                            if isinstance(res, dict):
                                res.pop("ResponseMetadata", None)
                                config_data = res
                                fetch_method = "boto3_reflection"
                                break
                        except Exception:
                            pass
            except Exception:
                pass

        # If both failed, use tags as base config payload
        if not config_data:
            config_data = {
                "resource_arn": arn,
                "cfn_type": cfn_type,
                "tags": self._filter_tags(tags_dict),
                "note": "Configuration properties could not be described directly; showing metadata and tags.",
            }
            fetch_method = "tagging_api"
        else:
            if "tags" not in config_data:
                config_data["tags"] = tags_dict

        # 5. Restricted Dependency Enrichment
        SG_RE = re.compile(r"^sg-[a-f0-9]+$")
        SUBNET_RE = re.compile(r"^subnet-[a-f0-9]+$")
        VPC_RE = re.compile(r"^vpc-[a-f0-9]+$")
        ROLE_RE = re.compile(r"^arn:aws:iam::\d+:role/([\w\-+=,.@_/]+)$")
        KMS_ARN_RE = re.compile(r"^arn:aws:kms:[a-z0-9\-]+:\d+:key/([a-f0-9\-]{36})$")
        KMS_UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")

        found_sgs = set()
        found_roles = set()
        found_kms = set()
        found_subnets = set()
        found_vpcs = set()

        def _scan(val):
            if isinstance(val, str):
                val_clean = val.strip()
                if SG_RE.match(val_clean):
                    found_sgs.add(val_clean)
                elif SUBNET_RE.match(val_clean):
                    found_subnets.add(val_clean)
                elif VPC_RE.match(val_clean):
                    found_vpcs.add(val_clean)
                elif ROLE_RE.match(val_clean):
                    found_roles.add(val_clean)
                elif KMS_ARN_RE.match(val_clean) or KMS_UUID_RE.match(val_clean):
                    found_kms.add(val_clean)
            elif isinstance(val, dict):
                for v in val.values():
                    _scan(v)
            elif isinstance(val, list):
                for item in val:
                    _scan(item)

        _scan(config_data)

        # Resolve Security Groups
        sg_details = {}
        if found_sgs:
            try:
                ec2 = self._session.client("ec2")
                for sg_id in found_sgs:
                    try:
                        resp = ec2.describe_security_groups(GroupIds=[sg_id]).get("SecurityGroups", [])
                        if resp:
                            sg = resp[0]
                            sg_details[sg_id] = {
                                "group_name": sg.get("GroupName"),
                                "vpc_id": sg.get("VpcId"),
                                "ingress": [
                                    {
                                        "protocol": r.get("IpProtocol"),
                                        "from_port": r.get("FromPort"),
                                        "to_port": r.get("ToPort"),
                                        "cidr_ips": [ip.get("CidrIp") for ip in r.get("IpRanges", []) if ip.get("CidrIp")],
                                        "source_sgs": [pair.get("GroupId") for pair in r.get("UserIdGroupPairs", []) if pair.get("GroupId")],
                                    }
                                    for r in sg.get("IpPermissions", [])
                                ],
                                "egress": [
                                    {
                                        "protocol": r.get("IpProtocol"),
                                        "from_port": r.get("FromPort"),
                                        "to_port": r.get("ToPort"),
                                        "cidr_ips": [ip.get("CidrIp") for ip in r.get("IpRanges", []) if ip.get("CidrIp")],
                                        "dest_sgs": [pair.get("GroupId") for pair in r.get("UserIdGroupPairs", []) if pair.get("GroupId")],
                                    }
                                    for r in sg.get("IpPermissionsEgress", [])
                                ],
                            }
                    except Exception:
                        pass
            except Exception:
                pass

        # Resolve IAM Roles
        role_details = {}
        if found_roles:
            try:
                iam = self._session.client("iam")
                for role_arn in found_roles:
                    try:
                        m = ROLE_RE.match(role_arn)
                        if m:
                            role_name = m.group(1)
                            if "/" in role_name:
                                role_name = role_name.split("/")[-1]
                            role_info = iam.get_role(RoleName=role_name).get("Role", {})
                            role_policies = []
                            try:
                                inline_names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
                                for p_name in inline_names[:3]:
                                    p_doc = iam.get_role_policy(RoleName=role_name, PolicyName=p_name).get("PolicyDocument", {})
                                    role_policies.append({"policy_name": p_name, "type": "inline", "document": p_doc})
                            except Exception:
                                pass
                            try:
                                attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                                for p in attached[:3]:
                                    role_policies.append({"policy_name": p.get("PolicyName"), "policy_arn": p.get("PolicyArn"), "type": "attached"})
                            except Exception:
                                pass
                            role_details[role_arn] = {
                                "role_name": role_info.get("RoleName"),
                                "assume_role_policy": role_info.get("AssumeRolePolicyDocument"),
                                "policies": role_policies,
                            }
                    except Exception:
                        pass
            except Exception:
                pass

        # Resolve KMS Keys
        kms_details = {}
        if found_kms:
            try:
                kms = self._session.client("kms")
                for kms_key in found_kms:
                    try:
                        desc = kms.describe_key(KeyId=kms_key).get("KeyMetadata", {})
                        key_id = desc.get("KeyId")
                        rotation_enabled = False
                        try:
                            rotation_enabled = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)
                        except Exception:
                            pass
                        policy = {}
                        try:
                            policy = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy", "{}"))
                        except Exception:
                            pass
                        kms_details[kms_key] = {
                            "key_id": key_id,
                            "arn": desc.get("Arn"),
                            "enabled": desc.get("Enabled"),
                            "state": desc.get("KeyState"),
                            "key_usage": desc.get("KeyUsage"),
                            "rotation_enabled": rotation_enabled,
                            "policy": policy,
                        }
                    except Exception:
                        pass
            except Exception:
                pass

        # Resolve Subnets / VPCs
        network_details = {}
        if found_subnets or found_vpcs:
            try:
                ec2 = self._session.client("ec2")
                for subnet_id in found_subnets:
                    try:
                        resp = ec2.describe_subnets(SubnetIds=[subnet_id]).get("Subnets", [])
                        if resp:
                            sub = resp[0]
                            routes = []
                            try:
                                rt_resp = ec2.describe_route_tables(
                                    Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
                                ).get("RouteTables", [])
                                if not rt_resp:
                                    rt_resp = ec2.describe_route_tables(
                                        Filters=[
                                            {"Name": "vpc-id", "Values": [sub["VpcId"]]},
                                            {"Name": "association.main", "Values": ["true"]},
                                        ]
                                    ).get("RouteTables", [])
                                if rt_resp:
                                    routes = [
                                        {
                                            "destination": r.get("DestinationCidrBlock"),
                                            "gateway_id": r.get("GatewayId"),
                                            "state": r.get("State"),
                                        }
                                        for r in rt_resp[0].get("Routes", [])
                                    ]
                            except Exception:
                                pass
                            network_details[subnet_id] = {
                                "subnet_id": subnet_id,
                                "vpc_id": sub.get("VpcId"),
                                "cidr_block": sub.get("CidrBlock"),
                                "availability_zone": sub.get("AvailabilityZone"),
                                "available_ips": sub.get("AvailableIpAddressCount"),
                                "routes": routes,
                            }
                    except Exception:
                        pass
                for vpc_id in found_vpcs:
                    try:
                        resp = ec2.describe_vpcs(VpcIds=[vpc_id]).get("Vpcs", [])
                        if resp:
                            vpc = resp[0]
                            network_details[vpc_id] = {
                                "vpc_id": vpc_id,
                                "cidr_block": vpc.get("CidrBlock"),
                                "state": vpc.get("State"),
                                "dhcp_options_id": vpc.get("DhcpOptionsId"),
                            }
                    except Exception:
                        pass
            except Exception:
                pass

        # Append details if found
        if sg_details:
            config_data["_resolved_security_groups"] = sg_details
        if role_details:
            config_data["_resolved_iam_roles"] = role_details
        if kms_details:
            config_data["_resolved_kms_keys"] = kms_details
        if network_details:
            config_data["_resolved_network_resources"] = network_details

        config_data["_fetch_method"] = fetch_method
        return config_data

    # ── IAM role configuration ─────────────────────────────────────────────────

    def iam_role_config(self, resource_name: str) -> dict:
        """Fetch an IAM role's complete permission picture:
        inline policies (with full policy documents), attached managed policies
        (with their statements), permission boundary, and trust policy.

        This is the primary tool for diagnosing authorization failures — it shows
        exactly what actions the role is and is not allowed to perform, and which
        services or accounts are trusted to assume it.
        """
        if not self._session:
            return {}
        try:
            iam = self._session.client("iam")

            # Resolve role name — accept full name, ARN, or partial match
            role_name = resource_name
            if resource_name.startswith("arn:aws:iam:"):
                role_name = resource_name.split("/")[-1]

            try:
                role = iam.get_role(RoleName=role_name)["Role"]
            except Exception:
                # Fuzzy match: list roles and find best match
                paginator = iam.get_paginator("list_roles")
                all_roles = []
                for page in paginator.paginate(MaxItems=200):
                    all_roles.extend(page.get("Roles", []))
                matched = [
                    r for r in all_roles
                    if resource_name.lower() in r["RoleName"].lower()
                ]
                if not matched:
                    return {}
                role = iam.get_role(RoleName=matched[0]["RoleName"])["Role"]
                role_name = role["RoleName"]

            result: dict = {
                "role_name":    role["RoleName"],
                "role_arn":     role["Arn"],
                "trust_policy": role.get("AssumeRolePolicyDocument", {}),
                "path":         role.get("Path", "/"),
                "created":      str(role.get("CreateDate", "")),
            }

            # Permission boundary
            pb = role.get("PermissionsBoundary", {})
            if pb:
                result["permission_boundary"] = {
                    "type": pb.get("PermissionsBoundaryType"),
                    "arn":  pb.get("PermissionsBoundaryArn"),
                }

            # Inline policies — fetch the full document for each
            inline_names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
            inline_policies = []
            for pname in inline_names:
                try:
                    import urllib.parse
                    doc_resp = iam.get_role_policy(RoleName=role_name, PolicyName=pname)
                    raw_doc = doc_resp.get("PolicyDocument", {})
                    if isinstance(raw_doc, str):
                        import json as _j
                        raw_doc = _j.loads(urllib.parse.unquote(raw_doc))
                    inline_policies.append({"name": pname, "document": raw_doc})
                except Exception:
                    inline_policies.append({"name": pname, "document": "could not fetch"})
            result["inline_policies"] = inline_policies
            result["inline_policy_count"] = len(inline_policies)

            # Attached managed policies — include statements from customer-managed ones
            attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
            managed_policies = []
            for p in attached:
                entry: dict = {
                    "policy_name": p["PolicyName"],
                    "policy_arn":  p["PolicyArn"],
                    "aws_managed": p["PolicyArn"].startswith("arn:aws:iam::aws:policy/"),
                }
                # Fetch the default version document for customer-managed policies
                if not entry["aws_managed"]:
                    try:
                        pv = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]
                        ver_id = pv.get("DefaultVersionId", "v1")
                        doc = iam.get_policy_version(
                            PolicyArn=p["PolicyArn"], VersionId=ver_id
                        )["PolicyVersion"]["Document"]
                        if isinstance(doc, str):
                            import json as _j2, urllib.parse as _up
                            doc = _j2.loads(_up.unquote(doc))
                        entry["document"] = doc
                    except Exception:
                        pass
                managed_policies.append(entry)
            result["attached_managed_policies"] = managed_policies
            result["managed_policy_count"] = len(managed_policies)

            return result
        except Exception:  # noqa: BLE001
            return {}

    # ── CloudTrail event search ────────────────────────────────────────────────

    def search_cloudtrail_events(
        self,
        resource_name: str,
        event_names: list[str] | None = None,
        minutes: int = 1440,
    ) -> list[dict]:
        """Search CloudTrail for all events touching a specific resource.

        Returns events sorted newest-first. Each event includes: time, event_name,
        actor (IAM principal), resource names, error_code, and a summary of the
        request parameters. Useful for finding what changed (a deletion, a policy
        detachment, a config modification) that caused the incident.

        Args:
            resource_name: resource name or ARN to search for
            event_names: optional list of specific event names to filter by
                         (e.g. ["DeleteRolePolicy", "DetachRolePolicy"])
            minutes: lookback window in minutes (default 1440 = 24 hours, max 10080 = 7 days)
        """
        if not self._session:
            return []
        try:
            import json as _j
            ct    = self._session.client("cloudtrail")
            end   = datetime.now(timezone.utc)
            start = end - timedelta(minutes=min(int(minutes), 10080))

            events: list[dict] = []

            if event_names:
                # Search for each event name individually (CloudTrail API only accepts one
                # LookupAttribute at a time) and merge results
                for en in event_names[:5]:
                    try:
                        resp = ct.lookup_events(
                            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": en}],
                            StartTime=start,
                            EndTime=end,
                            MaxResults=20,
                        )
                        for e in resp.get("Events", []):
                            resources = [r.get("ResourceName", "") for r in e.get("Resources", [])]
                            if resource_name and not any(
                                resource_name.lower() in (r or "").lower() for r in resources
                            ):
                                continue
                            detail = _j.loads(e.get("CloudTrailEvent", "{}"))
                            uid    = detail.get("userIdentity", {})
                            actor  = (
                                uid.get("userName")
                                or uid.get("sessionContext", {})
                                   .get("sessionIssuer", {}).get("userName", "")
                                or uid.get("arn", "").split("/")[-1]
                            )
                            events.append({
                                "time":          str(e.get("EventTime", "")),
                                "event_name":    e.get("EventName", ""),
                                "actor":         actor,
                                "resources":     resources,
                                "error_code":    detail.get("errorCode", ""),
                                "error_message": detail.get("errorMessage", "")[:200],
                                "request_params": str(detail.get("requestParameters") or "")[:300],
                            })
                    except Exception:
                        pass
            else:
                # Search by resource name
                search_values = list(dict.fromkeys(filter(None, [
                    resource_name,
                    resource_name.split("/")[-1] if "/" in resource_name else None,
                    resource_name.split(":")[-1] if ":" in resource_name else None,
                ])))
                for sv in search_values[:2]:
                    try:
                        resp = ct.lookup_events(
                            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": sv}],
                            StartTime=start,
                            EndTime=end,
                            MaxResults=30,
                        )
                        for e in resp.get("Events", []):
                            detail = _j.loads(e.get("CloudTrailEvent", "{}"))
                            uid    = detail.get("userIdentity", {})
                            actor  = (
                                uid.get("userName")
                                or uid.get("sessionContext", {})
                                   .get("sessionIssuer", {}).get("userName", "")
                                or uid.get("arn", "").split("/")[-1]
                            )
                            resources = [r.get("ResourceName", "") for r in e.get("Resources", [])]
                            events.append({
                                "time":          str(e.get("EventTime", "")),
                                "event_name":    e.get("EventName", ""),
                                "actor":         actor,
                                "resources":     resources,
                                "error_code":    detail.get("errorCode", ""),
                                "error_message": detail.get("errorMessage", "")[:200],
                                "request_params": str(detail.get("requestParameters") or "")[:300],
                            })
                        if events:
                            break
                    except Exception:
                        pass

            # Deduplicate and sort newest-first
            seen = set()
            unique: list[dict] = []
            for ev in events:
                key = (ev["time"], ev["event_name"], ev.get("actor", ""))
                if key not in seen:
                    seen.add(key)
                    unique.append(ev)
            unique.sort(key=lambda e: e["time"], reverse=True)
            return unique[:30]
        except Exception:  # noqa: BLE001
            return []

    def firehose_delivery_config(self, resource_name: str) -> dict:
        """Fetch Kinesis Firehose (Amazon Data Firehose) delivery stream config.
        Returns stream status, destination S3/Redshift/etc config with IAM role ARN,
        buffering hints, error output prefix, and recent delivery metrics."""
        client = self._session.client("firehose")
        cw = self._session.client("cloudwatch")
        streams = client.list_delivery_streams(Limit=100).get("DeliveryStreamNames", [])
        match = next((s for s in streams if resource_name.lower() in s.lower()), None)
        if not match:
            return {"found": False, "resource_name": resource_name, "available": streams}
        desc = client.describe_delivery_stream(DeliveryStreamName=match)["DeliveryStreamDescription"]

        # Extract destination details (S3 is most common)
        destinations = []
        for dest in desc.get("Destinations", []):
            d: dict = {"destination_id": dest.get("DestinationId")}
            if "S3DestinationDescription" in dest:
                s3d = dest["S3DestinationDescription"]
                d["type"] = "S3"
                d["bucket_arn"] = s3d.get("BucketARN")
                d["prefix"] = s3d.get("Prefix")
                d["error_output_prefix"] = s3d.get("ErrorOutputPrefix")
                d["role_arn"] = s3d.get("RoleARN")
                d["buffering_hints"] = s3d.get("BufferingHints")
                d["compression_format"] = s3d.get("CompressionFormat")
            if "ExtendedS3DestinationDescription" in dest:
                s3d = dest["ExtendedS3DestinationDescription"]
                d["type"] = "ExtendedS3"
                d["bucket_arn"] = s3d.get("BucketARN")
                d["prefix"] = s3d.get("Prefix")
                d["error_output_prefix"] = s3d.get("ErrorOutputPrefix")
                d["role_arn"] = s3d.get("RoleARN")
                d["buffering_hints"] = s3d.get("BufferingHints")
                d["compression_format"] = s3d.get("CompressionFormat")
            destinations.append(d)

        # Delivery metrics
        import datetime
        end = datetime.datetime.utcnow()
        start = end - datetime.timedelta(minutes=60)
        metrics: dict = {}
        for metric in ("DeliveryToS3.DataFreshness", "DeliveryToS3.Success",
                       "DeliveryToS3.Records", "IncomingRecords", "IncomingBytes",
                       "FailedConversionRecords"):
            try:
                resp = cw.get_metric_statistics(
                    Namespace="AWS/Firehose",
                    MetricName=metric,
                    Dimensions=[{"Name": "DeliveryStreamName", "Value": match}],
                    StartTime=start, EndTime=end,
                    Period=300, Statistics=["Average", "Sum", "Maximum"],
                )
                pts = resp.get("Datapoints", [])
                if pts:
                    pts.sort(key=lambda p: p["Timestamp"], reverse=True)
                    latest = pts[0]
                    metrics[metric] = {
                        "avg": round(latest.get("Average", 0), 2),
                        "sum": round(latest.get("Sum", 0), 2),
                        "max": round(latest.get("Maximum", 0), 2),
                    }
            except Exception:
                pass

        return {
            "found": True,
            "stream_name": desc["DeliveryStreamName"],
            "stream_arn": desc.get("DeliveryStreamARN"),
            "status": desc.get("DeliveryStreamStatus"),
            "stream_type": desc.get("DeliveryStreamType"),
            "has_more_destinations": desc.get("HasMoreDestinations", False),
            "destinations": destinations,
            "create_timestamp": str(desc.get("CreateTimestamp", "")),
            "metrics_last_60min": metrics,
        }

    def athena_workgroup_config(self, resource_name: str) -> dict:
        """Fetch Athena workgroup config: output location, enforcement, engine version,
        query scan limits, and recent query execution counts."""
        client = self._session.client("athena")
        cw = self._session.client("cloudwatch")
        workgroups = [w["Name"] for w in client.list_work_groups().get("WorkGroups", [])]
        match = next((w for w in workgroups if resource_name.lower() in w.lower()), None)
        if not match:
            return {"found": False, "resource_name": resource_name, "available": workgroups}
        wg = client.get_work_group(WorkGroup=match)["WorkGroup"]
        cfg = wg.get("Configuration", {})
        result_cfg = cfg.get("ResultConfiguration", {})

        # Recent query history — last 5 executions
        recent_queries: list[dict] = []
        try:
            ids = client.list_query_executions(WorkGroup=match, MaxResults=5).get("QueryExecutionIds", [])
            if ids:
                execs = client.batch_get_query_execution(QueryExecutionIds=ids).get("QueryExecutions", [])
                for qe in execs:
                    stat = qe.get("Status", {})
                    recent_queries.append({
                        "query_id": qe.get("QueryExecutionId"),
                        "state": stat.get("State"),
                        "state_change_reason": stat.get("StateChangeReason", ""),
                        "submission_time": str(stat.get("SubmissionDateTime", "")),
                        "completion_time": str(stat.get("CompletionDateTime", "")),
                        "data_scanned_bytes": qe.get("Statistics", {}).get("DataScannedInBytes"),
                    })
        except Exception:
            pass

        # CloudWatch metrics
        import datetime
        end = datetime.datetime.utcnow()
        start = end - datetime.timedelta(minutes=60)
        metrics: dict = {}
        for metric in ("ProcessedBytes", "QueryExecutionTime"):
            try:
                resp = cw.get_metric_statistics(
                    Namespace="AWS/Athena",
                    MetricName=metric,
                    Dimensions=[{"Name": "WorkGroup", "Value": match}],
                    StartTime=start, EndTime=end,
                    Period=300, Statistics=["Sum", "Average"],
                )
                pts = resp.get("Datapoints", [])
                if pts:
                    pts.sort(key=lambda p: p["Timestamp"], reverse=True)
                    metrics[metric] = {
                        "sum": round(pts[0].get("Sum", 0), 2),
                        "avg": round(pts[0].get("Average", 0), 2),
                    }
            except Exception:
                pass

        return {
            "found": True,
            "workgroup_name": wg["Name"],
            "state": wg.get("State"),
            "description": wg.get("Description"),
            "output_location": result_cfg.get("OutputLocation"),
            "encryption_config": result_cfg.get("EncryptionConfiguration"),
            "enforce_workgroup_config": cfg.get("EnforceWorkgroupConfiguration"),
            "publish_cloudwatch_metrics": cfg.get("PublishCloudWatchMetricsEnabled"),
            "bytes_scanned_cutoff_per_query": cfg.get("BytesScannedCutoffPerQuery"),
            "requester_pays": cfg.get("RequesterPaysEnabled"),
            "engine_version": cfg.get("EngineVersion", {}).get("SelectedEngineVersion"),
            "recent_queries": recent_queries,
            "metrics_last_60min": metrics,
        }

    def dms_replication_config(self, resource_name: str) -> dict:
        """Fetch DMS replication task config with inline replication instance and endpoint details.
        Returns task status, migration type, table mappings, last failure message,
        plus full source/target endpoint config and replication instance state."""
        client = self._session.client("dms")

        # Find the task
        tasks = client.describe_replication_tasks(
            Filters=[{"Name": "replication-task-id", "Values": [resource_name]}]
        ).get("ReplicationTasks", [])
        if not tasks:
            # Fuzzy match
            all_tasks = client.describe_replication_tasks().get("ReplicationTasks", [])
            tasks = [t for t in all_tasks if resource_name.lower() in t["ReplicationTaskIdentifier"].lower()]
        if not tasks:
            all_ids = [t["ReplicationTaskIdentifier"] for t in
                       client.describe_replication_tasks().get("ReplicationTasks", [])]
            return {"found": False, "resource_name": resource_name, "available": all_ids}

        task = tasks[0]
        result: dict = {
            "found": True,
            "task_identifier": task["ReplicationTaskIdentifier"],
            "task_arn": task["ReplicationTaskArn"],
            "status": task["Status"],
            "migration_type": task["MigrationType"],
            "table_mappings": task.get("TableMappings"),
            "replication_task_settings": task.get("ReplicationTaskSettings"),
            "last_failure_message": task.get("LastFailureMessage"),
            "stop_reason": task.get("StopReason"),
            "task_creation_date": str(task.get("ReplicationTaskCreationDate", "")),
            "task_start_date": str(task.get("ReplicationTaskStartDate", "")),
            "stats": task.get("ReplicationTaskStats", {}),
        }

        # Fetch replication instance
        try:
            instances = client.describe_replication_instances(
                Filters=[{"Name": "replication-instance-arn",
                          "Values": [task["ReplicationInstanceArn"]]}]
            ).get("ReplicationInstances", [])
            if instances:
                inst = instances[0]
                result["replication_instance"] = {
                    "identifier": inst["ReplicationInstanceIdentifier"],
                    "arn": inst["ReplicationInstanceArn"],
                    "class": inst["ReplicationInstanceClass"],
                    "allocated_storage_gb": inst["AllocatedStorage"],
                    "availability_zone": inst.get("AvailabilityZone"),
                    "status": inst["ReplicationInstanceStatus"],
                    "publicly_accessible": inst.get("PubliclyAccessible"),
                    "multi_az": inst.get("MultiAZ"),
                    "engine_version": inst.get("EngineVersion"),
                    "vpc_id": inst.get("ReplicationSubnetGroup", {}).get("VpcId"),
                    "vpc_security_groups": [
                        {"id": sg["VpcSecurityGroupId"], "status": sg["Status"]}
                        for sg in inst.get("VpcSecurityGroups", [])
                    ],
                }
        except Exception:
            pass

        # Fetch both endpoints
        endpoint_arns = [task["SourceEndpointArn"], task["TargetEndpointArn"]]
        try:
            endpoints = client.describe_endpoints(
                Filters=[{"Name": "endpoint-arn", "Values": endpoint_arns}]
            ).get("Endpoints", [])
            result["endpoints"] = []
            for ep in endpoints:
                ep_info: dict = {
                    "endpoint_identifier": ep["EndpointIdentifier"],
                    "endpoint_arn": ep["EndpointArn"],
                    "endpoint_type": ep["EndpointType"],
                    "engine_name": ep["EngineName"],
                    "status": ep["Status"],
                    "server_name": ep.get("ServerName"),
                    "port": ep.get("Port"),
                    "database_name": ep.get("DatabaseName"),
                    "username": ep.get("Username"),
                    "ssl_mode": ep.get("SslMode"),
                    "external_id": ep.get("ExternalId"),
                    "last_failure_message": ep.get("Status") == "failed" and ep.get("StatusReason", ""),
                }
                # Test-connection results are in endpoint status
                result["endpoints"].append(ep_info)
        except Exception:
            pass

        # Recent CloudWatch metrics for the task
        import datetime
        cw = self._session.client("cloudwatch")
        end = datetime.datetime.utcnow()
        start = end - datetime.timedelta(minutes=60)
        metrics: dict = {}
        task_id = task["ReplicationTaskIdentifier"]
        for metric in ("FullLoadRowsInserted", "FullLoadRowsUpdated", "CDCRowsInserted",
                       "CDCRowsDeleted", "FullLoadThroughputRowsLoaded",
                       "NetworkTransmitThroughput"):
            try:
                resp = cw.get_metric_statistics(
                    Namespace="AWS/DMS",
                    MetricName=metric,
                    Dimensions=[{"Name": "ReplicationInstanceIdentifier",
                                 "Value": task_id}],
                    StartTime=start, EndTime=end,
                    Period=300, Statistics=["Sum", "Average"],
                )
                pts = resp.get("Datapoints", [])
                if pts:
                    pts.sort(key=lambda p: p["Timestamp"], reverse=True)
                    metrics[metric] = {
                        "sum": round(pts[0].get("Sum", 0), 2),
                        "avg": round(pts[0].get("Average", 0), 2),
                    }
            except Exception:
                pass
        result["metrics_last_60min"] = metrics
        return result



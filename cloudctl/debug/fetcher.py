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

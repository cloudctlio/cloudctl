"""cloudctl MCP debug tools — full incident debug pipeline exposed as MCP tools.

Tools:
  cloudctl_debug_incident      Full pipeline: fetch all service configs +
                                correlate timeline + Bedrock AI analysis.
  cloudctl_get_service_config  Detailed config for any single AWS service.
  cloudctl_list_resources      List ECS services, Lambda functions, RDS
                                instances, etc. so you can find the exact name.
  cloudctl_tail_logs           Tail CloudWatch logs for a resource.
  cloudctl_get_event_timeline  Correlated event timeline with inflection detection.

All tools create a fresh boto3 Session per call so SSO tokens are always current.
"""
from __future__ import annotations

import json
import logging
import re

log = logging.getLogger(__name__)

# ── service-type → (fetcher_method, hint_param) ───────────────────────────

_SERVICE_FETCHERS: dict[str, tuple[str, str]] = {
    # ── Classic infrastructure ────────────────────────────────────────────────
    "ecs":             ("ecs_service_details",       "service_hint"),
    "lambda":          ("lambda_function_config",    "function_name"),
    "rds":             ("rds_instance_config",       "db_hint"),
    "aurora":          ("aurora_cluster_config",     "cluster_hint"),
    "redshift":        ("redshift_cluster_config",   "cluster_hint"),
    "glue":            ("glue_job_config",           "job_hint"),
    "api_gateway":     ("api_gateway_config",        "api_hint"),
    "dynamodb":        ("dynamodb_table_config",     "table_hint"),
    "s3":              ("s3_bucket_config",          "bucket_hint"),
    "secrets_manager": ("secrets_manager_config",    "secret_hint"),
    "sns":             ("sns_topic_config",          "topic_hint"),
    "sqs":             ("sqs_queue_config",          "queue_hint"),
    "elasticache":     ("elasticache_config",        "cluster_hint"),
    "kinesis":         ("kinesis_stream_config",     "stream_hint"),
    "eks":             ("eks_cluster_config",        "cluster_hint"),
    "stepfunctions":   ("stepfunctions_config",      "machine_hint"),
    "opensearch":      ("opensearch_config",         "domain_hint"),
    "eventbridge":     ("eventbridge_rule_config",   "rule_hint"),
    "cloudfront":      ("cloudfront_config",         "dist_hint"),
    "alb":             ("alb_config",                "lb_hint"),
    "ssm":             ("ssm_parameter_config",      "param_hint"),
    "acm":             ("acm_certificate_config",    "domain_hint"),
    "msk":             ("msk_cluster_config",        "cluster_hint"),
    "ecr":             ("ecr_repository_config",     "repo_hint"),
    "route53":         ("route53_zone_config",       "zone_hint"),
    "codepipeline":    ("codepipeline_config",       "pipeline_hint"),
    # ── AI / ML ───────────────────────────────────────────────────────────────
    "sagemaker":       ("sagemaker_endpoint_config", "endpoint_hint"),
    "bedrock_agent":   ("bedrock_agent_config",      "agent_hint"),
    "bedrock_kb":      ("bedrock_kb_config",         "kb_hint"),
    "agentcore":       ("agentcore_config",          "store_hint"),
}


_VALID_PROFILE_RE = re.compile(r'^[a-zA-Z0-9._\-]+$')
_VALID_REGION_RE  = re.compile(
    r'^(us|eu|ap|sa|ca|me|af|il|mx|ap)-(?:gov-)?[a-z]+-\d+$|^cn-[a-z]+-\d+$'
)


def _make_session(profile: str | None, region: str):
    """Fresh boto3 Session each call — keeps SSO tokens current."""
    import boto3
    if profile and not _VALID_PROFILE_RE.match(profile):
        raise ValueError("Invalid AWS profile name")
    if region and not _VALID_REGION_RE.match(region):
        raise ValueError(f"Invalid AWS region: {region}")
    return boto3.Session(profile_name=profile, region_name=region) if profile \
        else boto3.Session(region_name=region)


def _serialise(obj) -> object:
    import datetime
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _serialise(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialise(i) for i in obj]
    return obj


def _fetch_cw_logs(fetcher, hint: str, minutes: int) -> list[dict]:
    """Try hint as log group name directly, then common prefixes."""
    from cloudctl.debug.fetcher import DebugFetcher  # noqa: F401
    candidates = [
        hint,
        f"/aws/lambda/{hint}",
        f"/ecs/{hint}",
        f"/aws/ecs/containerinsights/{hint}/performance",
        f"/aws/rds/instance/{hint}/error",
        f"/aws/apigateway/{hint}",
    ]
    for lg in candidates:
        try:
            evts = fetcher.cloudwatch_logs(log_group=lg, minutes=minutes)
            if evts:
                return evts
        except Exception:  # noqa: BLE001
            pass
    # Fall back to discover_log_groups
    try:
        groups = fetcher.discover_log_groups(hint)
        for grp in groups[:3]:
            evts = fetcher.cloudwatch_logs(log_group=grp, minutes=minutes)
            if evts:
                return evts
    except Exception:  # noqa: BLE001
        pass
    return []


# ── tool implementations ───────────────────────────────────────────────────

def debug_incident(
    symptom: str,
    profile: str | None,
    region: str,
    minutes: int,
) -> str:
    """Full debug pipeline: fetch → correlate → Bedrock AI analysis."""
    from cloudctl.debug.fetcher    import DebugFetcher
    from cloudctl.debug.correlator import build_timeline, build_rich_timeline
    from cloudctl.debug.analyzer   import analyze
    from cloudctl.ai               import confidence as confidence_mod
    from cloudctl.debug.planner    import extract_service_hints

    session = _make_session(profile, region)
    fetcher = DebugFetcher(session)
    hints   = extract_service_hints(symptom)
    context: dict = {}

    # ── Symptom signals ───────────────────────────────────────────────────
    for hint in hints[:3]:
        evts = _fetch_cw_logs(fetcher, hint, minutes)
        if evts:
            context.setdefault("cloudwatch_logs", []).extend(evts)
            break

    ct = fetcher.cloudtrail(minutes=max(minutes, 60))
    if ct:
        context["cloudtrail"] = ct

    for hint in hints[:3]:
        alb = fetcher.build_alb_resource_map(resource_name=hint)
        if alb:
            context["alb_resource_map"] = alb
            break

    for hint in hints[:3]:
        evts = fetcher.ecs_events(cluster=hint, service=hint)
        if evts:
            context.setdefault("ecs_events", []).extend(evts)
            break

    for hint in hints[:3]:
        stopped = fetcher.ecs_stopped_tasks(cluster=hint, service=hint)
        if stopped:
            context.setdefault("ecs_stopped", []).extend(stopped)
            break

    for hint in hints[:3]:
        evts = fetcher.lambda_logs(function_name=hint, minutes=minutes)
        if evts:
            context.setdefault("lambda_logs", []).extend(evts)
            break

    for hint in hints[:3]:
        rpt = fetcher.lambda_report_metrics(function_name=hint, minutes=minutes)
        if rpt:
            context.setdefault("lambda_report", []).extend(rpt)
            break

    for hint in hints[:3]:
        slow = fetcher.rds_slow_queries(db_identifier=hint, minutes=minutes)
        if slow:
            context.setdefault("rds_slow", []).extend(slow)
            break

    for hint in hints[:3]:
        dlq = fetcher.sqs_with_dlq(queue_name_hint=hint)
        if dlq:
            context.setdefault("sqs_dlq", []).extend(dlq)
            break

    acm = fetcher.acm_certificates()
    if acm:
        context["acm_expiry_check"] = acm

    flow = fetcher.vpc_flow_logs(minutes=minutes)
    if flow:
        context["vpc_flow_logs"] = flow

    # ── Full service configs ───────────────────────────────────────────────
    all_hints = hints or [symptom.split()[0][:20]]

    for svc_type, (method_name, hint_key) in _SERVICE_FETCHERS.items():
        method = getattr(fetcher, method_name)
        for hint in all_hints[:3]:
            try:
                cfg = method(cluster_hint=hint, service_hint=hint) \
                      if svc_type == "ecs" \
                      else method(**{hint_key: hint})
            except Exception:  # noqa: BLE001
                cfg = {}
            if cfg:
                ctx_key = ("ecs_service_details" if svc_type == "ecs"
                           else "lambda_function_config" if svc_type == "lambda"
                           else f"{svc_type}_config")
                context[ctx_key] = cfg
                break

    # ── Correlate ──────────────────────────────────────────────────────────
    # Flatten context dict into a list of event dicts for the correlator
    event_list: list[dict] = []
    for key, val in context.items():
        if key.startswith("_"):
            continue
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    event_list.append({"source": key, **item})
        elif isinstance(val, dict):
            event_list.append({"source": key, **val})

    timeline      = build_timeline(event_list)
    rich_timeline = build_rich_timeline(context)
    rich = {
        "pattern":         rich_timeline.pattern,
        "correlation_pct": rich_timeline.correlation_pct,
        "inflection":      rich_timeline.inflection_point.event if rich_timeline.inflection_point else None,
        "event_count":     len(rich_timeline.events),
    }
    context["_rich_timeline"] = rich

    # ── Confidence ─────────────────────────────────────────────────────────
    cs = confidence_mod.score(
        context,
        timeline_pattern=rich["pattern"],
        timeline_correlation=rich["correlation_pct"],
        has_inflection=bool(rich["inflection"]),
    )

    # ── Bedrock AI (fresh session) ─────────────────────────────────────────
    class _BedrockAI:
        def __init__(self, prof, reg):
            self._profile = prof
            self._region  = reg

        def ask(self, prompt: str, context: dict | None = None) -> dict:
            import boto3, json as _j
            sess   = boto3.Session(profile_name=self._profile) if self._profile \
                     else boto3.Session()
            client = sess.client("bedrock-runtime", region_name=self._region)
            system = (context or {}).get("system", "")
            resp   = client.invoke_model(
                modelId="us.anthropic.claude-sonnet-4-6",
                body=_j.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens":        4096,
                    "system":            system,
                    "messages":          [{"role": "user", "content": prompt}],
                }),
            )
            data   = _j.loads(resp["body"].read())
            return {"answer": data.get("content", [{}])[0].get("text", "")}

    ai       = _BedrockAI(profile, region)
    tl_dicts = [e.__dict__ if hasattr(e, "__dict__") else dict(e) for e in timeline]
    result   = analyze(ai, symptom, tl_dicts, context)

    return json.dumps(_serialise({
        "root_cause":         result.root_cause_lines or [result.root_cause],
        "evidence":           result.evidence,
        "affected_resources": result.affected_resources,
        "remediation_steps":  result.remediation_steps,
        "confidence": {
            "level":       cs.level,
            "reasons":     cs.reasons,
            "sources":     cs.sources,
            "data_points": cs.data_points,
        },
        "severity":         result.severity,
        "timeline_summary": rich,
        "data_sources":     list(fetcher.availability.keys()),
    }), indent=2)


def query_metrics(
    namespace:   str,
    metric_name: str,
    dimensions:  dict,
    profile:     str | None,
    region:      str,
    minutes:     int = 30,
    stat:        str = "Average",
) -> str:
    """Generic CloudWatch metric query. The agent supplies namespace/metric/dims;
    we never pre-choose for it. Returns time-aligned datapoints summarised as
    first/last/delta/min/max/avg over the window."""
    import datetime as _dt
    minutes = max(1, min(int(minutes or 30), 360))

    stat_param = stat
    extended = None
    if stat and stat.lower().startswith("p"):
        extended = stat
        stat_param = None

    try:
        session = _make_session(profile, region)
        cw = session.client("cloudwatch")
        end   = _dt.datetime.now(_dt.timezone.utc)
        start = end - _dt.timedelta(minutes=minutes)
        kwargs = {
            "Namespace":  namespace,
            "MetricName": metric_name,
            "Dimensions": [{"Name": k, "Value": str(v)} for k, v in (dimensions or {}).items()],
            "StartTime":  start,
            "EndTime":    end,
            "Period":     300 if minutes >= 30 else 60,
        }
        if extended:
            kwargs["ExtendedStatistics"] = [extended]
        else:
            kwargs["Statistics"] = [stat_param or "Average"]

        r = cw.get_metric_statistics(**kwargs)
        pts = sorted(r.get("Datapoints", []), key=lambda p: p["Timestamp"])
        if not pts:
            return json.dumps({
                "namespace": namespace, "metric_name": metric_name,
                "dimensions": dimensions, "minutes": minutes, "stat": stat,
                "datapoints": 0,
                "note": "No data in the requested window — metric or dimensions may be wrong, or the resource has no recent traffic.",
            }, indent=2)

        def _v(p):
            if extended:
                return p.get("ExtendedStatistics", {}).get(extended, 0)
            return p.get(stat_param or "Average", 0)

        values = [_v(p) for p in pts]
        return json.dumps({
            "namespace":   namespace,
            "metric_name": metric_name,
            "dimensions":  dimensions,
            "minutes":     minutes,
            "stat":        stat,
            "unit":        r.get("Datapoints", [{}])[0].get("Unit", ""),
            "datapoints":  len(pts),
            "first":       values[0],
            "last":        values[-1],
            "delta":       values[-1] - values[0],
            "min":         min(values),
            "max":         max(values),
            "avg":         sum(values) / len(values),
        }, indent=2)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"query_metrics failed: {type(exc).__name__}"})


def get_service_config(
    service_type: str,
    resource_hint: str,
    profile: str | None,
    region: str,
) -> str:
    from cloudctl.debug.fetcher import DebugFetcher

    if service_type not in _SERVICE_FETCHERS:
        return json.dumps({"error": f"Unknown service_type '{service_type}'. "
                                    f"Valid: {sorted(_SERVICE_FETCHERS)}"})

    session     = _make_session(profile, region)
    fetcher     = DebugFetcher(session)
    method_name, hint_key = _SERVICE_FETCHERS[service_type]
    method      = getattr(fetcher, method_name)

    try:
        cfg = method(cluster_hint=resource_hint, service_hint=resource_hint) \
              if service_type == "ecs" \
              else method(**{hint_key: resource_hint})
    except Exception as exc:  # noqa: BLE001
        cfg = {}
        # Log only the exception type, not the message — AWS exceptions can contain
        # account IDs, ARNs, and resource names that should not appear in logs.
        log.warning("get_service_config %s: %s", service_type, type(exc).__name__)

    if not cfg:
        # Return a helpful "not found" with a list of what IS available
        available = _list_resources_for_type(fetcher, service_type)
        return json.dumps({
            "found":       False,
            "service_type": service_type,
            "hint":        resource_hint,
            "tip":         f"No {service_type} resource matched '{resource_hint}'. "
                           f"Use cloudctl_list_resources to see available names.",
            "available":   available,
        }, indent=2)

    return json.dumps({"found": True, "service_type": service_type,
                       "config": _serialise(cfg)}, indent=2)


def _list_ecs(s) -> list[str]:
    ecs = s.client("ecs")
    names = []
    for ca in ecs.list_clusters().get("clusterArns", [])[:3]:
        cn = ca.split("/")[-1]
        for sa in ecs.list_services(cluster=cn).get("serviceArns", [])[:20]:
            names.append(f"{cn}/{sa.split('/')[-1]}")
    return names

def _list_lambda(s) -> list[str]:
    return [f["FunctionName"]
            for f in s.client("lambda").list_functions(MaxItems=50).get("Functions", [])]

def _list_rds(s) -> list[str]:
    return [i["DBInstanceIdentifier"]
            for i in s.client("rds").describe_db_instances().get("DBInstances", [])]

def _list_aurora(s) -> list[str]:
    return [c["DBClusterIdentifier"]
            for c in s.client("rds").describe_db_clusters().get("DBClusters", [])]

def _list_dynamodb(s) -> list[str]:
    return s.client("dynamodb").list_tables().get("TableNames", [])

def _list_s3(s) -> list[str]:
    return [b["Name"] for b in s.client("s3").list_buckets().get("Buckets", [])]

def _list_sqs(s) -> list[str]:
    urls = s.client("sqs").list_queues(QueueNamePrefix="").get("QueueUrls", [])
    return [u.split("/")[-1] for u in urls]

def _list_sns(s) -> list[str]:
    return [t["TopicArn"].split(":")[-1]
            for t in s.client("sns").list_topics().get("Topics", [])]

def _list_eks(s) -> list[str]:
    return s.client("eks").list_clusters().get("clusters", [])

def _list_kinesis(s) -> list[str]:
    return s.client("kinesis").list_streams().get("StreamNames", [])

def _list_elasticache(s) -> list[str]:
    ec = s.client("elasticache")
    rg_ids = {r["ReplicationGroupId"]
               for r in ec.describe_replication_groups().get("ReplicationGroups", [])}
    standalone = [c["CacheClusterId"]
                  for c in ec.describe_cache_clusters().get("CacheClusters", [])
                  if not any(c["CacheClusterId"].startswith(rg) for rg in rg_ids)]
    return list(rg_ids) + standalone

def _list_redshift(s) -> list[str]:
    return [c["ClusterIdentifier"]
            for c in s.client("redshift").describe_clusters().get("Clusters", [])]

def _list_glue(s) -> list[str]:
    return [j["Name"]
            for j in s.client("glue").get_jobs().get("Jobs", [])]

def _list_api_gateway(s) -> list[str]:
    return [a["name"]
            for a in s.client("apigateway").get_rest_apis().get("items", [])]

def _list_secrets_manager(s) -> list[str]:
    return [sec["Name"]
            for sec in s.client("secretsmanager").list_secrets().get("SecretList", [])]

def _list_stepfunctions(s) -> list[str]:
    return [m["name"]
            for m in s.client("stepfunctions").list_state_machines().get("stateMachines", [])]

def _list_opensearch(s) -> list[str]:
    return [d["DomainName"]
            for d in s.client("opensearch").list_domain_names().get("DomainNames", [])]

def _list_sagemaker(s) -> list[str]:
    sm = s.client("sagemaker")
    endpoints = [e["EndpointName"] for e in sm.list_endpoints().get("Endpoints", [])]
    jobs = [j["TrainingJobName"]
            for j in sm.list_training_jobs(MaxResults=20).get("TrainingJobSummaries", [])]
    return endpoints + jobs

def _list_bedrock_agent(s) -> list[str]:
    ba = s.client("bedrock-agent")
    return [a["agentName"] for a in ba.list_agents().get("agentSummaries", [])]

def _list_bedrock_kb(s) -> list[str]:
    ba = s.client("bedrock-agent")
    return [kb["name"] for kb in ba.list_knowledge_bases().get("knowledgeBaseSummaries", [])]

def _list_agentcore(s) -> list[str]:
    ac = s.client("bedrock-agentcore")
    return [m["memoryStoreId"] for m in ac.list_memory_stores().get("memoryStoreSummaries", [])]

def _list_eventbridge(s) -> list[str]:
    eb = s.client("events")
    rules = eb.list_rules().get("Rules", [])
    return [r["Name"] for r in rules]

def _list_cloudfront(s) -> list[str]:
    cf = s.client("cloudfront")
    items = cf.list_distributions().get("DistributionList", {}).get("Items", [])
    return [f"{d['Id']} ({d.get('DomainName','')})" for d in items]

def _list_alb(s) -> list[str]:
    elb = s.client("elbv2")
    lbs = elb.describe_load_balancers().get("LoadBalancers", [])
    return [lb["LoadBalancerName"] for lb in lbs]

def _list_ssm(s) -> list[str]:
    ssm = s.client("ssm")
    params = ssm.describe_parameters(MaxResults=50).get("Parameters", [])
    return [p["Name"] for p in params]

def _list_acm(s) -> list[str]:
    acm = s.client("acm")
    certs = acm.list_certificates().get("CertificateSummaryList", [])
    return [c.get("DomainName", c["CertificateArn"].split("/")[-1]) for c in certs]

def _list_msk(s) -> list[str]:
    msk = s.client("kafka")
    clusters = msk.list_clusters_v2().get("ClusterInfoList", [])
    return [c["ClusterName"] for c in clusters]

def _list_ecr(s) -> list[str]:
    ecr = s.client("ecr")
    repos = ecr.describe_repositories().get("repositories", [])
    return [r["repositoryName"] for r in repos]

def _list_route53(s) -> list[str]:
    r53 = s.client("route53")
    zones = r53.list_hosted_zones().get("HostedZones", [])
    return [z["Name"].rstrip(".") for z in zones]

def _list_codepipeline(s) -> list[str]:
    cp = s.client("codepipeline")
    return [p["name"] for p in cp.list_pipelines().get("pipelines", [])]


_SERVICE_LISTERS: dict[str, object] = {
    # ── Classic infrastructure ────────────────────────────────────────────────
    "ecs":             _list_ecs,
    "lambda":          _list_lambda,
    "rds":             _list_rds,
    "aurora":          _list_aurora,
    "dynamodb":        _list_dynamodb,
    "s3":              _list_s3,
    "sqs":             _list_sqs,
    "sns":             _list_sns,
    "eks":             _list_eks,
    "kinesis":         _list_kinesis,
    "elasticache":     _list_elasticache,
    "redshift":        _list_redshift,
    "glue":            _list_glue,
    "api_gateway":     _list_api_gateway,
    "secrets_manager": _list_secrets_manager,
    "stepfunctions":   _list_stepfunctions,
    "opensearch":      _list_opensearch,
    "eventbridge":     _list_eventbridge,
    "cloudfront":      _list_cloudfront,
    "alb":             _list_alb,
    "ssm":             _list_ssm,
    "acm":             _list_acm,
    "msk":             _list_msk,
    "ecr":             _list_ecr,
    "route53":         _list_route53,
    "codepipeline":    _list_codepipeline,
    # ── AI / ML ───────────────────────────────────────────────────────────────
    "sagemaker":       _list_sagemaker,
    "bedrock_agent":   _list_bedrock_agent,
    "bedrock_kb":      _list_bedrock_kb,
    "agentcore":       _list_agentcore,
}


def _list_resources_for_type(fetcher, service_type: str) -> list[str]:
    """Return a flat list of resource names for a service type."""
    fn = _SERVICE_LISTERS.get(service_type)
    if not fn or not fetcher._session:
        return []
    try:
        return fn(fetcher._session)
    except Exception:  # noqa: BLE001
        return []


def list_resources(
    service_type: str,
    profile: str | None,
    region: str,
) -> str:
    """List resource names for a service type so users can find exact names."""
    session = _make_session(profile, region)
    from cloudctl.debug.fetcher import DebugFetcher
    fetcher = DebugFetcher(session)
    names   = _list_resources_for_type(fetcher, service_type)
    return json.dumps({
        "service_type": service_type,
        "region":       region,
        "count":        len(names),
        "resources":    names,
    }, indent=2)


def tail_logs(
    resource_hint: str,
    minutes: int,
    profile: str | None,
    region: str,
    max_events: int,
) -> str:
    from cloudctl.debug.fetcher import DebugFetcher

    session = _make_session(profile, region)
    fetcher = DebugFetcher(session)

    # Discover which log groups match
    discovered: list[str] = []
    logs: list[dict] = []

    # Try common log group patterns first
    candidates = [
        resource_hint,
        f"/aws/lambda/{resource_hint}",
        f"/ecs/{resource_hint}",
        f"/aws/ecs/containerinsights/{resource_hint}/performance",
        f"/aws/rds/instance/{resource_hint}/error",
        f"/aws/apigateway/{resource_hint}",
    ]
    for lg in candidates:
        try:
            evts = fetcher.cloudwatch_logs(log_group=lg, minutes=minutes)
            if evts:
                logs.extend(evts)
                discovered.append(lg)
                break
        except Exception:  # noqa: BLE001
            pass

    # Fall back to discover_log_groups
    if not logs:
        try:
            groups = fetcher.discover_log_groups(resource_hint)
            for grp in groups[:5]:
                evts = fetcher.cloudwatch_logs(log_group=grp, minutes=minutes)
                if evts:
                    logs.extend(evts)
                    discovered.append(grp)
        except Exception:  # noqa: BLE001
            pass

    # Last resort: tail_log_group (returns most recent lines regardless of filter)
    if not logs and discovered:
        for grp in discovered[:2]:
            evts = fetcher.tail_log_group(grp)
            logs.extend(evts)

    return json.dumps({
        "resource_hint":    resource_hint,
        "minutes":          minutes,
        "event_count":      len(logs[:max_events]),
        "log_groups_found": discovered,
        "events":           _serialise(logs[:max_events]),
    }, indent=2)


def get_event_timeline(
    symptom: str,
    profile: str | None,
    region: str,
    minutes: int,
) -> str:
    from cloudctl.debug.fetcher    import DebugFetcher
    from cloudctl.debug.correlator import build_timeline, build_rich_timeline
    from cloudctl.debug.planner    import extract_service_hints

    session = _make_session(profile, region)
    fetcher = DebugFetcher(session)
    hints   = extract_service_hints(symptom)
    context: dict = {}

    ct = fetcher.cloudtrail(minutes=max(minutes, 60))
    if ct:
        context["cloudtrail"] = ct

    for hint in hints[:3]:
        evts = _fetch_cw_logs(fetcher, hint, minutes)
        if evts:
            context.setdefault("cloudwatch_logs", []).extend(evts)
            break

    for hint in hints[:3]:
        evts = fetcher.ecs_events(cluster=hint, service=hint)
        if evts:
            context.setdefault("ecs_events", []).extend(evts)
            break

    for hint in hints[:3]:
        evts = fetcher.lambda_logs(function_name=hint, minutes=minutes)
        if evts:
            context.setdefault("lambda_logs", []).extend(evts)
            break

    for hint in hints[:3]:
        evts = fetcher.rds_events(db_identifier=hint, minutes=minutes)
        if evts:
            context.setdefault("rds_events", []).extend(evts)
            break

    for hint in hints[:3]:
        evts = fetcher.codepipeline_for_resource(resource_name=hint)
        if evts:
            context.setdefault("codepipeline", []).extend(evts)
            break

    event_list2: list[dict] = []
    for key, val in context.items():
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    event_list2.append({"source": key, **item})
        elif isinstance(val, dict):
            event_list2.append({"source": key, **val})

    timeline      = build_timeline(event_list2)
    rich_timeline = build_rich_timeline(context)
    tl_dicts      = [_serialise(e.__dict__ if hasattr(e, "__dict__") else dict(e))
                     for e in timeline]

    inflection = None
    if rich_timeline.inflection_point:
        ip = rich_timeline.inflection_point
        inflection = {
            "time":   str(getattr(ip, "time", "")),
            "source": getattr(ip, "source", ""),
            "event":  getattr(ip, "event",  str(ip)),
        }

    return json.dumps({
        "symptom":          symptom,
        "minutes":          minutes,
        "event_count":      len(tl_dicts),
        "pattern":          rich_timeline.pattern,
        "correlation_pct":  rich_timeline.correlation_pct,
        "inflection_point": inflection,
        "sources_fetched":  list(fetcher.availability.keys()),
        "timeline":         tl_dicts[-50:],
    }, indent=2)


def get_deployment_info(
    resource_name: str,
    service_type:  str,
    profile:       str | None,
    region:        str,
) -> str:
    """Detect how a resource was deployed and who last changed it via CloudTrail."""
    import datetime as _dt
    from cloudctl.debug.deployment_detector import detect, iac_drift_warning

    session      = _make_session(profile, region)
    resource_arn = resource_name   # default: use name as CloudTrail search value
    resource_tags: dict = {}

    # Resolve ARN + tags for supported service types
    try:
        if service_type == "lambda":
            fn = session.client("lambda").get_function(FunctionName=resource_name)
            resource_arn  = fn["Configuration"]["FunctionArn"]
            resource_tags = fn.get("Tags", {})

        elif service_type in ("rds", "aurora"):
            client = session.client("rds")
            try:
                db = client.describe_db_instances(
                    DBInstanceIdentifier=resource_name
                )["DBInstances"][0]
                resource_arn  = db["DBInstanceArn"]
                resource_tags = {t["Key"]: t["Value"] for t in db.get("TagList", [])}
            except Exception:
                clusters = client.describe_db_clusters(
                    DBClusterIdentifier=resource_name
                )["DBClusters"]
                if clusters:
                    resource_arn  = clusters[0]["DBClusterArn"]
                    resource_tags = {t["Key"]: t["Value"] for t in clusters[0].get("TagList", [])}

        elif service_type == "ecs":
            ecs = session.client("ecs")
            for ca in ecs.list_clusters().get("clusterArns", [])[:5]:
                for sa in ecs.list_services(cluster=ca).get("serviceArns", [])[:30]:
                    if sa.split("/")[-1] == resource_name or resource_name in sa:
                        resource_arn = sa
                        svcs = ecs.describe_services(cluster=ca, services=[sa],
                                                     include=["TAGS"]).get("services", [])
                        if svcs:
                            resource_tags = {t["key"]: t["value"]
                                             for t in svcs[0].get("tags", [])}
                        break
                if resource_arn != resource_name:
                    break

        elif service_type == "dynamodb":
            tbl = session.client("dynamodb").describe_table(TableName=resource_name)["Table"]
            resource_arn = tbl["TableArn"]
            arn_resp = session.client("dynamodb").list_tags_of_resource(ResourceArn=resource_arn)
            resource_tags = {t["Key"]: t["Value"] for t in arn_resp.get("Tags", [])}

        elif service_type == "sqs":
            sqs = session.client("sqs")
            url = sqs.get_queue_url(QueueName=resource_name)["QueueUrl"]
            attrs = sqs.get_queue_attributes(QueueUrl=url,
                                              AttributeNames=["QueueArn"])["Attributes"]
            resource_arn = attrs.get("QueueArn", resource_name)
            tags_resp = sqs.list_queue_tags(QueueUrl=url)
            resource_tags = tags_resp.get("Tags", {})

    except Exception:
        pass  # fall back to using resource_name as the search value

    deployment_source = detect(
        "aws", session=session,
        resource_arn=resource_arn, resource_tags=resource_tags,
    )
    drift_warning = iac_drift_warning(deployment_source) or ""

    # CloudTrail: last change actor + timestamp
    last_changed_by = ""
    last_changed_at = ""
    last_event_name = ""
    try:
        ct    = session.client("cloudtrail")
        end   = _dt.datetime.now(_dt.timezone.utc)
        start = end - _dt.timedelta(hours=72)

        search_values = list(dict.fromkeys(filter(None, [
            resource_arn,
            resource_name if resource_arn != resource_name else None,
            resource_arn.split(":")[-1] if ":" in resource_arn else None,
        ])))

        for sv in search_values:
            resp = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": sv}],
                StartTime=start, EndTime=end, MaxResults=20,
            )
            evs = resp.get("Events", [])
            if evs:
                ev = evs[0]
                import json as _json2
                detail = _json2.loads(ev.get("CloudTrailEvent", "{}"))
                uid = detail.get("userIdentity", {})
                last_changed_by = (
                    uid.get("userName")
                    or uid.get("sessionContext", {})
                       .get("sessionIssuer", {}).get("userName", "")
                    or ev.get("Username", "")
                )
                evt_time = ev.get("EventTime")
                last_changed_at = (
                    evt_time.isoformat() if hasattr(evt_time, "isoformat") else str(evt_time)
                )
                last_event_name = ev.get("EventName", "")
                break
    except Exception:
        pass

    # IaC file hint
    iac_file_hint = ""
    if deployment_source == "terraform":
        iac_file_hint = (
            f"Run: terraform state list | grep {resource_name}  "
            "to find the resource address, then edit the corresponding .tf file."
        )
    elif deployment_source in ("cloudformation", "cdk"):
        try:
            cf = session.client("cloudformation")
            def _lookup_cf(pid):
                try:
                    return cf.describe_stack_resources(PhysicalResourceId=pid).get("StackResources", [])
                except Exception:
                    return []
            stacks = _lookup_cf(resource_arn) or _lookup_cf(resource_name)
            if stacks:
                stack_name = stacks[0]["StackName"]
                iac_file_hint = (
                    f"CloudFormation stack: {stack_name}. "
                    + ("Edit CDK source and run cdk deploy." if deployment_source == "cdk"
                       else "Update stack via aws cloudformation update-stack.")
                )
        except Exception:
            pass
    elif deployment_source == "pulumi":
        iac_file_hint = f"Run: pulumi stack --show-urns | grep {resource_name} to find the resource URN."
    elif deployment_source in ("manual", "unknown"):
        iac_file_hint = "Resource appears to be managed manually via AWS Console or CLI."

    return json.dumps({
        "resource_name":     resource_name,
        "service_type":      service_type,
        "deployment_source": deployment_source,
        "last_changed_by":   last_changed_by,
        "last_changed_at":   last_changed_at,
        "last_event_name":   last_event_name,
        "iac_file_hint":     iac_file_hint,
        "drift_warning":     drift_warning,
    }, indent=2)


# ── Agent mode ────────────────────────────────────────────────────────────────

_AGENT_TOOLS = [
    {
        "toolSpec": {
            "name": "list_resources",
            "description": (
                "List all resource names for a given AWS service type. "
                "Call this first to find exact names before fetching config or logs. "
                "Classic infra: ecs, lambda, rds, aurora, dynamodb, s3, sqs, sns, eks, "
                "kinesis, elasticache, redshift, glue, api_gateway, secrets_manager, "
                "stepfunctions, opensearch, eventbridge, cloudfront, alb, ssm, acm, "
                "msk, ecr, route53, codepipeline. "
                "AI/ML: sagemaker, bedrock_agent, bedrock_kb, agentcore."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "service_type": {
                        "type": "string",
                        "enum": [
                            "ecs","lambda","rds","aurora","dynamodb","s3","sqs","sns",
                            "eks","kinesis","elasticache","redshift","glue","api_gateway",
                            "secrets_manager","stepfunctions","opensearch","eventbridge",
                            "cloudfront","alb","ssm","acm","msk","ecr","route53",
                            "codepipeline","sagemaker","bedrock_agent","bedrock_kb","agentcore",
                        ],
                    },
                },
                "required": ["service_type"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "get_service_config",
            "description": (
                "Get detailed config, metrics, and recent events for a specific AWS resource. "
                "Returns error rates, latency percentiles, memory usage, environment variables, "
                "VPC config, and recent CloudWatch alarm states."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "service_type":  {"type": "string"},
                    "resource_name": {"type": "string"},
                },
                "required": ["service_type", "resource_name"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "tail_logs",
            "description": (
                "Read recent CloudWatch log lines for a resource. "
                "Use filter_pattern to focus on ERROR, FATAL, Exception, or a specific error string. "
                "Always call this when you see elevated error rates or anomalies in metrics."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "resource_hint":   {"type": "string",
                                       "description": "Function name, ECS service, or log group prefix"},
                    "filter_pattern":  {"type": "string",
                                       "description": "CloudWatch Logs filter: ERROR, Exception, FATAL, or a literal string"},
                },
                "required": ["resource_hint"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "get_event_timeline",
            "description": (
                "Get a correlated event timeline with inflection-point detection across all services. "
                "Use this to find exactly when a problem started and how errors spread."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "symptom": {"type": "string"},
                },
                "required": ["symptom"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "query_metrics",
            "description": (
                "Read CloudWatch metric data for any AWS service. Use this whenever a "
                "config snapshot is not enough and you need to see TRENDS, RATES, or "
                "current VALUES against limits (e.g. DatabaseConnections, "
                "TargetResponseTime p99, ApproximateNumberOfMessagesVisible). "
                "Returns first/last/min/max/avg over the window so growth and spikes are visible. "
                "The model picks the namespace, metric name, and dimensions — they are not pre-chosen."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "namespace":   {"type": "string",
                                    "description": "CloudWatch namespace, e.g. AWS/RDS, AWS/ECS, AWS/SQS, AWS/ApplicationELB"},
                    "metric_name": {"type": "string",
                                    "description": "Metric name, e.g. DatabaseConnections, CPUUtilization, TargetResponseTime"},
                    "dimensions":  {"type": "object",
                                    "description": "Dimension name/value pairs, e.g. {\"DBInstanceIdentifier\": \"shopcore-orders-db\"}"},
                    "minutes":     {"type": "integer",
                                    "description": "Lookback window in minutes (default 30, max 360)"},
                    "stat":        {"type": "string",
                                    "description": "Statistic: Average, Sum, Maximum, Minimum, p99, p95, p90 (default Average)"},
                },
                "required": ["namespace", "metric_name", "dimensions"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "get_deployment_info",
            "description": (
                "Find out HOW a resource was deployed (terraform, cdk, cloudformation, manual) "
                "and WHO last changed it (IAM actor) and WHEN. "
                "Call this when the user asks about deployment method, or to tailor "
                "remediation_steps to the right IaC toolchain. "
                "Returns: deployment_source, last_changed_by, last_changed_at, "
                "iac_file_hint, and drift_warning."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "resource_name": {"type": "string",
                                     "description": "Exact resource name (e.g. ECS service name, Lambda function name)"},
                    "service_type":  {"type": "string",
                                     "description": "AWS service type — same values as list_resources service_type"},
                },
                "required": ["resource_name", "service_type"],
            }},
        }
    },
]

_AGENT_SYSTEM = """\
You are a senior cloud infrastructure engineer investigating a live AWS incident.
You have tools to read real AWS data. Investigate the symptom methodically:

1. Start with list_resources to find the exact resource names involved.
2. Use get_service_config to check error rates, latency, memory usage, and config.
3. When you see elevated errors or anomalies, ALWAYS call tail_logs with
   filter_pattern="ERROR" to read the actual error messages — never conclude
   without reading the logs.
4. Use get_event_timeline to find when the problem started.
5. Follow the evidence — if logs mention a database, check the DB config too.

Do NOT guess. Only conclude when you have direct log or metric evidence.

When done, respond ONLY with a JSON object (no markdown fences, no extra text):
{
  "root_cause": "one clear sentence naming the exact failure",
  "evidence": ["specific log line or metric that proves it"],
  "remediation_steps": ["concrete, actionable fix step"],
  "severity": "HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "resources_investigated": ["every resource name you checked"]
}"""


# ── Context management ────────────────────────────────────────────────────────

_MAX_LOG_LINES_IN_CONTEXT     = 50
_MAX_TOOL_OUTPUT_CHARS        = 8000   # ~2000 tokens


def _truncate_tool_output(result: str, tool_name: str) -> str:
    """Truncate large tool outputs to protect context window."""
    if len(result) <= _MAX_TOOL_OUTPUT_CHARS:
        return result

    if tool_name == "tail_logs":
        lines = result.strip().splitlines()
        if len(lines) > _MAX_LOG_LINES_IN_CONTEXT:
            kept    = lines[-_MAX_LOG_LINES_IN_CONTEXT:]
            omitted = len(lines) - _MAX_LOG_LINES_IN_CONTEXT
            return (
                f"[{omitted} older log lines omitted — "
                f"showing most recent {_MAX_LOG_LINES_IN_CONTEXT}]\n"
                + "\n".join(kept)
            )

    if tool_name == "get_event_timeline":
        lines = result.strip().splitlines()
        if len(lines) > 60:
            head    = lines[:20]
            tail    = lines[-20:]
            omitted = len(lines) - 40
            return (
                "\n".join(head)
                + f"\n[... {omitted} events omitted ...]\n"
                + "\n".join(tail)
            )

    half = _MAX_TOOL_OUTPUT_CHARS // 2
    return (
        result[:half]
        + "\n[... truncated — output too large ...]\n"
        + result[-half:]
    )


def _get_account_id(profile: str | None, region: str) -> str:
    """Resolve AWS account ID from STS (best-effort)."""
    try:
        session = _make_session(profile, region)
        return session.client("sts").get_caller_identity()["Account"]
    except Exception:
        return ""


def debug_incident_agent(
    symptom:   str,
    profile:   str | None,
    region:    str = "us-east-1",
    minutes:   int = 10,
    max_turns: int = 12,
) -> tuple[str, dict]:
    """Agentic debug: Claude drives its own AWS investigation via Bedrock tool use.

    Returns (result_json, all_fetched) so callers can pass fetched data to the
    live learner for hallucination detection and pattern extraction.
    """
    import hashlib as _hashlib
    import re as _re
    from cloudctl.ai.harness    import build_system_prompt
    from cloudctl.ai.guardrails import (
        validate_query, sanitise_fetched_data, redact_output,
        validate_tool_call, enforce_confidence, check_rate_limit,
        detect_hallucinations, verify_cited_values,
        audit_log_agent_call, audit_log_tool_call, new_session_id,
    )
    from cloudctl.ai.live_learner import get_investigation_hints

    # Guardrail 1 — rate limit
    rate_check = check_rate_limit()
    if not rate_check.allowed:
        return json.dumps({"error": rate_check.reason}), {}

    # Guardrail 2 — input validation
    query_check = validate_query(symptom)
    if not query_check.allowed:
        return json.dumps({"error": query_check.reason}), {}
    symptom = query_check.sanitised

    # Build 4-layer system prompt
    account_id = _get_account_id(profile, region)
    system_prompt = build_system_prompt(account_id=account_id or None)

    import time as _time
    from botocore.config import Config as _BotoConfig

    session = _make_session(profile, region)
    bedrock = session.client(
        "bedrock-runtime",
        region_name=region,
        config=_BotoConfig(retries={"mode": "adaptive", "max_attempts": 10}),
    )

    # Audit: open session (SOC2 CC6 — log query by hash only, never raw)
    session_id = new_session_id()
    query_hash = _hashlib.sha256(symptom.encode()).hexdigest()[:16]
    audit_log_agent_call(
        session_id=session_id, event="start",
        account_id=account_id, region=region, query_hash=query_hash,
    )

    # Collect all fetched data for hallucination detection and live learning.
    # Cap at 2 MB to prevent unbounded memory growth across 12 turns.
    all_fetched: dict = {}
    _ALL_FETCHED_MAX_BYTES = 2 * 1024 * 1024

    def _dispatch(tool_name: str, tool_input: dict) -> str:
        # Guardrail 4 — scope enforcement on every tool call
        if tool_name == "query_metrics":
            _ns  = tool_input.get("namespace", "")
            _met = tool_input.get("metric_name", "")
            resource_name = f"{_ns}/{_met}" if _ns or _met else "metric"
        elif tool_name == "get_deployment_info":
            resource_name = tool_input.get("resource_name", "")
        else:
            resource_name = tool_input.get("resource_name") or tool_input.get("service_type", "")
        tool_check = validate_tool_call(
            tool_name, tool_input,
            allowed_profile=profile,
            allowed_region=region,
        )
        audit_log_tool_call(
            session_id=session_id, tool_name=tool_name,
            resource_name=resource_name, allowed=tool_check.allowed,
            block_reason="" if tool_check.allowed else tool_check.reason,
        )
        if not tool_check.allowed:
            return json.dumps({"error": tool_check.reason})

        if tool_name == "list_resources":
            raw = list_resources(tool_input["service_type"], profile, region)
        elif tool_name == "get_service_config":
            raw = get_service_config(
                tool_input["service_type"], tool_input["resource_name"], profile, region
            )
        elif tool_name == "tail_logs":
            raw = tail_logs(
                resource_hint=tool_input["resource_hint"],
                minutes=minutes,
                profile=profile,
                region=region,
                max_events=100,
            )
        elif tool_name == "get_event_timeline":
            raw = get_event_timeline(tool_input["symptom"], profile, region, minutes)
        elif tool_name == "query_metrics":
            raw = query_metrics(
                namespace   = tool_input["namespace"],
                metric_name = tool_input["metric_name"],
                dimensions  = tool_input.get("dimensions") or {},
                profile     = profile,
                region      = region,
                minutes     = int(tool_input.get("minutes") or 30),
                stat        = tool_input.get("stat") or "Average",
            )
        elif tool_name == "get_deployment_info":
            raw = get_deployment_info(
                resource_name = tool_input["resource_name"],
                service_type  = tool_input["service_type"],
                profile       = profile,
                region        = region,
            )
        else:
            return json.dumps({"error": f"unknown tool: {tool_name}"})

        # Guardrail 2 — sanitise fetched data (redact secrets/PII, neutralise injection)
        try:
            parsed = json.loads(raw)
            sanitised = sanitise_fetched_data(parsed) if isinstance(parsed, dict) else parsed
            key = f"{tool_name}:{resource_name}"
            # Data minimisation: only store if under the cumulative size cap
            current_size = len(json.dumps(all_fetched, default=str))
            entry_size   = len(json.dumps(sanitised, default=str))
            if current_size + entry_size <= _ALL_FETCHED_MAX_BYTES:
                all_fetched[key] = sanitised
            raw = json.dumps(sanitised, default=str)
        except Exception:
            # Sanitisation failed — return an error rather than passing unsanitised data to the model
            raw = json.dumps({"error": "data fetched but could not be safely sanitised"})

        return _truncate_tool_output(raw, tool_name)

    # Prepend any investigation hints from confirmed past patterns
    hints = get_investigation_hints(symptom)
    user_content = f"Investigate this incident: {symptom}"
    if hints:
        user_content += "\n\nHINTS FROM PAST INCIDENTS IN THIS ACCOUNT:\n" + "\n".join(hints)

    messages: list[dict] = [{"role": "user", "content": [{"text": user_content}]}]
    turns_used = 0

    for _ in range(max_turns):
        turns_used += 1
        # Adaptive retries (mode="adaptive") handle most throttling, but if
        # all retries are exhausted we surface a clean error rather than crashing.
        try:
            resp = bedrock.converse(
                modelId="us.anthropic.claude-sonnet-4-6",
                system=[{"text": system_prompt}],
                messages=messages,
                toolConfig={"tools": _AGENT_TOOLS},
            )
        except bedrock.exceptions.ThrottlingException:
            # Last-resort: wait 30 s and retry once before giving up
            _time.sleep(30)
            try:
                resp = bedrock.converse(
                    modelId="us.anthropic.claude-sonnet-4-6",
                    system=[{"text": system_prompt}],
                    messages=messages,
                    toolConfig={"tools": _AGENT_TOOLS},
                )
            except Exception:
                return json.dumps({"error": "Bedrock rate limit exceeded — try again in a few minutes"}), all_fetched
        stop_reason = resp["stopReason"]
        msg         = resp["output"]["message"]
        messages.append(msg)

        if stop_reason == "end_turn":
            for block in msg.get("content", []):
                if "text" in block:
                    text = block["text"].strip()

                    # Extract JSON from response — try three forms in order:
                    # 1. Fenced code block: ```json { ... } ```
                    # 2. Bare JSON object anywhere in the text: { ... }
                    # 3. The whole text as-is (direct JSON response)
                    candidate = text
                    m = _re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, _re.DOTALL)
                    if m:
                        candidate = m.group(1)
                    else:
                        m2 = _re.search(r'\{.*"root_cause".*\}', text, _re.DOTALL)
                        if m2:
                            candidate = m2.group(0)

                    try:
                        parsed = json.loads(candidate)
                    except Exception:
                        parsed = {
                            "root_cause":            text,
                            "evidence":              [],
                            "remediation_steps":     [],
                            "severity":              "UNKNOWN",
                            "confidence":            "LOW",
                            "resources_investigated": [],
                        }

                    # Guardrail 5 — confidence enforcement
                    hal_report = detect_hallucinations(parsed, all_fetched)
                    parsed     = enforce_confidence(parsed, all_fetched, hal_report)

                    # Verification turn: every numeric/quoted claim must trace
                    # to fetched data. Unverified items are surfaced separately
                    # and force confidence to LOW — wrong facts are worse than
                    # admitted uncertainty.
                    verified, unverified = verify_cited_values(parsed, all_fetched)
                    if unverified:
                        parsed["unverified_claims"] = unverified
                        parsed["evidence"]          = verified
                        parsed["confidence"]        = "LOW"
                        parsed["confidence_override_reason"] = (
                            f"{len(unverified)} evidence item(s) cited values "
                            "not present in fetched data"
                        )

                    # Guardrail 3 — output redaction
                    parsed = redact_output(parsed)

                    # Attach guardrail metadata for harness scoring
                    parsed["_guardrails"] = {
                        "hallucination_rate":    hal_report.hallucination_rate,
                        "hallucination_verdict": hal_report.verdict,
                        "unsupported_claims":    hal_report.unsupported[:3],
                        "unverified_count":      len(unverified),
                        "confidence_overridden": "confidence_override_reason" in parsed,
                        "turns_used":            turns_used,
                        "account_id":            account_id,
                    }

                    audit_log_agent_call(
                        session_id=session_id, event="end",
                        account_id=account_id, region=region,
                        query_hash=query_hash, turns_used=turns_used,
                        confidence=parsed.get("confidence", ""),
                    )
                    return json.dumps(parsed, indent=2), all_fetched
            break

        if stop_reason == "tool_use":
            tool_results = []
            for block in msg.get("content", []):
                if "toolUse" in block:
                    tu = block["toolUse"]
                    result_str = _dispatch(tu["name"], tu["input"])
                    tool_results.append({
                        "toolResult": {
                            "toolUseId": tu["toolUseId"],
                            "content":   [{"text": result_str}],
                        }
                    })
            if tool_results:
                messages.append({"role": "user", "content": tool_results})

    audit_log_agent_call(
        session_id=session_id, event="end",
        account_id=account_id, region=region,
        query_hash=query_hash, turns_used=turns_used,
        confidence="",
    )
    return json.dumps({"error": "max_turns reached", "turns": max_turns}, indent=2), all_fetched

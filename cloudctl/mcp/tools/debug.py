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
    "lambda":          ("lambda_function_config",    "resource_name"),
    "rds":             ("rds_instance_config",       "resource_name"),
    "aurora":          ("aurora_cluster_config",     "resource_name"),
    "redshift":        ("redshift_cluster_config",   "resource_name"),
    "glue":            ("glue_job_config",           "resource_name"),
    "api_gateway":     ("api_gateway_config",        "resource_name"),
    "dynamodb":        ("dynamodb_table_config",     "resource_name"),
    "s3":              ("s3_bucket_config",          "resource_name"),
    "secrets_manager": ("secrets_manager_config",    "resource_name"),
    "sns":             ("sns_topic_config",          "resource_name"),
    "sqs":             ("sqs_queue_config",          "resource_name"),
    "elasticache":     ("elasticache_config",        "resource_name"),
    "kinesis":         ("kinesis_stream_config",     "resource_name"),
    "eks":             ("eks_cluster_config",        "resource_name"),
    "stepfunctions":   ("stepfunctions_config",      "resource_name"),
    "opensearch":      ("opensearch_config",         "resource_name"),
    "eventbridge":     ("eventbridge_rule_config",   "resource_name"),
    "cloudfront":      ("cloudfront_config",         "resource_name"),
    "alb":             ("alb_config",                "resource_name"),
    "ssm":             ("ssm_parameter_config",      "resource_name"),
    "acm":             ("acm_certificate_config",    "resource_name"),
    "msk":             ("msk_cluster_config",        "resource_name"),
    "ecr":             ("ecr_repository_config",     "resource_name"),
    "route53":         ("route53_zone_config",       "resource_name"),
    "codepipeline":    ("codepipeline_config",       "resource_name"),
    "efs":             ("efs_filesystem_config",     "resource_name"),
    "batch":           ("batch_config",              "resource_name"),
    "cognito":         ("cognito_user_pool_config",  "resource_name"),
    "iam":             ("iam_role_config",           "resource_name"),
    "waf":             ("waf_web_acl_config",        "resource_name"),
    "appsync":         ("appsync_api_config",        "resource_name"),
    "athena":          ("athena_workgroup_config",   "resource_name"),
    "firehose":        ("firehose_delivery_config",  "resource_name"),
    "dms":             ("dms_replication_config",    "resource_name"),
    # ── AI / ML ───────────────────────────────────────────────────────────────
    "sagemaker":       ("sagemaker_endpoint_config", "resource_name"),
    "bedrock_agent":   ("bedrock_agent_config",      "resource_name"),
    "bedrock_kb":      ("bedrock_kb_config",         "resource_name"),
    "agentcore":       ("agentcore_config",          "resource_name"),
}


_VALID_PROFILE_RE = re.compile(r'^[a-zA-Z0-9._\-]+$')
_VALID_REGION_RE  = re.compile(
    r'^(us|eu|ap|sa|ca|me|af|il|mx|ap)-(?:gov-)?[a-z]+-\d+$|^cn-[a-z]+-\d+$'
)


from cloudctl.mcp.tools.recorder import recordable, recorded  # noqa: E402


# Bounded timeouts + capped retries for EVERY tool-plane AWS read. A single
# boto call with no read timeout once stalled an investigation for 40 minutes
# (2026-07-04) — no read may block the agent indefinitely. Applied centrally so
# all ~40 client() call sites inherit it; a caller may still override per client.
def _tool_boto_config():
    from botocore.config import Config as _BotoConfig
    return _BotoConfig(
        connect_timeout=8,
        read_timeout=30,
        retries={"max_attempts": 3, "mode": "adaptive"},
    )


import boto3 as _boto3  # noqa: E402


class _BoundedSession(_boto3.Session):
    """boto3 Session whose every client carries bounded timeouts + capped
    retries, so no tool-plane AWS read can hang the investigation. Defined once
    at module scope (not per _make_session call); the default config is built
    once and merged under any caller-supplied config (caller wins on overlap)."""
    _DEFAULT_CFG = None

    def client(self, *args, **kwargs):
        if _BoundedSession._DEFAULT_CFG is None:
            _BoundedSession._DEFAULT_CFG = _tool_boto_config()
        cfg = kwargs.get("config")
        base = _BoundedSession._DEFAULT_CFG
        kwargs["config"] = base.merge(cfg) if cfg is not None else base
        return super().client(*args, **kwargs)


def _make_session(profile: str | None, region: str):
    """Fresh boto3 Session each call — keeps SSO tokens current. Returns a
    _BoundedSession so every client it hands out is timeout-bounded."""
    if profile and not _VALID_PROFILE_RE.match(profile):
        raise ValueError("Invalid AWS profile name")
    if region and not _VALID_REGION_RE.match(region):
        raise ValueError(f"Invalid AWS region: {region}")
    return _BoundedSession(profile_name=profile, region_name=region) if profile \
        else _BoundedSession(region_name=region)


def _serialise(obj) -> object:
    import datetime
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        # botocore returns some fields (e.g. WAF search_string) as raw bytes.
        # json.dumps can't serialise bytes and would crash the whole tool call,
        # so decode to text, or a safe placeholder for non-text blobs.
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return f"<{len(obj)} bytes, not UTF-8>"
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
    }), separators=(",", ":"))


@recordable("query_metrics")
def query_metrics(
    namespace:   str,
    metric_name: str,
    dimensions:  dict,
    profile:     str | None,
    region:      str,
    minutes:     int = 30,
    stat:        str = "Average",
    baseline_offset_hours: int = 0,
) -> str:
    """Generic CloudWatch metric query. The agent supplies namespace/metric/dims;
    we never pre-choose for it. Returns time-aligned datapoints summarised as
    first/last/delta/min/max/avg over the window.

    baseline_offset_hours > 0 additionally fetches the SAME window shifted that
    many hours earlier and reports both, so "is this value anomalous?" becomes
    arithmetic against the system's own history instead of a guess."""
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

        def _v(p):
            if extended:
                return p.get("ExtendedStatistics", {}).get(extended, 0)
            return p.get(stat_param or "Average", 0)

        def _window(end: "_dt.datetime") -> dict | None:
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
                return None
            values = [_v(p) for p in pts]
            # Downsample a timestamped series (≤24 points) so a STEP-CHANGE and
            # its ONSET time are visible — aggregates alone hide when a metric
            # moved, yet the temporal rules downstream need onset. Bounded size.
            step = max(1, len(pts) // 24)
            series = [
                {"t": p["Timestamp"].isoformat(), "v": _v(p)}
                for p in pts[::step]
            ][:24]
            return {
                "unit":       pts[0].get("Unit", ""),
                "datapoints": len(pts),
                "first":      values[0],
                "last":       values[-1],
                "delta":      values[-1] - values[0],
                "min":        min(values),
                "max":        max(values),
                "avg":        sum(values) / len(values),
                "first_time": pts[0]["Timestamp"].isoformat(),
                "last_time":  pts[-1]["Timestamp"].isoformat(),
                "series":     series,
            }

        now = _dt.datetime.now(_dt.timezone.utc)
        current = _window(now)
        if current is None:
            return json.dumps({
                "namespace": namespace, "metric_name": metric_name,
                "dimensions": dimensions, "minutes": minutes, "stat": stat,
                "datapoints": 0,
                "note": "No data in the requested window — metric or dimensions may be wrong, or the resource has no recent traffic.",
            }, separators=(",", ":"))

        out = {
            "namespace":   namespace,
            "metric_name": metric_name,
            "dimensions":  dimensions,
            "minutes":     minutes,
            "stat":        stat,
            **current,
        }
        offset = max(0, min(int(baseline_offset_hours or 0), 24 * 14))
        if offset:
            baseline = _window(now - _dt.timedelta(hours=offset))
            out["baseline_offset_hours"] = offset
            if baseline is None:
                out["baseline"] = "no data in baseline window"
            else:
                out["baseline"] = baseline
                if isinstance(baseline.get("avg"), (int, float)):
                    out["avg_vs_baseline_delta"] = current["avg"] - baseline["avg"]
        return json.dumps(out, separators=(",", ":"))
    except Exception as exc:  # noqa: BLE001
        # Surface the AWS error CODE (AccessDenied vs ValidationError vs
        # throttling), not just the Python exception type — the model cannot tell
        # "no permission" from "wrong dimensions" from a bare "ClientError".
        code = ""
        try:
            code = exc.response["Error"]["Code"]  # botocore ClientError
        except Exception:  # noqa: BLE001
            code = type(exc).__name__
        return json.dumps({
            "error": f"query_metrics failed: {code}",
            "detail": str(exc)[:200],
        })


@recordable("get_service_config")
def get_service_config(
    service_type: str,
    resource_hint: str,
    profile: str | None,
    region: str,
) -> str:
    from cloudctl.debug.fetcher import DebugFetcher

    session     = _make_session(profile, region)
    fetcher     = DebugFetcher(session)

    if service_type not in _SERVICE_FETCHERS:
        try:
            cfg = fetcher.generic_resource_config(service_type=service_type, resource_name=resource_hint)
        except Exception as exc:  # noqa: BLE001
            cfg = {}
            log.warning("get_service_config (generic) %s: %s", service_type, type(exc).__name__)
        if not cfg:
            return json.dumps({
                "found":       False,
                "service_type": service_type,
                "hint":        resource_hint,
                "tip":         f"No {service_type} resource matched '{resource_hint}' via generic fetcher, "
                               f"and it is not in the list of recognized optimized services. "
                               f"Use cloudctl_list_resources to see available names.",
                "available":   [],
            }, separators=(",", ":"))
        return json.dumps({"found": True, "service_type": service_type,
                           "config": _serialise(cfg)}, separators=(",", ":"))

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
        }, separators=(",", ":"))

    return json.dumps({"found": True, "service_type": service_type,
                       "config": _serialise(cfg)}, separators=(",", ":"))


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


def _list_efs(s) -> list[str]:
    efs = s.client("efs")
    return [fs["FileSystemId"] for fs in efs.describe_file_systems().get("FileSystems", [])]

def _list_batch(s) -> list[str]:
    batch = s.client("batch")
    envs = [e["computeEnvironmentName"] for e in batch.describe_compute_environments().get("computeEnvironments", [])]
    queues = [q["jobQueueName"] for q in batch.describe_job_queues().get("jobQueues", [])]
    jds = [j["jobDefinitionName"] for j in batch.describe_job_definitions(status="ACTIVE").get("jobDefinitions", [])]
    return envs + queues + jds


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
    "efs":             _list_efs,
    "batch":           _list_batch,
    # ── AI / ML ───────────────────────────────────────────────────────────────
    "sagemaker":       _list_sagemaker,
    "bedrock_agent":   _list_bedrock_agent,
    "bedrock_kb":      _list_bedrock_kb,
    "agentcore":       _list_agentcore,
}


def _list_resources_for_type(fetcher, service_type: str) -> list[str]:
    """Return a flat list of resource names for a service type."""
    fn = _SERVICE_LISTERS.get(service_type)
    if not fn:
        if not fetcher._session:
            return []
        try:
            tagger = fetcher._session.client("resourcegroupstaggingapi")
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
            resources = []
            paginator = tagger.get_paginator("get_resources")
            for page in paginator.paginate(ResourceTypeFilters=[tag_filter]):
                for item in page.get("ResourceTagMappingList", []):
                    arn = item.get("ResourceARN")
                    if arn:
                        resources.append(arn)
            return resources
        except Exception as exc:  # noqa: BLE001
            log.warning("list_resources tagging fallback for %s: %s", service_type, type(exc).__name__)
            return []
    if not fetcher._session:
        return []
    try:
        return fn(fetcher._session)
    except Exception:  # noqa: BLE001
        return []


def _enumerate_resources(session, max_total: int = 500) -> list[dict]:
    """Enumerate deployed resources account-wide, GENERICALLY — no curated
    service list. Same pattern get_dependency_graph uses:
      (a) AWS Resource Explorer — one query returns resources across ALL types
          (needs an index; skipped gracefully if none is configured).
      (b) Resource Groups Tagging API — every taggable resource in the region.
    Bounded (hard page/total caps) so it cannot hang. Returns
    [{"arn","service","name"}, ...] deduplicated on (service, name)."""
    resources: list[dict] = []
    seen: set = set()

    def _parse_arn(arn: str):
        parts = arn.split(":", 5)
        if len(parts) < 6:
            return None
        ns, rest = parts[2], parts[5]
        name = rest.split("/")[-1] if "/" in rest else rest.split(":")[-1]
        return ns, name

    def _add(arn: str, ns: str, name: str) -> None:
        if not name:
            return
        key = (ns, name)
        if key in seen:
            return
        seen.add(key)
        resources.append({"arn": arn, "service": ns, "name": name})

    # (a) Resource Explorer (bounded pagination)
    try:
        rex = session.client("resource-explorer-2")
        token = None
        for _ in range(10):
            kw = {"QueryString": "*", "MaxResults": 100}
            if token:
                kw["NextToken"] = token
            resp = rex.search(**kw)
            for r in resp.get("Resources", []):
                pa = _parse_arn(r.get("Arn", ""))
                if pa:
                    _add(r["Arn"], *pa)
            token = resp.get("NextToken")
            if not token or len(resources) >= max_total:
                break
    except Exception:  # noqa: BLE001
        pass   # no index / not enabled — fall back to tagging

    # (b) Resource Groups Tagging API (bounded)
    try:
        tagging = session.client("resourcegroupstaggingapi")
        paginator = tagging.get_paginator("get_resources")
        for page in paginator.paginate(PaginationConfig={"MaxItems": max_total}):
            for r in page.get("ResourceTagMappingList", []):
                pa = _parse_arn(r.get("ResourceARN", ""))
                if pa:
                    _add(r["ResourceARN"], *pa)
            if len(resources) >= max_total:
                break
    except Exception:  # noqa: BLE001
        pass

    return resources


@recordable("list_resources")
def list_resources(
    service_type: str = "",
    profile: str | None = None,
    region: str = "us-east-1",
) -> str:
    """Discover resource names GENERICALLY (Resource Explorer → Tagging API).

    service_type, if given, is used only as a FILTER over the generic results
    (matched against the resource's service namespace or name) — NOT as a router
    to a per-service lister, so discovery is never bounded by a maintained list.
    """
    session = _make_session(profile, region)
    resources = _enumerate_resources(session)

    filt = (service_type or "").strip().lower()
    if filt:
        matched = [
            r for r in resources
            if filt in r["service"].lower() or filt in r["name"].lower()
        ]
    else:
        matched = resources

    # Resource NAMES are what get_service_config / aws_read consume; include a
    # detailed view (service + arn) for disambiguation without breaking the
    # names contract.
    names = [r["name"] for r in matched]
    detailed = [
        {"service": r["service"], "name": r["name"], "arn": r["arn"]}
        for r in matched
    ]

    out = {
        "service_type":       service_type,
        "region":             region,
        "count":              len(names),
        "resources":          names,
        "resources_detailed": detailed,
    }
    if not resources:
        # Never a silent empty — say WHY discovery found nothing so the model
        # (and a human) can tell "no resources" from "enumeration failed".
        out["note"] = (
            "no resources discovered — AWS Resource Explorer has no index in this "
            "region and the Resource Groups Tagging API returned nothing (only "
            "tagged resources are visible to it). Use aws_read with a service's "
            "own list/describe API to enumerate a specific service directly."
        )
    elif filt and not matched:
        out["note"] = (
            f"{len(resources)} resources discovered but none matched filter "
            f"'{service_type}'. Retry without a filter to see everything, or use a "
            f"different service namespace."
        )
    return json.dumps(out, separators=(",", ":"))


_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# hex-looking ids ≥6 chars: require at least one letter so plain words and
# numbers are untouched but short trace ids / shas ("deadbeef", "0000000a")
# still normalize into the same template
_HEX_RE  = re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{6,}\b")
_NUM_RE  = re.compile(r"\b\d+(?:\.\d+)?\b")


def _mine_log_templates(events: list[dict], top: int = 12) -> list[dict]:
    """Cluster log lines into structural templates and count occurrences.

    Purely mechanical: variable parts (uuids, hex ids, numbers) are replaced
    with placeholders so identical line SHAPES group together. Frequency is
    the signal — one template appearing thousands of times while others appear
    a handful is a fact the raw line sample can miss entirely. No thresholds,
    no interpretation: counts only, the model does the reasoning.
    """
    from collections import Counter
    counts: Counter = Counter()
    example: dict[str, str] = {}
    for evt in events:
        msg = str(evt.get("event", ""))[:400]
        t = _UUID_RE.sub("<v>", msg)
        t = _HEX_RE.sub("<v>", t)
        t = _NUM_RE.sub("<v>", t)
        t = t[:200]
        counts[t] += 1
        example.setdefault(t, msg[:200])
    return [
        {"template": t, "count": c, "example": example[t]}
        for t, c in counts.most_common(top)
    ]


def _parse_log_events(events: list[dict]) -> dict:
    """Extract structured fields from log events for the AI log intelligence node.

    Parses JSON and key=value log messages into dicts. Returns counts and a
    sample of parsed rows so the log_intelligence_node can analyze them.
    No heuristics, no thresholds — pure extraction. The AI does the reasoning.
    """
    _KV_RE = re.compile(r'(\w+)=(\S+)')
    parsed: list[dict] = []
    for evt in events:
        msg = evt.get("event", "")
        try:
            data = json.loads(msg)
            if isinstance(data, dict):
                parsed.append(data)
                continue
        except (json.JSONDecodeError, ValueError):
            pass
        kv = dict(_KV_RE.findall(msg))
        if kv:
            parsed.append(kv)
    return {"parsed_count": len(parsed), "sample": parsed[:10]} if parsed else {}


@recordable("tail_logs")
def tail_logs(
    resource_hint: str,
    minutes: int,
    profile: str | None,
    region: str,
    max_events: int,
    filter_pattern: str = "",
) -> str:
    from cloudctl.debug.fetcher import DebugFetcher

    session = _make_session(profile, region)
    fetcher = DebugFetcher(session)

    # Groups that matched and returned events
    discovered: list[str] = []
    # Groups we know EXIST (even if the windowed/filtered fetch was empty) — used
    # for the retry-without-filter and last-resort tail below.
    existing:   list[str] = []
    # Fetch more events than we'll show so analytics has better signal
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
            evts = fetcher.cloudwatch_logs(
                log_group=lg, minutes=minutes,
                filter_pattern=filter_pattern, max_events=max_events,
            )
            if evts:
                logs.extend(evts)
                discovered.append(lg)
                existing.append(lg)
                break
        except Exception:  # noqa: BLE001
            pass

    # Fall back to discover_log_groups
    if not logs:
        try:
            groups = fetcher.discover_log_groups(resource_hint)
            existing.extend(groups[:5])
            for grp in groups[:5]:
                evts = fetcher.cloudwatch_logs(
                    log_group=grp, minutes=minutes,
                    filter_pattern=filter_pattern, max_events=max_events,
                )
                if evts:
                    logs.extend(evts)
                    discovered.append(grp)
        except Exception:  # noqa: BLE001
            pass

    # A filter that matched nothing must NOT be reported as "no logs": a stack
    # trace or structured JSON log rarely contains the literal filter word. Retry
    # the known groups WITHOUT the filter before concluding the logs are clean.
    if not logs and filter_pattern and existing:
        for grp in list(dict.fromkeys(existing))[:3]:
            try:
                evts = fetcher.cloudwatch_logs(
                    log_group=grp, minutes=minutes, max_events=max_events,
                )
                if evts:
                    logs.extend(evts)
                    discovered.append(grp)
            except Exception:  # noqa: BLE001
                pass

    # Last resort: tail the most recent stream directly (catches groups whose
    # events fall just outside the window). Reachable now via `existing`, which
    # is populated even when the windowed/filtered fetch returned nothing.
    if not logs and existing:
        for grp in list(dict.fromkeys(existing))[:2]:
            try:
                evts = fetcher.tail_log_group(grp)
                if evts:
                    logs.extend(evts)
                    discovered.append(grp)
            except Exception:  # noqa: BLE001
                pass

    return json.dumps({
        "resource_hint":    resource_hint,
        "minutes":          minutes,
        "filter_pattern":   filter_pattern,
        "event_count":      len(logs[:max_events]),
        "total_fetched":    len(logs),
        "log_groups_found": list(dict.fromkeys(discovered)),
        # Frequency view over ALL fetched lines (not just the shown sample) —
        # a template's count is a fact the line sample can miss.
        "log_templates":    _mine_log_templates(logs),
        "events":           _serialise(logs[:max_events]),
    }, separators=(",", ":"))


@recordable("get_event_timeline")
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
    }, separators=(",", ":"))


@recordable("search_cloudtrail")
def search_cloudtrail(
    resource_name: str,
    profile:       str | None,
    region:        str,
    event_names:   list[str] | None = None,
    minutes:       int = 1440,
) -> str:
    """Search CloudTrail for all events touching a specific resource.

    Returns events newest-first with: time, event_name, actor, error_code,
    and request parameters. Use this to find what changed (deletion, policy
    detachment, config modification) before failures started.
    """
    from cloudctl.debug.fetcher import DebugFetcher  # noqa: PLC0415
    session = _make_session(profile, region)
    fetcher = DebugFetcher(session)
    events  = fetcher.search_cloudtrail_events(
        resource_name=resource_name,
        event_names=event_names,
        minutes=minutes,
    )
    return json.dumps({
        "resource_name": resource_name,
        "minutes":       minutes,
        "event_count":   len(events),
        "events":        _serialise(events),
    }, separators=(",", ":"))


@recordable("get_prior_config")
def get_prior_config(
    resource_name: str,
    service_type:  str,
    profile:       str | None,
    region:        str,
    minutes:       int = 10080,
) -> str:
    """TEMPORAL baseline: what did this resource's config look like BEFORE?

    Real retained version history where AWS keeps it, plus a CloudTrail
    reconstruction (config-writing events' request parameters carry the values
    that were written), returned as structured before→after diffs. Raw facts
    only — never judges which value is correct. Read-only; degrades to a
    structured 'unavailable' result on denial/absence."""
    from cloudctl.debug.baseline import prior_config  # noqa: PLC0415
    try:
        session = _make_session(profile, region)
        result = prior_config(session, resource_name, service_type,
                              minutes=int(minutes or 10080))
    except Exception as exc:  # noqa: BLE001
        result = {
            "resource_name": resource_name,
            "baseline_unavailable": True,
            "error": type(exc).__name__,   # marks transient failure: not cached
            "reason": f"baseline unavailable ({type(exc).__name__})",
        }
    return json.dumps(_serialise(result), separators=(",", ":"))


@recordable("compare_peers")
def compare_peers(
    resource_name: str,
    service_type:  str,
    profile:       str | None,
    region:        str,
    peer_names:    list | None = None,
    configs:       dict | None = None,
) -> str:
    """PEER baseline: which config fields differ between a resource and its
    sibling resources of the same type. Raw differences only; identity-only
    differences are suppressed-but-listed. Read-only; degrades to a structured
    'unavailable' result when there is nothing to compare."""
    from cloudctl.debug.baseline import peer_comparison  # noqa: PLC0415
    try:
        session = _make_session(profile, region)
        result = peer_comparison(session, resource_name, service_type,
                                 peer_names=peer_names, configs=configs)
    except Exception as exc:  # noqa: BLE001
        result = {
            "resource_name": resource_name,
            "peers_unavailable": True,
            "error": type(exc).__name__,   # marks transient failure: not cached
            "reason": f"peer baseline unavailable ({type(exc).__name__})",
        }
    return json.dumps(_serialise(result), separators=(",", ":"))


@recordable("get_traces")
def get_traces(
    profile:           str | None,
    region:            str,
    minutes:           int = 60,
    resource_hint:     str | None = None,
    filter_expression: str | None = None,
) -> str:
    """Fuse AWS X-Ray distributed traces into a compact structured signal.

    Returns the service-dependency graph with per-edge latency/error/fault/
    throttle rates (WHERE faults concentrate in the call graph) plus the top
    slowest and top fault-bearing traces, each fault trace localized to the
    specific segment (service + operation) carrying it. NO raw segment docs.

    Graceful by design: most accounts have no X-Ray. When tracing is not
    enabled, no traces fall in-window, or permission is denied, this returns a
    clear structured "no trace data available" result — never an exception — so
    incidents without tracing are completely unaffected.
    """
    from cloudctl.debug.fetcher import DebugFetcher  # noqa: PLC0415
    try:
        session = _make_session(profile, region)
        fetcher = DebugFetcher(session)
        result  = fetcher.xray_traces(
            minutes=int(minutes or 60),
            resource_hint=resource_hint or None,
            filter_expression=filter_expression or None,
        )
    except Exception as exc:  # noqa: BLE001
        # Any unexpected failure degrades to the same informative signal — a
        # trace lookup must never derail an investigation.
        result = {
            "available": False,
            "reason": f"no trace data available ({type(exc).__name__})",
            "window_minutes": int(minutes or 60),
            "service_graph_summary": [],
            "top_slow_traces": [],
            "top_fault_traces": [],
        }
    return json.dumps(_serialise(result), separators=(",", ":"))


@recordable("get_deployment_info")
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
    }, separators=(",", ":"))


# ── Agent mode ────────────────────────────────────────────────────────────────

@recordable("probe_permission")
def probe_permission(
    role:            str,
    action:          str,
    resource_arn:    str,
    profile:         str | None,
    region:          str,
    resource_policy: str = "",
) -> str:
    """Deterministically test whether an IAM role can perform an action.

    Uses the IAM policy simulator — no traffic, no logs needed. Turns a
    permission hypothesis from an inference into a measurement. Pass
    resource_policy (the target's resource-based policy document, fetched with
    aws_read) to evaluate identity and resource layers together — this catches
    an identity-Allow overridden by a resource-side Deny, or vice versa. The
    tool never decides which policy to fetch; the caller supplies it.
    """
    session = _make_session(profile, region)
    iam = session.client("iam")
    try:
        role_arn = role
        if not role.startswith("arn:"):
            role_arn = iam.get_role(RoleName=role.split("/")[-1])["Role"]["Arn"]
        kwargs: dict = {"PolicySourceArn": role_arn, "ActionNames": [action]}
        if resource_arn:
            kwargs["ResourceArns"] = [resource_arn]
        resource_policy = (resource_policy or "").strip()
        if resource_policy:
            # Evaluate both layers together; CallerArn anchors the principal.
            kwargs["ResourcePolicy"] = resource_policy
            kwargs["CallerArn"] = role_arn
        try:
            results = iam.simulate_principal_policy(**kwargs).get("EvaluationResults", [])
        except Exception:  # noqa: BLE001
            # Resource policy rejected by the simulator (malformed/unsupported)
            # — fall back to identity-only rather than failing the probe.
            kwargs.pop("ResourcePolicy", None); kwargs.pop("CallerArn", None)
            resource_policy = ""
            results = iam.simulate_principal_policy(**kwargs).get("EvaluationResults", [])
        evaluated = [
            {
                "action":   r.get("EvalActionName"),
                "resource": r.get("EvalResourceName"),
                "decision": r.get("EvalDecision"),   # allowed | explicitDeny | implicitDeny
                "matched_statements": [
                    {
                        "policy": m.get("SourcePolicyId"),
                        "type":   m.get("SourcePolicyType"),
                    }
                    for m in r.get("MatchedStatements", [])
                ],
            }
            for r in results
        ]
        layers = ("identity + resource-based policy"
                  if resource_policy else "identity-based policy only")
        note = (
            f"decision evaluates {layers}. "
            + ("SCPs/permission boundaries are still not simulated."
               if resource_policy else
               "resource-based policies and SCPs are NOT simulated here (no "
               "resource ARN given or none attached) — an 'allowed' result can "
               "still be denied by those layers.")
        )
        return json.dumps({
            "role_arn":  role_arn,
            "resource_policy_evaluated": bool(resource_policy),
            "results":   evaluated,
            "note":      note,
        }, separators=(",", ":"))
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"[:400]})


_ARN_RE = re.compile(r"arn:aws[a-z0-9-]*:([a-z0-9-]+):[^:]*:[^:]*:([^\s\"',]+)")


# ── Universal read plane ──────────────────────────────────────────────────────
# The model knows every AWS service's APIs; hand-written fetchers will never
# keep up and their selection inevitably mirrors whatever we test. aws_read
# lets the model compose its own deep, service-specific analysis for ANY
# service — safety enforced deterministically in code, not by prompt.

_READ_VERBS = re.compile(
    r"^(describe_|get_|list_|search_|lookup_|head_|batch_get_|simulate_|preview_|scan$)"
)
_MUTATION_HINTS = (
    "delete", "create", "update", "put_", "modify", "terminate", "stop_",
    "start_", "reboot", "invoke", "send_", "publish", "execute", "run_",
    "cancel", "attach", "detach", "associate", "disassociate", "tag_",
    "untag", "import_", "restore", "reset_", "enable_", "disable_",
    "grant", "revoke", "assume", "register", "deregister", "purge",
    "accept", "reject", "release", "allocate", "copy_", "move_",
)
_SAFE_NAME_RE = re.compile(r"^[a-z0-9-]+$")


@recordable("aws_read")
def aws_read(
    service:   str,
    operation: str,
    params:    dict,
    profile:   str | None,
    region:    str,
) -> str:
    """Call any read-only AWS API operation. The model plans the calls; this
    layer only enforces that they cannot mutate anything."""
    from botocore import xform_name
    from cloudctl.ai.guardrails import sanitise_fetched_data

    if not _SAFE_NAME_RE.match(service or ""):
        return json.dumps({"error": f"invalid service name: {service!r}"})
    op_snake = operation if "_" in operation else xform_name(operation)
    op_snake = op_snake.lower()
    if not _READ_VERBS.match(op_snake) or any(h in op_snake for h in _MUTATION_HINTS):
        return json.dumps({
            "error": f"operation '{operation}' is not allowed — aws_read permits "
                     f"read-only verbs only (describe/get/list/search/lookup/"
                     f"head/batch_get/simulate/preview)."
        })

    session = _make_session(profile, region)
    try:
        client = session.client(service, region_name=region)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"unknown service '{service}': "
                                    f"{type(exc).__name__}: {exc}"[:300]})

    if not hasattr(client, op_snake):
        available = sorted(
            o for o in dir(client)
            if _READ_VERBS.match(o) and not o.startswith("_")
        )[:40]
        return json.dumps({
            "error": f"'{operation}' does not exist on '{service}'",
            "read_operations_available": available,
        })

    try:
        resp = getattr(client, op_snake)(**(params or {}))
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"[:500]})

    if isinstance(resp, dict):
        resp.pop("ResponseMetadata", None)
    try:
        data = json.loads(json.dumps(resp, default=str))
        if isinstance(data, dict):
            data = sanitise_fetched_data(data)
    except Exception:  # noqa: BLE001
        data = str(resp)[:4000]

    return json.dumps({
        "service":   service,
        "operation": op_snake,
        "data":      data,
    }, separators=(",", ":"), default=str)


@recordable("get_dependency_graph")
def get_dependency_graph(profile: str | None, region: str) -> str:
    """Build the real dependency graph of the deployed app from configuration.

    Fully service-agnostic by construction:
      1. Nodes come from the Resource Groups Tagging API — every taggable
         resource in the region, no curated service list.
      2. Edges come from ONE uniform rule: fetch each resource's configuration
         via the generic Cloud Control / reflection fetcher (keyed by the raw
         ARN namespace — no name translation anywhere), and scan the
         serialized config for references (ARNs or exact names) to any other
         enumerated resource. If X's config mentions Y, X depends on Y.
    No per-service edge logic and no namespace tables — a service AWS ships
    tomorrow is covered the day it appears in an ARN.
    """
    session = _make_session(profile, region)
    from concurrent.futures import ThreadPoolExecutor

    # 1. Enumerate resources from GENERIC account indexers — no curated service
    #    list, so a service AWS ships tomorrow is covered the day it appears:
    #      (a) AWS Resource Explorer — indexes EVERY resource type, including the
    #          non-taggable ones the Tagging API misses (route tables, ENIs, IAM,
    #          security groups). Requires Resource Explorer enabled with a default
    #          view; if not, it is skipped (not an error) and we fall back to (b).
    #      (b) Resource Groups Tagging API — every taggable resource in the region.
    #    Both are service-agnostic; neither is required alone.
    resources: list[dict] = []
    seen: set = set()

    def _parse_arn(arn: str):
        parts = arn.split(":", 5)
        if len(parts) < 6:
            return None
        ns, rest = parts[2], parts[5]
        name = rest.split("/")[-1] if "/" in rest else rest.split(":")[-1]
        return ns, name

    def _add(arn: str, ns: str, name: str) -> None:
        key = (ns, name)
        if key in seen:
            if arn:   # enrich an ARN-less earlier entry
                for ex in resources:
                    if (ex["service"], ex["name"]) == key and not ex["arn"]:
                        ex["arn"] = arn
                        break
            return
        seen.add(key)
        resources.append({"arn": arn, "service": ns, "name": name})

    try:
        rex = session.client("resource-explorer-2")
        token = None
        for _ in range(10):   # bounded pagination
            kw = {"QueryString": "*", "MaxResults": 100}
            if token:
                kw["NextToken"] = token
            resp = rex.search(**kw)
            for r in resp.get("Resources", []):
                pa = _parse_arn(r.get("Arn", ""))
                if pa:
                    _add(r["Arn"], *pa)
            token = resp.get("NextToken")
            if not token:
                break
    except Exception:  # noqa: BLE001
        pass   # Resource Explorer not enabled — fall back to tagging

    try:
        tagging = session.client("resourcegroupstaggingapi")
        paginator = tagging.get_paginator("get_resources")
        for page in paginator.paginate(PaginationConfig={"MaxItems": 300}):
            for r in page.get("ResourceTagMappingList", []):
                pa = _parse_arn(r.get("ResourceARN", ""))
                if pa:
                    _add(r["ResourceARN"], *pa)
    except Exception:  # noqa: BLE001
        pass

    if not resources:
        return json.dumps({"error": "resource enumeration returned nothing — "
                                    "neither Resource Explorer nor the Tagging API "
                                    "returned resources in this region"})

    nodes = {f"{r['service']}:{r['name']}" for r in resources}
    edges: list[dict] = []

    # 2. One uniform edge rule: whose config mentions whom.
    # Fetch every resource's config IN PARALLEL — the per-resource generic_
    # resource_config call is a 1-3s network round-trip, and doing up to 60 of
    # them sequentially added a 1-3 min bottleneck before triage. The edge match
    # below is fast CPU work and stays sequential.
    from concurrent.futures import ThreadPoolExecutor
    from cloudctl.debug.fetcher import DebugFetcher
    fetcher = DebugFetcher(session)

    def _fetch_cfg(res):
        try:
            return res, fetcher.generic_resource_config(res["service"], res["name"])
        except Exception:  # noqa: BLE001
            return res, None

    # Cap at 100 (was 60) so larger apps aren't cut off before the true
    # dependency is examined; still bounded + parallel so it can't hang.
    with ThreadPoolExecutor(max_workers=10) as _ex:
        fetched_cfgs = list(_ex.map(_fetch_cfg, resources[:100]))

    for res, cfg in fetched_cfgs:
        if not cfg:
            continue
        blob = json.dumps(cfg, default=str)
        src_node = f"{res['service']}:{res['name']}"
        for other in resources:
            if other is res:
                continue
            dst_node = f"{other['service']}:{other['name']}"
            if dst_node == src_node:
                continue
            name = other["name"]
            # ARN match is unambiguous. For NAME match, require length ≥6 AND a
            # token boundary — a bare ">=4 char substring anywhere" produced false
            # edges from common fragments ("prod", "main", "data") embedded in
            # unrelated strings, corrupting the very graph triage relies on.
            if other["arn"] and other["arn"] in blob:
                matched = True
            elif len(name) >= 6 and re.search(
                r'(?<![A-Za-z0-9])' + re.escape(name) + r'(?![A-Za-z0-9])', blob
            ):
                matched = True
            else:
                matched = False
            if matched:
                e = {"from": src_node, "to": dst_node, "via": "config_ref"}
                if e not in edges:
                    edges.append(e)

    return json.dumps({
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": sorted(nodes),
        "edges": edges,
        "note": "edges derived by one generic rule: a resource whose live "
                "configuration references another resource's ARN or name "
                "depends on it",
    }, separators=(",", ":"))


_AGENT_TOOLS = [
    {
        "toolSpec": {
            "name": "list_resources",
            "description": (
                "Discover deployed resources in the account/region GENERICALLY — "
                "enumerated account-wide across ALL service types (via AWS Resource "
                "Explorer, falling back to the Resource Groups Tagging API), with no "
                "fixed service list, so any service is discoverable. Call this first "
                "to find exact resource names before fetching config or logs. "
                "Optionally pass service_type to FILTER the results to one service "
                "(matched against the resource's service namespace or name); omit it "
                "to list everything discoverable."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "service_type": {
                        "type": "string",
                        "description": "Optional filter: an AWS service namespace or "
                                       "name fragment (e.g. lambda, rds, dynamodb). "
                                       "Omit to return all discovered resources.",
                    },
                },
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
                                       "description": "Resource name or log group prefix"},
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
                "current VALUES against limits. "
                "Set baseline_offset_hours to also fetch the same window N hours "
                "earlier and compare against the system's own history instead of "
                "guessing what is normal. "
                "Returns first/last/min/max/avg over the window so growth and spikes are visible. "
                "The model picks the namespace, metric name, and dimensions — they are not pre-chosen."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "namespace":   {"type": "string",
                                    "description": "CloudWatch namespace in AWS/<Service> format â use the namespace the service under investigation publishes to"},
                    "metric_name": {"type": "string",
                                    "description": "Metric name as published by that service"},
                    "dimensions":  {"type": "object",
                                    "description": "Dimension name/value pairs identifying the resource"},
                    "minutes":     {"type": "integer",
                                    "description": "Lookback window in minutes (default 30, max 360)"},
                    "stat":        {"type": "string",
                                    "description": "Statistic: Average, Sum, Maximum, Minimum, p99, p95, p90 (default Average)"},
                    "baseline_offset_hours": {"type": "integer",
                                    "description": "If >0, also fetch the same window this many hours earlier and report the comparison (max 336)"},
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
                                     "description": "Exact resource name as returned by list_resources"},
                    "service_type":  {"type": "string",
                                     "description": "AWS service type — same values as list_resources service_type"},
                },
                "required": ["resource_name", "service_type"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "search_cloudtrail",
            "description": (
                "Search CloudTrail management events touching a resource. "
                "Returns who did what, when — use to find configuration changes "
                "near symptom onset. Compare event timestamps against the "
                "measured onset before treating any change as causal."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "resource_name": {"type": "string",
                                      "description": "Resource name or ARN fragment to search for"},
                    "event_names":   {"type": "array", "items": {"type": "string"},
                                      "description": "Optional specific event names to filter"},
                    "minutes":       {"type": "integer",
                                      "description": "Lookback window in minutes (default 1440)"},
                },
                "required": ["resource_name"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "get_prior_config",
            "description": (
                "DIFFERENTIAL (temporal baseline): what did this resource's "
                "configuration look like BEFORE? Returns structured before→after "
                "diffs (changed keys with old→new values, when changed) from real "
                "retained version history where AWS keeps it, plus a CloudTrail "
                "reconstruction — config-writing events' request parameters carry "
                "the values that were written, so consecutive writes diff into "
                "before→after even where no version history exists. An incident "
                "is usually a CHANGE: a value that looks plausible on its own is "
                "often obviously wrong as a DIFFERENCE, and a field that changed "
                "at/near the measured onset on the failing path is a prime "
                "suspect. Cite the old→new values verbatim. The diff is raw "
                "evidence, not a verdict — the changed field must still explain "
                "the observed failure."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "resource_name": {"type": "string",
                                      "description": "resource name to fetch history for"},
                    "service_type":  {"type": "string",
                                      "description": "resource/service type (namespace "
                                      "from list_resources)"},
                    "minutes":       {"type": "integer",
                                      "description": "CloudTrail lookback window "
                                      "(default 10080 = 7 days)"},
                },
                "required": ["resource_name", "service_type"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "compare_peers",
            "description": (
                "DIFFERENTIAL (peer baseline): which configuration fields DIFFER "
                "between a resource and its sibling resources of the same type "
                "(siblings discovered generically by type + shared name prefix, "
                "or pass peer_names). A field where the failing resource diverges "
                "from otherwise-identical peers is a prime suspect — cite the "
                "differing values verbatim. Differences that are only the "
                "resources' own identities are suppressed but still listed. If "
                "the siblings are NESTED resources you already fetched with "
                "aws_read (e.g. two children of the same parent), pass their raw "
                "configs via 'configs' to get the structural diff directly with "
                "no re-fetch. Raw differences only — a difference is evidence to "
                "weigh, never proof by itself."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "resource_name": {"type": "string",
                                      "description": "the resource under suspicion"},
                    "service_type":  {"type": "string",
                                      "description": "resource/service type"},
                    "peer_names":    {"type": "array", "items": {"type": "string"},
                                      "description": "optional: sibling resource "
                                      "names you already identified"},
                    "configs":       {"type": "object",
                                      "description": "optional: {name: config} dicts "
                                      "you already fetched — pure structural diff, "
                                      "no AWS calls"},
                },
                "required": ["resource_name", "service_type"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "get_traces",
            "description": (
                "Fuse AWS X-Ray distributed traces into a compact signal. Returns "
                "the service-dependency graph with per-edge latency, error, fault, "
                "and throttle rates — showing exactly WHERE in the call graph time "
                "and failures accumulate — plus the slowest and most fault-bearing "
                "traces, each localized to the specific segment (service + "
                "operation) carrying the fault. Traces are the richest signal for "
                "latency/timeout/error-propagation incidents: reach for this to "
                "pinpoint which hop in a multi-service call path is the culprit. "
                "If X-Ray is not enabled or has no traces in the window, it returns "
                "a clear 'no trace data available' result (available=false) — a "
                "normal outcome, not an error."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "resource_hint":     {"type": "string",
                                          "description": "Optional resource/service name to focus the trace search on"},
                    "filter_expression": {"type": "string",
                                          "description": "Optional raw X-Ray filter expression (advanced); omit to let resource_hint drive the search"},
                    "minutes":           {"type": "integer",
                                          "description": "Lookback window in minutes (default 60, max 360)"},
                },
            }},
        }
    },
    {
        "toolSpec": {
            "name": "probe_permission",
            "description": (
                "Deterministically test whether an IAM role is allowed to perform "
                "an action on a resource, using the IAM policy simulator. No "
                "traffic or logs needed — use this to CONFIRM or REFUTE a "
                "permission hypothesis directly. When a resource ARN is supplied, "
                "the target's resource-based policy is fetched and evaluated "
                "together with the role's identity policy, so a deny on either "
                "layer is caught. SCPs and permission boundaries remain outside "
                "the simulation."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "role":         {"type": "string",
                                     "description": "IAM role name or ARN of the caller"},
                    "action":       {"type": "string",
                                     "description": "IAM action to test, in service:Operation format"},
                    "resource_arn": {"type": "string",
                                     "description": "Target resource ARN (optional; * if omitted)"},
                    "resource_policy": {"type": "string",
                                     "description": "Optional: the target's resource-based policy document (fetch it with aws_read, e.g. get_resource_policy / get_bucket_policy / get_key_policy). Supplying it makes the check evaluate identity and resource layers together."},
                },
                "required": ["role", "action"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "aws_read",
            "description": (
                "Call ANY read-only AWS API operation on ANY service — you plan "
                "the calls using your own knowledge of the service's APIs. Use "
                "this when the dedicated tools don't go deep enough for the "
                "service you are investigating: quotas, versioned configs, "
                "policies, statuses, per-feature settings. Mutating operations "
                "are blocked in code. service = boto3 client name; operation = "
                "API operation (CamelCase or snake_case); params = operation "
                "parameters."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "service":   {"type": "string",
                                  "description": "boto3 service/client name"},
                    "operation": {"type": "string",
                                  "description": "read-only API operation to call"},
                    "params":    {"type": "object",
                                  "description": "operation parameters (optional)"},
                },
                "required": ["service", "operation"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "probe_http",
            "description": (
                "Active reproduction: make ONE bounded, READ-ONLY HTTP request "
                "to a service endpoint you discovered from config and observe the "
                "ACTUAL response. Reach for this whenever passive evidence cannot "
                "settle the question — in particular, when every reading "
                "(metrics, logs, config) looks clean yet the symptom persists, the "
                "fault may live only in the response itself (a success status "
                "carrying wrong data, one broken path); telemetry cannot show that "
                "and reading more of it will not help — you must exercise the "
                "system once and look. The observed response (status, body, "
                "timing) is ground truth for the failure MECHANISM: reason from "
                "what it actually returned, never from what it 'should' return. "
                "Strictly read-only (GET/HEAD always; POST admitted ONLY when "
                "`body` is a provably non-mutating query document — anything "
                "mutating is blocked in code), budget-limited. Use only "
                "credentials discoverable from the environment (e.g. a key "
                "already configured on the resource); never invent one — if no "
                "credential is available, the response will say auth_sent=false "
                "and an auth rejection is then inconclusive. "
                "NOTE: each probe is shown to a human operator for approval before "
                "it runs, so state a clear, specific reason; the operator may run "
                "it for you and paste back the response, or decline. If declined, "
                "do not claim the response was verified."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "url":     {"type": "string",
                                "description": "endpoint URL discovered from config"},
                    "method":  {"type": "string",
                                "description": "GET or HEAD (read-only); POST only "
                                "together with a read-only query `body`"},
                    "headers": {"type": "object",
                                "description": "optional auth headers from config"},
                    "body":    {"type": "string",
                                "description": "optional payload for a query POST: "
                                "a JSON object like {\"query\": \"...\"} whose "
                                "document is a READ-ONLY query. Mutation/"
                                "subscription payloads are rejected in code — "
                                "never attempt one"},
                    "reason":  {"type": "string",
                                "description": "one line: what you expect to learn "
                                "and why passive evidence can't settle it (shown "
                                "to the operator who approves the probe)"},
                },
                "required": ["url", "reason"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "native_reproduce",
            "description": (
                "NATIVE-FIRST reproduction: exercise a discovered operation "
                "SERVER-SIDE through the AWS control plane using cloudctl's own "
                "IAM role — no network path to the endpoint and no separate "
                "auth, so it reproduces operations the HTTP probe cannot reach "
                "(e.g. one behind an identity provider). PREFER this over "
                "probe_http whenever it is available for the resource type. It "
                "uses ONLY pure evaluation / documented test APIs that AWS runs "
                "without touching the deployed stage (side-effect-free — never a "
                "live invoke or mutation). It returns the RAW produced result "
                "(evaluation output, or test status+body+logs); reason from what "
                "it actually produced, never from what it 'should' produce. "
                "Supply service_type (from list_resources) and the identifiers/"
                "inputs the primitive needs in params — e.g. for a resolver, the "
                "response mapping 'template' (or 'code') you READ plus a sample "
                "'context'; for an API method, rest_api_id + resource_id + a "
                "read-only http_method + path. If it returns "
                "native_reproduction=unavailable (no primitive for the type, "
                "access denied, or missing inputs), FALL BACK to probe_http, "
                "then to the frontier-honest verdict — never fabricate the "
                "result."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "service_type": {"type": "string",
                                     "description": "resource/service type to "
                                     "reproduce (e.g. the namespace from "
                                     "list_resources)"},
                    "params":       {"type": "object",
                                     "description": "identifiers + inputs the "
                                     "primitive needs (e.g. template/code+context, "
                                     "or rest_api_id+resource_id+http_method+path). "
                                     "All READ from config; no expected values"},
                    "reason":       {"type": "string",
                                     "description": "one line: what you expect to "
                                     "learn (shown to the operator who approves)"},
                },
                "required": ["service_type", "reason"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "get_dependency_graph",
            "description": (
                "Build the REAL dependency graph of the deployed application: "
                "every resource in the region, with an edge wherever one "
                "resource's live configuration references another. Use it to "
                "see exactly what an operation depends on before hypothesizing — "
                "hypothesis coverage should follow these edges, not guesses."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {},
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

_MAX_LOG_LINES_IN_CONTEXT     = 35     # was 50 — enough for pattern detection
_MAX_TOOL_OUTPUT_CHARS        = 4500   # was 8000 — ~1100 tokens per tool result


def _truncate_tool_output(result: str, tool_name: str) -> str:
    """Truncate large tool outputs to protect context window.

    Tool outputs are single-line compact JSON, so the old splitlines()-based
    branches never fired and every large output fell through to a blind
    middle byte-cut — which BOTH corrupted the JSON and dropped a random middle
    slice of evidence. Instead, trim structurally: drop the OLDEST entries from
    the largest list field (events/timeline/datapoints), keeping the recent,
    high-signal tail, and leaving valid JSON. Only fall back to a head-preserving
    cut (never a middle cut) if the payload isn't parseable JSON.
    """
    if len(result) <= _MAX_TOOL_OUTPUT_CHARS:
        return result

    try:
        data = json.loads(result)
    except Exception:  # noqa: BLE001
        data = None

    if isinstance(data, dict):
        list_keys = [k for k, v in data.items() if isinstance(v, list) and len(v) > 1]
        # Trim the biggest list(s) first, keeping the most-recent tail (events are
        # ordered oldest→newest, so the tail is the recent, relevant data).
        list_keys.sort(key=lambda k: len(json.dumps(data[k], default=str)), reverse=True)
        for k in list_keys:
            guard = 0
            while (len(json.dumps(data, default=str, separators=(",", ":"))) > _MAX_TOOL_OUTPUT_CHARS
                   and len(data[k]) > 1 and guard < 32):
                data[k] = data[k][len(data[k]) // 2:]   # drop oldest half
                data[f"_{k}_truncated"] = "older entries dropped to fit context window"
                guard += 1
            if len(json.dumps(data, default=str, separators=(",", ":"))) <= _MAX_TOOL_OUTPUT_CHARS:
                break
        out = json.dumps(data, default=str, separators=(",", ":"))
        if len(out) <= _MAX_TOOL_OUTPUT_CHARS:
            return out
        # Still too large after trimming lists — head-preserve (summary fields
        # live at the front); never a middle cut.
        return out[:_MAX_TOOL_OUTPUT_CHARS] + "\n[... truncated — output too large ...]"

    # Non-JSON payload: keep the head + marker (no corrupting middle cut).
    return result[:_MAX_TOOL_OUTPUT_CHARS] + "\n[... truncated — output too large ...]"


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
        detect_hallucinations, verify_cited_values, verify_tool_coverage,
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
        # Bounded timeouts are a hard requirement for an unattended tool: without
        # them a network hang on converse() can freeze for over an hour with no
        # catchable exception (the vector_bucket_access_denied 118-min hang).
        config=_BotoConfig(
            retries={"mode": "adaptive", "max_attempts": 10},
            connect_timeout=10,
            read_timeout=120,
        ),
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
    tools_called: set[str] = set()

    def _dispatch(tool_name: str, tool_input: dict) -> str:
        tools_called.add(tool_name)
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
            raw = list_resources(tool_input.get("service_type", ""), profile, region)
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
                filter_pattern=tool_input.get("filter_pattern", ""),
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
    invalid_json_retries = 0   # retry once if the model returns non-JSON
    coverage_retries = 0       # retry once if mandatory tools were never called

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
            text = next(
                (b["text"] for b in msg.get("content", []) if "text" in b), ""
            ).strip()
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
                # Don't accept chatty prose as a diagnosis — retry once asking
                # for valid JSON, then fall back.
                if invalid_json_retries < 1:
                    invalid_json_retries += 1
                    messages.append({"role": "user", "content": [{"text": (
                        "Your response was not valid JSON. Respond again with "
                        "ONLY the final JSON object: root_cause, evidence, "
                        "remediation_steps, severity, confidence, "
                        "resources_investigated."
                    )}]})
                    continue
                parsed = {
                    "root_cause":            text,
                    "evidence":              [],
                    "remediation_steps":     [],
                    "severity":              "UNKNOWN",
                    "confidence":            "LOW",
                    "resources_investigated": [],
                }

            # Guardrail 8 — mandatory tool coverage: a conclusion drawn without
            # the tools the symptom class requires is untrustworthy. Retry once,
            # forcing the missing tools, before accepting.
            cov = verify_tool_coverage(symptom, tools_called)
            if not cov.satisfied and coverage_retries < 1:
                coverage_retries += 1
                missing = ", ".join(cov.missing_tools)
                them = "them" if len(cov.missing_tools) > 1 else "it"
                messages.append({"role": "user", "content": [{"text": (
                    f"You concluded without calling {missing}. Call {them} now "
                    f"before finalizing, then output your final JSON."
                )}]})
                continue

            # Guardrail 5 — confidence enforcement
            hal_report = detect_hallucinations(parsed, all_fetched)
            parsed     = enforce_confidence(parsed, all_fetched, hal_report)

            # Verification turn: every numeric/quoted claim must trace to fetched
            # data. Unverified items are surfaced separately and force confidence
            # to LOW — wrong facts are worse than admitted uncertainty.
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

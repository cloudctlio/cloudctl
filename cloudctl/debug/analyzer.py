"""Debug analyzer — calls AI with correlated evidence and parses structured response.

Receives: correlated timeline + full fetched context
Returns:  structured AnalysisResult with root cause, evidence, steps

The AI does NOT fetch data. It does NOT make API calls.
It receives pre-fetched, pre-correlated data and reasons over it.
All facts in the output must come from the fetched data.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from cloudctl.debug.correlator import TimelineEvent


_SYSTEM_PROMPT = """\
You are a senior cloud infrastructure engineer analyzing a production incident.
You will receive correlated data from cloud APIs and a causal timeline.
Your job is to identify the root cause and suggest resolution steps.

Rules:
  - Base your answer ONLY on the data provided. Do not infer or assume.
  - If data is insufficient, say so in root_cause — but only say data is missing if it was truly not provided. If the data section contains service config, task definitions, container config, Lambda config, VPC config, SG rules etc., use them — do not claim they are missing.
  - Never infer that a resource is a test, demo, or non-production based on its name. Treat every resource as production and diagnose accordingly.
  - Cite specific resource names, ARNs, port numbers, SG IDs, and metric values from the evidence. Be precise.
  - Be calm and factual. No urgency language.
  - Respond with valid JSON ONLY. No markdown, no explanation outside the JSON.

Required JSON schema:
{
  "root_cause": [
    "line 1 — what happened",
    "line 2 — why it happened",
    "line 3 — what the impact was"
  ],
  "evidence": [
    {"source": "CloudTrail", "finding": "ECS RegisterTaskDefinition at 14:52 UTC"},
    {"source": "ECS events", "finding": "3 tasks UNHEALTHY 15:01-15:04 UTC"},
    {"source": "ALB", "finding": "502 errors began at 15:03:12 UTC"}
  ],
  "affected_resources": ["arn:aws:ecs:...", "arn:aws:rds:..."],
  "remediation_steps": ["step 1", "step 2", "step 3"],
  "confidence_notes": "one sentence explaining HIGH/MEDIUM/LOW confidence",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL"
}
"""


@dataclass
class AnalysisResult:
    root_cause: str
    root_cause_lines: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    affected_resources: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)
    confidence_notes: str = ""
    severity: str = "MEDIUM"
    raw_response: str = ""


def _build_prompt(symptom: str, timeline: list[dict], context: dict) -> str:
    lines = [
        f"SYMPTOM: {symptom}",
        "",
        "CAUSAL TIMELINE (most recent last):",
    ]
    for ev in timeline[-30:]:
        inf_marker = "  ← CHANGE" if ev.get("is_inflection") else ""
        etype      = f"[{ev.get('event_type', '')}]" if ev.get("event_type") else ""
        lines.append(
            f"  {ev.get('time', '—')}  [{ev.get('source', '—')}]{etype}  "
            f"{ev.get('event', '')}{inf_marker}"
        )

    # Include structured summaries from rich context
    lines.append("")
    lines.append("FETCHED DATA SUMMARY:")

    ecs_svc = context.get("ecs_service_details")
    if isinstance(ecs_svc, dict):
        svc = ecs_svc.get("service", {})
        lines.append(
            f"  ECS service {svc.get('name', '—')}: "
            f"running={svc.get('running_count', 0)} desired={svc.get('desired_count', 0)} "
            f"pending={svc.get('pending_count', 0)} status={svc.get('status', '—')}"
        )
        for dep in svc.get("deployments", [])[:2]:
            lines.append(
                f"    deployment: status={dep.get('status')} "
                f"running={dep.get('running_count', 0)}/{dep.get('desired_count', 0)} "
                f"failed_tasks={dep.get('failed_tasks', 0)} "
                f"rollout={dep.get('rollout_state', '—')}"
            )
        for ev in svc.get("events", [])[:5]:
            lines.append(f"    event: {ev.get('time', '—')} — {ev.get('message', '')}")
        td = ecs_svc.get("task_def", {})
        if td:
            lines.append(
                f"    task_def: {td.get('family')}:{td.get('revision')} "
                f"cpu={td.get('cpu')} memory={td.get('memory')} "
                f"network={td.get('network_mode')}"
            )
        for ctr in ecs_svc.get("containers", []):
            ports = ", ".join(
                f"{p.get('containerPort', '?')}/{p.get('protocol', 'tcp')}"
                for p in ctr.get("port_mappings", [])
            )
            lines.append(
                f"    container {ctr.get('name')}: image={ctr.get('image')} "
                f"cpu={ctr.get('cpu', 0)} memory={ctr.get('memory', '—')} "
                f"ports=[{ports}] "
                f"env_vars={ctr.get('env_var_keys', [])} "
                f"secrets={ctr.get('secrets', [])}"
            )
            if ctr.get("health_check"):
                hc = ctr["health_check"]
                lines.append(
                    f"      health_check: cmd={hc.get('Command', [])} "
                    f"interval={hc.get('Interval', 30)}s "
                    f"retries={hc.get('Retries', 3)}"
                )

    fn_cfg = context.get("lambda_function_config")
    if isinstance(fn_cfg, dict):
        lines.append(
            f"  Lambda {fn_cfg.get('function_name', '—')}: "
            f"runtime={fn_cfg.get('runtime')} "
            f"memory={fn_cfg.get('memory_mb')}MB timeout={fn_cfg.get('timeout_s')}s "
            f"state={fn_cfg.get('state')} "
            f"reserved_concurrency={fn_cfg.get('reserved_concurrency', 'unreserved')}"
        )
        vpc = fn_cfg.get("vpc_config", {})
        if vpc.get("in_vpc"):
            lines.append(
                f"    vpc_config: vpc={vpc.get('vpc_id')} "
                f"subnets={vpc.get('subnet_ids', [])} "
                f"security_groups={vpc.get('security_group_ids', [])}"
            )
        else:
            lines.append("    vpc_config: not in VPC (has direct internet access)")
        if fn_cfg.get("env_var_keys"):
            lines.append(f"    env_vars present: {fn_cfg.get('env_var_keys')}")
        else:
            lines.append("    env_vars: none configured")
        layers = fn_cfg.get("layers", [])
        if layers:
            lines.append(f"    layers: {[lyr.get('arn', '').split(':')[-2] for lyr in layers]}")
        else:
            lines.append("    layers: none")
        if fn_cfg.get("state_reason"):
            lines.append(f"    state_reason: {fn_cfg.get('state_reason')}")
        if fn_cfg.get("last_update_reason"):
            lines.append(f"    last_update_reason: {fn_cfg.get('last_update_reason')}")

    rds_cfg = context.get("rds_instance_config")
    if isinstance(rds_cfg, dict):
        lines.append(
            f"  RDS {rds_cfg.get('db_instance_identifier', '—')}: "
            f"engine={rds_cfg.get('engine')}/{rds_cfg.get('engine_version')} "
            f"class={rds_cfg.get('db_instance_class')} "
            f"status={rds_cfg.get('status')} "
            f"multi_az={rds_cfg.get('multi_az')} "
            f"storage={rds_cfg.get('allocated_storage_gb')}GB/{rds_cfg.get('storage_type')} "
            f"encrypted={rds_cfg.get('storage_encrypted')}"
        )
        ep = rds_cfg.get("endpoint", {})
        if ep.get("address"):
            lines.append(f"    endpoint: {ep['address']}:{ep.get('port', 0)}")
        if rds_cfg.get("vpc_security_groups"):
            lines.append(f"    security_groups: {[sg['sg_id'] for sg in rds_cfg['vpc_security_groups']]}")
        if rds_cfg.get("parameter_group"):
            lines.append(f"    parameter_group: {rds_cfg['parameter_group']}")
        if rds_cfg.get("cloudwatch_log_exports"):
            lines.append(f"    cw_log_exports: {rds_cfg['cloudwatch_log_exports']}")
        if rds_cfg.get("recent_events"):
            for ev in rds_cfg["recent_events"][:3]:
                lines.append(f"    event: {ev.get('message', '')}")

    aurora_cfg = context.get("aurora_cluster_config")
    if isinstance(aurora_cfg, dict):
        lines.append(
            f"  Aurora {aurora_cfg.get('cluster_identifier', '—')}: "
            f"engine={aurora_cfg.get('engine')}/{aurora_cfg.get('engine_version')} "
            f"mode={aurora_cfg.get('engine_mode')} "
            f"status={aurora_cfg.get('status')} "
            f"multi_az={aurora_cfg.get('multi_az')}"
        )
        lines.append(f"    endpoint: {aurora_cfg.get('endpoint', '—')} (reader: {aurora_cfg.get('reader_endpoint', '—')})")
        members = aurora_cfg.get("members", [])
        writers = [m["instance_id"] for m in members if m.get("is_writer")]
        readers = [m["instance_id"] for m in members if not m.get("is_writer")]
        if writers:
            lines.append(f"    writer: {writers[0]}, readers: {readers}")
        sv2 = aurora_cfg.get("serverless_v2_config", {})
        if sv2:
            lines.append(f"    serverless_v2: min={sv2.get('MinCapacity')} max={sv2.get('MaxCapacity')} ACU")

    rs_cfg = context.get("redshift_cluster_config")
    if isinstance(rs_cfg, dict):
        lines.append(
            f"  Redshift {rs_cfg.get('cluster_identifier', '—')}: "
            f"status={rs_cfg.get('cluster_status')} "
            f"node_type={rs_cfg.get('node_type')} "
            f"nodes={rs_cfg.get('number_of_nodes')} "
            f"encrypted={rs_cfg.get('encrypted')}"
        )
        ep = rs_cfg.get("endpoint", {})
        if ep.get("address"):
            lines.append(f"    endpoint: {ep['address']}:{ep.get('port', 5439)}")
        if rs_cfg.get("recent_events"):
            for ev in rs_cfg["recent_events"][:2]:
                lines.append(f"    event: {ev.get('message', '')}")

    glue_cfg = context.get("glue_job_config")
    if isinstance(glue_cfg, dict):
        lines.append(
            f"  Glue job {glue_cfg.get('job_name', '—')}: "
            f"type={glue_cfg.get('job_type')} "
            f"glue_version={glue_cfg.get('glue_version')} "
            f"worker={glue_cfg.get('worker_type')} x{glue_cfg.get('num_workers')} "
            f"timeout={glue_cfg.get('timeout_minutes')}m "
            f"max_retries={glue_cfg.get('max_retries')}"
        )
        if glue_cfg.get("bookmark_option"):
            lines.append(f"    bookmark: {glue_cfg['bookmark_option']}")
        if glue_cfg.get("connections"):
            lines.append(f"    connections: {glue_cfg['connections']}")
        for run in (glue_cfg.get("last_runs") or [])[:3]:
            lines.append(
                f"    run {run.get('job_run_id', '?')[:8]}: "
                f"state={run.get('state')} "
                f"duration={run.get('duration_s')}s "
                f"dpu={run.get('dpu_seconds')}s"
                + (f" error: {run['error_message']}" if run.get("error_message") else "")
            )

    apigw_cfg = context.get("api_gateway_config")
    if isinstance(apigw_cfg, dict):
        lines.append(
            f"  API Gateway ({apigw_cfg.get('type', '—')}) {apigw_cfg.get('api_name', '—')}: "
            f"id={apigw_cfg.get('api_id', '—')}"
        )
        cors = apigw_cfg.get("cors_config", {})
        if cors:
            lines.append(f"    cors: origins={cors.get('AllowOrigins', [])} methods={cors.get('AllowMethods', [])}")
        for stage in (apigw_cfg.get("stages") or [])[:3]:
            lines.append(
                f"    stage {stage.get('name', '—')}: "
                f"throttle_rate={stage.get('throttling_rate')} "
                f"throttle_burst={stage.get('throttling_burst')} "
                f"metrics={stage.get('detailed_metrics', stage.get('metrics_enabled'))}"
            )
        routes = apigw_cfg.get("routes", [])
        if routes:
            lines.append(f"    routes ({len(routes)}): {[r.get('route_key') for r in routes[:5]]}")

    ddb_cfg = context.get("dynamodb_table_config")
    if isinstance(ddb_cfg, dict):
        pt = ddb_cfg.get("provisioned_throughput", {})
        lines.append(
            f"  DynamoDB {ddb_cfg.get('table_name', '—')}: "
            f"status={ddb_cfg.get('table_status')} "
            f"billing={ddb_cfg.get('billing_mode')} "
            f"items={ddb_cfg.get('item_count')} "
            f"size={ddb_cfg.get('size_bytes', 0) // 1024}KB "
            f"class={ddb_cfg.get('table_class')}"
        )
        if ddb_cfg.get("billing_mode") == "PROVISIONED":
            lines.append(
                f"    capacity: RCU={pt.get('read_capacity_units')} "
                f"WCU={pt.get('write_capacity_units')} "
                f"decreases_today={pt.get('decreases_today', 0)}"
            )
        gsis = ddb_cfg.get("global_secondary_indexes", [])
        if gsis:
            lines.append(f"    GSIs ({len(gsis)}): {[g.get('name') for g in gsis[:3]]}")
        ttl = ddb_cfg.get("ttl", {})
        if ttl.get("status") == "ENABLED":
            lines.append(f"    TTL: enabled on attribute '{ttl.get('attribute')}'")
        stream = ddb_cfg.get("stream_specification", {})
        if stream.get("StreamEnabled"):
            lines.append(f"    streams: enabled view_type={stream.get('StreamViewType')}")

    s3_cfg = context.get("s3_bucket_config")
    if isinstance(s3_cfg, dict):
        lines.append(
            f"  S3 {s3_cfg.get('bucket_name', '—')}: "
            f"versioning={s3_cfg.get('versioning', 'Disabled')} "
            f"encryption={s3_cfg.get('encryption', 'none')} "
            f"lifecycle_rules={s3_cfg.get('lifecycle_rules_count', 0)}"
        )
        pab = s3_cfg.get("public_access_block", {})
        if pab:
            lines.append(
                f"    public_access_block: "
                f"block_acls={pab.get('block_public_acls')} "
                f"block_policy={pab.get('block_public_policy')} "
                f"restrict={pab.get('restrict_public_buckets')}"
            )
        notif = s3_cfg.get("notifications", {})
        if notif:
            lines.append(
                f"    notifications: lambda={notif.get('lambda_configs', 0)} "
                f"sns={notif.get('sns_configs', 0)} "
                f"sqs={notif.get('sqs_configs', 0)}"
            )

    sm_cfg = context.get("secrets_manager_config")
    if isinstance(sm_cfg, dict):
        lines.append(
            f"  SecretsManager {sm_cfg.get('secret_name', '—')}: "
            f"rotation={sm_cfg.get('rotation_enabled')} "
            f"kms={sm_cfg.get('kms_key_id', 'aws/secretsmanager')} "
            f"last_rotated={sm_cfg.get('last_rotated_date', 'never')} "
            f"last_accessed={sm_cfg.get('last_accessed_date', '—')}"
        )
        if sm_cfg.get("deleted_date") and sm_cfg["deleted_date"] != "None":
            lines.append(f"    WARNING: secret is scheduled for deletion on {sm_cfg['deleted_date']}")
        if sm_cfg.get("rotation_lambda_arn"):
            lines.append(f"    rotation_lambda: {sm_cfg['rotation_lambda_arn'].split(':')[-1]}")

    sns_cfg = context.get("sns_topic_config")
    if isinstance(sns_cfg, dict):
        lines.append(
            f"  SNS {sns_cfg.get('topic_name', '—')}: "
            f"confirmed={sns_cfg.get('subscriptions_confirmed')} "
            f"pending={sns_cfg.get('subscriptions_pending')} "
            f"fifo={sns_cfg.get('fifo_topic')} "
            f"kms={sns_cfg.get('kms_master_key_id', 'none')}"
        )
        subs = sns_cfg.get("subscriptions", [])
        if subs:
            lines.append(f"    subscriptions: {[(s.get('protocol'), s.get('endpoint_hint', '')[:30]) for s in subs[:4]]}")

    sqs_cfg = context.get("sqs_queue_config")
    if isinstance(sqs_cfg, dict):
        lines.append(
            f"  SQS {sqs_cfg.get('queue_name', '—')}: "
            f"messages={sqs_cfg.get('approximate_messages')} "
            f"in_flight={sqs_cfg.get('approximate_messages_not_visible')} "
            f"delayed={sqs_cfg.get('approximate_messages_delayed')} "
            f"visibility_timeout={sqs_cfg.get('visibility_timeout_s')}s "
            f"delay={sqs_cfg.get('delay_seconds')}s "
            f"fifo={sqs_cfg.get('fifo')}"
        )
        if sqs_cfg.get("dlq_arn"):
            lines.append(f"    dlq: {sqs_cfg['dlq_arn'].split(':')[-1]} max_receive={sqs_cfg.get('max_receive_count')}")
        else:
            lines.append("    dlq: not configured")
        if sqs_cfg.get("kms_key_id"):
            lines.append(f"    kms: {sqs_cfg['kms_key_id']}")

    ec_cfg = context.get("elasticache_config")
    if isinstance(ec_cfg, dict):
        if ec_cfg.get("type") == "redis_replication_group":
            lines.append(
                f"  ElastiCache Redis {ec_cfg.get('replication_group_id', '—')}: "
                f"status={ec_cfg.get('status')} "
                f"nodes={ec_cfg.get('node_count')} "
                f"node_type={ec_cfg.get('node_type', '—')} "
                f"engine={ec_cfg.get('engine_version', '—')} "
                f"multi_az={ec_cfg.get('multi_az')} "
                f"auto_failover={ec_cfg.get('automatic_failover')} "
                f"at_rest_enc={ec_cfg.get('at_rest_encryption')} "
                f"transit_enc={ec_cfg.get('transit_encryption')} "
                f"auth_token={ec_cfg.get('auth_token_enabled')}"
            )
        else:
            lines.append(
                f"  ElastiCache Memcached {ec_cfg.get('cluster_id', '—')}: "
                f"status={ec_cfg.get('status')} "
                f"nodes={ec_cfg.get('num_cache_nodes')} "
                f"node_type={ec_cfg.get('node_type', '—')}"
            )
        if ec_cfg.get("security_groups"):
            lines.append(f"    security_groups: {[sg['sg_id'] for sg in ec_cfg['security_groups']]}")

    kin_cfg = context.get("kinesis_stream_config")
    if isinstance(kin_cfg, dict):
        lines.append(
            f"  Kinesis {kin_cfg.get('stream_name', '—')}: "
            f"status={kin_cfg.get('stream_status')} "
            f"mode={kin_cfg.get('stream_mode')} "
            f"shards={kin_cfg.get('shard_count')} "
            f"retention={kin_cfg.get('retention_period_hours')}h "
            f"encryption={kin_cfg.get('encryption_type')} "
            f"consumers={kin_cfg.get('consumer_count')}"
        )
        for cons in (kin_cfg.get("consumers") or [])[:3]:
            lines.append(f"    consumer: {cons.get('name')} status={cons.get('status')}")

    eks_cfg = context.get("eks_cluster_config")
    if isinstance(eks_cfg, dict):
        lines.append(
            f"  EKS {eks_cfg.get('cluster_name', '—')}: "
            f"k8s={eks_cfg.get('kubernetes_version')} "
            f"status={eks_cfg.get('status')} "
            f"platform={eks_cfg.get('platform_version', '—')} "
            f"public_access={eks_cfg.get('endpoint_public_access')} "
            f"private_access={eks_cfg.get('endpoint_private_access')}"
        )
        if eks_cfg.get("enabled_log_types"):
            lines.append(f"    logging: {eks_cfg['enabled_log_types']}")
        if eks_cfg.get("oidc_provider"):
            lines.append(f"    oidc: {eks_cfg['oidc_provider'].split('/')[-1]}")
        for ng in (eks_cfg.get("node_groups") or [])[:3]:
            sc = ng.get("scaling", {})
            lines.append(
                f"    nodegroup {ng.get('name')}: "
                f"status={ng.get('status')} "
                f"instance={ng.get('instance_types', ['?'])[0]} "
                f"desired={sc.get('desired')}/{sc.get('min')}-{sc.get('max')}"
            )
        for addon in (eks_cfg.get("addons") or [])[:5]:
            lines.append(f"    addon {addon.get('name')}: {addon.get('version')} status={addon.get('status')}")

    alb_map = context.get("alb_resource_map")
    if isinstance(alb_map, dict):
        lines.append(f"  ALB: {alb_map.get('alb_name', '—')}")
        for tg in alb_map.get("all_tgs", []):
            lines.append(
                f"    TG {tg.get('name')}: {tg.get('healthy_count', 0)} healthy, "
                f"{tg.get('unhealthy_count', 0)} unhealthy, "
                f"routes: {', '.join(tg.get('routing_paths', [])) or 'default'}"
            )

    acm = context.get("acm_expiry_check")
    if isinstance(acm, dict) and acm.get("has_issues"):
        for issue in acm.get("issues", [])[:3]:
            lines.append(
                f"  ACM cert {issue.get('domain')}: {issue.get('status')} "
                f"(expires in {issue.get('days_to_expiry')} days)"
            )

    ecs_stopped = context.get("ecs_stopped", [])
    if ecs_stopped:
        lines.append(f"  ECS stopped tasks: {len(ecs_stopped)}")
        for t in ecs_stopped[:3]:
            lines.append(f"    stop_reason: {t.get('event', '')}")

    lambda_report = context.get("lambda_report", [])
    if lambda_report:
        durations = [e.get("duration_ms", 0) for e in lambda_report if e.get("duration_ms")]
        if durations:
            lines.append(
                f"  Lambda: p99={sorted(durations)[int(len(durations)*0.99)]}ms, "
                f"cold_starts={sum(1 for e in lambda_report if e.get('cold_start'))}"
            )

    vpc_flow = context.get("vpc_flow_logs", [])
    if vpc_flow:
        rejects = [e for e in vpc_flow if "REJECT" in e.get("event", "")]
        if rejects:
            lines.append(f"  VPC Flow Log REJECT records: {len(rejects)}")

    if context:
        remaining_keys = {
            k for k in context
            if k not in {"alb_resource_map", "acm_expiry_check", "ecs_stopped",
                         "lambda_report", "vpc_flow_logs", "deployment_method",
                         "iac_resource_config"}
            and isinstance(context[k], (str, int, float, bool))
        }
        for k in list(remaining_keys)[:5]:
            lines.append(f"  {k}: {context[k]}")

    iac = context.get("iac_resource_config")
    if iac:
        lines.append(f"  IaC stack: {iac.get('stack', '—')}")
        for lid, res in list(iac.get("resources", {}).items())[:3]:
            lines.append(f"    {lid}: type={res.get('Type', '?')}")

    return "\n".join(lines)


def _parse_response(text: str) -> dict:
    """Extract JSON from AI response text, handling code blocks."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text  = "\n".join(l for l in lines if not l.startswith("```")).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end   = text.rfind("}")
        if start != -1 and end != -1:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
    return {}


def analyze(
    ai,
    symptom: str,
    timeline: list[dict],
    context: dict,
) -> AnalysisResult:
    """
    Call AI with symptom + evidence timeline, return structured AnalysisResult.
    Falls back gracefully if AI is unavailable or returns malformed JSON.
    """
    prompt = _build_prompt(symptom, timeline, context)

    try:
        response = ai.ask(prompt, context={"system": _SYSTEM_PROMPT})
        raw = response.get("answer", "") or str(response)
    except Exception as exc:  # noqa: BLE001
        return AnalysisResult(
            root_cause=f"AI analysis failed: {exc}",
            confidence_notes="AI unavailable — manual investigation required.",
        )

    parsed = _parse_response(raw)

    # root_cause: accept list or string
    rc_raw  = parsed.get("root_cause", raw[:500] if raw else "Unknown")
    if isinstance(rc_raw, list):
        rc_lines = [str(l) for l in rc_raw]
        rc_str   = "\n".join(rc_lines)
    else:
        rc_str   = str(rc_raw)
        rc_lines = [rc_str]

    return AnalysisResult(
        root_cause=rc_str,
        root_cause_lines=rc_lines,
        evidence=parsed.get("evidence", []),
        affected_resources=parsed.get("affected_resources", []),
        remediation_steps=parsed.get("remediation_steps", []),
        confidence_notes=parsed.get("confidence_notes", ""),
        severity=parsed.get("severity", "MEDIUM"),
        raw_response=raw,
    )

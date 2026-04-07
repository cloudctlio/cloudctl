"""Debug engine — wires together planner, fetcher, correlator, analyzer, resolver."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cloudctl.debug.planner import plan_sources, extract_service_hints
from cloudctl.debug.correlator import build_timeline, summarise
from cloudctl.debug.resolver import build_steps
from cloudctl.debug.renderer import (
    diagnosing_banner,
    fetch_start,
    fetch_item,
    fetch_skipped,
    fetch_error,
    section_header,
    root_cause as render_root_cause,
    evidence_table,
    affected_resources as render_resources,
    remediation_steps as render_steps,
    iac_drift_warning as render_drift_warning,
    confidence_note,
    incident_saved,
    missing_source_warning,
)
from cloudctl.config.manager import ConfigManager


_INCIDENTS_DIR = Path.home() / ".cloudctl" / "incidents"


@dataclass
class DebugResult:
    symptom: str
    root_cause: str
    affected_resources: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    confidence_label: str = "LOW confidence"
    deployment_method: str = "unknown"
    timeline: list[dict] = field(default_factory=list)
    incident_path: Optional[str] = None


def run(
    cfg: ConfigManager,
    symptom: str,
    cloud: str = "aws",
    account: Optional[str] = None,
    region: Optional[str] = None,
) -> DebugResult:
    """
    Full debug pipeline:
      1. Plan which data sources to query
      2. Fetch evidence from each source
      3. Build causal timeline
      4. Analyze with AI
      5. Detect deployment method
      6. Build IaC-aware resolution steps
      7. Render output
      8. Save incident report
    """
    diagnosing_banner(symptom)

    # ── 1. Plan ───────────────────────────────────────────────────
    sources = plan_sources(symptom)
    hints   = extract_service_hints(symptom)

    # ── 2. Fetch ──────────────────────────────────────────────────
    all_evidence: list[dict] = []
    context: dict = {}

    if cloud == "aws":
        session = _get_aws_session(cfg, account, region)
        all_evidence, context = _fetch_aws(session, sources, hints)
    else:
        section_header("Data Fetch")
        fetch_skipped(cloud, "deep debug only supports AWS in this version")

    # ── 3. Correlate ──────────────────────────────────────────────
    timeline       = build_timeline(all_evidence)
    timeline_dicts = summarise(timeline)

    # ── 4. Analyze ────────────────────────────────────────────────
    from cloudctl.ai.factory import get_ai, is_ai_configured  # noqa: PLC0415
    from cloudctl.debug.analyzer import analyze  # noqa: PLC0415
    from cloudctl.ai import confidence as confidence_mod  # noqa: PLC0415
    from cloudctl.ai.feedback import lookup_accuracy  # noqa: PLC0415

    if not is_ai_configured(cfg):
        result = DebugResult(
            symptom=symptom,
            root_cause="AI not configured. Run: cloudctl config set ai.provider <provider>",
        )
        _render(result)
        return result

    ai = get_ai(cfg, purpose="analysis")

    # Historical accuracy from feedback
    hist_acc = lookup_accuracy(symptom, context)

    analysis = analyze(ai, symptom, timeline_dicts, context)

    cs = confidence_mod.score(
        context,
        historical_accuracy=hist_acc,
    )

    # ── 5. Detect deployment method ───────────────────────────────
    from cloudctl.debug.deployment_detector import detect  # noqa: PLC0415
    deploy_method = "unknown"
    if cloud == "aws" and all_evidence and session:
        # Use the first affected resource hint
        resource_arn = analysis.affected_resources[0] if analysis.affected_resources else None
        deploy_method = detect(session, resource_arn=resource_arn)

    # ── 6. Build resolution steps ─────────────────────────────────
    steps = build_steps(deploy_method, analysis.remediation_steps)

    # ── 7. Build result ───────────────────────────────────────────
    dr = DebugResult(
        symptom=symptom,
        root_cause=analysis.root_cause,
        affected_resources=analysis.affected_resources,
        remediation_steps=steps,
        severity=analysis.severity,
        confidence_label=cs.label,
        deployment_method=deploy_method,
        timeline=timeline_dicts,
    )

    # ── 8. Render ─────────────────────────────────────────────────
    _render(dr)

    # ── 9. Save incident report ───────────────────────────────────
    dr.incident_path = _save_incident(dr)
    incident_saved(dr.incident_path)

    return dr


def _render(dr: DebugResult) -> None:
    if dr.timeline:
        section_header("Evidence Timeline")
        # Show only inflection points + last 5 events
        inf_events = [e for e in dr.timeline if e.get("is_inflection")]
        recent     = dr.timeline[-5:]
        display    = {id(e): e for e in (inf_events + recent)}.values()
        evidence_table(list(display))

    render_root_cause(dr.root_cause, dr.confidence_label)
    render_resources(dr.affected_resources)
    render_steps(dr.remediation_steps, dr.deployment_method)

    from cloudctl.debug.deployment_detector import iac_drift_warning  # noqa: PLC0415
    warning = iac_drift_warning(dr.deployment_method)
    if warning:
        render_drift_warning(dr.deployment_method)


def _save_incident(dr: DebugResult) -> str:
    """Save a markdown incident report to ~/.cloudctl/incidents/."""
    _INCIDENTS_DIR.mkdir(parents=True, exist_ok=True)
    slug  = dr.symptom[:40].lower().replace(" ", "-").replace("/", "-")
    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M")
    fname = f"{ts}-{slug}.md"
    path  = _INCIDENTS_DIR / fname

    lines = [
        f"# Incident: {dr.symptom}",
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Severity: {dr.severity}",
        f"Confidence: {dr.confidence_label}",
        f"Deployment method: {dr.deployment_method}",
        "",
        "## Root Cause",
        dr.root_cause,
        "",
    ]
    if dr.affected_resources:
        lines += ["## Affected Resources", ""]
        lines += [f"- {r}" for r in dr.affected_resources]
        lines.append("")

    if dr.timeline:
        lines += ["## Evidence Timeline", ""]
        for ev in dr.timeline:
            inf = " ← CHANGE" if ev.get("is_inflection") else ""
            lines.append(f"- {ev.get('time', '—')}  [{ev.get('source', '—')}]  {ev.get('event', '')}{inf}")
        lines.append("")

    if dr.remediation_steps:
        lines += ["## Resolution Steps", ""]
        for i, step in enumerate(dr.remediation_steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


def _get_aws_session(cfg: ConfigManager, account: Optional[str], region: Optional[str]):
    """Create a boto3 session for the given profile/region."""
    try:
        import boto3  # noqa: PLC0415
        profiles = cfg.accounts.get("aws", [])
        profile  = account or (profiles[0]["name"] if profiles else None)
        return boto3.Session(profile_name=profile, region_name=region)
    except Exception:  # noqa: BLE001
        return None


def _collect(evidence: list, context: dict, key: str, evts: list, extend: bool = False) -> None:
    """Append events to evidence and store under context[key]; extend=True uses setdefault+extend."""
    if evts:
        evidence.extend(evts)
        if extend:
            context.setdefault(key, []).extend(evts)
        else:
            context[key] = evts


def _fetch_cloudwatch(fetcher, evidence: list, context: dict) -> None:
    fetch_start("CloudWatch Metrics")
    for ns, metric in [
        ("AWS/EC2",            "CPUUtilization"),
        ("AWS/ECS",            "CPUUtilization"),
        ("AWS/RDS",            "DatabaseConnections"),
        ("AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count"),
    ]:
        _collect(evidence, context, "metrics", fetcher.cloudwatch_metrics(namespace=ns, metric_name=metric), extend=True)
    fetch_item("CloudWatch Metrics", len([e for e in evidence if "CloudWatch" in e.get("source", "")]))


def _fetch_cloudtrail(fetcher, evidence: list, context: dict) -> None:
    fetch_start("CloudTrail")
    evts = fetcher.cloudtrail(minutes=120)
    _collect(evidence, context, "cloudtrail_events", evts)
    if evts:
        fetch_item("CloudTrail", len(evts))
    elif fetcher.availability.get("cloudtrail") is False:
        fetch_skipped("CloudTrail", "not enabled in this region or no permissions")
        missing_source_warning(
            "CloudTrail",
            "Enable CloudTrail: `aws cloudtrail create-trail --name cloudctl-trail --s3-bucket-name <bucket>`",
        )


def _fetch_aws(session, sources: list[str], hints: list[str]) -> tuple[list[dict], dict]:
    """Fetch all planned AWS data sources, return (evidence_list, context_dict)."""
    from cloudctl.debug.fetcher import DebugFetcher  # noqa: PLC0415

    fetcher  = DebugFetcher(session)
    evidence: list[dict] = []
    context:  dict       = {}

    if "cloudwatch_metrics" in sources:
        _fetch_cloudwatch(fetcher, evidence, context)

    if "cloudtrail" in sources:
        _fetch_cloudtrail(fetcher, evidence, context)

    if "ecs_events" in sources and hints:
        fetch_start("ECS Events")
        for cluster_hint in hints[:2]:
            _collect(evidence, context, "ecs_events", fetcher.ecs_events(cluster=cluster_hint, service=cluster_hint), extend=True)
        fetch_item("ECS Events", len(context.get("ecs_events", [])))

    if "rds_events" in sources:
        fetch_start("RDS Events")
        evts = fetcher.rds_events()
        _collect(evidence, context, "rds_events", evts)
        if evts:
            fetch_item("RDS Events", len(evts))

    if "codepipeline" in sources:
        fetch_start("CodePipeline")
        evts = fetcher.codepipeline()
        _collect(evidence, context, "pipeline_executions", evts)
        if evts:
            fetch_item("CodePipeline", len(evts))

    if "network_context" in sources:
        fetch_start("Network Context")
        evts = fetcher.network_context()
        _collect(evidence, context, "network_issues", evts)
        if evts:
            fetch_item("Network Context", len(evts))

    return evidence, context

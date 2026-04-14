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
  - If data is insufficient, say so in root_cause.
  - Cite specific timestamps, resource names, and metric values from the evidence.
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

"""Debug analyzer — calls AI with correlated evidence and parses structured response."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from cloudctl.debug.correlator import TimelineEvent


_SYSTEM_PROMPT = """\
You are an expert cloud SRE. You are given a symptom reported by an on-call engineer
and a timeline of evidence from cloud data sources (CloudWatch, CloudTrail, ALB, ECS, RDS, etc.).

Respond ONLY with a JSON object — no markdown, no code block, no explanation outside the JSON.

Required fields:
  root_cause         (string)  — concise technical root cause
  affected_resources (array)   — list of resource identifiers involved
  remediation_steps  (array)   — ordered steps to resolve the issue
  confidence_notes   (string)  — why confidence is high/low (e.g. missing data sources)
  severity           (string)  — LOW | MEDIUM | HIGH | CRITICAL
"""


@dataclass
class AnalysisResult:
    root_cause: str
    affected_resources: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)
    confidence_notes: str = ""
    severity: str = "MEDIUM"
    raw_response: str = ""


def _build_prompt(symptom: str, timeline: list[dict], context: dict) -> str:
    lines = [
        f"SYMPTOM: {symptom}",
        "",
        "EVIDENCE TIMELINE (most recent last):",
    ]
    for ev in timeline[-30:]:  # cap at 30 events
        inf_marker = " ← CHANGE" if ev.get("is_inflection") else ""
        lines.append(f"  {ev.get('time', '—')}  [{ev.get('source', '—')}]  {ev.get('event', '')}{inf_marker}")

    if context:
        lines.append("")
        lines.append("ADDITIONAL CONTEXT:")
        for k, v in context.items():
            if isinstance(v, (str, int, float)):
                lines.append(f"  {k}: {v}")
            elif isinstance(v, list) and v:
                lines.append(f"  {k}: {len(v)} items")

    return "\n".join(lines)


def _parse_response(text: str) -> dict:
    """Extract JSON from AI response text, handling code blocks."""
    text = text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.splitlines()
        # Remove first and last fence lines
        inner = [l for l in lines if not l.startswith("```")]
        text = "\n".join(inner).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find first { ... } block
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
    return AnalysisResult(
        root_cause=parsed.get("root_cause", raw[:500] if raw else "Unknown"),
        affected_resources=parsed.get("affected_resources", []),
        remediation_steps=parsed.get("remediation_steps", []),
        confidence_notes=parsed.get("confidence_notes", ""),
        severity=parsed.get("severity", "MEDIUM"),
        raw_response=raw,
    )

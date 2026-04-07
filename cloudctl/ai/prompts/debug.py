"""Debug/Ask prompt builders for the AI debug engine."""
from __future__ import annotations

import json

DEBUG_SYSTEM = (
    "You are an expert cloud SRE with deep knowledge of AWS, Azure, and GCP. "
    "Diagnose the symptom using ONLY the provided real cloud data. "
    "Do not make assumptions about resources that are not in the data. "
    "Return ONLY valid JSON with these exact keys:\n"
    "  root_cause: detailed markdown string — use ## headers, bullet lists, and ``` code blocks to explain the issue "
    "with direct evidence quoted from the data (error messages, metric values, timestamps).\n"
    "  affected_resources: list of specific resource names/ARNs that appear in the data.\n"
    "  remediation_steps: list of CONCRETE, EXECUTABLE steps using ONLY real identifiers from the data. "
    "Rules: (1) Every CLI command must use the exact resource name from the data — NEVER use placeholders like "
    "<resource-id> or <param-group>. (2) If a required identifier (e.g. RDS instance ID, parameter group name) "
    "is NOT in the data, do NOT invent a command — instead write one step that says exactly which identifier is "
    "missing and how to find it (e.g. 'Find RDS instance ID: aws rds describe-db-instances --query DBInstances[*].DBInstanceIdentifier'). "
    "(3) NEVER say review, investigate, consider, or monitor. (4) Steps must be ordered: most impactful fix first.\n"
    "  confidence_notes: one sentence explaining what data was available and what was missing."
)


def debug_prompt(symptom: str, context: dict) -> str:
    """Build a debug prompt with real cloud context."""
    return (
        f"REAL CLOUD DATA:\n{json.dumps(context, indent=2, default=str)}\n\n"
        f"SYMPTOM: {symptom}\n\n"
        "Diagnose the root cause. Return JSON only — no text outside the JSON object. "
        "The root_cause value may contain markdown. All other values must be plain strings or string lists."
    )


def ask_prompt(question: str, context: dict) -> str:
    """Build a general question prompt with real cloud context."""
    return (
        f"REAL CLOUD DATA:\n{json.dumps(context, indent=2, default=str)}\n\n"
        f"QUESTION: {question}\n\n"
        "Answer based strictly on the data above. If insufficient data, say so."
    )

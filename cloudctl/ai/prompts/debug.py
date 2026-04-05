"""Debug/Ask prompt builders for the AI debug engine."""
from __future__ import annotations

import json

DEBUG_SYSTEM = (
    "You are an expert cloud SRE with deep knowledge of AWS, Azure, and GCP. "
    "Diagnose the symptom using ONLY the provided real cloud data. "
    "Do not make assumptions about resources that are not in the data. "
    "Return ONLY valid JSON with these exact keys: "
    "root_cause (string), affected_resources (list of strings), "
    "remediation_steps (list of actionable strings), confidence_notes (string)."
)


def debug_prompt(symptom: str, context: dict) -> str:
    """Build a debug prompt with real cloud context."""
    return (
        f"REAL CLOUD DATA:\n{json.dumps(context, indent=2, default=str)}\n\n"
        f"SYMPTOM: {symptom}\n\n"
        "Diagnose the root cause and return JSON only. No markdown, no explanation outside JSON."
    )


def ask_prompt(question: str, context: dict) -> str:
    """Build a general question prompt with real cloud context."""
    return (
        f"REAL CLOUD DATA:\n{json.dumps(context, indent=2, default=str)}\n\n"
        f"QUESTION: {question}\n\n"
        "Answer based strictly on the data above. If insufficient data, say so."
    )

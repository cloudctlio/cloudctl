"""Pipeline / DevOps analysis prompts for AI layer."""
from __future__ import annotations

import json


SYSTEM = (
    "You are a senior DevOps engineer. "
    "Analyze the provided pipeline data and identify failures, bottlenecks, and risks. "
    "Only report findings backed by data. Be specific about which pipeline and stage failed."
)


def failure_prompt(pipeline_data: dict, pipeline_name: str) -> str:
    return (
        f"PIPELINE: {pipeline_name}\n"
        f"DATA:\n{json.dumps(pipeline_data, indent=2)}\n\n"
        "Diagnose the failure. Return JSON with keys:\n"
        "  root_cause: what failed and why\n"
        "  failed_stage: stage name\n"
        "  steps: ordered list of resolution steps (match team's IaC/pipeline tooling)\n"
        "  permanent_fix: how to prevent recurrence\n"
        "No markdown fences."
    )


def slow_pipeline_prompt(pipeline_data: dict) -> str:
    return (
        f"PIPELINE DATA:\n{json.dumps(pipeline_data, indent=2)}\n\n"
        "Identify the slowest stages and recommend optimizations. "
        "Return JSON array with: stage, duration_seconds, bottleneck_reason, optimization."
    )


def fix_prompt(issue: dict) -> str:
    return (
        f"PIPELINE ISSUE:\n{json.dumps(issue, indent=2)}\n\n"
        "Generate a fix. Return JSON with keys: steps, iac_note, root_cause. No markdown."
    )

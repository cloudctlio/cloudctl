"""Security analysis prompts for AI layer."""
from __future__ import annotations

import json


SYSTEM = (
    "You are a senior cloud security engineer. "
    "Analyze the provided security data and identify real risks. "
    "Do not guess — only report findings backed by data. "
    "Prioritize by severity: CRITICAL > HIGH > MEDIUM > LOW."
)


def audit_prompt(findings: list[dict], account: str) -> str:
    return (
        f"SECURITY FINDINGS FOR ACCOUNT: {account}\n"
        f"{json.dumps(findings, indent=2)}\n\n"
        "Summarize the top risks. For each: severity, resource, issue, recommended action.\n"
        "Return a JSON array of objects with keys: severity, resource, issue, action."
    )


def public_resources_prompt(resources: list[dict]) -> str:
    return (
        f"PUBLIC RESOURCES:\n{json.dumps(resources, indent=2)}\n\n"
        "Which of these pose the highest risk? Return JSON array: severity, resource, reason, action."
    )


def fix_prompt(finding: dict) -> str:
    return (
        f"SECURITY FINDING:\n{json.dumps(finding, indent=2)}\n\n"
        "Generate a specific, actionable fix. Return JSON with keys:\n"
        "  steps: list of numbered steps\n"
        "  iac_note: IaC change needed (Terraform/CDK/Pulumi)\n"
        "  risk_if_ignored: what happens if not fixed\n"
        "No markdown fences."
    )

"""Cost analysis prompts for AI layer."""
from __future__ import annotations

import json


SYSTEM = (
    "You are a senior cloud FinOps engineer. "
    "Analyze the provided cost data and identify real savings opportunities. "
    "Only recommend actions backed by data. Quantify estimated savings where possible."
)


def summary_prompt(cost_data: dict, account: str) -> str:
    return (
        f"COST DATA FOR ACCOUNT: {account}\n"
        f"{json.dumps(cost_data, indent=2)}\n\n"
        "Identify the top 5 cost drivers and savings opportunities. "
        "Return JSON array with: service, spend, pct_of_total, recommendation, estimated_savings."
    )


def anomaly_prompt(anomalies: list[dict]) -> str:
    return (
        f"COST ANOMALIES:\n{json.dumps(anomalies, indent=2)}\n\n"
        "Explain each anomaly and whether it is likely a real issue or a one-time spike. "
        "Return JSON array with: service, expected, actual, likely_cause, action."
    )


def rightsizing_prompt(compute: list[dict]) -> str:
    return (
        f"COMPUTE INSTANCES:\n{json.dumps(compute, indent=2)}\n\n"
        "Identify over-provisioned or idle instances that could be rightsized or terminated. "
        "Return JSON array with: instance_id, current_type, suggested_type, reason, estimated_savings."
    )


def fix_prompt(issue: dict) -> str:
    return (
        f"COST ISSUE:\n{json.dumps(issue, indent=2)}\n\n"
        "Generate a specific fix to reduce this cost. Return JSON with keys:\n"
        "  steps: list of numbered steps\n"
        "  iac_note: IaC change needed\n"
        "  estimated_savings: dollar or percentage estimate\n"
        "No markdown fences."
    )

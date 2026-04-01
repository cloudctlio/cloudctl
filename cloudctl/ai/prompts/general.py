"""General cloud infrastructure prompts for AI layer."""
from __future__ import annotations

import json


SYSTEM = (
    "You are a senior cloud infrastructure expert. "
    "Answer questions using ONLY the real data provided. "
    "Cite specific resource names and values. "
    "If data is insufficient, say so explicitly. Never guess."
)


def question_prompt(question: str, context: dict) -> str:
    return (
        f"REAL DATA FROM CLOUD:\n{json.dumps(context, indent=2)}\n\n"
        f"QUESTION: {question}\n\n"
        "Base your answer strictly on the data above."
    )


def summarize_prompt(context: dict, focus: str = "all") -> str:
    return (
        f"CLOUD INFRASTRUCTURE SUMMARY:\n{json.dumps(context, indent=2)}\n\n"
        f"Provide a concise operational summary focusing on: {focus}. "
        "Highlight anything unusual, expensive, or risky. "
        "Return JSON with keys: summary, highlights, concerns."
    )


def compare_prompt(left: dict, right: dict, label_left: str = "left", label_right: str = "right") -> str:
    return (
        f"COMPARE TWO ENVIRONMENTS:\n\n"
        f"{label_left.upper()}:\n{json.dumps(left, indent=2)}\n\n"
        f"{label_right.upper()}:\n{json.dumps(right, indent=2)}\n\n"
        "What are the key differences? Return JSON with keys:\n"
        "  only_in_left: list of resources\n"
        "  only_in_right: list of resources\n"
        "  config_differences: list of config diffs\n"
        "  concerns: any asymmetries that look risky"
    )

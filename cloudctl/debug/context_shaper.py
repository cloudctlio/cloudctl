"""Context shaping — what the model sees, in what order, within a size budget.

The inventory from DataFetcher is nested as context["aws"][<profile>][...],
so pruning and dedup have to walk the whole tree, not just top-level keys.
"""
from __future__ import annotations

import json

# Characters of serialized JSON sent to the model (~4 chars per token, so
# ~30k tokens). Leaves room for the system prompt and the answer.
DEFAULT_BUDGET_CHARS = 120_000

# Highest priority first. Lists under lower-priority keys are trimmed first
# when the context is over budget.
KEY_PRIORITY = (
    # Resource-specific evidence the symptom fetch found
    "acm_issues",
    "ecs_stopped",
    "ecs_service_details",
    "alb_resource_map",
    "lambda_function_config",
    "lambda_report",
    "sqs_dlq",
    "rds_slow",
    "rds_instance_config",
    "aurora_cluster_config",
    "redshift_cluster_config",
    "codepipeline_resource",
    # Event streams
    "audit_logs",
    "service_logs",
    # Deployment / IaC
    "iac_resource_config",
    "deployment_method",
    "acm_expiry_check",
    "network_context",
    # Broad inventory last: the first thing to trim
    "aws",
    "azure",
    "gcp",
)

# Lists where the newest entries are at the end (keep the tail when trimming)
# CloudWatch Logs returns oldest first, so keep the tail. CloudTrail returns
# newest first, so audit_logs keeps its head (the default).
_TIME_ORDERED_KEYS = {"service_logs"}

_UNHEALTHY = {"stopped", "stopping", "failed", "error", "degraded",
              "impaired", "unavailable", "draining", "inactive"}
_HEALTHY   = {"running", "active", "available", "ok", "healthy", "started"}
_PRUNABLE  = {"compute", "database"}


def _prune_list(key: str, items: list) -> list:
    if len(items) <= 5:
        return items
    tier1, tier2 = [], []
    for item in items:
        if not isinstance(item, dict):
            tier1.append(item)
            continue
        state = str(item.get("state") or item.get("status") or "").lower()
        if state in _UNHEALTHY or (state and state not in _HEALTHY):
            tier1.append(item)
        else:
            tier2.append({"name": item.get("name") or item.get("id", ""), "state": state or "unknown"})
    pruned = tier1 + tier2[:3]
    if len(tier2) > 3:
        pruned.append({"_summary": f"{len(tier2) - 3} additional healthy {key} resources omitted"})
    return pruned


def prune_nested(node) -> None:
    """Health-tier compute/database lists at any depth (in place)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _PRUNABLE and isinstance(value, list):
                node[key] = _prune_list(key, value)
            else:
                prune_nested(value)
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                prune_nested(item)


def _identity(item: dict):
    return item.get("arn") or item.get("ARN") or item.get("id") or item.get("name")


def dedup_nested(node, seen: set | None = None) -> None:
    """Drop resources already seen elsewhere in the tree (in place).

    Only items with a stable identity (arn/id/name) are deduped. Event dicts
    keyed by 'source' are left alone: many log lines share one source.
    """
    seen = set() if seen is None else seen
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, list):
                kept = []
                for item in value:
                    if isinstance(item, dict):
                        ident = _identity(item)
                        if ident and "event" not in item:
                            if ident in seen:
                                continue
                            seen.add(ident)
                        dedup_nested(item, seen)
                    kept.append(item)
                node[key] = kept
            elif isinstance(value, dict):
                dedup_nested(value, seen)


def serialize(context: dict) -> str:
    """Compact JSON for the prompt (indentation alone can double the size)."""
    return json.dumps(context, separators=(",", ":"), default=str)


def _ordered_keys(context: dict) -> list[str]:
    known = [k for k in KEY_PRIORITY if k in context]
    other = [k for k in context if k not in KEY_PRIORITY]
    return known + other


def fit_to_budget(context: dict, max_chars: int = DEFAULT_BUDGET_CHARS) -> list[str]:
    """Trim lists from the lowest-priority keys until the context fits.

    Returns a list of notes about what was trimmed, so the prompt can tell
    the model (and the user) that data was left out.
    """
    notes: list[str] = []
    if len(serialize(context)) <= max_chars:
        return notes

    for key in reversed(_ordered_keys(context)):
        if len(serialize(context)) <= max_chars:
            break
        value = context[key]
        if isinstance(value, list) and value:
            keep_tail = key in _TIME_ORDERED_KEYS
            original = len(value)
            while value and len(serialize(context)) > max_chars:
                cut = max(1, len(value) // 4)
                value = value[cut:] if keep_tail else value[:-cut]
                context[key] = value
            notes.append(f"{key}: kept {len(value)} of {original} items to fit the size budget")
        elif isinstance(value, dict):
            before = len(serialize(context))
            context[key] = {"_summary": f"{key} omitted to fit the size budget"}
            if len(serialize(context)) < before:
                notes.append(f"{key}: omitted to fit the size budget")
    return notes

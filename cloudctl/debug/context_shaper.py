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
    # What could not be fetched (small; says which data is partial)
    "source_errors",
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


def _dedup_key(list_key: str, item: dict):
    """Key for spotting the same resource in two places, or None to keep it.

    An ARN or a provider id names one resource, so the same one under two
    profiles (or a profile and a symptom fetch) is a true duplicate. A bare
    name is not: a Lambda and an ALB can both be called "api", and two
    accounts can each have a "worker". Name-only items are dropped only when
    they are identical in full.
    """
    if "event" in item:  # log lines and audit events share sources; keep all
        return None
    ident = item.get("arn") or item.get("ARN") or item.get("id")
    if ident:
        return (list_key, "id", str(ident))
    return (list_key, "full", json.dumps(item, sort_keys=True, default=str))


def dedup_nested(node, seen: set | None = None) -> None:
    """Drop resources already listed elsewhere in the tree (in place).

    Resource lists are found by walking dicts. The key is the list's own key
    plus the resource's identity, so only lists of the same kind dedupe
    against each other ("compute" with "compute"). The walk never goes into a
    resource itself: env vars, tags, containers and rules are attributes of
    that resource and must stay whole.
    """
    seen = set() if seen is None else seen
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if isinstance(value, list):
            kept = []
            for item in value:
                if isinstance(item, dict):
                    dk = _dedup_key(key, item)
                    if dk is not None:
                        if dk in seen:
                            continue
                        seen.add(dk)
                kept.append(item)
            node[key] = kept
        elif isinstance(value, dict):
            dedup_nested(value, seen)


def serialize(context: dict) -> str:
    """Compact JSON for the prompt (indentation alone can double the size)."""
    return json.dumps(context, separators=(",", ":"), default=str)


_INVENTORY_KEYS = ("aws", "azure", "gcp")


def _ordered_keys(context: dict) -> list[str]:
    """Highest priority first: known evidence, then unknown keys, then inventory.

    Unknown keys are usually new evidence a fetcher added; the broad inventory
    is the cheapest thing to lose, so it sits last and is trimmed first.
    """
    known = [k for k in KEY_PRIORITY if k in context and k not in _INVENTORY_KEYS]
    other = [k for k in context if k not in KEY_PRIORITY]
    inventory = [k for k in _INVENTORY_KEYS if k in context]
    return known + other + inventory


def _size(context: dict) -> int:
    return len(serialize(context))


def _inner_lists(node, path: str, out: list) -> None:
    """Collect (path, parent, key) for every non-empty list reachable via dicts."""
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        sub = f"{path}.{key}"
        if isinstance(value, list) and value:
            out.append((sub, node, key))
        elif isinstance(value, dict):
            _inner_lists(value, sub, out)


def _cut(items: list, keep_tail: bool, excess: int) -> list:
    """Drop just enough items (oldest or newest end) to save ``excess`` chars."""
    saved, n = 0, 0
    order = items if keep_tail else reversed(items)
    for item in order:
        if saved >= excess:
            break
        saved += len(serialize({"x": item})) - 5  # the item plus its comma
        n += 1
    n = max(1, n)
    return items[n:] if keep_tail else items[:-n]


def _shrink_dict(context: dict, key: str, max_chars: int) -> list[str]:
    """Trim the largest lists inside context[key] until the context fits.

    Each pass takes just enough off whichever inner list is biggest, so a
    context that is barely over budget loses a few items, not a whole section.
    """
    originals: dict[str, int] = {}
    lists: list = []
    _inner_lists(context[key], key, lists)
    while lists and _size(context) > max_chars:
        lists.sort(key=lambda t: len(serialize({"x": t[1][t[2]]})), reverse=True)
        path, parent, lkey = lists[0]
        items = parent[lkey]
        originals.setdefault(path, len(items))
        parent[lkey] = _cut(items, lkey in _TIME_ORDERED_KEYS, _size(context) - max_chars)
        if not parent[lkey]:
            lists.pop(0)
    return [f"{p}: kept {len(_get(context, p))} of {n} items to fit the size budget"
            for p, n in originals.items()]


def _get(context: dict, path: str):
    node = context
    for part in path.split("."):
        node = node[part]
    return node


def fit_to_budget(context: dict, max_chars: int = DEFAULT_BUDGET_CHARS) -> list[str]:
    """Trim lists from the lowest-priority keys until the context fits.

    Returns a list of notes about what was trimmed, so the prompt can tell
    the model (and the user) that data was left out. A whole section is
    replaced by a summary only when trimming its lists was not enough.
    """
    notes: list[str] = []
    if _size(context) <= max_chars:
        return notes

    for key in reversed(_ordered_keys(context)):
        if _size(context) <= max_chars:
            break
        value = context[key]
        if isinstance(value, list) and value:
            keep_tail = key in _TIME_ORDERED_KEYS
            original = len(value)
            while value and _size(context) > max_chars:
                value = _cut(value, keep_tail, _size(context) - max_chars)
                context[key] = value
            notes.append(f"{key}: kept {len(value)} of {original} items to fit the size budget")
        elif isinstance(value, dict):
            notes.extend(_shrink_dict(context, key, max_chars))
            if _size(context) > max_chars:
                before = _size(context)
                context[key] = {"_summary": f"{key} omitted to fit the size budget"}
                if _size(context) < before:
                    notes.append(f"{key}: omitted to fit the size budget")
    return notes

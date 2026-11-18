"""Expected-state diff: live config vs what the IaC (or baseline) declares."""

from __future__ import annotations

import time
from typing import Any

from cloudctl.debug.diff_first.iac import ExpectedState
from cloudctl.debug.diff_first.live import NOT_FOUND
from cloudctl.debug.diff_first.model import DriftItem
from cloudctl.debug.diff_first.normalize import OBSERVER_TYPES, diff_configs
from cloudctl.debug.diff_first.topology import FLOW_TYPES
from cloudctl.debug.diff_first.normalize import ATTACHMENT_TYPES


def compute_drift(expected: ExpectedState, live: Any, deadline: float | None = None,
                  max_reads: int = 120) -> tuple[list[DriftItem], dict, dict]:
    """Return (drift items, stats, live configs read). Resources the IaC tool already diffed
    (CloudFormation drift detection, Terraform plan drift) are not re-read."""
    items: list[DriftItem] = list(expected.drift)
    already = {d.resource_key for d in items}
    stats = {"compared": 0, "unreadable": 0, "skipped_budget": 0, "tool_drift": len(items)}
    # Read the resources that can change behaviour first; observers last.
    order = sorted(expected.resources.values(), key=lambda r: (
        r.type in OBSERVER_TYPES, r.type not in FLOW_TYPES and r.type not in ATTACHMENT_TYPES, r.key))
    reads = 0
    configs: dict[str, dict] = {}
    for r in order:
        if r.key in already or r.type in OBSERVER_TYPES:
            continue
        if deadline is not None and time.monotonic() > deadline:
            stats["skipped_budget"] += 1
            continue
        if reads >= max_reads:
            stats["skipped_budget"] += 1
            continue
        reads += 1
        try:
            cfg = live.read(r)
        except Exception:  # noqa: BLE001
            cfg = None
        if cfg is None:
            stats["unreadable"] += 1
            continue
        configs[r.key] = cfg
        if cfg is NOT_FOUND or (isinstance(cfg, dict) and cfg.get("__not_found__")):
            items.append(DriftItem(r.key, r.type, r.label(), [], kind="deleted",
                                   source=f"{expected.kind} vs live"))
            continue
        stats["compared"] += 1
        fields = diff_configs(r.config, cfg)
        if fields:
            items.append(DriftItem(r.key, r.type, r.label(), fields,
                                   source=f"{expected.kind} vs live"))
    return items, stats, configs

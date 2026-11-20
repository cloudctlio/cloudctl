"""Expected-state diff: live config vs what the IaC (or baseline) declares.

Monitors (alarms, alert rules, dashboards, log pipelines) are compared too and
their drift is reported with ``observer=True``: a hand-raised threshold or a
switched-off alarm action hides the next outage, so it is a finding. It is
never a cause candidate (``explain`` keeps observers out of every scope)."""

from __future__ import annotations

import time
from typing import Any

from cloudctl.debug.diff_first.iac import ExpectedState
from cloudctl.debug.diff_first.live import NOT_FOUND
from cloudctl.debug.diff_first.model import DriftItem
from cloudctl.debug.diff_first.normalize import ATTACHMENT_TYPES, diff_configs, is_observer
from cloudctl.debug.diff_first.topology import FLOW_TYPES


def compute_drift(expected: ExpectedState, live: Any, deadline: float | None = None,
                  max_reads: int = 120) -> tuple[list[DriftItem], dict, dict]:
    """Return (drift items, stats, live configs read). Resources the IaC tool already diffed
    (CloudFormation drift detection, Terraform plan drift) are not re-read."""
    items: list[DriftItem] = list(expected.drift)
    for d in items:
        d.observer = is_observer(d.resource_type)
    already = {d.resource_key for d in items}
    stats = {"compared": 0, "unreadable": 0, "skipped_budget": 0, "tool_drift": len(items),
             "observers_compared": 0, "observers_skipped_budget": 0, "compared_keys": []}
    # Read the resources that can change behaviour first; observers last, so a
    # tight budget still covers everything that can cause an outage.
    order = sorted(expected.resources.values(), key=lambda r: (
        is_observer(r.type), r.type not in FLOW_TYPES and r.type not in ATTACHMENT_TYPES, r.key))
    reads = 0
    configs: dict[str, dict] = {}
    for r in order:
        obs = is_observer(r.type)
        if r.key in already:
            continue
        if (deadline is not None and time.monotonic() > deadline) or reads >= max_reads:
            stats["skipped_budget"] += 1
            stats["observers_skipped_budget"] += int(obs)
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
                                   source=f"{expected.kind} vs live", observer=obs))
            continue
        stats["compared"] += 1
        stats["observers_compared"] += int(obs)
        stats["compared_keys"].append(r.key)
        fields = diff_configs(r.config, cfg)
        if fields:
            items.append(DriftItem(r.key, r.type, r.label(), fields,
                                   source=f"{expected.kind} vs live", observer=obs))
    return items, stats, configs

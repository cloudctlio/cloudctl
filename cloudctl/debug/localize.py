"""LOCALIZE pillar of the frontier-honest engine.

A diagnosis must anchor on the component that is ACTUALLY emitting the failure —
not on whatever configuration happens to look unusual on a quiet component. The
recurring hallucinations (blaming a benign authorizer, an IAM role churned by a
prior deploy) all share one shape: the agent built a story around a component
that was NOT failing, while the component that WAS failing sat un-inspected.

This module reads recent log/telemetry lines per discovered component and reports
which components are genuinely failing right now, with the failure message. It is
SERVICE-AGNOSTIC: it never judges what a component's config "should" look like —
it only reports observed failure. That is what makes it transfer to workloads we
have never tested. Where a fault is silent (emits no signal at all), this map is
correctly EMPTY, and the frontier-honest core takes over (report the boundary,
reproduce to confirm) rather than fabricate.
"""
from __future__ import annotations

import re

# Generic error-in-a-log-line detection. Log lines are where runtime failures
# surface; these markers are universal across languages/services. Kept broad for
# LOGS specifically (unlike the conservative report-claim check in guardrails),
# because a line that says ERROR / Exception / Traceback / denied / timeout IS an
# observed failure regardless of the service that emitted it.
_ERROR_LINE = re.compile(
    r'(\[ERROR\]|\bERROR\b|\bCRITICAL\b|\bFATAL\b|traceback|exception'
    r'|\bfailed\b|\bfailure\b|\bdenied\b|accessdenied|unauthorized'
    r'|timeout|timed out|throttl|refused|unreachable|\bpanic\b|oomkill'
    r'|\b5\d\d\b|\b429\b|\braise[sd]?\b)',
    re.I,
)
# Lines that merely contain a zero-valued metric or the word "error" in a benign
# field name ("errorCount": 0) must not count as a failure.
_BENIGN = re.compile(r'("?errors?"?\s*[:=]\s*0\b|no errors|0 errors|error_?rate"?\s*[:=]\s*0)', re.I)


def _clean(line: str) -> str:
    return re.sub(r'\s+', ' ', str(line)).strip()


def localize_failures(component_logs: dict) -> list:
    """Given {component_name: [recent log lines]}, return a failure map:
    [{component, error_count, sample}] for the components actually emitting
    failures, ranked by error_count (desc). Components with no observed failure
    are omitted. Pure/deterministic; service-agnostic.
    """
    failure_map: list = []
    for component, lines in (component_logs or {}).items():
        hits = []
        for ln in lines or []:
            s = _clean(ln)
            if not s:
                continue
            if _BENIGN.search(s):
                continue
            if _ERROR_LINE.search(s):
                hits.append(s)
        if hits:
            # Sample = the most informative error line (longest tends to carry the
            # message/stack head); truncate for the evidence corpus.
            sample = max(hits, key=len)[:280]
            failure_map.append({
                "component": component,
                "error_count": len(hits),
                "sample": sample,
            })
    failure_map.sort(key=lambda e: -e["error_count"])
    return failure_map


def diagnosis_is_anchored(root_cause: str, failure_map: list) -> bool:
    """True when the diagnosis anchors on a component that is ACTUALLY emitting a
    failure. If the failure_map is non-empty, the root cause should name one of the
    emitting components; blaming a component that is absent from the map (a quiet
    one) while another is actively failing is the localization miss behind the
    hallucinations. An EMPTY map imposes no constraint — a silent fault legitimately
    emits nothing, and the frontier-honest core owns that case."""
    if not failure_map:
        return True
    rc = (root_cause or "").lower()
    return any(str(e.get("component", "")).lower() in rc
               for e in failure_map if e.get("component"))


def enforce_localization_anchor(agent_output: dict, failure_map: list) -> dict:
    """When components are observably failing but the verdict blames a component
    that is NOT among them, the diagnosis is mis-localized: downgrade confidence
    and surface WHERE the failures actually are. Deterministic; does not rewrite
    the root cause (that is the reasoning pass's job) but refuses to let a
    mis-localized verdict ship confidently."""
    import copy
    if not failure_map or diagnosis_is_anchored(agent_output.get("root_cause", ""), failure_map):
        return agent_output
    claimed = agent_output.get("confidence", "MEDIUM")
    output = copy.deepcopy(agent_output)
    emitting = ", ".join(str(e.get("component")) for e in failure_map[:3])
    output["localization"] = {
        "anchored": False,
        "emitting_components": [e.get("component") for e in failure_map],
        "note": (f"The root cause names a component that is not among those observed "
                 f"emitting failures. Components actually failing now: {emitting}. "
                 "Anchor the diagnosis on an emitting component."),
    }
    if claimed != "LOW":
        output["confidence"] = "LOW"
        output["confidence_override_reason"] = (
            f"Confidence capped from {claimed} to LOW: the verdict blames a component "
            f"that is not emitting any failure, while these are: {emitting}. The "
            "diagnosis is not localized to where the failure is actually observed."
        )
    return output


def scan_component_failures(fetcher, components: list, minutes: int = 60,
                            per_group_lines: int = 60) -> list:
    """Wire the pure localizer to real telemetry. For each discovered component
    name, find its log group(s) and read recent lines, then localize. Best-effort
    and defensive: a component with no log group / no access is simply absent from
    the map (never an exception). `fetcher` is a DebugFetcher-like object exposing
    discover_log_groups(prefix, limit) and tail_log_group(log_group, lines)."""
    component_logs: dict = {}
    for comp in components or []:
        name = comp if isinstance(comp, str) else (comp.get("name") or comp.get("resource_name") or "")
        if not name:
            continue
        try:
            groups = fetcher.discover_log_groups(name, limit=3) or []
        except Exception:  # noqa: BLE001
            groups = []
        lines: list = []
        for g in groups:
            try:
                events = fetcher.tail_log_group(g, lines=per_group_lines) or []
            except Exception:  # noqa: BLE001
                events = []
            for ev in events:
                lines.append(ev.get("message", ev) if isinstance(ev, dict) else ev)
        if lines:
            component_logs[name] = lines
    return localize_failures(component_logs)

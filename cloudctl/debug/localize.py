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


# Distinctive error identifiers: exception classes and API error codes
# (ProvisionedThroughputExceededException, AccessDenied, ThrottlingException,
# ConditionalCheckFailedException ...). Language-generic classes say nothing
# about WHICH dependency failed, so they never link a verdict to a failure.
_ERROR_ID = re.compile(
    r'\b([A-Z][A-Za-z0-9]{2,}(?:Exception|Error|Exceeded|Denied|Fault'
    r'|Throttling|Throttled|Timeout|Unavailable|Failed))\b')
_GENERIC_IDS = {
    "RuntimeError", "ClientError", "BotoCoreError", "ServiceException",
    "TypeError", "ValueError", "KeyError", "AttributeError", "IndexError",
    "NameError", "AssertionError", "InternalError", "InternalServerError",
    "UnknownError", "UnhandledException", "HandlerError", "LambdaError",
    "SystemError", "OSError", "IOError", "ImportError",
}
# Resource-like names: at least one separator, so ordinary words ("orders",
# "table") never count as a reference to a component.
_NAME = re.compile(r'(?<![A-Za-z0-9_.-])([A-Za-z0-9][A-Za-z0-9_.-]*[-_.][A-Za-z0-9_.-]*[A-Za-z0-9])')
# Tokens that look like names but identify nothing in particular: request
# ids, numbers, dates, source files, regions, AWS service endpoints, and
# dotted error classes (Runtime.UnhandledException).
_NOISE = re.compile(
    r'^(?:[0-9a-f-]{16,}|[0-9.:_-]+|\d{4}-\d{2}-\d{2}.*'
    r'|[a-z0-9_.]+\.(?:py|js|ts|go|java|rb)'
    r'|[a-z]{2}(?:-gov)?-[a-z]+-\d'
    r'|(?:[a-z0-9-]+\.)?(?:[a-z]{2}(?:-gov)?-[a-z]+-\d\.)?amazonaws\.com'
    r'|.*(?:exception|error))$', re.I)


def _error_ids(text: str) -> set:
    return {m for m in _ERROR_ID.findall(text or "") if m not in _GENERIC_IDS}


def _names(text: str, exclude: set) -> set:
    """Resource-like tokens in free text, including each segment of an ARN or
    path (arn:...:table/orders-prod -> orders-prod)."""
    out = set()
    for tok in _NAME.findall(text or ""):
        for part in {tok, *re.split(r'[/:]', tok)}:
            part = part.strip(".-_")
            if (len(part) >= 6 and _NAME.fullmatch(part) and not _NOISE.match(part)
                    and part.lower() not in exclude):
                out.add(part.lower())
    for arn in re.findall(r'arn:aws[a-z0-9-]*:[^\s"\',]+', text or ""):
        for part in re.split(r'[/:]', arn):
            if (len(part) >= 6 and _NAME.fullmatch(part) and not _NOISE.match(part)
                    and part.lower() not in exclude):
                out.add(part.lower())
    return out


def _mentions(text: str, token: str) -> bool:
    return re.search(r'(?<![A-Za-z0-9_-])' + re.escape(token) + r'(?![A-Za-z0-9_-])',
                     text or "", re.I) is not None


def _string_values(obj, limit: int = 4000) -> list:
    """Every string value in a fetched config, flattened (bounded)."""
    out: list = []
    stack = [obj]
    while stack and len(out) < limit:
        cur = stack.pop()
        if isinstance(cur, str):
            if cur.lstrip().startswith(("{", "[")):
                try:
                    import json
                    stack.append(json.loads(cur))
                    continue
                except Exception:  # noqa: BLE001
                    pass
            out.append(cur)
        elif isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, (list, tuple)):
            stack.extend(cur)
    return out


def failure_link(agent_output: dict, failure_map: list, all_fetched: dict | None = None) -> dict | None:
    """Find evidence that ties a component observed emitting failures to the
    component the verdict blames, when the verdict names that cause rather
    than the emitting component itself (an upstream or downstream cause: a
    throttled table behind a failing function, a role behind denied calls).

    Service-agnostic. A link is any of:
      * the emitting component's own error lines name a resource the root
        cause names (an error that says which table/queue/host failed);
      * a distinctive error identifier from those lines (an exception class
        or API error code, not a generic language error) is in the root cause;
      * a verdict evidence line names the emitting component (or carries one
        of its error identifiers) and also names a resource the root cause
        names;
      * fetched configuration of the emitting component holds, as a whole
        value or ARN/path segment, a resource the root cause names (a declared
        dependency, e.g. an environment variable pointing at the table).
    Returns {"component", "via", "detail"} for the first link found, else None.
    """
    rc = str(agent_output.get("root_cause") or "")
    if not rc or not failure_map:
        return None
    evidence = [str(e) for e in (agent_output.get("evidence") or []) if e]
    emitting = {str(e.get("component", "")).lower() for e in failure_map if e.get("component")}
    rc_names = _names(rc, emitting)

    for entry in failure_map:
        comp = str(entry.get("component") or "")
        if not comp:
            continue
        lines = [str(x) for x in (entry.get("samples") or [])] or [str(entry.get("sample") or "")]
        text = " ".join(lines)
        ids = set(entry.get("error_ids") or []) | _error_ids(text)
        ids -= _GENERIC_IDS

        for name in sorted(_names(text, emitting)):
            if _mentions(rc, name):
                return {"component": comp, "via": "error_names_cause",
                        "detail": f"{comp}'s errors name {name}, which the root cause blames"}
        for eid in sorted(ids):
            if _mentions(rc, eid):
                return {"component": comp, "via": "error_id_in_root_cause",
                        "detail": f"the root cause explains {comp}'s {eid}"}
        for ev in evidence:
            if (_mentions(ev, comp) or any(_mentions(ev, i) for i in ids)):
                hit = next((n for n in sorted(rc_names) if _mentions(ev, n)), None)
                if hit:
                    return {"component": comp, "via": "evidence_links",
                            "detail": f"evidence ties {comp}'s failure to {hit}"}
        if all_fetched and rc_names:
            for key, val in all_fetched.items():
                if not _mentions(str(key), comp):
                    continue
                values = _string_values(val)
                for name in sorted(rc_names):
                    for v in values:
                        segs = {v.strip().lower(), *(x.lower() for x in re.split(r'[/:]', v.strip()))}
                        if name in segs:
                            return {"component": comp, "via": "declared_dependency",
                                    "detail": f"{comp}'s configuration references {name}"}
    return None


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
            distinct = list(dict.fromkeys(h[:280] for h in hits))
            failure_map.append({
                "component": component,
                "error_count": len(hits),
                "sample": sample,
                # A few distinct lines and the error identifiers they carry, so
                # the anchor check can see what the failure points at (a
                # downstream resource, an error code) — not only one line.
                "samples": sorted(distinct, key=len, reverse=True)[:5],
                "error_ids": sorted(_error_ids(" ".join(hits)))[:10],
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


def enforce_localization_anchor(agent_output: dict, failure_map: list,
                                all_fetched: dict | None = None) -> dict:
    """When components are observably failing but the verdict blames a component
    that is NOT among them, and nothing ties the blamed component to the
    observed failure, the diagnosis is mis-localized: downgrade confidence and
    surface WHERE the failures actually are. A cause upstream or downstream of
    the emitting component is localized when evidence links the two (see
    failure_link) and is left alone. Deterministic; does not rewrite the root
    cause (that is the reasoning pass's job) but refuses to let a mis-localized
    verdict ship confidently."""
    import copy
    if not failure_map or diagnosis_is_anchored(agent_output.get("root_cause", ""), failure_map):
        return agent_output
    link = failure_link(agent_output, failure_map, all_fetched)
    if link:
        output = copy.deepcopy(agent_output)
        output["localization"] = {
            "anchored": True,
            "emitting_components": [e.get("component") for e in failure_map],
            "linked_via": link["via"],
            "note": (f"The root cause names a component other than the one emitting "
                     f"failures, and {link['detail']}."),
        }
        return output
    claimed = agent_output.get("confidence", "MEDIUM")
    output = copy.deepcopy(agent_output)
    emitting = ", ".join(str(e.get("component")) for e in failure_map[:3])
    output["localization"] = {
        "anchored": False,
        "emitting_components": [e.get("component") for e in failure_map],
        "note": (f"The root cause names a component that is not among those observed "
                 f"emitting failures, and no evidence links it to them. Components "
                 f"actually failing now: {emitting}. Anchor the diagnosis on an "
                 "emitting component, or show how the blamed one causes its errors."),
    }
    if claimed != "LOW":
        output["confidence"] = "LOW"
        output["confidence_override_reason"] = (
            f"Confidence capped from {claimed} to LOW: the verdict blames a component "
            f"that is not emitting any failure, while these are: {emitting}, and no "
            "evidence links the two. The diagnosis is not localized to where the "
            "failure is actually observed."
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

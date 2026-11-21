"""Explain-everything: a diagnosis must account for every observed symptom, and
each cause must come before the symptom it explains.

Candidates are the drifted resources and the in-window changes that still
hold. A candidate explains a symptom when it sits inside the symptom's scope
(from the wiring) and is not later than the symptom's onset. We then pick the
smallest set of candidates that covers all symptoms (several causes are
allowed). Any symptom no candidate explains stays on the table: the search
is not finished and confidence is capped.
"""

from __future__ import annotations

from datetime import timedelta

from cloudctl.debug.diff_first.changes import _value_keys
from cloudctl.debug.diff_first.model import Candidate, Change, DriftItem, Symptom, to_dt
from cloudctl.debug.diff_first.normalize import identifiers_in
from cloudctl.debug.diff_first.topology import FLOW_TYPES, Topology, service_of_type, services_in

ONSET_SKEW_S = 120


def build_candidates(drift: list[DriftItem], changes: list[Change], window_start: str | None,
                     topo: Topology) -> tuple[list[Candidate], list[dict]]:
    """Merge drift and in-window changes into candidates. Drift whose latest
    recorded change predates the last healthy point was there while the system
    was healthy, so it is context, not a cause."""
    cands: list[Candidate] = []
    context: list[dict] = []
    start = to_dt(window_start)
    by_key_changes: dict[str, list[Change]] = {}
    for c in changes:
        for k in filter(None, c.resource_key.split(",")):
            by_key_changes.setdefault(k, []).append(c)
    used_drift: set[int] = set()
    for c in changes:
        if c.status not in ("candidate", "after_metrics"):
            continue
        keys = [k for k in c.resource_key.split(",") if k]
        drift_here = [d for d in drift if d.resource_key in keys]
        for d in drift_here:
            used_drift.add(id(d))
            d.changed_at, d.changed_by = c.time, c.actor
        cands.append(Candidate(
            id=f"C{len(cands) + 1}", kind="change+drift" if drift_here else "change",
            resource_key=",".join(keys), resource_name=c.resource_name, time=c.time,
            summary=f"{c.event_name} on {c.resource_name} at {c.time} by {c.actor or 'unknown'}"
                    + (f"; live differs from declared on {', '.join(f['field'] for d in drift_here for f in d.fields[:4])}"
                       if drift_here else ""),
            evidence={"params": c.params, "drift": [d.to_dict() for d in drift_here],
                      "holds": c.reason, "event": c.event_name,
                      "after_metrics": c.status == "after_metrics",
                      "restores": c.restores and not drift_here,
                      "one_off": c.one_off and not drift_here}))
    for d in drift:
        if id(d) in used_drift:
            continue
        hist = sorted(by_key_changes.get(d.resource_key, []), key=lambda c: c.time or "")
        last = hist[-1] if hist else None
        if last is not None:
            d.changed_at, d.changed_by = last.time, last.actor
        if last is not None and start and to_dt(last.time) and to_dt(last.time) < start:
            d.note = (f"last changed at {last.time}, before the last healthy point: it was "
                      "already there while the system worked")
            context.append({"drift": d.to_dict(), "why_not_a_cause": d.note})
            continue
        what = ("deleted outside IaC" if d.kind == "deleted" else
                f"live differs from declared on {', '.join(str(f['field']) for f in d.fields[:5])}")
        cands.append(Candidate(
            id=f"C{len(cands) + 1}", kind="drift", resource_key=d.resource_key,
            resource_name=d.resource_name, time=d.changed_at,
            summary=f"{d.resource_name or d.resource_key}: {what}"
                    + ("" if d.changed_at else " (when it changed is unknown)"),
            evidence={"drift": [d.to_dict()]}))
    return cands, context


def _changed_values(c: Candidate) -> list:
    vals: list = [c.evidence.get("params") or {}]
    for d in c.evidence.get("drift") or []:
        for f in d.get("fields") or []:
            vals.extend([f.get("expected"), f.get("live")])
    return vals


def _settings(c: Candidate) -> dict:
    params = c.evidence.get("params") or {}
    if not isinstance(params, dict):
        return {}
    from cloudctl.debug.diff_first.changes import _value_keys
    return _value_keys(params)


_OFF_WORDS = {"false", "disabled", "disabling", "inactive", "off", "paused", "stopped"}


def _switches_off(c: Candidate) -> bool:
    """True when every value the candidate changed is an on/off switch now set
    to off (Enabled=false, State=DISABLED). Field names only, any service."""
    seen = False
    for d in c.evidence.get("drift") or []:
        for f in d.get("fields") or []:
            leaf = str(f.get("field", "")).split(".")[-1].lower()
            if leaf not in ("enabled", "state", "status"):
                return False
            if str(f.get("live")).lower() not in _OFF_WORDS:
                return False
            seen = True
    params = c.evidence.get("params") or {}
    vals = {k.split(".")[-1].lower(): v for k, v in params.items()
            if not k.lower().endswith(("name", "arn", "id", "uuid", "url"))} if isinstance(params, dict) else {}
    for k, v in vals.items():
        if k not in ("enabled", "state", "status"):
            return False
        if str(v).lower() not in _OFF_WORDS:
            return False
        seen = True
    return seen


def explains(c: Candidate, s: Symptom, topo: Topology) -> str:
    """'' when it doesn't; else how: direct | link | repointed."""
    t, onset = to_dt(c.time), to_dt(s.onset)
    if t and onset and t > onset + timedelta(seconds=ONSET_SKEW_S):
        return ""
    keys = set(filter(None, c.resource_key.split(",")))
    if s.kind == "errors_up" and keys and all(topo.is_connector(k) for k in keys) and _switches_off(c):
        # A connector switched off (a disabled trigger or rule) stops work from
        # arriving; it raises no errors anywhere, so it can't explain an error rise.
        return ""
    if keys & set(s.scope):
        return "direct"
    vals = _changed_values(c)
    if s.link_scope and keys & set(s.link_scope):
        target_tokens = set().union(*(topo.resources[k].tokens() for k in s.link_targets
                                      if k in topo.resources)) if s.link_targets else set()
        target_svcs = {service_of_type(topo.type_of(k)) for k in s.link_targets}
        if identifiers_in(vals) & target_tokens or services_in(vals) & target_svcs:
            return "link"
    if s.open_service and s.open_service in services_in(vals):
        return "repointed"
    return ""


_STRENGTH = {"direct": 3, "link": 2, "repointed": 1}

# How close to the end of the metrics a fix has to land for the metrics to still
# be showing the symptom it fixed (CloudWatch fills its last few points late).
FIX_GRACE_S = 300


def mark_may_be_over(symptoms: list[Symptom], changes: list[Change], cands: list[Candidate],
                     drift: list[DriftItem], read_keys: set[str], metrics_end: str | None,
                     topo: Topology) -> None:
    """Flag symptoms a later change has probably already fixed.

    A symptom may be over when, after it began and close to where the metrics
    end, a change touched something in its scope, live config there now matches
    what is declared, and no drifted resource explains the symptom. That is
    what a revert or a fix looks like; the lagging metrics still show what came
    before it. Such a symptom is still reported, but a diagnosis need not
    explain it. Needs a declared state to compare with: with none, nothing is
    flagged."""
    m_end = to_dt(metrics_end)
    if not m_end or not read_keys:
        return
    drifted = {d.resource_key for d in drift}
    drift_cands = [c for c in cands if "drift" in c.kind]
    for s in symptoms:
        onset = to_dt(s.onset)
        if not onset:
            continue
        scope = set(s.scope) | {s.node}
        for c in changes:
            t = to_dt(c.time)
            if c.error_code or not c.resource_key or not t or t <= onset:
                continue
            if c.one_off or not c.params or not _value_keys(c.params):
                continue        # sets nothing (a purge, a restart): not a fix
            if t < m_end - timedelta(seconds=FIX_GRACE_S):
                continue
            keys = set(filter(None, c.resource_key.split(",")))
            hit = keys & scope
            if not hit or not hit <= read_keys or hit & drifted:
                continue
            if any(explains(dc, s, topo) for dc in drift_cands):
                break
            s.may_be_over = (f"{c.event_name} on {c.resource_name} at {c.time} came after this "
                             f"symptom began and live config there matches what is declared; the "
                             f"metrics end at {metrics_end}, so this may already be over")
            break


def explain_all(symptoms: list[Symptom], cands: list[Candidate], topo: Topology) -> dict:
    # A symptom that a later change may already have fixed is reported, not required.
    over = [s for s in symptoms if s.may_be_over]
    # Failing since it first got work: reported, not required (no onset to place a cause).
    standing = [s for s in symptoms if s.standing and not s.may_be_over]
    symptoms = [s for s in symptoms if not s.may_be_over and not s.standing]
    cover_map: dict[str, dict[str, str]] = {}      # cand id -> {symptom id: how}
    for c in cands:
        cover_map[c.id] = {s.id: how for s in symptoms if (how := explains(c, s, topo))}
    remaining = {s.id for s in symptoms}
    chosen: list[Candidate] = []
    # A likely revert, or a call that left nothing behind, can fit a symptom on
    # timing and still not be what keeps it going. Show it as a lead; never
    # rank it as a cause.
    held = [c for c in cands if c.evidence.get("restores") or c.evidence.get("one_off")]
    pool = [c for c in cands if c not in held]
    while remaining and pool:
        def score(c: Candidate):
            hits = {sid: how for sid, how in cover_map[c.id].items() if sid in remaining}
            return (len(hits), sum(_STRENGTH[h] for h in hits.values()),
                    1 if c.time else 0, 1 if "drift" in c.kind else 0, c.time or "")
        pool.sort(key=score, reverse=True)
        best = pool[0]
        if not score(best)[0]:
            break
        chosen.append(best)
        remaining -= set(cover_map[best.id])
        pool.remove(best)
    chosen_ids = {c.id for c in chosen}
    alternatives = [c for c in cands if c.id not in chosen_ids and c not in held and cover_map[c.id]]
    reverts = [c for c in held if c.evidence.get("restores") and cover_map[c.id]]
    one_offs = [c for c in held if not c.evidence.get("restores") and cover_map[c.id]]
    idle = [c for c in cands if not cover_map[c.id]]
    unexplained = [s for s in symptoms if s.id in remaining]
    # Leads no current metric symptom can place: changes newer than the metrics,
    # and live state that differs from what's declared on something that moves
    # work. The metrics lag, so these are exactly what a fresh fault looks like.
    # An action that sets nothing (a purge, a restart) is not a configuration lead.
    newer = [c for c in idle if c.evidence.get("after_metrics")
             and (c.evidence.get("drift") or _settings(c) or str(c.evidence.get("event", "")).startswith("Delete"))]
    unplaced = [c for c in idle if "drift" in c.kind and c not in newer
                and any(topo.type_of(k) in FLOW_TYPES for k in c.resource_key.split(",") if k)]

    if not symptoms:
        conf, why = "UNKNOWN", "no metric showed a current anomaly, so there is nothing to explain yet"
    elif unexplained and not chosen:
        conf, why = "LOW", "no in-window change or drift explains the symptoms"
    elif unexplained:
        conf, why = "MEDIUM", f"{len(unexplained)} symptom(s) are not explained by any cause found"
    elif all(c.time for c in chosen) and all(
            "still has its values" in str(c.evidence.get("holds", "")) or "drift" in c.kind for c in chosen):
        conf, why = "HIGH", "every symptom is explained by a change inside the window that still holds"
    else:
        conf, why = "MEDIUM", "every symptom is explained, but a cause's timing or current state is unconfirmed"
    return {
        "causes": [{**c.to_dict(), "explains": cover_map[c.id]} for c in chosen],
        "alternatives": [{**c.to_dict(), "explains": cover_map[c.id]} for c in alternatives],
        "changes_explaining_nothing": [c.to_dict() for c in idle],
        "unexplained_symptoms": [s.to_dict() for s in unexplained],
        "may_be_over": [s.to_dict() for s in over],
        "standing_symptoms": [s.to_dict() for s in standing],
        "newer_than_metrics": [c.to_dict() for c in newer],
        "unplaced_drift": [c.to_dict() for c in unplaced],
        "likely_reverts": [{**c.to_dict(), "explains": cover_map[c.id]} for c in reverts],
        "one_off_actions": [{**c.to_dict(), "explains": cover_map[c.id]} for c in one_offs],
        "confidence": conf,
        "confidence_reason": why,
    }

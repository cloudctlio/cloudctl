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

from cloudctl.debug.diff_first.model import Candidate, Change, DriftItem, Symptom, to_dt
from cloudctl.debug.diff_first.normalize import identifiers_in
from cloudctl.debug.diff_first.topology import Topology, service_of_type, services_in

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
        if c.status != "candidate":
            continue
        keys = [k for k in c.resource_key.split(",") if k]
        drift_here = [d for d in drift if d.resource_key in keys and not d.observer]
        for d in drift_here:
            used_drift.add(id(d))
            d.changed_at, d.changed_by = c.time, c.actor
        cands.append(Candidate(
            id=f"C{len(cands) + 1}", kind="change+drift" if drift_here else "change",
            resource_key=",".join(keys), resource_name=c.resource_name, time=c.time,
            summary=f"{c.event_name} on {c.resource_name} at {c.time} by {c.actor or 'unknown'}"
                    + (f"; live differs from declared on {', '.join(f['field'] for d in drift_here for f in d.fields[:4])}"
                       if drift_here else "")
                    + (f" [{c.route_label}]" if c.route_label else ""),
            evidence={"params": c.params, "drift": [d.to_dict() for d in drift_here],
                      "holds": c.reason, "event": c.event_name, "route": c.route,
                      "route_label": c.route_label, "route_confidence": c.route_confidence,
                      "fix_direction": c.fix_direction, "route_evidence": c.route_evidence}))
    for d in drift:
        if id(d) in used_drift:
            continue
        if d.observer:
            # A monitor's drift is reported (run.py lists it as observer_drift)
            # but never offered as a cause: it can hide an outage, not make one.
            d.note = d.note or ("a monitor: its drift can hide an outage but cannot cause one")
            context.append({"drift": d.to_dict(), "why_not_a_cause": d.note, "observer": True})
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
                    + ("" if d.changed_at else " (when it changed is unknown)")
                    + (f" [{d.route_label}]" if d.route_label else ""),
            evidence={"drift": [d.to_dict()], "route": d.route, "route_label": d.route_label,
                      "route_confidence": d.route_confidence, "fix_direction": d.fix_direction,
                      "route_evidence": d.route_evidence}))
    return cands, context


def _changed_values(c: Candidate) -> list:
    vals: list = [c.evidence.get("params") or {}]
    for d in c.evidence.get("drift") or []:
        for f in d.get("fields") or []:
            vals.extend([f.get("expected"), f.get("live")])
    return vals


def explains(c: Candidate, s: Symptom, topo: Topology) -> str:
    """'' when it doesn't; else how: direct | link | repointed."""
    t, onset = to_dt(c.time), to_dt(s.onset)
    if t and onset and t > onset + timedelta(seconds=ONSET_SKEW_S):
        return ""
    keys = set(filter(None, c.resource_key.split(",")))
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


def explain_all(symptoms: list[Symptom], cands: list[Candidate], topo: Topology) -> dict:
    cover_map: dict[str, dict[str, str]] = {}      # cand id -> {symptom id: how}
    for c in cands:
        cover_map[c.id] = {s.id: how for s in symptoms if (how := explains(c, s, topo))}
    remaining = {s.id for s in symptoms}
    chosen: list[Candidate] = []
    pool = list(cands)
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
    alternatives = [c for c in cands if c.id not in chosen_ids and cover_map[c.id]]
    idle = [c for c in cands if not cover_map[c.id]]
    unexplained = [s for s in symptoms if s.id in remaining]

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
        "confidence": conf,
        "confidence_reason": why,
    }

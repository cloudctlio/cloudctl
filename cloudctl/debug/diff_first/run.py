"""Run the diff-first checks and hand the result to the agent.

``run_diff_first`` is plain logic over read-only data; it never calls a model.
``apply_to_report`` holds the agent's final answer to what the checks found:
a cause the answer doesn't mention, a symptom nothing explains, or a blamed
change that predates the incident or no longer holds all cap confidence.
"""

from __future__ import annotations

import json
import re
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from cloudctl.debug.diff_first.changes import classify, iac_commits, to_changes
from cloudctl.debug.diff_first.drift import compute_drift
from cloudctl.debug.diff_first.explain import build_candidates, explain_all
from cloudctl.debug.diff_first.flow import build_symptoms
from cloudctl.debug.diff_first.iac import BaselineAdapter, load_expected_state
from cloudctl.debug.diff_first.live import NOT_FOUND
from cloudctl.debug.diff_first.model import to_dt
from cloudctl.debug.diff_first.topology import build_topology
from cloudctl.debug.diff_first.window import METRICS, detect_anomaly, fill, incident_window, metric_queries

_CONF = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


@dataclass
class DiffFirstReport:
    expected_kind: str = "none"
    expected_notes: list[str] = field(default_factory=list)
    expected_unavailable: str = ""
    resources: int = 0
    window: dict = field(default_factory=dict)
    drift: list[dict] = field(default_factory=list)
    drift_stats: dict = field(default_factory=dict)
    changes: list[dict] = field(default_factory=list)
    iac_commits: list[dict] = field(default_factory=list)
    topology: dict = field(default_factory=dict)
    flow: list[dict] = field(default_factory=list)
    symptoms: list[dict] = field(default_factory=list)
    explanation: dict = field(default_factory=dict)
    context: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0
    budget_s: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

    # for the model --------------------------------------------------------
    def prompt_text(self, max_chars: int = 3500) -> str:
        return prompt_text(self.to_dict(), max_chars)


def _series_by_node(queries: list[dict], data: dict, start: datetime, end: datetime,
                    period: int) -> dict[str, dict[str, list]]:
    """{node: {role: filled series}}; series with the same role are summed."""
    out: dict[str, dict[str, list]] = {}
    for q in queries:
        pts = data.get(q["id"])
        if pts is None:
            continue
        filled = fill(pts, start, end, period, zero_fill=q.get("stat", "Sum") == "Sum")
        roles = out.setdefault(q["node"], {})
        role = q["role"]
        if role in roles and role in ("errors",):
            roles[role] = [(t, (a or 0.0) + (b or 0.0) if a is not None or b is not None else None)
                           for (t, a), (_, b) in zip(roles[role], filled)]
        elif role not in roles:
            roles[role] = filled
        roles.setdefault("_metrics", []).append(q["metric"])
    return out


def run_diff_first(live: Any, iac_root: str | None = None, account: str = "", region: str = "",
                   now: datetime | None = None, lookback_minutes: int = 180, period: int = 60,
                   metric_lag_s: int = 180, budget_s: float = 90.0,
                   onset_override: str | None = None) -> DiffFirstReport:
    t0 = time.monotonic()
    deadline = t0 + budget_s
    rep = DiffFirstReport(budget_s=budget_s)
    now = now or (live.now() if hasattr(live, "now") else datetime.now(timezone.utc))
    start = now - timedelta(minutes=lookback_minutes)
    metric_end = now - timedelta(seconds=metric_lag_s)

    # 1. expected state
    expected = load_expected_state(iac_root, live)
    resources = dict(expected.resources)
    if not resources:
        try:
            resources = {r.key: r for r in live.discover()}
            rep.notes.append(f"no IaC state: wired up {len(resources)} discovered resources instead")
        except Exception as exc:  # noqa: BLE001
            rep.notes.append(f"discovery failed: {exc}")
    rep.resources = len(resources)
    topo = build_topology(resources)
    rep.topology = topo.to_dict()

    # 2. incident window from metrics
    queries = metric_queries(resources)
    data: dict = {}
    if queries and time.monotonic() < deadline:
        try:
            data = live.metrics(queries, start, metric_end, period)
        except Exception as exc:  # noqa: BLE001
            rep.notes.append(f"metrics unavailable: {exc}")
    series = _series_by_node(queries, data, start, metric_end, period)
    anomalies = []
    for node, roles in series.items():
        for role, s in roles.items():
            if role.startswith("_"):
                continue
            metric = next((m for (m, r, _) in METRICS[resources[node].type][2] if r == role), role) \
                if resources[node].type in METRICS else role
            a = detect_anomaly(s, role, node=node, metric=metric)
            if a:
                anomalies.append(a)
    window = incident_window(anomalies, topo.components(), period, start,
                             override_onset=onset_override)
    rep.window = window.to_dict()

    # 3. no IaC: the last-known-good snapshot at the last healthy time
    if expected.kind == "none" and resources:
        base = BaselineAdapter().load(None, live, account=account, region=region,
                                      at=window.last_healthy, discovered=list(resources.values()))
        if base.resources:
            expected = base
        else:
            rep.notes.append(base.unavailable)
    rep.expected_kind = expected.kind
    rep.expected_notes = list(expected.notes)
    rep.expected_unavailable = expected.unavailable

    # 4. expected-state diff
    drift, stats, configs = ([], {}, {})
    if expected.resources:
        drift, stats, configs = compute_drift(expected, live, deadline)
    rep.drift_stats = stats

    # 5. changes in the window that still hold
    rows: list[dict] = []
    if time.monotonic() < deadline:
        try:
            rows = live.write_events(start, now)
        except Exception as exc:  # noqa: BLE001
            rep.notes.append(f"CloudTrail unavailable: {exc}")
    changes = to_changes(rows, resources)
    for c in changes:          # live config of changed resources, for the holds check
        for k in filter(None, c.resource_key.split(",")):
            if k not in configs and time.monotonic() < deadline and len(configs) < 200:
                try:
                    cfg = live.read(resources[k])
                except Exception:  # noqa: BLE001
                    cfg = None
                if cfg is not None:
                    configs[k] = cfg
    classify(changes, window, {k: v for k, v in configs.items() if v is not NOT_FOUND})
    rep.changes = [c.to_dict() for c in changes if c.resource_key][-60:]
    rep.iac_commits = [c.to_dict() for c in iac_commits(iac_root, to_dt(window.start), to_dt(window.end))]

    # 6. flow checks and symptoms
    symptoms, flow_table, notes = build_symptoms(topo, anomalies, series, window)
    rep.symptoms = [s.to_dict() for s in symptoms]
    rep.flow = flow_table
    rep.notes.extend(notes)

    # 7. explain everything
    cands, context = build_candidates(drift, changes, window.start, topo)
    rep.drift = [d.to_dict() for d in drift]
    rep.context = context
    expl = explain_all(symptoms, cands, topo)
    for group in ("causes", "alternatives"):
        for c in expl[group]:
            c["match_names"] = match_names(c["resource_key"], resources)
    rep.explanation = expl
    if time.monotonic() > deadline:
        rep.notes.append(f"stopped at the {budget_s:.0f}s budget; some reads were skipped")
    rep.elapsed_s = round(time.monotonic() - t0, 2)
    return rep


def match_names(resource_key: str, resources: dict) -> list[str]:
    """Words that show a diagnosis names this resource: its own name and id,
    its IaC address tail, and its type spelled out ("event source mapping")
    when it is the only one of its type. A token that is part of another
    resource's name ("worker" inside "cctl-complexapp-worker-policy") is too
    loose to count."""
    import re as _re
    keys = [k for k in resource_key.split(",") if k in resources]
    others = [r.name.lower() for k, r in resources.items() if k not in keys and r.name]
    out: set[str] = set()
    for k in keys:
        r = resources[k]
        toks = {r.name, r.physical_id if r.physical_id and not r.physical_id.startswith("https://") else "",
                k.split(".")[-1].split("/")[-1]} - {""}
        for tok in toks:
            low = tok.lower()
            if len(low) < 3:
                continue
            if tok == r.name or not any(low in o and low != o for o in others):
                out.add(tok)
        words = [w.lower() for w in _re.findall(r"[A-Z][a-z0-9]*", r.type.split("::")[-1])]
        same_type = sum(1 for x in resources.values() if x.type == r.type)
        if len(words) >= 2 and same_type == 1:
            out.add(" ".join(words))
            out.add("".join(words))
    return sorted(out)


# ── Text for the model ───────────────────────────────────────────────────────

def prompt_text(d: dict, max_chars: int = 3500) -> str:
    if not d or d.get("error"):
        return ""
    w = d.get("window") or {}
    ex = d.get("explanation") or {}
    lines = ["DIFF-FIRST CHECKS (deterministic, read-only, ran before any hypothesis):",
             f"- Expected state: {d.get('expected_kind')} ({d.get('resources')} resources)"
             + (f"; {d['expected_unavailable']}" if d.get("expected_unavailable") else ""),
             f"- Incident window: last healthy {w.get('last_healthy')}, onset {w.get('onset')} "
             f"({w.get('method')}). Only changes between these can be the cause."]
    for s in d.get("symptoms") or []:
        lines.append(f"- Symptom {s['id']} ({s['kind']}): {s['detail']}")
    for c in ex.get("causes") or []:
        lines.append(f"- CAUSE CANDIDATE {c['id']}: {c['summary']} -> explains {', '.join(c['explains'])}")
    for c in ex.get("alternatives") or []:
        lines.append(f"- Also consistent {c['id']}: {c['summary']} -> {', '.join(c['explains'])}")
    for s in ex.get("unexplained_symptoms") or []:
        lines.append(f"- UNEXPLAINED {s['id']}: {s['detail']} (keep looking)")
    dropped = [c for c in d.get("changes") or [] if c.get("status") in ("before_window", "superseded", "reverted")]
    for c in dropped[-6:]:
        lines.append(f"- NOT a cause: {c['event_name']} on {c['resource_name']} at {c['time']}: {c['reason']}")
    for n in (d.get("notes") or [])[:4]:
        lines.append(f"- Note: {n}")
    lines.append("Rules: your answer must explain EVERY symptom above, each cause must come "
                 "before the symptom it explains, and more than one cause is allowed. Do not "
                 "blame a change listed as NOT a cause.")
    text = "\n".join(lines)
    return text if len(text) <= max_chars else text[:max_chars - 20] + "\n- (truncated)"


def seed_hypotheses(d: dict, existing: list[dict], limit: int = 2) -> list[dict]:
    """One hypothesis per cause candidate the model's hypotheses don't already target."""
    out: list[dict] = []
    blob = json.dumps(existing).lower()
    for c in ((d or {}).get("explanation") or {}).get("causes") or []:
        names = [n for n in c.get("match_names") or [] if n]
        if any(n.lower() in blob for n in names):
            continue
        name = names[0] if names else c["resource_key"]
        out.append({
            "service": name,
            "reason": f"diff-first check: {c['summary']}; it explains symptoms {', '.join(c['explains'])}",
            "focus": f"{name} — confirm this change/drift and that it explains the observed symptoms",
            "predictions": [{
                "if_true": f"{name}'s live configuration still shows the change, and the symptoms began after it",
                "check": f"get_service_config and search_cloudtrail_events on {name}",
                "if_absent": "refutes"}],
            "_source": "diff_first",
        })
        if len(out) >= limit:
            break
    return out


# ── Hold the final answer to the checks ──────────────────────────────────────

def _cap(out: dict, level: str, reason: str) -> None:
    cur = str(out.get("confidence") or "MEDIUM").upper()
    if _CONF.get(cur, 1) > _CONF[level]:
        out["confidence"] = level
        prev = out.get("confidence_override_reason")
        out["confidence_override_reason"] = f"{prev} | {reason}" if prev else reason


def _mentioned(names: list[str], text: str) -> bool:
    """A name counts only as a whole token: ``cctl-app-worker`` inside
    ``cctl-app-worker-policy`` names the policy, not the function."""
    for n in names:
        if n and len(n) >= 3 and re.search(r"(?<![a-z0-9_-])" + re.escape(n.lower()) + r"(?![a-z0-9_-])", text):
            return True
    return False


def apply_to_report(report: dict, d: dict | None) -> dict:
    """Attach the checks to the agent's answer and cap confidence when the
    answer leaves a found cause out, leaves a symptom unexplained, or rests on
    a change that predates the incident or no longer holds."""
    if not d or d.get("error") or not isinstance(report, dict):
        return report
    out = dict(report)
    ex = d.get("explanation") or {}
    causes = ex.get("causes") or []
    unexplained = ex.get("unexplained_symptoms") or []
    out["diff_first"] = {
        "expected_state": d.get("expected_kind"),
        "window": {k: (d.get("window") or {}).get(k) for k in ("last_healthy", "onset", "method")},
        "symptoms": [f"{s['id']}: {s['detail']}" for s in d.get("symptoms") or []],
        "causes": [{"summary": c["summary"], "explains": sorted(c["explains"])} for c in causes],
        "unexplained": [f"{s['id']}: {s['detail']}" for s in unexplained],
        "not_causes": [f"{c['event_name']} on {c['resource_name']} at {c['time']}: {c['reason']}"
                       for c in d.get("changes") or []
                       if c.get("status") in ("before_window", "superseded", "reverted")][-5:],
        "confidence": ex.get("confidence"),
    }
    if not causes and not unexplained:
        return out
    text = " ".join([str(out.get("root_cause", ""))] + [str(e) for e in out.get("evidence") or []]).lower()
    root = str(out.get("root_cause", "")).lower()
    missed = [c for c in causes if not _mentioned(c.get("match_names") or [], text)]
    if causes and len(missed) == len(causes):
        _cap(out, "LOW", "diff-first checks found a cause the diagnosis does not mention: "
                         + "; ".join(c["summary"] for c in missed))
        out["additional_causes"] = [c["summary"] for c in missed]
    elif missed:
        _cap(out, "MEDIUM", "the diagnosis leaves out a cause the diff-first checks found: "
                            + "; ".join(c["summary"] for c in missed))
        out["additional_causes"] = [c["summary"] for c in missed]
    if unexplained:
        _cap(out, "MEDIUM", f"{len(unexplained)} observed symptom(s) are not explained by any "
                            "cause found; the search is not finished")
        out["unexplained_symptoms"] = [s["detail"] for s in unexplained]
    stale = [c for c in d.get("changes") or []
             if c.get("status") in ("before_window", "superseded", "reverted")
             and c.get("resource_name") and any(n.strip().lower() in root
                                                for n in c["resource_name"].split(",") if len(n.strip()) >= 3)]
    if stale and causes and len(missed) == len(causes):
        _cap(out, "LOW", "the diagnosis blames " + stale[-1]["resource_name"] + ", whose change "
                         + stale[-1]["reason"])
    return out


# ── Entry point used by the agent ────────────────────────────────────────────

def run_for_agent(profile: str | None, region: str, iac_root: str | None,
                  account: str = "", onset_override: str | None = None) -> dict:
    """Pick a live source (AWS, or a recording), run, and return a dict. Never
    raises: a failure here must not stop the investigation."""
    if os.environ.get("CLOUDCTL_DIFF_FIRST", "1") == "0":
        return {}
    budget = float(os.environ.get("CLOUDCTL_DIFF_FIRST_BUDGET_S", "90"))
    try:
        replay = os.environ.get("CLOUDCTL_DIFF_FIRST_REPLAY")
        if replay:
            from cloudctl.debug.diff_first.live import RecordedLive
            with open(replay, encoding="utf-8") as fh:
                live: Any = RecordedLive(json.load(fh))
        elif os.environ.get("CLOUDCTL_REPLAY"):
            return {"error": "skipped: tool replay without a diff-first recording"}
        else:
            from cloudctl.debug.diff_first.live import AwsLive
            from cloudctl.mcp.tools.debug import _make_session
            live = AwsLive(_make_session(profile, region), region)
            rec_path = os.environ.get("CLOUDCTL_DIFF_FIRST_RECORD")
            if rec_path:
                from cloudctl.debug.diff_first.recording import RecordingLive
                live = RecordingLive(live, rec_path)
        rep = run_diff_first(live, iac_root=iac_root, account=account, region=region,
                             budget_s=budget, onset_override=onset_override)
        if hasattr(live, "save"):
            live.save()
        return rep.to_dict()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"diff-first checks failed: {exc}"}

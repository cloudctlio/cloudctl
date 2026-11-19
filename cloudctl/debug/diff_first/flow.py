"""Flow checks: is work still moving along every edge of the app's wiring?

Errors are only half the picture. A disabled trigger or a rule that stopped
matching produces no error anywhere: work just stops arriving. For each node
with throughput metrics we compare "before the last healthy point" with
"since the onset". A node that went quiet while the node feeding it is still
working marks where the flow stopped. Every observed symptom also gets a
SCOPE: the resources whose config could have caused it, read off the wiring.
"""

from __future__ import annotations

import statistics
from datetime import datetime

from cloudctl.debug.diff_first.model import IncidentWindow, Symptom, iso, to_dt
from cloudctl.debug.diff_first.topology import Topology, service_of_type
from cloudctl.debug.diff_first.window import Anomaly

QUIET_RATIO = 0.2      # "went quiet": below 20% of its healthy rate
ACTIVE_RATIO = 0.3     # "still working": at least 30% of its healthy successful rate


def _mean(series, lo: datetime | None, hi: datetime | None) -> float | None:
    vals = [v for t, v in series if v is not None and (lo is None or t >= lo) and (hi is None or t <= hi)]
    return statistics.fmean(vals) if vals else None


class NodeStats:
    def __init__(self, node: str, series_by_role: dict[str, list], window: IncidentWindow):
        self.node = node
        lh, on = to_dt(window.last_healthy), to_dt(window.onset)
        ins = series_by_role.get("in") or []
        errs = series_by_role.get("errors") or []
        self.has_metrics = bool(ins)
        self.base_in = _mean(ins, None, lh) if ins else None
        self.win_in = _mean(ins, on, None) if ins else None
        be = _mean(errs, None, lh) if errs else 0.0
        we = _mean(errs, on, None) if errs else 0.0
        self.base_ok = max(0.0, (self.base_in or 0.0) - (be or 0.0)) if ins else None
        self.win_ok = max(0.0, (self.win_in or 0.0) - (we or 0.0)) if ins else None

    @property
    def quiet(self) -> bool:
        return bool(self.has_metrics and self.base_in and self.base_in > 0
                    and self.win_in is not None and self.win_in < QUIET_RATIO * self.base_in)

    @property
    def active(self) -> bool:
        return bool(self.has_metrics and self.base_ok and self.base_ok > 0
                    and self.win_ok is not None and self.win_ok >= ACTIVE_RATIO * self.base_ok)

    def to_dict(self) -> dict:
        r = lambda x: None if x is None else round(x, 3)  # noqa: E731
        return {"node": self.node, "healthy_rate": r(self.base_in), "rate_now": r(self.win_in),
                "healthy_ok_rate": r(self.base_ok), "ok_rate_now": r(self.win_ok),
                "quiet": self.quiet, "working": self.active}


def _feeders(topo: Topology, node: str, stats: dict[str, NodeStats], max_depth: int = 4):
    """Nearest upstream nodes that have metrics, with the metric-less nodes
    passed on the way (connectors, buses)."""
    out: list[tuple[str, list[str]]] = []
    stack = [(p, []) for p in topo.upstream(node)]
    seen = {node}
    while stack:
        cur, via = stack.pop()
        if cur in seen or len(via) > max_depth:
            continue
        seen.add(cur)
        st = stats.get(cur)
        if st is not None and st.has_metrics:
            out.append((cur, list(reversed(via))))
        else:
            stack.extend((p, via + [cur]) for p in topo.upstream(cur))
    return out


def _errors_scope(topo: Topology, n: str) -> set[str]:
    scope = topo.config_scope(n)
    for d in topo.downstream(n):
        scope.add(d)
        if topo.is_connector(d):
            scope |= topo.downstream(d)
    return scope


def _consumer_scope(topo: Topology, q: str) -> set[str]:
    scope = {q}
    for c in topo.downstream(q):
        scope |= {c} | topo.config_scope(c)
        if topo.is_connector(c):
            for d in topo.downstream(c):
                scope |= topo.config_scope(d)
    return scope


def _backlog_scope(topo: Topology, q: str) -> set[str]:
    scope = _consumer_scope(topo, q)
    for src, targets in topo.redrive.items():
        if q in targets:            # q is where src's failed work goes
            scope |= _consumer_scope(topo, src) if topo.downstream(src) else topo.config_scope(src)
    return scope


def build_symptoms(topo: Topology, anomalies: list[Anomaly], series: dict[str, dict[str, list]],
                   window: IncidentWindow) -> tuple[list[Symptom], list[dict], list[str]]:
    """Return (symptoms, per-node flow stats, notes)."""
    symptoms: list[Symptom] = []
    notes: list[str] = []
    stats = {n: NodeStats(n, roles, window) for n, roles in series.items()}

    def label(k: str) -> str:
        r = topo.resources.get(k)
        return r.label() if r else k

    for a in anomalies:
        if a.role not in ("errors", "backlog"):
            continue
        if a.role == "errors":
            symptoms.append(Symptom(
                id=f"S{len(symptoms) + 1}", kind="errors_up", node=a.node, onset=iso(a.onset),
                detail=f"{a.metric} on {label(a.node)} rose from {a.ref_mean:.1f} to {a.win_mean:.1f} per bucket",
                scope=sorted(_errors_scope(topo, a.node))))
        else:
            symptoms.append(Symptom(
                id=f"S{len(symptoms) + 1}", kind="backlog_up", node=a.node, onset=iso(a.onset),
                detail=f"{a.metric} on {label(a.node)} keeps growing ({a.ref_mean:.0f} -> {a.win_mean:.0f})",
                scope=sorted(_backlog_scope(topo, a.node))))

    in_onset = {a.node: a.onset for a in anomalies if a.role == "in"}
    for n, st in sorted(stats.items()):
        if not st.quiet:
            continue
        feeders = _feeders(topo, n, stats)
        onset = iso(in_onset.get(n)) or window.onset
        if not feeders:
            r = topo.resources.get(n)
            symptoms.append(Symptom(
                id=f"S{len(symptoms) + 1}", kind="throughput_down", node=n, onset=onset,
                detail=(f"work arriving at {label(n)} dropped from {st.base_in:.1f} to {st.win_in:.1f} "
                        "per bucket, and nothing known feeds it"),
                scope=sorted(topo.config_scope(n)),
                open_service=service_of_type(r.type) if r else ""))
            continue
        working = [(p, via) for p, via in feeders if stats[p].active]
        if not working:
            notes.append(f"{label(n)} went quiet, but everything feeding it is failing or quiet too; "
                         "a fault on it could be hidden until the upstream one is fixed")
            continue
        for p, via in working:
            scope = {n} | set(via) | topo.config_scope(n)
            for v in via:
                if topo.is_connector(v):
                    scope |= topo.config_scope(v)
            connector_hop = topo.is_connector(n) or any(topo.is_connector(v) for v in via)
            sym = Symptom(
                id=f"S{len(symptoms) + 1}", kind="flow_stopped", node=n, onset=onset,
                detail=(f"{label(p)} is still working ({stats[p].win_ok:.1f}/bucket ok, healthy "
                        f"{stats[p].base_ok:.1f}) but work reaching {label(n)} dropped from "
                        f"{st.base_in:.1f} to {st.win_in:.1f}"
                        + (f" (via {', '.join(label(v) for v in via)})" if via else "")),
                scope=sorted(scope))
            if not connector_hop:
                # p's own code writes to n: p's config explains this only if a
                # change touched the link (the reference to n, or its access).
                sym.link_scope = sorted(topo.config_scope(p))
                sym.link_targets = sorted({n} | set(via))
            symptoms.append(sym)
    flow_table = [st.to_dict() for st in stats.values() if st.has_metrics]
    return symptoms, flow_table, notes

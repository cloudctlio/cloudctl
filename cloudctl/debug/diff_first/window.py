"""Incident window from metrics: when did the symptom start, and when was the
system last seen healthy? Only changes inside that window can be the cause.

Each resource type has a few standard CloudWatch metrics with a ROLE:
``in`` (work arriving: bad when it drops), ``errors`` (bad when it rises),
``backlog`` (bad when it keeps growing). The table only names metrics; the
anomaly logic is the same for every type.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from cloudctl.debug.diff_first.model import IncidentWindow, Resource, iso, to_dt
from cloudctl.debug.diff_first.normalize import get_field

# type -> (namespace, dimension builder, [(metric, role, stat)])
_M = dict
METRICS: dict[str, tuple] = {
    "AWS::Lambda::Function": ("AWS/Lambda", lambda r: {"FunctionName": r.name},
                              [("Invocations", "in", "Sum"), ("Errors", "errors", "Sum"),
                               ("Throttles", "errors", "Sum")]),
    "AWS::SQS::Queue": ("AWS/SQS", lambda r: {"QueueName": r.name},
                        [("NumberOfMessagesSent", "in", "Sum"), ("NumberOfMessagesDeleted", "out", "Sum"),
                         ("ApproximateNumberOfMessagesVisible", "backlog", "Maximum")]),
    "AWS::Events::Rule": ("AWS/Events", lambda r: _rule_dims(r),
                          [("MatchedEvents", "in", "Sum"), ("FailedInvocations", "errors", "Sum")]),
    "AWS::ApiGatewayV2::Api": ("AWS/ApiGateway", lambda r: {"ApiId": r.physical_id},
                               [("Count", "in", "Sum"), ("5xx", "errors", "Sum")]),
    "AWS::DynamoDB::Table": ("AWS/DynamoDB", lambda r: {"TableName": r.name},
                             [("ConsumedWriteCapacityUnits", "in", "Sum"),
                              ("ThrottledRequests", "errors", "Sum"), ("SystemErrors", "errors", "Sum")]),
    "AWS::SNS::Topic": ("AWS/SNS", lambda r: {"TopicName": r.name},
                        [("NumberOfMessagesPublished", "in", "Sum"),
                         ("NumberOfNotificationsFailed", "errors", "Sum")]),
    "AWS::Kinesis::Stream": ("AWS/Kinesis", lambda r: {"StreamName": r.name},
                             [("IncomingRecords", "in", "Sum")]),
    "AWS::StepFunctions::StateMachine": ("AWS/States", lambda r: {"StateMachineArn": r.arn},
                                         [("ExecutionsStarted", "in", "Sum"),
                                          ("ExecutionsFailed", "errors", "Sum")]),
}


def _rule_dims(r: Resource) -> dict:
    bus = get_field(r.config, "event_bus_name", "EventBusName") or "default"
    bus = str(bus).split("/")[-1]
    return {"RuleName": r.name} if bus == "default" else {"EventBusName": bus, "RuleName": r.name}


def metric_queries(resources: dict[str, Resource]) -> list[dict]:
    qs: list[dict] = []
    for k, r in resources.items():
        spec = METRICS.get(r.type)
        if not spec or not (r.name or r.physical_id):
            continue
        ns, dims, metrics = spec
        try:
            d = dims(r)
        except Exception:  # noqa: BLE001
            continue
        if not all(d.values()):
            continue
        for metric, role, stat in metrics:
            qs.append({"id": f"m{len(qs)}", "node": k, "metric": metric, "role": role,
                       "stat": stat, "namespace": ns, "dims": d,
                       "key": f"{r.type}|{r.name or r.physical_id}|{metric}"})
    return qs


def fill(points: list, start: datetime, end: datetime, period: int, zero_fill: bool) -> list[tuple[datetime, float | None]]:
    """Regular buckets. CloudWatch omits a Sum bucket when nothing happened, so
    a missing Sum bucket is 0 (that is how a stopped flow looks)."""
    got = {}
    for t, v in points:
        dt = to_dt(t)
        if dt is not None:
            got[int(dt.timestamp()) // period] = float(v)
    out = []
    b0, b1 = int(start.timestamp()) // period, int(end.timestamp()) // period
    for b in range(b0, b1 + 1):
        v = got.get(b)
        out.append((datetime.fromtimestamp(b * period, tz=start.tzinfo), v if v is not None else (0.0 if zero_fill else None)))
    return out


@dataclass
class Anomaly:
    node: str
    metric: str
    role: str
    onset: datetime
    last_normal: datetime | None
    ref_mean: float
    win_mean: float
    detail: str = ""
    series: list = field(default_factory=list, repr=False)
    threshold: float = 0.0             # a bucket at or past this is abnormal ("in": below it)
    # Set when the node was never seen working normally before the onset: it
    # has been failing since it first got work, so the onset is not when an
    # incident began (see mark_standing).
    standing: str = ""

    def to_dict(self) -> dict:
        d = {"node": self.node, "metric": self.metric, "role": self.role,
             "onset": iso(self.onset), "last_normal": iso(self.last_normal),
             "baseline_mean": round(self.ref_mean, 3), "now_mean": round(self.win_mean, 3),
             "detail": self.detail}
        if self.standing:
            d["standing"] = self.standing
        return d


def detect_anomaly(series: list[tuple[datetime, float | None]], role: str,
                   node: str = "", metric: str = "", ref_frac: float = 0.4) -> Anomaly | None:
    """Is this series abnormal NOW, and since when? Returns None when it is
    normal at the end (a past spike that has stopped is not a current symptom)."""
    pts = [(t, v) for t, v in series if v is not None]
    if len(pts) < 8:
        return None
    n_ref = max(4, int(len(pts) * ref_frac))
    ref = [v for _, v in pts[:n_ref]]
    ref_mean = statistics.fmean(ref)
    ref_sd = statistics.pstdev(ref) if len(ref) > 1 else 0.0
    if role in ("in", "out"):
        if ref_mean <= 0:
            return None
        thr = 0.2 * ref_mean
        def bad(v: float) -> bool:
            return v < 0.2 * ref_mean
    elif role == "errors":
        thr = max(ref_mean + 3 * ref_sd, max(ref) * 1.5 if max(ref) > 0 else 0.0, 1.0)
        def bad(v: float) -> bool:
            return v >= thr
    elif role == "backlog":
        thr = max(ref_mean + 3 * ref_sd, max(ref) * 1.5 if max(ref) > 0 else 0.0, 5.0)
        def bad(v: float) -> bool:
            return v >= thr
    else:
        return None
    tail = pts[-3:]
    if sum(1 for _, v in tail if bad(v)) < 2:
        return None
    if role == "backlog":
        # A backlog left over from an earlier incident (a DLQ that nobody
        # drained) is not happening now: require it to still be growing.
        recent = [v for _, v in pts[-10:]]
        if recent[-1] <= recent[0] * 1.05 + 1:
            return None
    # Walk back over the current abnormal run, tolerating short normal gaps.
    i = len(pts) - 1
    start_i = i
    gap = 0
    while i >= 0:
        if bad(pts[i][1]):
            start_i, gap = i, 0
        else:
            gap += 1
            if gap > 2:
                break
        i -= 1
    onset = pts[start_i][0]
    last_normal = pts[start_i - 1][0] if start_i > 0 else None
    win = [v for _, v in pts[start_i:]]
    return Anomaly(node=node, metric=metric, role=role, onset=onset, last_normal=last_normal,
                   ref_mean=ref_mean, win_mean=statistics.fmean(win) if win else 0.0,
                   detail="" if start_i > 0 else "abnormal since the start of the lookback",
                   series=pts, threshold=thr)


def mark_standing(anomalies: list[Anomaly], traffic: dict[str, list]) -> None:
    """Mark error signals that carry no onset information.

    An error count of 0 in a minute with no work says nothing about health:
    nothing ran, so nothing could fail (and CloudWatch reports no Sum before a
    resource exists, which is filled as 0). A node whose errors were already
    abnormal in every minute it had work, back to its first work, was never
    seen healthy: the "onset" is just when work first arrived (often right
    after a deploy), not when something broke. Such a signal is still a
    symptom, but it must not set the incident window for the others, or every
    later change lands "after the onset" and the deploy is blamed.

    ``traffic`` maps node -> its "in" series. Only applied when at least one
    other current signal has a real healthy-then-abnormal edge; when every
    signal is like this, nothing is marked (the deploy may be the cause)."""
    for a in anomalies:
        a.standing = ""
        if a.role != "errors" or not traffic.get(a.node):
            continue
        errs = {t: v for t, v in a.series}
        busy = [(t, v) for t, v in traffic[a.node] if (v or 0) > 0 and t < a.onset]
        if not any((errs.get(t) or 0.0) < a.threshold for t, _ in busy):
            first = min((t for t, v in traffic[a.node] if (v or 0) > 0), default=a.onset)
            a.standing = (f"abnormal in every minute it had work since it first got work at {iso(first)}; "
                          "never seen healthy, so this is not when the incident began")
    if all(a.standing for a in anomalies):
        for a in anomalies:
            a.standing = ""


def incident_window(anomalies: list[Anomaly], components: list[set[str]] | None,
                    period: int, lookback_start: datetime,
                    skew_before: int = 300, skew_after: int = 120,
                    override_onset: str | None = None,
                    metrics_end: datetime | None = None) -> IncidentWindow:
    """Onset = earliest current anomaly in the connected part of the app that
    holds the most anomalies; last healthy = the bucket before it. A cause must
    sit between (last healthy - clock skew) and (onset + metric skew).
    ``metrics_end`` is the last bucket the metrics cover: anything after it is
    not visible in them, so it is recorded for the change checks."""
    w = IncidentWindow(metrics_end=iso(metrics_end))
    if override_onset:
        onset = to_dt(override_onset)
        if onset:
            w.onset, w.last_healthy = iso(onset), iso(onset - timedelta(seconds=period))
            w.method = "override"
    if not w.onset and anomalies:
        group = anomalies
        if components:
            best, best_n = None, 0
            for comp in components:
                n = sum(1 for a in anomalies if a.node in comp)
                if n > best_n:
                    best, best_n = comp, n
            if best:
                group = [a for a in anomalies if a.node in best]
        # A signal that was never seen healthy has no onset to offer; anchor on
        # the ones that were, when there are any.
        group = [a for a in group if not a.standing] or group
        first = min(group, key=lambda a: a.onset)
        onset = first.onset
        lh = first.last_normal or lookback_start
        w.onset, w.last_healthy, w.method = iso(onset), iso(lh), "metrics"
        w.signals = [a.to_dict() for a in sorted(group, key=lambda a: a.onset)][:12]
        standing = [a for a in anomalies if a.standing]
        if standing:
            w.signals += [a.to_dict() for a in standing][:4]
        if not first.last_normal:
            w.note = ("the first signal was already abnormal at the start of the lookback: "
                      "the last healthy point is unknown, so older changes stay in play")
    if not w.onset:
        w.method = "unknown"
        w.note = "no metric showed a current anomaly; the window is the whole lookback"
        w.start = iso(lookback_start)
        return w
    w.start = iso(to_dt(w.last_healthy) - timedelta(seconds=skew_before))
    w.end = iso(to_dt(w.onset) + timedelta(seconds=skew_after))
    return w

"""Debug correlator — builds a causal timeline from fetched evidence.

Core job:
  1. Collect all timestamped events from all data sources
  2. Sort into a single chronological timeline
  3. Find the inflection point (when did things change?)
  4. Calculate correlation between events and symptom onset
  5. Return structured Timeline for analyzer to reason over

Correlation is deterministic — no AI involved here.
AI only runs in analyzer.py after correlation is complete.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class TimelineEvent:
    time: str
    source: str
    event: str
    is_inflection: bool = False
    tags: list[str] = field(default_factory=list)
    # Extended fields for richer correlator
    event_type: str = "info"      # deployment | error_spike | task_stopped | config_change | info
    severity: str = "info"        # high | medium | low | info
    data: dict = field(default_factory=dict)


@dataclass
class Timeline:
    events: list[TimelineEvent]
    inflection_point: Optional[TimelineEvent]
    correlation_pct: float         # 0-100
    pattern: str                   # single_event | gradual_degradation | intermittent | cascading | no_signal
    window_start: str
    window_end: str


# ── Inflection keywords ───────────────────────────────────────────────────────

_DEPLOYMENT_KEYWORDS = {
    "registerTaskDefinition", "UpdateService", "deploy", "register",
    "CreateChangeSet", "ExecuteChangeSet", "UpdateStack",
}
_ERROR_KEYWORDS = {
    "unhealthy", "stopped", "failed", "error", "exception", "timed out",
    "connection refused", "5xx", "502", "503", "504",
    "accessdenied", "AccessDenied", "throttl",
    "OutOfMemory", "OOMKilled", "CannotPullContainer",
}
_CONFIG_KEYWORDS = {
    "update", "change", "create", "delete", "modify", "put", "set",
}


def _classify_event(event_text: str, source: str) -> tuple[str, str]:
    """Return (event_type, severity) for an event."""
    lower = event_text.lower()
    src   = source.lower()

    if any(k.lower() in lower for k in _DEPLOYMENT_KEYWORDS):
        return "deployment", "medium"
    if any(k.lower() in lower for k in _ERROR_KEYWORDS):
        sev = "high" if any(x in lower for x in ("502", "503", "504", "oom", "killed", "failed")) else "medium"
        return "error_spike", sev
    if "stoppedreason" in lower or "stoppedtask" in src or "stopped" in lower:
        return "task_stopped", "high"
    if any(k.lower() in lower for k in _CONFIG_KEYWORDS):
        return "config_change", "low"
    return "info", "info"


def _inflection_keywords() -> list[str]:
    return list(_DEPLOYMENT_KEYWORDS | _ERROR_KEYWORDS | _CONFIG_KEYWORDS)


# ── Main build_timeline ───────────────────────────────────────────────────────

def build_timeline(evidence: list[dict]) -> list[TimelineEvent]:
    """
    Merge all evidence events into a sorted timeline.
    Mark events as inflection points if they contain change/failure keywords.
    """
    keywords = {k.lower() for k in _inflection_keywords()}
    timeline: list[TimelineEvent] = []

    for ev in evidence:
        text     = (ev.get("event", "") + " " + ev.get("error_code", "")).lower()
        src      = ev.get("source", "—")
        etype, sev = _classify_event(ev.get("event", ""), src)
        is_inf   = any(kw in text for kw in keywords) or ev.get("is_inflection", False)

        tags: list[str] = []
        if ev.get("error_code"):
            tags.append("error")
        if etype == "deployment":
            tags.append("deployment")
        if etype == "task_stopped":
            tags.append("stopped")

        timeline.append(TimelineEvent(
            time=ev.get("time", "—"),
            source=src,
            event=ev.get("event", ""),
            is_inflection=is_inf,
            tags=tags,
            event_type=etype,
            severity=sev,
            data=ev,
        ))

    timeline.sort(key=lambda e: e.time)
    return timeline


def find_inflection_point(timeline: list[TimelineEvent]) -> Optional[TimelineEvent]:
    """Return the earliest inflection-point event (first significant change)."""
    for ev in timeline:
        if ev.is_inflection:
            return ev
    return None


# ── Full timeline builder (for structured FetchedData context) ────────────────

def build_rich_timeline(context: dict) -> Timeline:
    """Build a rich Timeline from the full context dict produced by debug_engine.

    Accepts the `context` dict that has keys like:
      audit_logs, service_logs, network_context, ecs_events,
      alb_resource_map, ecs_stopped_tasks, lambda_report, sqs_dlq,
      codepipeline, rds_events, acm_expiry_check, vpc_flow_logs, etc.

    Returns a Timeline with pattern detection and inflection scoring.
    """
    all_events: list[TimelineEvent] = []

    # Flatten all list-valued sources into TimelineEvent objects
    _SOURCE_PRIORITY = {
        "audit_logs":      5,
        "ecs_stopped":     5,
        "codepipeline":    4,
        "ecs_events":      4,
        "rds_events":      3,
        "service_logs":    3,
        "alb_logs":        3,
        "network_context": 2,
        "metrics":         2,
    }

    for key, value in context.items():
        if not isinstance(value, list):
            continue
        for ev in value:
            if not isinstance(ev, dict):
                continue
            time_str = ev.get("time", "—")
            source   = ev.get("source", key)
            text     = ev.get("event", "")
            etype, sev = _classify_event(text, source)

            keywords = {k.lower() for k in _inflection_keywords()}
            is_inf = any(kw in text.lower() for kw in keywords)

            tags: list[str] = []
            if ev.get("error_code"):
                tags.append("error")
            if etype == "deployment":
                tags.append("deployment")
            if etype == "task_stopped":
                tags.append("stopped")

            all_events.append(TimelineEvent(
                time=time_str,
                source=source,
                event=text,
                is_inflection=is_inf,
                tags=tags,
                event_type=etype,
                severity=sev,
                data=ev,
            ))

    # Sort lexicographically (ISO 8601 sorts correctly)
    all_events.sort(key=lambda e: e.time)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    window_start = all_events[0].time if all_events else now_str
    window_end   = all_events[-1].time if all_events else now_str

    if not all_events:
        return Timeline(
            events=[], inflection_point=None,
            correlation_pct=0.0, pattern="no_signal",
            window_start=window_start, window_end=window_end,
        )

    pattern    = _detect_pattern(all_events, context)
    inflection = _find_best_inflection(all_events, pattern)
    corr       = _calculate_correlation(inflection, all_events)

    return Timeline(
        events=all_events,
        inflection_point=inflection,
        correlation_pct=corr,
        pattern=pattern,
        window_start=window_start,
        window_end=window_end,
    )


def _detect_pattern(events: list[TimelineEvent], context: dict) -> str:
    """Classify the error pattern from available signals.

    single_event:        errors start at one clear point, stay elevated
    gradual_degradation: errors increase over time (memory leak / disk fill)
    intermittent:        errors appear in repeated bursts
    cascading:           multiple services degrading in sequence
    no_signal:           no clear error pattern
    """
    error_events = [e for e in events if e.event_type in ("error_spike", "task_stopped")]
    if not error_events:
        return "no_signal"

    # Intermittent: look for 3+ separate time windows of errors
    if len(error_events) >= 3:
        times = sorted(e.time for e in error_events)
        gaps  = []
        for i in range(1, len(times)):
            # rough gap estimate from ISO strings
            if times[i] > times[i - 1]:
                gaps.append(times[i][11:16])  # HH:MM
        unique_minutes = len(set(t[:13] for t in times))  # unique hours
        if unique_minutes >= 2 and len(gaps) >= 2:
            return "intermittent"

    # Cascading: multiple different sources reporting errors
    error_sources = {e.source.split("/")[0] for e in error_events}
    if len(error_sources) >= 3:
        return "cascading"

    # Check ALB map for multiple unhealthy TGs
    alb_map = context.get("alb_resource_map")
    if isinstance(alb_map, dict):
        unhealthy_tgs = sum(
            1 for tg in alb_map.get("all_tgs", []) if tg.get("unhealthy_count", 0) > 0
        )
        if unhealthy_tgs >= 2:
            return "cascading"

    # Gradual: error count monotonically increasing across time buckets
    if len(error_events) >= 4:
        bucket_counts: dict[str, int] = {}
        for e in error_events:
            bucket = e.time[:13]  # hour bucket
            bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
        counts = list(bucket_counts.values())
        if len(counts) >= 2 and all(counts[i] <= counts[i + 1] for i in range(len(counts) - 1)):
            return "gradual_degradation"

    return "single_event"


def _find_best_inflection(events: list[TimelineEvent], pattern: str) -> Optional[TimelineEvent]:
    """Find the most likely root-cause event.

    Scoring:
      deployment      = 1.0
      task_stopped    = 0.9
      config_change   = 0.8
      error_spike     = 0.6
      info            = 0.1
    Plus recency bonus: events near the first error score higher.
    """
    if not events:
        return None

    if pattern == "no_signal":
        high = [e for e in reversed(events) if e.severity == "high"]
        return high[0] if high else events[-1]

    # Find first error event as reference point
    first_error = next(
        (e for e in events if e.event_type in ("error_spike", "task_stopped")), None
    )

    candidates = [
        e for e in events
        if e.event_type in ("deployment", "task_stopped", "config_change", "error_spike")
    ]
    if not candidates:
        candidates = events

    _TYPE_WEIGHT = {
        "deployment":    1.0,
        "task_stopped":  0.9,
        "config_change": 0.8,
        "error_spike":   0.6,
    }

    def _score(ev: TimelineEvent) -> float:
        w = _TYPE_WEIGHT.get(ev.event_type, 0.1)
        if first_error and first_error.time > "1900":
            # Proximity: events just before the first error score highest
            if ev.time <= first_error.time:
                # Rough proximity (lexicographic difference — good enough for ISO strings)
                lag = max(0, ord(first_error.time[-1]) - ord(ev.time[-1]))
                proximity = max(0.3, 1.0 - lag * 0.05)
            else:
                proximity = 0.2  # after error — less likely cause
        else:
            proximity = 0.5
        return w * proximity

    return max(candidates, key=_score)


def _calculate_correlation(
    inflection: Optional[TimelineEvent],
    events: list[TimelineEvent],
) -> float:
    """Estimate how strongly the inflection point correlates with errors.

    Returns 0-100.
    """
    if not inflection or not events:
        return 0.0

    error_events = [e for e in events if e.event_type in ("error_spike", "task_stopped")]
    if not error_events:
        return 0.0

    # How many error events come after the inflection point?
    after  = sum(1 for e in error_events if e.time >= inflection.time)
    total  = len(error_events)
    base   = (after / total) * 100 if total else 0.0

    # Bonus if inflection is a deployment (most common cause)
    if inflection.event_type == "deployment":
        base = min(100.0, base + 10.0)

    return round(base, 1)


def summarise(timeline: list[TimelineEvent], max_events: int = 20) -> list[dict]:
    """Convert timeline to list of dicts for serialisation / AI context."""
    return [
        {
            "time":          ev.time,
            "source":        ev.source,
            "event":         ev.event,
            "is_inflection": ev.is_inflection,
            "event_type":    ev.event_type,
            "severity":      ev.severity,
            "tags":          ev.tags,
        }
        for ev in timeline[:max_events]
    ]

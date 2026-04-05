"""Debug correlator — builds a causal timeline from fetched evidence."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TimelineEvent:
    time: str
    source: str
    event: str
    is_inflection: bool = False
    tags: list[str] = field(default_factory=list)


def _inflection_keywords() -> list[str]:
    return [
        "deploy", "register", "update", "change", "create", "delete",
        "unhealthy", "stopped", "failed", "error", "exception",
        "connection refused", "timed out", "5xx", "502", "503", "504",
        "accessdenied", "throttl",
    ]


def build_timeline(evidence: list[dict]) -> list[TimelineEvent]:
    """
    Merge all evidence events into a sorted timeline.
    Mark events as inflection points if they contain change/failure keywords.
    """
    keywords = _inflection_keywords()

    timeline: list[TimelineEvent] = []
    for ev in evidence:
        text = (ev.get("event", "") + " " + ev.get("error_code", "")).lower()
        is_inf = any(kw in text for kw in keywords)
        tags: list[str] = []
        if ev.get("error_code"):
            tags.append("error")
        if "deploy" in text or "register" in text:
            tags.append("deployment")

        timeline.append(TimelineEvent(
            time=ev.get("time", "—"),
            source=ev.get("source", "—"),
            event=ev.get("event", ""),
            is_inflection=is_inf,
            tags=tags,
        ))

    # Sort by time string (ISO 8601 sorts lexicographically)
    timeline.sort(key=lambda e: e.time)
    return timeline


def find_inflection_point(timeline: list[TimelineEvent]) -> Optional[TimelineEvent]:
    """Return the earliest inflection-point event (first significant change)."""
    for ev in timeline:
        if ev.is_inflection:
            return ev
    return None


def summarise(timeline: list[TimelineEvent], max_events: int = 20) -> list[dict]:
    """Convert timeline to list of dicts for serialisation / AI context."""
    return [
        {
            "time":          ev.time,
            "source":        ev.source,
            "event":         ev.event,
            "is_inflection": ev.is_inflection,
            "tags":          ev.tags,
        }
        for ev in timeline[:max_events]
    ]

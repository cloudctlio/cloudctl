"""Feedback store — read/write feedback.jsonl and patterns.yaml."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

_DIR           = Path.home() / ".cloudctl" / "feedback"
_JSONL_FILE    = _DIR / "feedback.jsonl"
_PATTERNS_FILE = _DIR / "patterns.yaml"


@dataclass
class FeedbackEntry:
    question:      str
    answer:        str
    rating:        int          # 1-5
    cloud:         str
    account:       str
    provider:      str
    timestamp:     str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


def append(entry: FeedbackEntry) -> None:
    """Append one feedback record to feedback.jsonl."""
    _DIR.mkdir(parents=True, exist_ok=True)
    with open(_JSONL_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(entry)) + "\n")


def read_all(limit: int = 0) -> list[dict]:
    """Return all feedback records, oldest first. Pass limit>0 to cap."""
    if not _JSONL_FILE.exists():
        return []
    lines = _JSONL_FILE.read_text(encoding="utf-8").strip().splitlines()
    records: list[dict] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    if limit:
        return records[-limit:]
    return records


def load_patterns() -> dict:
    """Load learned patterns from patterns.yaml, returning {} if missing."""
    if not _PATTERNS_FILE.exists():
        return {}
    try:
        return yaml.safe_load(_PATTERNS_FILE.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return {}


def save_patterns(patterns: dict) -> None:
    """Persist patterns.yaml."""
    _DIR.mkdir(parents=True, exist_ok=True)
    _PATTERNS_FILE.write_text(
        yaml.dump(patterns, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )

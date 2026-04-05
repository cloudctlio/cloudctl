"""Feedback store — records session outcomes to improve future confidence scoring."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


_FEEDBACK_DIR  = Path.home() / ".cloudctl" / "feedback"
_FEEDBACK_FILE = _FEEDBACK_DIR / "feedback.jsonl"


@dataclass
class FeedbackRecord:
    question:       str
    context_hash:   str
    answer:         str
    rating:         int        # 1-5 (5=perfect, 1=wrong)
    timestamp:      str
    provider:       str
    cloud:          str = "all"
    account:        str = ""


def _context_hash(context: dict) -> str:
    key = json.dumps(sorted(context.keys()), sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def record(
    question: str,
    context: dict,
    answer: str,
    rating: int,
    provider: str,
    cloud: str = "all",
    account: str = "",
) -> None:
    """Append a feedback record to feedback.jsonl."""
    _FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
    rec = FeedbackRecord(
        question=question,
        context_hash=_context_hash(context),
        answer=answer,
        rating=rating,
        timestamp=datetime.now(timezone.utc).isoformat(),
        provider=provider,
        cloud=cloud,
        account=account,
    )
    with open(_FEEDBACK_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(rec)) + "\n")


def lookup_accuracy(question: str, context: dict) -> Optional[float]:
    """
    Return historical accuracy (0.0-1.0) for similar questions in this context.
    Returns None if no history found.
    """
    if not _FEEDBACK_FILE.exists():
        return None

    q_lower = question.lower().split()
    c_hash  = _context_hash(context)
    matching: list[int] = []

    with open(_FEEDBACK_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Match on context hash OR keyword overlap
            ctx_match = rec.get("context_hash") == c_hash
            kw_match  = any(w in rec.get("question", "").lower() for w in q_lower if len(w) > 4)
            if ctx_match or kw_match:
                matching.append(rec.get("rating", 3))

    if not matching:
        return None
    # Convert 1-5 rating to 0-1 accuracy
    return (sum(matching) / len(matching) - 1) / 4.0


def list_records(limit: int = 20) -> list[dict]:
    """Return the last N feedback records."""
    if not _FEEDBACK_FILE.exists():
        return []
    lines = _FEEDBACK_FILE.read_text(encoding="utf-8").strip().splitlines()
    records = []
    for line in reversed(lines[-limit:]):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return records

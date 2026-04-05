"""Feedback processor — extracts signals from free-text feedback."""
from __future__ import annotations

import re
from typing import Optional


_POSITIVE_WORDS = {
    "correct", "right", "accurate", "perfect", "exactly", "yes", "helped",
    "worked", "fixed", "solved", "resolved", "good", "great", "excellent",
}
_NEGATIVE_WORDS = {
    "wrong", "incorrect", "inaccurate", "no", "false", "bad", "poor",
    "failed", "useless", "unhelpful", "off", "missed", "didn't", "didnt",
    "not right", "not correct",
}


def classify_text(text: str) -> int:
    """
    Convert free-text feedback to a 1-5 rating.
    5 = positive, 3 = neutral, 1 = negative.
    """
    lower = text.lower()
    pos = sum(1 for w in _POSITIVE_WORDS if w in lower)
    neg = sum(1 for w in _NEGATIVE_WORDS if w in lower)
    if pos > neg:
        return 5
    if neg > pos:
        return 1
    return 3


def extract_signals(records: list[dict]) -> dict:
    """
    Analyse a list of feedback records and extract pattern signals:
      - question patterns that correlate with high/low accuracy
      - provider-level accuracy by cloud
    """
    by_cloud:    dict[str, list[int]] = {}
    by_keyword:  dict[str, list[int]] = {}

    for rec in records:
        rating = rec.get("rating", 3)
        cloud  = rec.get("cloud", "all")
        q      = rec.get("question", "").lower()

        by_cloud.setdefault(cloud, []).append(rating)

        for word in re.findall(r'\b[a-z]{4,}\b', q):
            by_keyword.setdefault(word, []).append(rating)

    def avg(lst: list[int]) -> float:
        return sum(lst) / len(lst) if lst else 3.0

    cloud_accuracy = {c: (avg(v) - 1) / 4.0 for c, v in by_cloud.items()}
    # Only keep keywords with >= 3 samples and clear signal
    keyword_accuracy = {
        k: (avg(v) - 1) / 4.0
        for k, v in by_keyword.items()
        if len(v) >= 3 and abs(avg(v) - 3) > 0.5
    }

    return {
        "cloud_accuracy":   cloud_accuracy,
        "keyword_accuracy": keyword_accuracy,
        "total_records":    len(records),
    }

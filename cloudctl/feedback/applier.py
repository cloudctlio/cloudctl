"""Feedback applier — applies learned patterns to planner and confidence scorer."""
from __future__ import annotations

from cloudctl.feedback.store import load_patterns, save_patterns
from cloudctl.feedback.processor import extract_signals


def rebuild_patterns(records: list[dict]) -> None:
    """Re-derive patterns from all feedback records and persist them."""
    signals  = extract_signals(records)
    patterns = load_patterns()
    patterns.update({
        "cloud_accuracy":   signals["cloud_accuracy"],
        "keyword_accuracy": signals["keyword_accuracy"],
        "total_records":    signals["total_records"],
    })
    save_patterns(patterns)


def adjust_confidence(base_score: float, question: str, cloud: str) -> float:
    """
    Apply learned patterns to nudge the base confidence score.
    Returns adjusted score clamped to [0.0, 1.0].
    """
    import re  # noqa: PLC0415
    patterns = load_patterns()
    if not patterns:
        return base_score

    adjustment = 0.0

    # Cloud-level historical accuracy
    cloud_acc = patterns.get("cloud_accuracy", {}).get(cloud)
    if cloud_acc is not None:
        adjustment += (cloud_acc - 0.5) * 0.1  # gentle nudge

    # Keyword-level accuracy
    kw_acc_map = patterns.get("keyword_accuracy", {})
    words      = re.findall(r'\b[a-z]{4,}\b', question.lower())
    kw_signals = [kw_acc_map[w] for w in words if w in kw_acc_map]
    if kw_signals:
        kw_avg = sum(kw_signals) / len(kw_signals)
        adjustment += (kw_avg - 0.5) * 0.15

    return max(0.0, min(1.0, base_score + adjustment))

"""AI confidence scoring — rates AI results based on data completeness and timeline quality."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ConfidenceScore:
    level: str          # HIGH | MEDIUM | LOW
    reason: str
    reasons: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    data_points: int = 0
    accounts_covered: int = 0
    accounts_total: int = 0

    @property
    def label(self) -> str:
        color = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(self.level, "dim")
        parts = [f"[{color}]{self.level} confidence[/{color}]"]
        if self.sources:
            parts.append(f"sources: {', '.join(self.sources[:4])}")
        if self.data_points:
            parts.append(f"{self.data_points} data points")
        if self.accounts_total:
            parts.append(f"{self.accounts_covered}/{self.accounts_total} accounts")
        return "  |  ".join(parts)


def score(
    data: dict,
    *,
    required_keys: Optional[list[str]] = None,
    expected_accounts: int = 1,
    historical_accuracy: Optional[float] = None,
    timeline_pattern: Optional[str] = None,
    timeline_correlation: Optional[float] = None,
    has_inflection: bool = False,
) -> ConfidenceScore:
    """
    Score a data payload for AI context quality.

    HIGH   = ≥3 sources with data, clear inflection, correlation ≥80%, single_event/cascading pattern
    MEDIUM = partial data OR correlation < 80% OR intermittent/gradual pattern
    LOW    = no data OR no signal OR pattern == no_signal OR AI failed
    """
    reasons: list[str] = []

    if not data:
        return ConfidenceScore(
            level="LOW", reason="No cloud data was fetched.",
            reasons=["No cloud data was fetched."],
            sources=[], data_points=0,
        )

    sources   = list(data.keys())
    total_pts = sum(_count_items(v) for v in data.values())
    covered   = sum(1 for v in data.values() if _count_items(v) > 0)
    missing   = [k for k in (required_keys or []) if k not in data or not data[k]]

    numeric_score = 0

    # ── Data completeness ──────────────────────────────────────────────────────
    if covered >= 4:
        numeric_score += 3
        reasons.append(f"All {covered} data sources available")
    elif covered >= 2:
        numeric_score += 1
        reasons.append(f"{covered} of {len(sources)} data sources available")
    else:
        numeric_score -= 1
        reasons.append(f"Limited data: only {covered} sources returned data")

    if missing:
        reasons.append(f"Missing data for: {', '.join(missing)}")

    # ── Timeline quality ───────────────────────────────────────────────────────
    if has_inflection:
        numeric_score += 2
        reasons.append("Clear inflection point identified")
    else:
        reasons.append("No clear inflection point found")

    if timeline_correlation is not None:
        if timeline_correlation >= 80:
            numeric_score += 1
            reasons.append(f"Strong correlation: {timeline_correlation:.0f}%")
        elif timeline_correlation >= 50:
            reasons.append(f"Moderate correlation: {timeline_correlation:.0f}%")
        else:
            numeric_score -= 1
            reasons.append(f"Weak correlation: {timeline_correlation:.0f}%")

    if timeline_pattern:
        if timeline_pattern == "intermittent":
            numeric_score -= 1
            reasons.append(
                "Intermittent pattern — errors not continuous, "
                "may not be visible at query time"
            )
        elif timeline_pattern == "no_signal":
            numeric_score -= 2
            reasons.append("No clear signal found in time window")
        elif timeline_pattern in ("single_event", "cascading"):
            numeric_score += 1
            reasons.append(f"Clear {timeline_pattern.replace('_', ' ')} pattern")
        elif timeline_pattern == "gradual_degradation":
            reasons.append("Gradual degradation pattern — root cause may be gradual resource exhaustion")

    # ── Historical accuracy ────────────────────────────────────────────────────
    if historical_accuracy is not None:
        if historical_accuracy >= 0.8:
            numeric_score += 1
            reasons.append(f"Historical accuracy {historical_accuracy:.0%} for similar queries")
        elif historical_accuracy < 0.5:
            numeric_score -= 1
            reasons.append(f"Historical accuracy {historical_accuracy:.0%} — low confidence from past experience")

    # ── Map numeric score to level ─────────────────────────────────────────────
    if numeric_score >= 5:
        level = "HIGH"
    elif numeric_score >= 2:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Override: force MEDIUM for intermittent regardless of score
    if timeline_pattern == "intermittent" and level == "HIGH":
        level = "MEDIUM"

    return ConfidenceScore(
        level=level,
        reason=reasons[0] if reasons else "insufficient data",
        reasons=reasons,
        sources=sources,
        data_points=total_pts,
        accounts_covered=covered,
        accounts_total=expected_accounts,
    )


def _count_items(value) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return sum(_count_items(v) for v in value.values())
    return 1 if value else 0

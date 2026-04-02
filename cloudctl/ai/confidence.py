"""AI confidence scoring — rates AI results based on data completeness."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ConfidenceScore:
    level: str          # HIGH | MEDIUM | LOW
    reason: str
    sources: list[str] = field(default_factory=list)
    data_points: int = 0
    accounts_covered: int = 0
    accounts_total: int = 0

    @property
    def label(self) -> str:
        color = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(self.level, "dim")
        parts = [f"[{color}]{self.level} confidence[/{color}]"]
        if self.sources:
            parts.append(f"sources: {', '.join(self.sources)}")
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
    days_requested: int = 14,
    historical_accuracy: Optional[float] = None,
) -> ConfidenceScore:
    """
    Score a data payload for AI context quality.

    HIGH   = real API data, full time range, all accounts covered, accuracy > 80%
    MEDIUM = partial data OR accuracy 50-80%
    LOW    = very little data OR accuracy < 50%
    """
    if not data:
        return ConfidenceScore(
            level="LOW", reason="No cloud data was fetched.",
            sources=[], data_points=0,
        )

    sources   = list(data.keys())
    total_pts = sum(_count_items(v) for v in data.values())
    covered   = sum(1 for v in data.values() if _count_items(v) > 0)
    missing   = [k for k in (required_keys or []) if k not in data or not data[k]]

    if historical_accuracy is not None:
        if historical_accuracy < 0.5:
            return ConfidenceScore(
                level="LOW",
                reason=f"Historical accuracy {historical_accuracy:.0%} for similar queries.",
                sources=sources, data_points=total_pts,
                accounts_covered=covered, accounts_total=expected_accounts,
            )
        if historical_accuracy < 0.8:
            return ConfidenceScore(
                level="MEDIUM",
                reason=f"Historical accuracy {historical_accuracy:.0%} for similar queries.",
                sources=sources, data_points=total_pts,
                accounts_covered=covered, accounts_total=expected_accounts,
            )

    if missing:
        return ConfidenceScore(
            level="MEDIUM",
            reason=f"Missing data for: {', '.join(missing)}",
            sources=sources, data_points=total_pts,
            accounts_covered=covered, accounts_total=expected_accounts,
        )

    if total_pts == 0:
        return ConfidenceScore(
            level="LOW", reason="Data was fetched but returned empty results.",
            sources=sources, data_points=0,
            accounts_covered=0, accounts_total=expected_accounts,
        )

    if covered < expected_accounts:
        return ConfidenceScore(
            level="MEDIUM",
            reason=f"Only {covered}/{expected_accounts} accounts returned data.",
            sources=sources, data_points=total_pts,
            accounts_covered=covered, accounts_total=expected_accounts,
        )

    return ConfidenceScore(
        level="HIGH",
        reason=f"Full data from {covered} account(s), {total_pts} resources.",
        sources=sources, data_points=total_pts,
        accounts_covered=covered, accounts_total=expected_accounts,
    )


def _count_items(value) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return sum(_count_items(v) for v in value.values())
    return 1 if value else 0

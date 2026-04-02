"""AI context builder — assembles cloud data into a structured context dict for AI prompts."""
from __future__ import annotations

from typing import Optional

from cloudctl.config.manager import ConfigManager


def build_context(
    cfg: ConfigManager,
    *,
    cloud: str = "all",
    account: Optional[str] = None,
    region: Optional[str] = None,
    include: Optional[list[str]] = None,
) -> dict:
    """
    Build a context dict for AI prompts.

    Args:
        cfg:     ConfigManager instance.
        cloud:   Which cloud(s) to include.
        account: Scope to a specific account (optional).
        region:  Scope to a specific region (optional).
        include: List of data categories to include.
                 Options: compute, storage, database, cost, security, iam
                 Default: all available.
    """
    from cloudctl.ai.data_fetcher import DataFetcher  # noqa: PLC0415
    fetcher = DataFetcher(cfg)
    return fetcher.fetch_summary(
        cloud=cloud, account=account, region=region, include=include
    )


def trim_context(context: dict, max_items_per_key: int = 50) -> dict:
    """
    Trim context to avoid exceeding token limits.
    Keeps first max_items_per_key items per list.
    """
    result: dict = {}
    for key, value in context.items():
        if isinstance(value, list) and len(value) > max_items_per_key:
            result[key] = value[:max_items_per_key]
            result[f"_{key}_truncated"] = len(value) - max_items_per_key
        elif isinstance(value, dict):
            result[key] = trim_context(value, max_items_per_key)
        else:
            result[key] = value
    return result

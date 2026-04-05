"""MCP tool implementations for cloud infrastructure queries."""
from __future__ import annotations

import json
from typing import Any

from cloudctl.mcp.context import get_cfg
from cloudctl.ai.data_fetcher import DataFetcher


def _fetcher() -> DataFetcher:
    return DataFetcher(get_cfg())


def list_compute(cloud: str = "all", account: str = "", region: str = "") -> str:
    """List compute instances across clouds."""
    ctx = _fetcher().fetch_summary(
        cloud=cloud,
        account=account or None,
        region=region or None,
        include=["compute"],
    )
    return json.dumps(ctx, default=str)


def list_storage(cloud: str = "all", account: str = "", region: str = "") -> str:
    """List storage buckets/accounts across clouds."""
    ctx = _fetcher().fetch_summary(
        cloud=cloud,
        account=account or None,
        region=region or None,
        include=["storage"],
    )
    return json.dumps(ctx, default=str)


def list_databases(cloud: str = "all", account: str = "", region: str = "") -> str:
    """List database instances across clouds."""
    ctx = _fetcher().fetch_summary(
        cloud=cloud,
        account=account or None,
        region=region or None,
        include=["database"],
    )
    return json.dumps(ctx, default=str)


def get_inventory(cloud: str = "all", account: str = "", region: str = "") -> str:
    """Get full infrastructure inventory for an account."""
    ctx = _fetcher().fetch_summary(
        cloud=cloud,
        account=account or None,
        region=region or None,
    )
    return json.dumps(ctx, default=str)


def check_security(cloud: str = "all", account: str = "") -> str:
    """Run security audit across cloud accounts."""
    ctx = _fetcher().fetch_summary(
        cloud=cloud,
        account=account or None,
        include=["security"],
    )
    return json.dumps(ctx, default=str)


def list_accounts() -> str:
    """List all configured cloud accounts."""
    cfg = get_cfg()
    return json.dumps({
        "clouds": cfg.clouds,
        "accounts": cfg.accounts,
    }, default=str)

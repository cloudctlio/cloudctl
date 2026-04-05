"""MCP tool implementations for cloud cost queries."""
from __future__ import annotations

import json

from cloudctl.mcp.context import get_cfg
from cloudctl.ai.data_fetcher import DataFetcher


def _fetcher() -> DataFetcher:
    return DataFetcher(get_cfg())


def get_cost_summary(cloud: str = "all", account: str = "", region: str = "") -> str:
    """Get cost summary across clouds."""
    ctx = _fetcher().fetch_summary(
        cloud=cloud,
        account=account or None,
        region=region or None,
        include=["cost"],
    )
    return json.dumps(ctx, default=str)


def get_cost_by_service(cloud: str = "aws", account: str = "") -> str:
    """Get cost breakdown by service for an account."""
    cfg = get_cfg()
    result: dict = {}
    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile in targets:
            try:
                from cloudctl.commands._helpers import get_aws_provider  # noqa: PLC0415
                prov = get_aws_provider(profile)
                result[profile] = prov.cost_by_service(account=profile, days=30)
            except Exception as e:
                result[profile] = {"error": str(e)}
    return json.dumps(result, default=str)

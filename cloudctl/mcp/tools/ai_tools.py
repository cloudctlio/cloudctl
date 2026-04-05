"""MCP tool implementations for AI-powered cloud analysis."""
from __future__ import annotations

import json

from cloudctl.mcp.context import get_cfg
from cloudctl.ai.data_fetcher import DataFetcher


def ask_cloud(question: str, cloud: str = "all", account: str = "") -> str:
    """Ask an AI question about your cloud infrastructure using real data."""
    cfg = get_cfg()
    try:
        from cloudctl.ai.factory import get_ai, is_ai_configured  # noqa: PLC0415
    except ImportError:
        return json.dumps({"error": "AI module not installed. Run: pip install 'cctl[ai]'"})

    if not is_ai_configured(cfg):
        return json.dumps({"error": "AI not configured. Run: cloudctl config set ai.provider <provider>"})

    ctx = DataFetcher(cfg).fetch_summary(
        cloud=cloud,
        account=account or None,
    )
    ai = get_ai(cfg, purpose="analysis")
    result = ai.ask(question, context=ctx)
    return json.dumps(result, default=str)


def analyze_logs(logs: str, context_json: str = "{}") -> str:
    """Analyze cloud logs using AI."""
    cfg = get_cfg()
    try:
        from cloudctl.ai.factory import get_ai, is_ai_configured  # noqa: PLC0415
    except ImportError:
        return json.dumps({"error": "AI module not installed."})

    if not is_ai_configured(cfg):
        return json.dumps({"error": "AI not configured."})

    try:
        context = json.loads(context_json) if context_json else {}
    except json.JSONDecodeError:
        context = {"raw_context": context_json}

    ai = get_ai(cfg)
    result = ai.analyze_logs(logs, context=context)
    return json.dumps(result, default=str)

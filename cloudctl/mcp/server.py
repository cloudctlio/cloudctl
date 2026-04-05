"""cloudctl MCP server — exposes cloud tools to Claude Desktop, Cursor, and MCP clients."""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

log = logging.getLogger(__name__)

# Tool schema helpers
def _schema(description: str, properties: dict, required: list | None = None) -> dict:
    return {
        "type": "object",
        "description": description,
        "properties": properties,
        "required": required or [],
    }

_CLOUD_PROP  = {"type": "string", "enum": ["aws", "azure", "gcp", "all"], "default": "all"}
_ACCOUNT_PROP = {"type": "string", "description": "AWS profile / Azure subscription ID / GCP project ID"}
_REGION_PROP  = {"type": "string", "description": "Cloud region to query"}
_DRY_RUN_PROP = {"type": "boolean", "description": "Dry run — describe action without executing", "default": True}

_TOOLS = [
    # ── Infra tools ────────────────────────────────────────────
    {
        "name": "cloudctl_list_accounts",
        "description": "List all configured cloud accounts and their clouds.",
        "inputSchema": _schema("List configured accounts", {}),
    },
    {
        "name": "cloudctl_get_inventory",
        "description": "Get full infrastructure inventory (compute, storage, databases, cost, security) for a cloud account.",
        "inputSchema": _schema("Get inventory",
            {"cloud": _CLOUD_PROP, "account": _ACCOUNT_PROP, "region": _REGION_PROP}),
    },
    {
        "name": "cloudctl_list_compute",
        "description": "List compute instances (EC2, Azure VMs, GCE) across clouds.",
        "inputSchema": _schema("List compute",
            {"cloud": _CLOUD_PROP, "account": _ACCOUNT_PROP, "region": _REGION_PROP}),
    },
    {
        "name": "cloudctl_list_storage",
        "description": "List storage buckets and accounts (S3, Azure Blob, GCS) across clouds.",
        "inputSchema": _schema("List storage",
            {"cloud": _CLOUD_PROP, "account": _ACCOUNT_PROP, "region": _REGION_PROP}),
    },
    {
        "name": "cloudctl_list_databases",
        "description": "List database instances (RDS, Azure SQL, Cloud SQL) across clouds.",
        "inputSchema": _schema("List databases",
            {"cloud": _CLOUD_PROP, "account": _ACCOUNT_PROP, "region": _REGION_PROP}),
    },
    {
        "name": "cloudctl_check_security",
        "description": "Run a security audit — public buckets, open security groups, IAM issues.",
        "inputSchema": _schema("Check security",
            {"cloud": _CLOUD_PROP, "account": _ACCOUNT_PROP}),
    },
    # ── Cost tools ─────────────────────────────────────────────
    {
        "name": "cloudctl_get_cost_summary",
        "description": "Get total cost summary for cloud accounts.",
        "inputSchema": _schema("Get cost summary",
            {"cloud": _CLOUD_PROP, "account": _ACCOUNT_PROP}),
    },
    {
        "name": "cloudctl_get_cost_by_service",
        "description": "Get cost breakdown by cloud service (AWS Cost Explorer).",
        "inputSchema": _schema("Get cost by service",
            {"cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "default": "aws"},
             "account": _ACCOUNT_PROP}),
    },
    # ── AI tools ───────────────────────────────────────────────
    {
        "name": "cloudctl_ask",
        "description": "Ask an AI question about your cloud infrastructure. Fetches real data first.",
        "inputSchema": _schema("Ask AI",
            {"question": {"type": "string", "description": "Your question about the cloud infrastructure"},
             "cloud": _CLOUD_PROP, "account": _ACCOUNT_PROP},
            required=["question"]),
    },
    {
        "name": "cloudctl_analyze_logs",
        "description": "Analyze cloud log data using AI.",
        "inputSchema": _schema("Analyze logs",
            {"logs": {"type": "string", "description": "Log content to analyze"},
             "context_json": {"type": "string", "description": "Optional JSON context string", "default": "{}"}},
            required=["logs"]),
    },
    # ── Action tools ───────────────────────────────────────────
    {
        "name": "cloudctl_stop_compute",
        "description": "Stop a compute instance. Defaults to dry_run=true — set dry_run=false to execute.",
        "inputSchema": _schema("Stop compute",
            {"instance_id": {"type": "string", "description": "Instance ID to stop"},
             "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "default": "aws"},
             "account": _ACCOUNT_PROP, "region": _REGION_PROP, "dry_run": _DRY_RUN_PROP},
            required=["instance_id"]),
    },
    {
        "name": "cloudctl_start_compute",
        "description": "Start a compute instance. Defaults to dry_run=true — set dry_run=false to execute.",
        "inputSchema": _schema("Start compute",
            {"instance_id": {"type": "string", "description": "Instance ID to start"},
             "cloud": {"type": "string", "enum": ["aws", "azure", "gcp"], "default": "aws"},
             "account": _ACCOUNT_PROP, "region": _REGION_PROP, "dry_run": _DRY_RUN_PROP},
            required=["instance_id"]),
    },
]


def _dispatch(tool_name: str, args: dict) -> str:
    """Route a tool call to the appropriate handler."""
    # ── Infra ──
    if tool_name == "cloudctl_list_accounts":
        from cloudctl.mcp.tools.infra import list_accounts  # noqa: PLC0415
        return list_accounts()
    if tool_name == "cloudctl_get_inventory":
        from cloudctl.mcp.tools.infra import get_inventory  # noqa: PLC0415
        return get_inventory(**{k: args.get(k, "") for k in ("cloud", "account", "region")})
    if tool_name == "cloudctl_list_compute":
        from cloudctl.mcp.tools.infra import list_compute  # noqa: PLC0415
        return list_compute(**{k: args.get(k, "") for k in ("cloud", "account", "region")})
    if tool_name == "cloudctl_list_storage":
        from cloudctl.mcp.tools.infra import list_storage  # noqa: PLC0415
        return list_storage(**{k: args.get(k, "") for k in ("cloud", "account", "region")})
    if tool_name == "cloudctl_list_databases":
        from cloudctl.mcp.tools.infra import list_databases  # noqa: PLC0415
        return list_databases(**{k: args.get(k, "") for k in ("cloud", "account", "region")})
    if tool_name == "cloudctl_check_security":
        from cloudctl.mcp.tools.infra import check_security  # noqa: PLC0415
        return check_security(**{k: args.get(k, "") for k in ("cloud", "account")})
    # ── Cost ──
    if tool_name == "cloudctl_get_cost_summary":
        from cloudctl.mcp.tools.cost import get_cost_summary  # noqa: PLC0415
        return get_cost_summary(**{k: args.get(k, "") for k in ("cloud", "account")})
    if tool_name == "cloudctl_get_cost_by_service":
        from cloudctl.mcp.tools.cost import get_cost_by_service  # noqa: PLC0415
        return get_cost_by_service(**{k: args.get(k, "") for k in ("cloud", "account")})
    # ── AI ──
    if tool_name == "cloudctl_ask":
        from cloudctl.mcp.tools.ai_tools import ask_cloud  # noqa: PLC0415
        return ask_cloud(
            question=args["question"],
            cloud=args.get("cloud", "all"),
            account=args.get("account", ""),
        )
    if tool_name == "cloudctl_analyze_logs":
        from cloudctl.mcp.tools.ai_tools import analyze_logs  # noqa: PLC0415
        return analyze_logs(
            logs=args["logs"],
            context_json=args.get("context_json", "{}"),
        )
    # ── Actions ──
    if tool_name == "cloudctl_stop_compute":
        from cloudctl.mcp.tools.action import stop_compute  # noqa: PLC0415
        return stop_compute(
            instance_id=args["instance_id"],
            cloud=args.get("cloud", "aws"),
            account=args.get("account", ""),
            region=args.get("region", ""),
            dry_run=args.get("dry_run", True),
        )
    if tool_name == "cloudctl_start_compute":
        from cloudctl.mcp.tools.action import start_compute  # noqa: PLC0415
        return start_compute(
            instance_id=args["instance_id"],
            cloud=args.get("cloud", "aws"),
            account=args.get("account", ""),
            region=args.get("region", ""),
            dry_run=args.get("dry_run", True),
        )

    return json.dumps({"error": f"Unknown tool: {tool_name}"})


async def main() -> None:
    """Run the cloudctl MCP server over stdio."""
    from mcp.server import Server  # noqa: PLC0415
    from mcp.server.stdio import stdio_server  # noqa: PLC0415
    from mcp.types import Tool, TextContent  # noqa: PLC0415

    server = Server("cloudctl")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name=t["name"],
                description=t["description"],
                inputSchema=t["inputSchema"],
            )
            for t in _TOOLS
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        try:
            result = _dispatch(name, arguments or {})
        except Exception as e:
            log.exception("Tool %s failed", name)
            result = json.dumps({"error": str(e)})
        return [TextContent(type="text", text=result)]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def sync_main() -> None:
    """Synchronous entry point for the cloudctl-mcp script."""
    asyncio.run(main())

"""The MCP server starts and serves tools on the installed mcp SDK (1.x or 2.x)."""
import asyncio
import os
import sys

import pytest

pytest.importorskip("mcp")


def test_server_lists_and_calls_tools_over_stdio(tmp_path):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env.update(HOME=str(tmp_path), AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull,
               AWS_EC2_METADATA_DISABLED="true")
    params = StdioServerParameters(command=sys.executable,
                                   args=["-c", "from cloudctl.mcp.server import sync_main; sync_main()"],
                                   env=env)

    async def go():
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                names = [t.name for t in (await s.list_tools()).tools]
                stop = await s.call_tool("cloudctl_stop_compute", {"instance_id": "i-0", "cloud": "aws"})
                unknown = await s.call_tool("nope", {})
                return names, stop.content[0].text, unknown.content[0].text

    names, stop, unknown = asyncio.run(asyncio.wait_for(go(), 60))
    assert "cloudctl_debug_incident" in names and len(names) >= 17
    assert '"dry_run": true' in stop
    assert "Unknown tool" in unknown


def test_tool_errors_do_not_leak_exception_text(monkeypatch):
    from cloudctl.mcp import server

    def boom(name, args):
        raise RuntimeError("arn:aws:iam::123456789012:role/secret")
    monkeypatch.setattr(server, "_dispatch", boom)
    assert server._run_tool("x", {}) == '{"error": "Tool execution failed"}'

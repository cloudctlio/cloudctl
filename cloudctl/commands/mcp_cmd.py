"""cloudctl mcp — MCP server management commands."""
from __future__ import annotations

import typer

app = typer.Typer(help="Run the cloudctl MCP server for Claude Desktop, Cursor, and MCP clients.")


@app.command("serve")
def serve(
    transport: str = typer.Option(
        "stdio", "--transport", "-t",
        help="Transport protocol: stdio (default) | sse",
    ),
) -> None:
    """
    Start the cloudctl MCP server.

    Add to Claude Desktop config:
      {
        "mcpServers": {
          "cloudctl": {
            "command": "cloudctl-mcp"
          }
        }
      }
    """
    try:
        import mcp  # noqa: F401  # noqa: PLC0415
    except ImportError:
        typer.echo("MCP not installed. Run: pip install 'cctl[mcp]'", err=True)
        raise typer.Exit(1)

    import asyncio  # noqa: PLC0415
    from cloudctl.mcp.server import main  # noqa: PLC0415
    asyncio.run(main())


@app.command("config")
def mcp_config() -> None:
    """Print the Claude Desktop configuration snippet for cloudctl."""
    import shutil  # noqa: PLC0415
    cmd = shutil.which("cloudctl-mcp") or "cloudctl-mcp"
    snippet = {
        "mcpServers": {
            "cloudctl": {
                "command": cmd
            }
        }
    }
    import json  # noqa: PLC0415
    typer.echo(json.dumps(snippet, indent=2))

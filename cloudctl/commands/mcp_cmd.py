"""cloudctl mcp — MCP server management commands."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import typer

app = typer.Typer(help="Run and install the cloudctl MCP server for Claude Desktop, Cursor, and MCP clients.")

# ── helpers ────────────────────────────────────────────────────────────────

def _claude_config_path() -> Path:
    """Return the platform-specific Claude Desktop config file path."""
    if sys.platform == "win32":
        base = Path.home() / "AppData" / "Roaming" / "Claude"
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "Claude"
    else:
        # Linux / XDG
        xdg = Path(
            __import__("os").environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
        )
        base = xdg / "Claude"
    return base / "claude_desktop_config.json"


def _entry() -> dict:
    """Build the mcpServers entry for cloudctl."""
    cmd = shutil.which("cloudctl-mcp")
    if cmd:
        return {"command": cmd}
    # Fallback: use the current Python interpreter with -m
    return {"command": sys.executable, "args": ["-m", "cloudctl.mcp.server"]}


# ── commands ───────────────────────────────────────────────────────────────

@app.command("serve")
def serve(
    transport: str = typer.Option(
        "stdio", "--transport", "-t",
        help="Transport protocol: stdio (default) | sse",
    ),
) -> None:
    """Start the cloudctl MCP server (used by Claude Desktop automatically)."""
    try:
        import mcp  # noqa: F401  # noqa: PLC0415
    except ImportError:
        typer.echo("MCP not installed. Run: pip install 'cctl[mcp]'", err=True)
        raise typer.Exit(1)

    import asyncio  # noqa: PLC0415
    from cloudctl.mcp.server import main  # noqa: PLC0415
    asyncio.run(main())


@app.command("install")
def install(
    client: str = typer.Option(
        "claude", "--client", "-c",
        help="MCP client to configure: claude | cursor | vscode",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Print what would be written without modifying any files.",
    ),
) -> None:
    """
    Auto-install cloudctl into your MCP client config.

    Writes (or updates) the MCP server entry so you don't have to edit
    config files manually.  Restarts are still required after install.

      cloudctl mcp install                  # Claude Desktop (default)
      cloudctl mcp install --client cursor  # Cursor
      cloudctl mcp install --dry-run        # Preview changes only
    """
    # ── resolve config path ────────────────────────────────────────────────
    if client == "claude":
        config_path = _claude_config_path()
    elif client == "cursor":
        if sys.platform == "win32":
            config_path = Path.home() / "AppData" / "Roaming" / "Cursor" / "User" / "settings.json"
        elif sys.platform == "darwin":
            config_path = Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "settings.json"
        else:
            config_path = Path.home() / ".config" / "Cursor" / "User" / "settings.json"
    elif client == "vscode":
        if sys.platform == "win32":
            config_path = Path.home() / "AppData" / "Roaming" / "Code" / "User" / "settings.json"
        elif sys.platform == "darwin":
            config_path = Path.home() / "Library" / "Application Support" / "Code" / "User" / "settings.json"
        else:
            config_path = Path.home() / ".config" / "Code" / "User" / "settings.json"
    else:
        typer.echo(f"Unknown client '{client}'. Choose: claude, cursor, vscode", err=True)
        raise typer.Exit(1)

    # ── check mcp is installed ─────────────────────────────────────────────
    try:
        import mcp  # noqa: F401  # noqa: PLC0415
    except ImportError:
        typer.echo("MCP not installed. Run: pip install 'cctl[mcp]'", err=True)
        raise typer.Exit(1)

    # ── load existing config ───────────────────────────────────────────────
    config: dict = {}
    if config_path.exists():
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            typer.echo(f"Warning: could not read {config_path}: {exc}", err=True)

    # ── build entry ────────────────────────────────────────────────────────
    entry   = _entry()
    already = config.get("mcpServers", {}).get("cloudctl") == entry

    if already:
        typer.echo(f"cloudctl is already registered in {config_path}")
        return

    config.setdefault("mcpServers", {})["cloudctl"] = entry
    new_content = json.dumps(config, indent=2)

    # ── dry run ────────────────────────────────────────────────────────────
    if dry_run:
        typer.echo(f"[dry-run] Would write to: {config_path}")
        typer.echo(new_content)
        return

    # ── write ──────────────────────────────────────────────────────────────
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(new_content, encoding="utf-8")

    typer.echo(f"[+] cloudctl added to {config_path}")
    typer.echo(f"    command: {entry['command']}")
    if entry.get("args"):
        typer.echo(f"    args:    {entry['args']}")
    typer.echo("")
    typer.echo("Restart Claude Desktop (or your MCP client) to activate.")
    typer.echo("")
    typer.echo("Available tools after restart:")
    typer.echo("  cloudctl_debug_incident      — full AI incident diagnosis")
    typer.echo("  cloudctl_get_service_config  — fetch any AWS service config")
    typer.echo("  cloudctl_tail_logs           — tail CloudWatch logs")
    typer.echo("  cloudctl_get_event_timeline  — correlated event timeline")
    typer.echo("  cloudctl_list_compute        — list EC2 / VMs / GCE")
    typer.echo("  cloudctl_check_security      — security audit")
    typer.echo("  cloudctl_get_cost_summary    — cost summary")
    typer.echo("  ... and more")


@app.command("config")
def mcp_config() -> None:
    """Print the Claude Desktop configuration snippet for manual setup."""
    entry   = _entry()
    snippet = {"mcpServers": {"cloudctl": entry}}
    typer.echo(json.dumps(snippet, indent=2))
    typer.echo("")
    typer.echo(f"Config file location: {_claude_config_path()}")
    typer.echo("")
    typer.echo("Or run:  cloudctl mcp install")

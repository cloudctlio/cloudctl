"""cloudctl ai — AI provider configuration and model management."""
from __future__ import annotations

import json
from typing import Optional

import typer
from rich.console import Console

from cloudctl.commands._helpers import require_init
from cloudctl.output.formatter import error, warn

app     = typer.Typer(help="AI provider configuration and model management.")
console = Console()


def _get_ai(cfg):
    """Load AI provider or exit with a helpful hint."""
    try:
        from cloudctl.ai.factory import get_ai, is_ai_configured  # noqa: PLC0415
    except ImportError:
        error("AI module not installed. Run: [cyan]pip install 'cctl[ai]'[/cyan]")
        raise typer.Exit(1)

    if not is_ai_configured(cfg):
        error(
            "AI is not configured. Run: [cyan]cloudctl config set ai.provider bedrock[/cyan]\n"
            "  Supported: bedrock | azure | vertex | anthropic | openai | ollama"
        )
        raise typer.Exit(1)

    return get_ai(cfg)


def _fetch_context(cfg, cloud, account, region) -> dict:
    """Fetch real cloud data to include as context for the AI."""
    from cloudctl.ai.data_fetcher import DataFetcher  # noqa: PLC0415
    fetcher = DataFetcher(cfg)
    return fetcher.fetch_summary(cloud=cloud, account=account, region=region)




@app.command("status")
def ai_status() -> None:
    """Show current AI provider configuration."""
    cfg = require_init()
    try:
        from cloudctl.ai.factory import get_ai_status, is_ai_configured  # noqa: PLC0415
        if not is_ai_configured(cfg):
            warn("AI is not configured. Run: cloudctl config set ai.provider <provider>")
            return
        status = get_ai_status(cfg)
    except ImportError:
        error("AI module not installed. Run: [cyan]pip install 'cctl[ai]'[/cyan]")
        raise typer.Exit(1)

    rows = [{"Setting": k, "Value": str(v)} for k, v in status.items()]
    from cloudctl.output.formatter import print_table  # noqa: PLC0415
    print_table(rows, title="AI Configuration")


@app.command("models")
def ai_models() -> None:
    """List available AI models for the configured provider."""
    cfg = require_init()
    ai  = _get_ai(cfg)

    try:
        models = ai.list_models() if hasattr(ai, "list_models") else []
    except Exception as e:
        error(f"Could not list models: {e}")
        raise typer.Exit(1)

    if not models:
        console.print("[dim]Model listing not supported by this provider.[/dim]")
        return

    rows = [{"Model": m.get("id", str(m)), "Description": m.get("name", "—")} for m in models]
    from cloudctl.output.formatter import print_table  # noqa: PLC0415
    print_table(rows, title="Available AI Models")

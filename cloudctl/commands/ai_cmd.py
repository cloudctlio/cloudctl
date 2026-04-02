"""cloudctl ai — natural language cloud queries powered by configured AI provider."""
from __future__ import annotations

import json
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from cloudctl.commands._helpers import require_init
from cloudctl.output.formatter import error, warn

app    = typer.Typer(help="Ask questions about your cloud infrastructure using AI.")
console = Console()

_CLOUD   = typer.Option("all",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="Scope to a specific account/profile.")
_REGION  = typer.Option(None,   "--region",  "-r", help="Scope to a specific region.")


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


@app.command("ask")
def ai_ask(
    question: str           = typer.Argument(..., help="Natural language question about your infrastructure."),
    cloud:    str           = _CLOUD,
    account:  Optional[str] = _ACCOUNT,
    region:   Optional[str] = _REGION,
    no_data:  bool          = typer.Option(False, "--no-data", help="Skip data fetch, answer from config only."),
) -> None:
    """Ask a natural language question about your cloud infrastructure."""
    cfg = require_init()
    ai  = _get_ai(cfg)

    context: dict = {}
    if not no_data:
        with console.status("[dim]Fetching cloud data...[/dim]"):
            try:
                context = _fetch_context(cfg, cloud, account, region)
            except Exception as e:
                warn(f"Could not fetch cloud context: {e}")

    with console.status("[dim]Thinking...[/dim]"):
        try:
            result = ai.ask(question, context=context)
        except Exception as e:
            error(f"AI error: {e}")
            raise typer.Exit(1)

    answer     = result.get("answer", str(result))
    confidence = result.get("confidence", "UNKNOWN")
    sources    = result.get("sources", [])

    confidence_color = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(confidence, "dim")
    footer = f"[{confidence_color}]{confidence} confidence[/{confidence_color}]"
    if sources:
        footer += f"  |  sources: {', '.join(sources)}"

    console.print(Panel(answer, title=f"[bold cyan]{question}[/bold cyan]", subtitle=footer))


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

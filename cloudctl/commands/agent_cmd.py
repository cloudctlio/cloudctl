"""cloudctl agent — multi-turn agentic cloud queries."""
from __future__ import annotations

from typing import Optional

import typer
from rich.panel import Panel

from cloudctl.commands._helpers import console, require_init
from cloudctl.output.formatter import warn

app = typer.Typer(help="Multi-turn agentic cloud queries (iterative data fetching).")

_CLOUD   = typer.Option("all", "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,  "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,  "--region",  "-r", help="Region to focus on")


@app.command("run")
def agent_run(
    question: str           = typer.Argument(..., help="Your question about the cloud infrastructure"),
    cloud:    str           = _CLOUD,
    account:  Optional[str] = _ACCOUNT,
    region:   Optional[str] = _REGION,
    rounds:   bool          = typer.Option(False, "--show-rounds", help="Show how many fetch rounds were used"),
) -> None:
    """
    Run a multi-turn agentic cloud query.

    Starts with a summary, then iteratively fetches more data if needed.
    Max 3 rounds of data fetching.

    Examples:
      cloudctl agent run "which services are costing the most?"
      cloudctl agent run "are any of my databases publicly accessible?"
      cloudctl agent run "what's using the most compute?" --cloud aws
    """
    cfg = require_init()

    try:
        from cloudctl.ai.factory import is_ai_configured  # noqa: PLC0415
    except ImportError:
        warn("AI module not installed. Run: [cyan]pip install 'cctl[ai]'[/cyan]")
        raise typer.Exit(1)

    if not is_ai_configured(cfg):
        warn("AI not configured. Run: [cyan]cloudctl config set ai.provider <provider>[/cyan]")
        raise typer.Exit(1)

    console.print(f"\n[bold]Agent:[/bold] {question}")
    console.print("[dim]Fetching data (up to 3 rounds)...[/dim]\n")

    from cloudctl.ai.agent import CloudAgent  # noqa: PLC0415
    agent  = CloudAgent(cfg)
    result = agent.run(question, cloud=cloud, account=account, region=region)

    confidence_color = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(
        result.confidence_level, "dim"
    )
    subtitle = (
        f"[{confidence_color}]{result.confidence_level} confidence[/{confidence_color}]"
        f" · {result.rounds} round(s) · {', '.join(result.context_categories_used) or 'no data'}"
    )

    console.print(Panel(
        result.answer,
        title="[bold cyan]Answer[/bold cyan]",
        subtitle=subtitle,
        border_style="cyan",
    ))
    console.print()

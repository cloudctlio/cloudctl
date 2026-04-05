"""cloudctl debug — AI-powered cloud infrastructure debugging."""
from __future__ import annotations

from typing import Optional

import typer
from rich.panel import Panel

from cloudctl.commands._helpers import console, require_init
from cloudctl.output.formatter import warn

app = typer.Typer(help="AI-powered cloud infrastructure debugging.")

_CLOUD   = typer.Option("all",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region to focus on")


@app.command("symptom")
def debug_symptom(
    symptom:  str           = typer.Argument(..., help="Describe the symptom, e.g. 'payments returning 502s'"),
    cloud:    str           = _CLOUD,
    account:  Optional[str] = _ACCOUNT,
    region:   Optional[str] = _REGION,
    include:  Optional[str] = typer.Option(
        None, "--include", "-i",
        help="Comma-separated data categories: compute,cost,security,database,storage",
    ),
) -> None:
    """
    Debug a cloud infrastructure symptom using AI analysis of real data.

    Examples:
      cloudctl debug symptom "payments returning 502s"
      cloudctl debug symptom "Lambda timing out" --cloud aws
      cloudctl debug symptom "high costs this month" --include cost
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

    include_list = [s.strip() for s in include.split(",")] if include else None

    console.print(f"\n[bold]Diagnosing:[/bold] {symptom}")
    console.print("[dim]Fetching real cloud data...[/dim]\n")

    from cloudctl.ai.debug_engine import DebugEngine  # noqa: PLC0415
    engine  = DebugEngine(cfg)
    finding = engine.debug(
        symptom=symptom,
        cloud=cloud,
        account=account,
        region=region,
        include=include_list,
    )

    # Render confidence
    cs_label = finding.confidence.label if finding.confidence else "unknown confidence"

    # Root cause panel
    console.print(Panel(
        finding.root_cause,
        title="[bold red]Root Cause[/bold red]",
        subtitle=cs_label,
        border_style="red",
    ))

    # Affected resources
    if finding.affected_resources:
        console.print("\n[bold]Affected Resources:[/bold]")
        for r in finding.affected_resources:
            console.print(f"  - {r}")

    # Remediation steps
    if finding.remediation_steps:
        console.print("\n[bold]Remediation Steps:[/bold]")
        for i, step in enumerate(finding.remediation_steps, 1):
            console.print(f"  [cyan]{i}.[/cyan] {step}")

    if finding.confidence_notes:
        console.print(f"\n[dim]Note: {finding.confidence_notes}[/dim]")

    console.print()

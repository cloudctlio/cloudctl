"""Debug renderer — all terminal output for debug sessions. No logic, no cloud calls."""
from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

_console = Console()


def fetch_start(label: str) -> None:
    _console.print(f"  [dim]↳ fetching {label}...[/dim]")


def fetch_item(label: str, count: int) -> None:
    _console.print(f"  [dim]↳ {label}: {count} item(s)[/dim]")


def fetch_skipped(label: str, reason: str) -> None:
    _console.print(f"  [yellow]⚠[/yellow] [dim]{label} skipped — {reason}[/dim]")


def fetch_error(label: str, error: str) -> None:
    _console.print(f"  [red]✗[/red] [dim]{label} error: {error}[/dim]")


def section_header(title: str) -> None:
    _console.print(f"\n[bold cyan]── {title} ──[/bold cyan]")


def root_cause(cause: str, confidence_label: str) -> None:
    _console.print(Panel(
        cause,
        title="[bold red]Root Cause[/bold red]",
        subtitle=f"[dim]{confidence_label}[/dim]",
        border_style="red",
    ))


def evidence_table(events: list[dict]) -> None:
    """Render a timeline of evidence events."""
    if not events:
        return
    t = Table(title="Evidence Timeline", show_lines=False, header_style="bold")
    t.add_column("Time (UTC)", style="dim", no_wrap=True)
    t.add_column("Source", style="cyan", no_wrap=True)
    t.add_column("Event")
    for ev in events:
        t.add_row(
            str(ev.get("time", "—")),
            str(ev.get("source", "—")),
            str(ev.get("event", "—")),
        )
    _console.print(t)


def affected_resources(resources: list[str]) -> None:
    if not resources:
        return
    _console.print("\n[bold]Affected Resources:[/bold]")
    for r in resources:
        _console.print(f"  [red]•[/red] {r}")


def remediation_steps(steps: list[str], deployment_method: Optional[str] = None) -> None:
    if not steps:
        return
    title = "[bold]Remediation Steps"
    if deployment_method and deployment_method != "unknown":
        title += f" (via {deployment_method})"
    title += "[/bold]"
    _console.print(f"\n{title}")
    for i, step in enumerate(steps, 1):
        _console.print(f"  [cyan]{i}.[/cyan] {step}")


def iac_drift_warning(method: str) -> None:
    warnings = {
        "cdk":            "Direct changes will be overwritten on the next cdk deploy.",
        "terraform":      "Direct changes will be overwritten on the next terraform apply.",
        "pulumi":         "Direct changes will be overwritten on the next pulumi up.",
        "cloudformation": "Direct changes will be overwritten on the next stack update.",
    }
    msg = warnings.get(method.lower())
    if msg:
        _console.print(f"\n[yellow]⚠ IaC drift:[/yellow] [dim]{msg}[/dim]")


def confidence_note(note: str) -> None:
    if note:
        _console.print(f"\n[dim]Note: {note}[/dim]")


def incident_saved(path: str) -> None:
    _console.print(f"\n[dim]Incident report saved: {path}[/dim]")


def no_data_found(categories: list[str]) -> None:
    cats = ", ".join(categories)
    _console.print(f"[dim]No data found for: {cats}[/dim]")


def diagnosing_banner(symptom: str) -> None:
    _console.print(f"\n[bold]Diagnosing:[/bold] {symptom}")
    _console.print("[dim]Fetching real cloud data...[/dim]\n")


def missing_source_warning(source: str, instructions: str) -> None:
    _console.print(f"[yellow]⚠[/yellow] {source} — {instructions}")

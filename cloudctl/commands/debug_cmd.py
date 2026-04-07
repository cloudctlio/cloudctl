"""cloudctl debug — AI-powered cloud infrastructure debugging."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import typer
from rich.markdown import Markdown
from rich.markup import escape
from rich.table import Table, box
from rich.text import Text

from cloudctl.commands._helpers import console, require_init
from cloudctl.output.formatter import warn

app = typer.Typer(help="AI-powered cloud infrastructure debugging.")

_CLOUD   = typer.Option("all",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region to focus on")


def _render_incident(finding, account: Optional[str]) -> None:
    cs        = finding.confidence
    cs_level  = cs.level if cs else "UNKNOWN"   # HIGH / MEDIUM / LOW — plain string, no markup
    cs_reason = cs.reason if cs else ""
    sources   = finding.context_summary
    ts        = datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M UTC")
    acct      = account or "—"
    data_pts  = sum(v if isinstance(v, int) else 0 for v in sources.values())
    src_names = "  +  ".join(k for k in sources if k not in ("aws",))

    cs_color      = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(cs_level, "dim")
    status_color  = cs_color
    affected_name = finding.affected_resources[0] if finding.affected_resources else finding.symptom[:60]

    def _cell(text: str) -> Text:
        """Wrap plain text so Rich never parses it as markup."""
        return Text(text)

    # Single table — one consistent box, two columns
    t = Table(
        box=box.DOUBLE,
        show_header=False,
        padding=(0, 1),
        expand=True,
        show_edge=True,
    )
    t.add_column(style="bold cyan", no_wrap=True, min_width=14, max_width=14)
    t.add_column()

    t.add_row(
        Text(""),
        Text(f"INCIDENT ANALYSIS  ·  {ts}  ·  account: {acct}", style="bold"),
        end_section=True,
    )

    t.add_row(
        Text("STATUS"),
        Text(f"DEGRADED  —  {affected_name}", style=status_color),
        end_section=True,
    )

    confidence_val = cs_level
    if cs_reason:
        confidence_val += f"  ({cs_reason})"
    t.add_row(Text("CONFIDENCE"), Text(confidence_val, style=cs_color), end_section=True)

    t.add_row(Text("ROOT CAUSE"), Markdown((finding.root_cause or "").strip()), end_section=True)

    # Extract [ERROR] / RuntimeError lines as evidence
    evidence_lines = [ln.strip() for ln in (finding.root_cause or "").splitlines()
                      if "[ERROR]" in ln or "RuntimeError" in ln]
    if evidence_lines:
        t.add_row(Text("EVIDENCE"), _cell("\n".join(evidence_lines[:3])), end_section=True)

    if finding.confidence_notes:
        t.add_row(Text("NOTE"), _cell(finding.confidence_notes), end_section=True)

    # Split steps: those with real IDs vs those needing a lookup first
    fix_steps  = [s for s in finding.remediation_steps if "<" not in s]
    need_steps = [s for s in finding.remediation_steps if "<" in s]

    if fix_steps:
        t.add_row(Text("FIX NOW"), _cell("\n".join(fix_steps)), end_section=True)

    if need_steps:
        t.add_row(Text("NEED FIRST"), _cell("\n".join(need_steps)), end_section=True)

    t.add_row(
        Text(""),
        Text(f"{data_pts} data points  ·  {src_names}", style="dim"),
    )

    console.print(t)
    console.print()


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

    _render_incident(finding, account)

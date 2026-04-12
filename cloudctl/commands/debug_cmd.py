"""cloudctl debug — AI-powered cloud infrastructure debugging."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

import typer
from rich.markdown import Markdown
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
    cs_level  = cs.level if cs else "UNKNOWN"
    cs_reason = cs.reason if cs else ""
    sources   = finding.context_summary
    from datetime import timezone as _tz
    ts        = datetime.now(_tz.utc).strftime("%Y-%m-%d  %H:%M UTC")
    acct      = account or "—"
    data_pts  = sum(v if isinstance(v, int) else 0 for v in sources.values())
    src_names = "  +  ".join(k for k in sources if k not in ("aws",))

    cs_color     = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(cs_level, "dim")
    affected     = finding.affected_resources[0] if finding.affected_resources else finding.issue[:60]
    deploy       = getattr(finding, "deployment_method", "unknown")
    fix_steps    = [s for s in finding.remediation_steps if "<" not in s]
    need_steps   = [s for s in finding.remediation_steps if "<" in s]

    t = Table(
        box=box.DOUBLE,
        show_header=False,
        padding=(0, 1),
        expand=True,
        show_edge=True,
    )
    t.add_column(style="bold cyan", no_wrap=True, min_width=14, max_width=14)
    t.add_column(overflow="fold")

    t.add_row(
        Text(""),
        Text(f"INCIDENT ANALYSIS  ·  {ts}  ·  account: {acct}", style="bold"),
        end_section=True,
    )

    t.add_row(
        Text("STATUS"),
        Text(f"DEGRADED  —  {affected}", style="bold red"),
        end_section=True,
    )

    if deploy and deploy != "unknown":
        t.add_row(
            Text("DEPLOYED VIA"),
            Text(deploy.upper(), style="bold blue"),
            end_section=True,
        )

    # Only show reason for non-HIGH (missing data is actionable; "300 resources" is noise)
    confidence_val = cs_level
    if cs_level != "HIGH" and cs_reason:
        confidence_val += f"  —  {cs_reason}"
    t.add_row(
        Text("CONFIDENCE"),
        Text(confidence_val, style=f"bold {cs_color}"),
        end_section=True,
    )

    import re as _re
    root_cause_text = (finding.root_cause or "").strip()
    # Normalize inline bullets: insert newline before '•' or '-' that aren't already on their own line
    root_cause_text = _re.sub(r'(?<!\n)\s*([•\-])\s+', r'\n- ', root_cause_text)
    root_cause_text = _re.sub(r'\n{3,}', '\n\n', root_cause_text)
    t.add_row(
        Text("ROOT CAUSE"),
        Markdown(root_cause_text),
        end_section=True,
    )

    if finding.confidence_notes:
        t.add_row(
            Text("NOTE", style="dim"),
            Text(finding.confidence_notes, style="dim"),
            end_section=True,
        )

    if fix_steps:
        t.add_row(
            Text("FIX NOW", style="bold cyan"),
            Text("\n".join(fix_steps)),
            end_section=True,
        )

    if need_steps:
        t.add_row(
            Text("NEED FIRST", style="bold yellow"),
            Text("\n".join(need_steps), style="yellow"),
            end_section=True,
        )

    t.add_row(
        Text(""),
        Text(f"{data_pts} data points  ·  {src_names}", style="dim"),
    )

    console.print(t)
    console.print()


def _render_explain(finding) -> None:
    """Show how cloudctl fetched and analyzed the incident (--explain output)."""
    console.print("\n[bold]HOW THIS ANALYSIS WORKS:[/bold]\n")

    console.print("  [bold]Step 1 — Data fetched (deterministic, read-only):[/bold]")
    for source, count in finding.context_summary.items():
        if source == "deployment_method":
            continue
        console.print(f"    - {source}: {count} items")

    console.print()
    console.print("  [bold]Step 2 — AI reasoning:[/bold]")
    deploy = getattr(finding, "deployment_method", "unknown")
    if deploy and deploy != "unknown":
        console.print(f"    - Deployment method detected: {deploy.upper()}")
        console.print(f"    - Remediation steps tailored to {deploy} tooling")
    else:
        console.print("    - Deployment method: not detected (remediation uses CLI commands)")

    console.print()
    cs = finding.confidence
    level = cs.level if cs else "UNKNOWN"
    console.print(f"  [bold]Confidence: {level}[/bold]")
    if finding.confidence_notes:
        console.print(f"    {finding.confidence_notes}")
    console.print()


@app.command()
def debug_issue(
    issue:    str           = typer.Argument(..., metavar="TEXT", help="Describe what's wrong, e.g. 'payments returning 502s'"),
    cloud:    str           = _CLOUD,
    account:  Optional[str] = _ACCOUNT,
    region:   Optional[str] = _REGION,
    include:  Optional[str] = typer.Option(
        None, "--include", "-i",
        help="Comma-separated data categories: compute,cost,security,database,storage",
    ),
    dry_run:  bool          = typer.Option(
        False, "--dry-run",
        help="Show what cloudctl will fetch without running the analysis (all operations are read-only)",
    ),
    explain:  bool          = typer.Option(
        False, "--explain",
        help="Show how cloudctl fetched and analyzed this incident after the result",
    ),
) -> None:
    """
    Debug a cloud infrastructure issue using AI analysis of real data.

    Examples:
      cloudctl debug "payments returning 502s"
      cloudctl debug "Lambda timing out" --cloud aws
      cloudctl debug "checkout service degraded" --account my-profile
      cloudctl debug "something broke" --dry-run
    """
    cfg = require_init()

    if dry_run:
        from cloudctl.debug.planner import plan_sources, extract_service_hints  # noqa: PLC0415
        sources = plan_sources(issue)
        hints   = extract_service_hints(issue)
        console.print("\n[bold]DRY RUN — no data will be fetched, no changes made[/bold]\n")
        console.print("This session would fetch (all operations are read-only):\n")
        source_descriptions = {
            "service_logs":    "application/service logs matching issue hints",
            "audit_logs":      "API call audit trail (last 2h)",
            "network_context": "network topology (VPCs/VNets, security groups, routing, load balancers)",
        }
        for src in sources:
            desc = source_descriptions.get(src, src)
            console.print(f"   - {src}: {desc}")
        if hints:
            console.print(f"\nResource hints extracted from issue: {', '.join(hints)}")
        console.print("\nRun without --dry-run to execute the analysis.")
        return

    try:
        from cloudctl.ai.factory import is_ai_configured  # noqa: PLC0415
    except ImportError:
        warn("AI module not installed. Run: [cyan]pip install 'cctl[ai]'[/cyan]")
        raise typer.Exit(1)

    if not is_ai_configured(cfg):
        warn("AI not configured. Run: [cyan]cloudctl config set ai.provider <provider>[/cyan]")
        raise typer.Exit(1)

    include_list = [s.strip() for s in include.split(",")] if include else None

    console.print(f"\n[bold]Diagnosing:[/bold] {issue}")

    from cloudctl.ai.debug_engine import DebugEngine  # noqa: PLC0415
    engine = DebugEngine(cfg)
    with console.status("[dim]Fetching real cloud data...[/dim]"):
        finding = engine.debug(
            symptom=issue,
            cloud=cloud,
            account=account,
            region=region,
            include=include_list,
        )

    _render_incident(finding, account)

    if explain:
        _render_explain(finding)

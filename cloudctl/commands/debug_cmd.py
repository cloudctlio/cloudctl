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


def _render_agent_result(d: dict, account: Optional[str]) -> None:
    """Render the structured JSON from debug_incident_agent in the same table format."""
    from datetime import timezone as _tz
    ts       = datetime.now(_tz.utc).strftime("%Y-%m-%d  %H:%M UTC")
    cs_level = d.get("confidence", "MEDIUM")
    cs_color = {"HIGH": "green", "MEDIUM": "yellow", "LOW": "red"}.get(cs_level, "dim")

    t = Table(box=box.DOUBLE, show_header=False, padding=(0, 1), expand=True, show_edge=True)
    t.add_column(style="bold cyan", no_wrap=True, min_width=14, max_width=14)
    t.add_column(overflow="fold")

    t.add_row(
        Text(""),
        Text(f"INCIDENT ANALYSIS  ·  {ts}  ·  account: {account or '—'}", style="bold"),
        end_section=True,
    )
    t.add_row(
        Text("STATUS"),
        Text(f"DEGRADED  —  {d.get('root_cause', '?')[:80]}", style="bold red"),
        end_section=True,
    )
    t.add_row(
        Text("CONFIDENCE"),
        Text(cs_level, style=f"bold {cs_color}"),
        end_section=True,
    )
    t.add_row(
        Text("ROOT CAUSE"),
        Markdown((d.get("root_cause") or "").strip()),
        end_section=True,
    )

    deploy = d.get("deployment_source", "")
    if deploy and deploy not in ("unknown", ""):
        t.add_row(
            Text("DEPLOYED VIA"),
            Text(deploy.upper(), style="bold blue"),
            end_section=True,
        )
    iac_hint = d.get("iac_file_hint", "")
    if iac_hint:
        t.add_row(
            Text("IaC HINT"),
            Text(iac_hint),
            end_section=True,
        )

    evidence = d.get("evidence") or []
    if evidence:
        t.add_row(
            Text("EVIDENCE"),
            Markdown("\n".join(f"- {e}" for e in evidence)),
            end_section=True,
        )

    fix_steps = d.get("remediation_steps") or []
    if fix_steps:
        t.add_row(
            Text("FIX NOW", style="bold cyan"),
            Text("\n".join(fix_steps)),
            end_section=True,
        )

    investigated = d.get("resources_investigated") or []
    src_str = "  +  ".join(investigated) if investigated else "—"
    t.add_row(Text(""), Text(f"investigated: {src_str}", style="dim"))

    console.print(t)
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
    agent:    bool          = typer.Option(
        False, "--agent",
        help="Agentic mode: Claude drives the investigation across parallel hypothesis branches",
    ),
    verdict:  Optional[str] = typer.Option(
        None, "--verdict", "-v",
        help="Skip prompt and feed verdict into the learning loop. One of: y, n, partial, skip. Use in CI/scripts.",
    ),
    correction: Optional[str] = typer.Option(
        None, "--correction",
        help="Free-text correction passed to live_learner when --verdict is n or partial.",
    ),
    resolve: bool = typer.Option(
        False, "--resolve",
        help="After a confirmed diagnosis, run the resolution agent to create a fix branch and PR.",
    ),
    iac_root: Optional[str] = typer.Option(
        None, "--iac-root",
        help="Local path to IaC root directory (Terraform / CDK). Required when --resolve is set.",
    ),
    resolve_yes: bool = typer.Option(
        False, "--yes",
        help="With --resolve: skip the two approval gates (fix plan, and "
             "diff+validation before push). Without this flag the agent stops "
             "at each gate for confirmation; non-interactive runs stop safely.",
    ),
    json_out: Optional[str] = typer.Option(
        None, "--json-out",
        help="With --agent: also write the raw agent JSON (root_cause, evidence, "
             "confidence, etc.) to this file path, alongside the normal rendered "
             "table. For automated grading (tests/harness/scorer.py) — the "
             "rendered table is lossy, the raw JSON is the actual grading input.",
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

    if agent:
        import json as _json  # noqa: PLC0415
        from cloudctl.ai.graph_agent import debug_incident_graph  # noqa: PLC0415
        from cloudctl.ai.live_learner  import (  # noqa: PLC0415
            on_confirmed_correct, on_confirmed_wrong, best_pattern_match,
        )

        console.print(f"\n[bold]Agent investigating:[/bold] {issue}")
        with console.status("[dim]Claude is driving the investigation (3 parallel branches)...[/dim]"):
            raw, all_fetched = debug_incident_graph(
                symptom=issue,
                profile=account,
                region=region or "us-east-1",
            )
        d = _json.loads(raw)

        # Surface guardrail errors before rendering
        if "error" in d and len(d) == 1:
            warn(d["error"])
            raise typer.Exit(1)

        # Fixture-match boost: when this symptom has been confirmed correct N>=3
        # times before with the agent's chosen evidence sources, promote
        # MEDIUM -> HIGH. Stops the agent self-rating MEDIUM on incidents we've
        # already validated repeatedly.
        match = best_pattern_match(issue)
        if match and match.get("confirmed_count", 0) >= 3:
            agent_sources = {k.split(":", 1)[0] for k in (all_fetched or {})}
            pattern_sources = set(match.get("data_sources") or [])
            if pattern_sources and pattern_sources.issubset(agent_sources):
                if d.get("confidence") == "MEDIUM":
                    d["confidence"] = "HIGH"
                    d.setdefault("evidence", []).append(
                        f"Pattern '{match['pattern_id']}' confirmed correct "
                        f"{match['confirmed_count']}x previously; confidence promoted."
                    )

        _render_agent_result(d, account)

        if json_out:
            from pathlib import Path as _Path  # noqa: PLC0415
            _Path(json_out).write_text(_json.dumps(d, indent=2), encoding="utf-8")

        # y/n confirmation — feeds the live learning loop
        if verdict is not None:
            verdict_value = verdict.strip().lower()
        else:
            try:
                verdict_value = console.input(
                    "[dim]Was this diagnosis correct? [[bold]y[/bold]/[bold]n[/bold]/partial/skip]: [/dim]"
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                verdict_value = "skip"

        if verdict_value in ("y", "yes"):
            meta = d.get("_guardrails", {})
            on_confirmed_correct(
                query=issue,
                fetched_data=all_fetched,
                agent_output=d,
                account_id=meta.get("account_id") or account or "",
                region=region or "us-east-1",
                turns_used=meta.get("turns_used", 0),
            )

            # ── Resolution agent ───────────────────────────────────────────
            if resolve:
                import os as _os  # noqa: PLC0415
                from cloudctl.ai.resolution_agent import run as _resolve_run  # noqa: PLC0415

                root = iac_root
                if not root:
                    try:
                        root = console.input(
                            "[dim]IaC root directory (Terraform/CDK): [/dim]"
                        ).strip()
                    except (EOFError, KeyboardInterrupt):
                        root = ""
                if not root or not _os.path.isdir(root):
                    warn("--iac-root is required and must be a valid directory. Skipping resolution.")
                else:
                    base = "develop"
                    try:
                        base = console.input(
                            "[dim]Base branch for fix PR [develop]: [/dim]"
                        ).strip() or "develop"
                    except (EOFError, KeyboardInterrupt):
                        pass

                    import sys as _sys  # noqa: PLC0415

                    def _approve(stage: str, detail: str) -> bool:
                        """Two-gate operator approval: 'plan' before any file
                        write, 'push' before commit/push/PR."""
                        console.print(f"\n[bold yellow]— approval gate: {stage} —[/bold yellow]")
                        console.print(detail)
                        if resolve_yes:
                            console.print("[dim]--yes given: auto-approved[/dim]")
                            return True
                        if not _sys.stdin.isatty():
                            warn("Non-interactive run without --yes: stopping at "
                                 f"the '{stage}' gate. Re-run with --yes to proceed.")
                            return False
                        try:
                            ans = console.input(f"Approve {stage}? [y/N]: ").strip().lower()
                        except (EOFError, KeyboardInterrupt):
                            return False
                        return ans in ("y", "yes")

                    # No status spinner here: the approval gates prompt for
                    # input mid-run, which conflicts with a live status display.
                    console.print(f"\n[bold]Resolution agent starting (base: {base})...[/bold]")
                    console.print("[dim]Claude is drafting the fix (approval gates active)...[/dim]")
                    result = _resolve_run(
                        diagnosis=d,
                        iac_root=root,
                        base_branch=base,
                        profile=account,
                        region=region or "us-east-1",
                        approve=_approve,
                    )

                    status = result.get("status", "error")
                    if status == "success":
                        console.print(
                            f"\n[green bold]PR created:[/green bold] {result.get('pr_url', '—')}"
                        )
                        console.print(f"  Branch:  {result.get('branch', '—')}")
                        console.print(f"  Summary: {result.get('pr_summary', '—')}")
                    elif status == "manual_required":
                        console.print(
                            "\n[yellow bold]Manual steps required "
                            "(resource is not IaC-managed):[/yellow bold]"
                        )
                        for step in result.get("manual_steps", []):
                            console.print(f"  - {step}")
                    else:
                        warn(f"Resolution failed: {result.get('detail', 'unknown error')}")

        elif verdict_value in ("n", "no", "partial"):
            if correction is not None:
                correction_value = correction.strip()
            else:
                try:
                    correction_value = console.input(
                        "[dim]What was wrong or missing? (Enter to skip): [/dim]"
                    ).strip()
                except (EOFError, KeyboardInterrupt):
                    correction_value = ""
            meta = d.get("_guardrails", {})
            on_confirmed_wrong(
                query=issue,
                fetched_data=all_fetched,
                agent_output=d,
                user_correction=correction_value,
                account_id=meta.get("account_id") or account or "",
            )

        return

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

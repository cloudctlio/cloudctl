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


def _probe_consent(plan: dict) -> dict:
    """Interactive consent gate for one reproduction probe. Shows the operator
    exactly what will run and why, then returns their decision. Runs under the
    probe module's lock, so prompts never overlap across parallel branches."""
    import os as _os  # noqa: PLC0415
    import sys as _sys  # noqa: PLC0415
    console.print()
    console.print("[bold yellow]⚠  Active reproduction requested[/bold yellow]")
    console.print(f"    [bold]{plan['method']}[/bold] {plan['url']}")
    if plan.get("body"):
        console.print(f"    body:   {plan['body']}")
    console.print(f"    why:    {plan['reason']}")
    console.print(f"    safety: [dim]{plan['safety']}[/dim]")
    # Explicit unattended auto-approve (CI / replay / batch) must be honored even
    # though the interactive handler is registered — otherwise the non-TTY branch
    # below silently declines and CLOUDCTL_PROBE_AUTO can never take effect. Safe
    # default is unchanged: absent this explicit opt-in, a non-TTY session still
    # declines.
    if _os.environ.get("CLOUDCTL_PROBE_AUTO", "").lower() in ("approve", "yes", "y"):
        console.print("[dim]    CLOUDCTL_PROBE_AUTO=approve — auto-approving[/dim]")
        return {"decision": "approve"}
    if not _sys.stdin.isatty():
        console.print("[dim]    non-interactive session — declining probe[/dim]")
        return {"decision": "skip", "reason": "non-interactive session"}
    try:
        ans = console.input(
            "    [a]pprove (cloudctl runs it)  /  "
            "[p] I'll run it (paste response)  /  [s]kip: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return {"decision": "skip", "reason": "operator interrupted"}

    if ans in ("a", "approve", "y", "yes"):
        return {"decision": "approve"}
    if ans in ("p", "paste"):
        console.print("    Run this from anywhere that can reach it, then paste "
                      "the response body (end with an empty line):")
        curl_cmd = f"curl -s -X {plan['method']} '{plan['url']}'"
        if plan.get("body"):
            curl_cmd += (" -H 'content-type: application/json' "
                         f"-d '{plan['body']}'")
        console.print(f"      [dim]{curl_cmd}[/dim]")
        lines: list[str] = []
        while True:
            try:
                line = input()
            except (EOFError, KeyboardInterrupt):
                break
            if line == "":
                break
            lines.append(line)
        return {"decision": "paste", "pasted": "\n".join(lines)}
    return {"decision": "skip", "reason": "operator skipped"}


def _enable_active_reproduction() -> None:
    """Opt in to active reproduction: turn the capability on, wire the
    interactive consent gate, and explain to the operator what it does before
    anything runs — never hidden."""
    import os as _os  # noqa: PLC0415
    from cloudctl.mcp.tools.probe import set_consent_handler  # noqa: PLC0415

    _os.environ["CLOUDCTL_ENABLE_PROBES"] = "1"
    set_consent_handler(_probe_consent)

    console.print(
        "\n[bold]Active reproduction is ON.[/bold] When passive telemetry can't "
        "settle the diagnosis, the agent may propose a [bold]read-only[/bold] "
        "HTTP probe (a single GET/HEAD, or a provably non-mutating query "
        "request) to see what the service actually returns."
        "\n  • Every probe is shown to you first — nothing runs without approval."
        "\n  • Approve to have cloudctl run it, or run it yourself and paste the "
        "response (useful when the endpoint isn't reachable from here), or skip."
        "\n  • Probes are bounded (timeout, size cap, no redirects) and can never "
        "mutate anything.\n"
    )


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


def _render_diff_first_rows(t, d: dict) -> None:
    """Rows for the deterministic diff-first checks: the incident window, the
    causes they found, symptoms nothing explains, and changes ruled out."""
    df = d.get("diff_first") or {}
    if not df:
        return
    if df.get("ran") is False:
        t.add_row(Text("CHANGE CHECK"),
                  Text(f"did not run: {df.get('error')}", style="yellow"), end_section=True)
        return
    if df.get("recording_error"):
        t.add_row(Text("RECORDING"), Text(str(df["recording_error"]), style="yellow"),
                  end_section=True)
    w = df.get("window") or {}
    if w.get("onset"):
        t.add_row(Text("WINDOW"),
                  Text(f"last healthy {w.get('last_healthy')}  →  onset {w.get('onset')}  "
                       f"(expected state: {df.get('expected_state') or 'none'})"),
                  end_section=True)
    causes = df.get("causes") or []
    extra = d.get("additional_causes") or []
    if causes:
        lines = []
        for c in causes:
            flag = "  **(not in the diagnosis above)**" if c.get("summary") in extra else ""
            lines.append(f"- {c.get('summary')} → explains {', '.join(c.get('explains') or [])}{flag}")
        t.add_row(Text("CHANGE CHECK"), Markdown("\n".join(lines)), end_section=True)
    if df.get("unexplained"):
        t.add_row(Text("UNEXPLAINED"),
                  Markdown("\n".join(f"- {s}" for s in df["unexplained"])), end_section=True)
    if df.get("not_causes"):
        t.add_row(Text("RULED OUT"),
                  Markdown("\n".join(f"- {s}" for s in df["not_causes"])), end_section=True)


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

    _render_diff_first_rows(t, d)

    evidence = d.get("evidence") or []
    # Provenance trail: under each evidence line, show the fetched-corpus key
    # (tool + identifying inputs) that sources it, so a human can trace the
    # claim back to the raw tool call. Compact: first key + count of others.
    prov_by_claim: dict = {}
    for p in d.get("provenance") or []:
        if isinstance(p, dict) and p.get("claim"):
            prov_by_claim.setdefault(str(p["claim"]).strip(), p)
    unsourced = [str(u).strip() for u in d.get("unsourced_claims") or []]
    if evidence:
        lines = []
        for e in evidence:
            e_str = str(e).strip()
            lines.append(f"- {e_str}")
            keys = [str(k) for k in (prov_by_claim.get(e_str) or {}).get("evidence_keys", []) if k]
            if keys:
                shown = keys[0] if len(keys[0]) <= 64 else keys[0][:61] + "..."
                more = f" (+{len(keys) - 1} more)" if len(keys) > 1 else ""
                lines.append(f"  - `src: {shown}`{more}")
            elif e_str in unsourced:
                lines.append("  - `src: none — not traceable to fetched data`")
        t.add_row(
            Text("EVIDENCE"),
            Markdown("\n".join(lines)),
            end_section=True,
        )

    # Unsourced claims that are not evidence items (root-cause sentences with
    # specifics that traced to no fetched source) get their own row.
    uns_extra = [u for u in unsourced
                 if u not in {str(e).strip() for e in evidence}]
    if uns_extra:
        t.add_row(
            Text("UNSOURCED", style="bold yellow"),
            Text("\n".join(f"- {u[:120]}" for u in uns_extra), style="yellow"),
            end_section=True,
        )

    fix_steps = d.get("remediation_steps") or []
    rc = d.get("remediation_check") or {}
    if rc and not d.get("remediation_confirmed", True):
        # Fail closed: the cause stands, the fix is not presented as the fix.
        lines = [f"Found the cause but couldn't confirm the fix: {rc.get('reason', 'unchecked')}."]
        if rc.get("candidates"):
            lines.append("Resources it could be:")
            lines += [f"  - {c}" for c in rc["candidates"]]
        unv = {u["step"]: u["reason"] for u in rc.get("unverified") or []}
        if fix_steps:
            lines.append("Unverified steps, check each before running:")
            for st in fix_steps:
                lines.append(f"  [unverified] {st}" + (f"  ({unv[st]})" if st in unv else ""))
        for f in rc.get("flagged") or []:
            lines.append(f"  [held back] {f['step']}  ({f['reason']})")
        t.add_row(
            Text("FIX NOT\nCONFIRMED", style="bold yellow"),
            Text("\n".join(lines), style="yellow"),
            end_section=True,
        )
    elif fix_steps:
        lines = list(fix_steps)
        for f in rc.get("flagged") or []:
            lines.append(f"[held back] {f['step']}  ({f['reason']})")
        t.add_row(
            Text("FIX NOW", style="bold cyan"),
            Text("\n".join(lines)),
            end_section=True,
        )

    investigated = d.get("resources_investigated") or []
    src_str = "  +  ".join(investigated) if investigated else "—"
    t.add_row(Text(""), Text(f"investigated: {src_str}", style="dim"))

    console.print(t)
    console.print()


def _render_iac_fix(fix: dict) -> None:
    """Show the read-only IaC fix suggestion, apart from the diagnosis. It
    never changes the diagnosis or its confidence."""
    from rich.panel import Panel  # noqa: PLC0415
    from rich.syntax import Syntax  # noqa: PLC0415
    from rich.console import Group  # noqa: PLC0415

    status = fix.get("status")
    where = ""
    if fix.get("resource"):
        where = f"{fix['resource']}  ({fix.get('file')}:{fix.get('lines')}), matched because {fix.get('how')}"
    if status == "suggested":
        check = fix.get("check") or {}
        if fix.get("verified"):
            label, style = "CHECKED: " + check.get("detail", ""), "green"
            note = "Well-formed, but not proven to fix the incident. Nothing was applied."
        elif check.get("status") == "failed":
            label, style = "CHECK FAILED", "red"
            note = check.get("detail", "")
        else:
            label, style = "UNVERIFIED", "yellow"
            note = f"Not checked ({check.get('detail', 'no check ran')}). Nothing was applied."
        body = [Text(where, style="dim")]
        if fix.get("summary"):
            body.append(Text(fix["summary"]))
        body.append(Syntax(fix.get("diff", ""), "diff", theme="ansi_dark", word_wrap=True))
        body.append(Text(note, style="dim"))
        for p in fix.get("rejected_edits") or []:
            body.append(Text(f"Ignored: {p}", style="dim yellow"))
        console.print(Panel(Group(*body), title=f"[bold]IaC FIX SUGGESTION — {label}[/bold]",
                            border_style=style, expand=True))
    else:
        msg = fix.get("detail", "")
        if status == "ambiguous":
            msg += "\n" + "\n".join(f"  - {c}" for c in fix.get("candidates") or [])
        elif status in ("not_found", "no_iac") and fix.get("searched_for"):
            msg += f"\nLooked for: {', '.join(fix['searched_for'])} under {fix.get('iac_root')}"
        if where:
            msg = where + "\n" + msg
        console.print(Panel(Text(msg), title="[bold]IaC FIX SUGGESTION — none[/bold]",
                            border_style="dim", expand=True))
    console.print()


def _ground_remediation(d: dict, fix: Optional[dict], iac_root: Optional[str], all_fetched) -> None:
    """Check the fix steps against the resolved resource before they are
    shown (see cloudctl.debug.remediation_check). Steps the IaC lookup wrote
    for the resolved resource replace the agent's own; the originals are kept
    in remediation_steps_original. Never touches root cause or confidence."""
    import json as _json  # noqa: PLC0415
    from cloudctl.debug.remediation_check import (  # noqa: PLC0415
        check_remediation, iac_text_for, resolve_target,
    )
    original = list(d.get("remediation_steps") or [])
    steps = original
    if fix and fix.get("remediation_steps"):
        steps = list(fix["remediation_steps"])
        d["remediation_steps_original"] = original
    target = resolve_target(d, fix)
    try:
        fetched_text = _json.dumps(all_fetched or {}, default=str)[:3_000_000]
    except (TypeError, ValueError):
        fetched_text = ""
    rc = check_remediation(steps, d, target, iac_text_for(iac_root), fix, fetched_text)
    d["remediation_steps"] = rc["steps"]
    d["remediation_confirmed"] = rc["confirmed"]
    d["remediation_check"] = {k: rc[k] for k in ("reason", "flagged", "unverified", "candidates",
                                                  "replaced_with_iac_step", "target")}


def _iac_fix(diagnosis: dict, iac_dir: str, account: Optional[str], region: Optional[str]) -> dict:
    from cloudctl.debug.iac_fix import suggest_fix  # noqa: PLC0415
    with console.status("[dim]Looking up the blamed resource in your IaC...[/dim]"):
        return suggest_fix(diagnosis, iac_dir, profile=account, region=region or "us-east-1")


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
        help="Local path to your IaC root (Terraform / CDK Python). With it, debug finds the "
             "blamed resource there and shows a read-only diff that would fix it (nothing is "
             "applied). Also read from CLOUDCTL_IAC_ROOT. Required when --resolve is set.",
    ),
    resolve_yes: bool = typer.Option(
        False, "--yes",
        help="With --resolve: skip the two approval gates (fix plan, and "
             "diff+validation before push). Without this flag the agent stops "
             "at each gate for confirmation; non-interactive runs stop safely.",
    ),
    base_branch: Optional[str] = typer.Option(
        None, "--base-branch",
        help="With --resolve: git branch to base the fix on (e.g. develop). "
             "Skips the interactive prompt; defaults to 'develop' if omitted.",
    ),
    json_out: Optional[str] = typer.Option(
        None, "--json-out",
        help="With --agent: also write the raw agent JSON (root_cause, evidence, "
             "confidence, etc.) to this file path, alongside the normal rendered "
             "table. For automated grading (tests/harness/scorer.py) — the "
             "rendered table is lossy, the raw JSON is the actual grading input.",
    ),
    reproduce: bool = typer.Option(
        False, "--reproduce",
        help="Opt in to ACTIVE REPRODUCTION: allow the agent to propose bounded, "
             "read-only HTTP probes when passive telemetry can't settle the "
             "diagnosis. Every probe is shown to you for approval before it runs "
             "(approve / run-it-yourself-and-paste / skip). Off by default.",
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
        import os as _os_iac  # noqa: PLC0415
        iac_root = iac_root or _os_iac.environ.get("CLOUDCTL_IAC_ROOT") or None

        if reproduce:
            _enable_active_reproduction()

        if reproduce:
            # Active reproduction pauses for interactive consent; a live spinner
            # would clobber the prompt, so run without it.
            raw, all_fetched = debug_incident_graph(
                symptom=issue,
                profile=account,
                region=region or "us-east-1",
                iac_root=iac_root,
            )
        else:
            with console.status("[dim]Claude is driving the investigation (3 parallel branches)...[/dim]"):
                raw, all_fetched = debug_incident_graph(
                    symptom=issue,
                    profile=account,
                    region=region or "us-east-1",
                    iac_root=iac_root,
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
        # Scoped to this account and region: a pattern learned elsewhere must
        # never change this run's confidence.
        match = best_pattern_match(issue, account_id=(d.get("_guardrails") or {}).get("account_id"),
                                   region=region or "us-east-1")
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

        fix = None
        if iac_root and d.get("root_cause"):
            fix = _iac_fix(d, iac_root, account, region)
            d["iac_fix"] = fix
            # The located resource is better evidence of how it is deployed
            # than CloudTrail (which lags and only covers 24 h): let --resolve
            # use it instead of refusing on an unknown deployment source.
            if fix.get("resource") and d.get("deployment_source") in (None, "", "unknown", "manual"):
                d["deployment_source"] = fix.get("kind")
                d["iac_file_hint"] = f"{fix.get('file')}:{fix.get('lines')} ({fix.get('resource')})"
        if d.get("root_cause"):
            _ground_remediation(d, fix, iac_root, all_fetched)

        _render_agent_result(d, account)
        if fix is not None:
            _render_iac_fix(fix)
        elif d.get("root_cause"):
            console.print("[dim]Tip: add --iac-root <dir> to get a diff against your own "
                          "Terraform/CDK for this root cause.[/dim]\n")

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
                import sys as _sys  # noqa: PLC0415
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
                    if base_branch:
                        base = base_branch          # --base-branch flag wins, no prompt
                    else:
                        base = "develop"
                        if _sys.stdin.isatty():
                            try:
                                base = console.input(
                                    "[dim]Base branch for fix PR [develop]: [/dim]"
                                ).strip() or "develop"
                            except (EOFError, KeyboardInterrupt):
                                pass

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
                        if result.get("branch"):
                            console.print(f"  Branch (local): {result['branch']}")
                        if result.get("files_changed"):
                            console.print("  Edited but not pushed: "
                                          + ", ".join(result["files_changed"]))
                    for w in result.get("warnings") or []:
                        warn(w)

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
                region=region or "us-east-1",
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

    import os as _os_iac  # noqa: PLC0415
    iac_dir = iac_root or _os_iac.environ.get("CLOUDCTL_IAC_ROOT")
    if iac_dir and finding.root_cause:
        _render_iac_fix(_iac_fix({
            "root_cause": finding.root_cause,
            "affected_resources": finding.affected_resources,
            "remediation_steps": finding.remediation_steps,
        }, iac_dir, account, region))

    if explain:
        _render_explain(finding)

"""cctl drift — find drift between live cloud state and IaC, and repair it within the autonomy table.

    cloudctl drift scan [--env E] [--no-repair]   one pass over every IaC root
    cloudctl drift loop --interval 900            keep scanning; also takes rollback requests
    cloudctl drift list                           drift events
    cloudctl drift show EVENT                     one event, with its factors and history
    cloudctl drift repair EVENT [--override WHY]  a person's go-ahead to repair one event
    cloudctl drift table                          the autonomy table in force

Exit codes: 0 no open drift, 1 error, 5 drift needs a person (approve or report).
"""
from __future__ import annotations

import json
from typing import Any, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

app = typer.Typer(help="Detect drift from IaC and repair it within the autonomy table.", no_args_is_help=True)
console = Console()

_CONFIG_OPT = typer.Option(None, "--config", help="Gate config path (default: $CLOUDCTL_GATE_CONFIG or "
                                                   "~/.cloudctl/controlplane.yaml).")
_STYLE = {"repaired": "green", "resolved": "green", "reported": "red", "repair_failed": "red", "open": "yellow",
          "awaiting_approval": "yellow", "repair_rejected": "yellow", "repairing": "cyan"}
_NEEDS_PERSON = {"open", "reported", "awaiting_approval", "repair_failed", "repair_rejected"}


def _gate(path: Optional[str]) -> Any:
    from cloudctl.gate.config import load_config  # noqa: PLC0415
    from cloudctl.gate.gate import PolicyGate  # noqa: PLC0415
    from cloudctl.gate.models import ConfigError  # noqa: PLC0415
    try:
        return PolicyGate.from_config(load_config(path))
    except ConfigError as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1) from None


def _loop(gate: Any) -> Any:
    from cloudctl.controlplane.drift import DriftLoop  # noqa: PLC0415
    return DriftLoop(gate)


def _store() -> Any:
    from cloudctl.controlplane.drift import DriftStore  # noqa: PLC0415
    return DriftStore()


def _print_events(events: list[Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps([e.to_dict() for e in events], indent=1, default=str))
        return
    if not events:
        console.print("No drift.")
        return
    t = Table(show_header=True, header_style="bold")
    for col in ("event", "env", "root", "class", "severity", "conf", "decision", "status"):
        t.add_column(col)
    for e in events:
        st = _STYLE.get(e.status, "")
        t.add_row(e.id[:12], e.environment, escape(e.root[-40:]), e.drift_class, e.severity, f"{e.confidence:.2f}",
                  e.decision.get("mode", ""), f"[{st}]{e.status}[/{st}]" if st else e.status)
    console.print(t)
    for e in events:
        if e.status == "awaiting_approval" and e.run_id:
            console.print(escape(f"{e.id[:12]}: the repair waits for approval; see cloudctl change status {e.run_id}"))
        elif e.status in ("open", "reported"):
            console.print(escape(f"{e.id[:12]}: {'; '.join(e.decision.get('reasons', []))[:200]}"))


def _exit_for(events: list[Any]) -> None:
    if any(e.status in _NEEDS_PERSON for e in events):
        raise typer.Exit(5)


@app.command("scan")
def scan_cmd(
    env: list[str] = typer.Option([], "--env", "-e", help="Environment to scan; repeat. Default: all."),
    no_repair: bool = typer.Option(False, "--no-repair", help="Detect and decide only; repair nothing."),
    as_json: bool = typer.Option(False, "--json"),
    config: Optional[str] = _CONFIG_OPT,
) -> None:
    """One pass over every IaC root of the chosen environments."""
    from cloudctl.gate.models import AuditError, ConfigError  # noqa: PLC0415
    gate = _gate(config)
    try:
        events = _loop(gate).scan_once(env or None, repair=not no_repair)
    except (ConfigError, AuditError, RuntimeError) as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1) from None
    _print_events(events, as_json)
    _exit_for(events)


@app.command("loop")
def loop_cmd(
    interval: int = typer.Option(900, "--interval", help="Seconds between passes (at least 60)."),
    env: list[str] = typer.Option([], "--env", "-e"),
    no_repair: bool = typer.Option(False, "--no-repair"),
    passes: Optional[int] = typer.Option(None, "--passes", help="Stop after this many passes."),
    config: Optional[str] = _CONFIG_OPT,
) -> None:
    """Keep scanning. Each pass first takes rollback requests from failed change runs."""
    from cloudctl.controlplane.orchestrator import QueuedRollback  # noqa: PLC0415
    from cloudctl.gate.models import AuditError, ConfigError  # noqa: PLC0415
    gate = _gate(config)
    try:
        _loop(gate).run_forever(interval=interval, environments=env or None, repair=not no_repair,
                                rollbacks=QueuedRollback(), max_passes=passes)
    except (ConfigError, AuditError, RuntimeError, ValueError) as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1) from None


@app.command("list")
def list_cmd(
    all_: bool = typer.Option(False, "--all", help="Include resolved events."),
    limit: int = typer.Option(50, "--limit"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Drift events, newest first."""
    events = [e for e in _store().list() if all_ or e.status != "resolved"][:limit]
    _print_events(events, as_json)


@app.command("show")
def show_cmd(event_id: str = typer.Argument(...), as_json: bool = typer.Option(False, "--json")) -> None:
    """One event: what drifted, why it was classed as it was, and what happened."""
    ev = _find(event_id)
    if as_json:
        print(json.dumps(ev.to_dict(), indent=1, default=str))
        return
    console.print(escape(f"{ev.id}  {ev.environment} ({ev.tier}, {ev.cloud})  {ev.platform}  {ev.root}"))
    console.print(escape(f"{ev.drift_class}, {ev.severity}, confidence {ev.confidence:.2f}, "
                         f"seen {ev.sightings}x, {ev.status}"))
    console.print(escape(f"decision: {ev.decision.get('mode')}: {'; '.join(ev.decision.get('reasons', []))}"))
    for f in ev.factors:
        console.print(escape(f"  confidence: {f}"))
    for r in ev.reasons[:20]:
        console.print(escape(f"  - {r}"))
    for i in ev.items[:50]:
        flag = " EXPOSED" if i.get("exposed") else ""
        console.print(escape(f"  {i['action']:8} {i['address']} ({i['category']}){flag}"))
    for h in ev.history[-10:]:
        console.print(escape(f"  {h['at']}  {h['what']}"))


def _find(event_id: str) -> Any:
    store = _store()
    matches = [e for e in store.list() if e.id.startswith(event_id)] if len(event_id) < 32 else []
    try:
        return store.load(event_id) if len(event_id) == 32 else _one(matches, event_id)
    except KeyError as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1) from None


def _one(matches: list[Any], prefix: str) -> Any:
    if len(matches) != 1 or len(prefix) < 6:
        raise KeyError(f"{prefix!r} matches {len(matches)} drift events; give at least 6 characters of one id")
    return matches[0]


@app.command("repair")
def repair_cmd(
    event_id: str = typer.Argument(...),
    override: str = typer.Option("", "--override", help="Why a report-only event should be repaired anyway "
                                                         "(written to the audit log)."),
    yes: bool = typer.Option(False, "--yes", "-y"),
    as_json: bool = typer.Option(False, "--json"),
    config: Optional[str] = _CONFIG_OPT,
) -> None:
    """Repair one event through the gate (the gate may still ask for an approval)."""
    from cloudctl.gate.gate import default_requester  # noqa: PLC0415
    from cloudctl.gate.models import AuditError  # noqa: PLC0415
    ev = _find(event_id)
    if not yes and not typer.confirm(f"Re-apply the declared state of {ev.root} in {ev.environment} "
                                     "through the policy gate?"):
        raise typer.Exit(1)
    gate = _gate(config)
    try:
        ev = _loop(gate).repair(ev.id, requester=default_requester(), override=override)
    except (RuntimeError, AuditError, KeyError) as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1) from None
    _print_events([ev], as_json)
    _exit_for([ev])


@app.command("table")
def table_cmd(as_json: bool = typer.Option(False, "--json"), config: Optional[str] = _CONFIG_OPT) -> None:
    """The autonomy table and θ in force."""
    from cloudctl.controlplane.autonomy import SEVERITIES, AutonomyTable  # noqa: PLC0415
    gate = _gate(config)
    tbl = gate.config.drift or AutonomyTable()
    if as_json:
        print(json.dumps(tbl.to_dict(), indent=1))
        return
    t = Table(show_header=True, header_style="bold")
    for col in ("tier", *SEVERITIES, "θ"):
        t.add_column(col)
    for tier, row in tbl.table.items():
        t.add_row(tier, *(row[s] for s in SEVERITIES), f"{tbl.theta[tier]:.2f}")
    console.print(t)
    console.print("Security incidents are always report. CloudFormation and CDK drift is always report.")

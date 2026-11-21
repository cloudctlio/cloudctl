"""cctl change — compile a change request into a graph and carry it out through the gate.

    cloudctl change compile "..."   ask the model for a change graph (validated, nothing applied)
    cloudctl change run graph.json  run a graph node by node through the policy gate
    cloudctl change resume RUN --approval node=REQUEST_ID
    cloudctl change status RUN      where a run stands
    cloudctl change list            recent runs
    cloudctl change rollbacks       rollback requests waiting for the drift repair loop

Exit codes: 0 done, 1 error, 2 a node failed or was rejected, 3 the compiler
has questions, 4 waiting for approval.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

app = typer.Typer(help="Compile change requests into a change graph and run it through the policy gate.",
                  no_args_is_help=True)
console = Console()

_CONFIG_OPT = typer.Option(None, "--config", help="Gate config path (default: $CLOUDCTL_GATE_CONFIG or "
                                                   "~/.cloudctl/controlplane.yaml).")
_STATUS_STYLE = {"succeeded": "green", "failed": "red", "rejected": "red", "awaiting_approval": "yellow",
                 "blocked": "yellow", "skipped": "dim", "pending": "dim", "running": "cyan"}


def _gate(path: Optional[str]) -> Any:
    from cloudctl.gate.config import load_config  # noqa: PLC0415
    from cloudctl.gate.gate import PolicyGate  # noqa: PLC0415
    from cloudctl.gate.models import ConfigError  # noqa: PLC0415
    try:
        return PolicyGate.from_config(load_config(path))
    except ConfigError as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1) from None


def _orchestrator(gate: Any) -> Any:
    from cloudctl.controlplane.orchestrator import Orchestrator  # noqa: PLC0415
    from cloudctl.controlplane.state import LocalRunStore  # noqa: PLC0415
    return Orchestrator(gate, LocalRunStore())


def _print_run(run: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(run.to_dict(), indent=1, default=str))
        return
    console.print(f"Run [bold]{run.run_id}[/bold]: {run.status}")
    t = Table(show_header=True, header_style="bold")
    for col in ("node", "status", "stage", "detail"):
        t.add_column(col)
    for nid, ns in run.nodes.items():
        detail = ns.error or "; ".join(ns.reasons)
        if ns.status == "awaiting_approval":
            detail = f"approve with: cloudctl gate approve {ns.approval_id}"
        if ns.rollback_id:
            detail += f" (rollback request {ns.rollback_id})"
        style = _STATUS_STYLE.get(ns.status, "")
        t.add_row(nid, f"[{style}]{ns.status}[/{style}]" if style else ns.status, ns.stage, escape(detail[:200]))
    console.print(t)
    waiting = [ns for ns in run.nodes.values() if ns.status == "awaiting_approval"]
    if waiting:
        flags = " ".join(f"--approval {ns.id}={ns.approval_id}" for ns in waiting)
        console.print(f"After approval, run: cloudctl change resume {run.run_id} {flags}")


def _exit_for(run: Any) -> None:
    code = {"succeeded": 0, "awaiting_approval": 4, "failed": 2}.get(run.status, 2)
    if code:
        raise typer.Exit(code)


@app.command("compile")
def compile_cmd(
    request: str = typer.Argument(..., help="What to change, in plain words."),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write the graph JSON here."),
    iac_root: list[str] = typer.Option([], "--iac-root", help="Extra IaC root the graph may use."),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile for Bedrock models."),
    region: str = typer.Option("us-east-1", "--region", help="Region for Bedrock models."),
    as_json: bool = typer.Option(False, "--json"),
    config: Optional[str] = _CONFIG_OPT,
) -> None:
    """Turn a request into a validated change graph. Applies nothing."""
    from cloudctl.controlplane.compiler import RequestCompiler  # noqa: PLC0415
    from cloudctl.controlplane.model import ConverseAdapter  # noqa: PLC0415

    gate = _gate(config)
    model = ConverseAdapter.from_environment(profile=profile, region=region)
    res = RequestCompiler(gate.config, model, allowed_roots=iac_root, audit=gate.record).compile(request)
    if as_json:
        print(json.dumps(res.to_dict(), indent=1))
    if res.questions:
        if not as_json:
            console.print("[yellow]The request needs an answer first:[/yellow]")
            for q in res.questions:
                opts = f" ({', '.join(q.options)})" if q.options else ""
                console.print(escape(f"  - {q.question}{opts}"))
        raise typer.Exit(3)
    if res.errors:
        if not as_json:
            console.print("[red]Could not compile a valid graph:[/red]")
            for e in res.errors:
                console.print(escape(f"  - {e}"))
        raise typer.Exit(1)
    graph = res.graph
    if graph is None:  # unreachable: ok means a graph
        raise typer.Exit(1)
    if out:
        out.write_text(json.dumps(graph.to_dict(), indent=1) + "\n", encoding="utf-8")
    if not as_json:
        console.print(f"Change graph ({len(graph.nodes)} node(s), digest {graph.digest()[:12]}):")
        for nid in graph.order():
            n = graph.node(nid)
            target = n.iac_root or f"{n.issue.get('issue', '')} on {n.issue.get('resource', '')}"
            after = f" after {', '.join(n.depends_on)}" if n.depends_on else ""
            console.print(escape(f"  {nid} [{n.kind} in {n.environment}]{after}: {n.summary} ({target})"))
        if out:
            console.print(f"Written to {out}. Review it, then: cloudctl change run {out}")


@app.command("run")
def run_cmd(
    graph_file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask before starting."),
    as_json: bool = typer.Option(False, "--json"),
    config: Optional[str] = _CONFIG_OPT,
) -> None:
    """Run a change graph through the gate, node by node."""
    from cloudctl.controlplane.graph import GraphError, parse_graph  # noqa: PLC0415
    from cloudctl.controlplane.orchestrator import OrchestratorError  # noqa: PLC0415
    from cloudctl.controlplane.state import StateError  # noqa: PLC0415
    from cloudctl.gate.models import AuditError  # noqa: PLC0415

    try:
        graph = parse_graph(json.loads(graph_file.read_text(encoding="utf-8")))
    except (ValueError, GraphError) as e:
        console.print(f"[red]Invalid change graph: {escape(str(e))}[/red]")
        raise typer.Exit(1) from None
    if not as_json:
        console.print(f"{len(graph.nodes)} node(s), in this order: {' → '.join(graph.order())}")
    if not yes and not typer.confirm("Send each node through the policy gate and apply what it authorizes?"):
        raise typer.Exit(1)
    gate = _gate(config)
    try:
        run = _orchestrator(gate).start(graph)
    except (GraphError, OrchestratorError, StateError, AuditError) as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1) from None
    _print_run(run, as_json)
    _exit_for(run)


@app.command("resume")
def resume_cmd(
    run_id: str = typer.Argument(...),
    approval: list[str] = typer.Option([], "--approval", help="node=approval-request-id; repeat per node."),
    as_json: bool = typer.Option(False, "--json"),
    config: Optional[str] = _CONFIG_OPT,
) -> None:
    """Carry on a run that was waiting for approvals."""
    from cloudctl.controlplane.graph import GraphError  # noqa: PLC0415
    from cloudctl.controlplane.orchestrator import OrchestratorError  # noqa: PLC0415
    from cloudctl.controlplane.state import StateError  # noqa: PLC0415
    from cloudctl.gate.models import AuditError  # noqa: PLC0415

    approvals: dict[str, str] = {}
    for a in approval:
        node, sep, rid = a.partition("=")
        if not sep or not node or not rid:
            console.print(f"[red]--approval takes node=request-id, got {a!r}[/red]")
            raise typer.Exit(1)
        approvals[node.strip()] = rid.strip()
    gate = _gate(config)
    try:
        run = _orchestrator(gate).resume(run_id, approvals)
    except (GraphError, OrchestratorError, StateError, AuditError) as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1) from None
    _print_run(run, as_json)
    _exit_for(run)


@app.command("status")
def status_cmd(run_id: str = typer.Argument(...), as_json: bool = typer.Option(False, "--json")) -> None:
    """Show where a run stands."""
    from cloudctl.controlplane.state import LocalRunStore, StateError  # noqa: PLC0415
    try:
        run = LocalRunStore().load(run_id)
    except StateError as e:
        console.print(f"[red]{escape(str(e))}[/red]")
        raise typer.Exit(1) from None
    _print_run(run, as_json)


@app.command("list")
def list_cmd(limit: int = typer.Option(20, "--limit")) -> None:
    """Recent runs."""
    from cloudctl.controlplane.state import LocalRunStore  # noqa: PLC0415
    runs = LocalRunStore().list()[:limit]
    if not runs:
        console.print("No runs yet.")
        return
    t = Table(show_header=True, header_style="bold")
    for col in ("run", "status", "created", "request"):
        t.add_column(col)
    for r in runs:
        t.add_row(r.run_id, r.status, r.created_at, escape(str(r.graph.get("request", ""))[:80]))
    console.print(t)


@app.command("rollbacks")
def rollbacks_cmd(as_json: bool = typer.Option(False, "--json")) -> None:
    """Rollback requests from failed nodes, waiting for the drift repair loop."""
    from cloudctl.controlplane.orchestrator import QueuedRollback  # noqa: PLC0415
    items = QueuedRollback().pending()
    if as_json:
        print(json.dumps(items, indent=1))
        return
    if not items:
        console.print("No rollback requests.")
        return
    for i in items:
        console.print(escape(f"{i['id']}: run {i['run_id']} node {i['node_id']} in {i['environment']}: "
                             f"{i['error'][:160]}"))

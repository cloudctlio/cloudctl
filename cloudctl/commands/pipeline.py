"""cloudctl pipeline — list/analyze CI/CD pipelines (CodePipeline)."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import cloud_label, error, print_table, warn

app = typer.Typer(help="Inspect CI/CD pipelines (CodePipeline, Azure DevOps, Cloud Build).")
console = Console()


def _require_init() -> ConfigManager:
    cfg = ConfigManager()
    if not cfg.is_initialized:
        warn("cloudctl not initialized. Run: [cyan]cloudctl init[/cyan]")
        raise typer.Exit(1)
    return cfg


@app.command("list")
def pipeline_list(
    cloud: str = typer.Option("aws", "--cloud", "-c"),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
) -> None:
    """List CI/CD pipelines."""
    cfg = _require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                from cloudctl.providers.aws.provider import AWSProvider
                session = AWSProvider(profile=profile_name, region=region)._session
                cp = session.client("codepipeline", region_name=region)
                pipelines = cp.list_pipelines().get("pipelines", [])
                for p in pipelines:
                    state = cp.get_pipeline_state(name=p["name"])
                    last_exec = state.get("stageStates", [{}])[0].get("latestExecution", {})
                    rows.append({
                        "Cloud": cloud_label("aws"),
                        "Account": profile_name,
                        "Name": p["name"],
                        "Status": last_exec.get("status", "—"),
                        "Updated": p.get("updated", "—"),
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[dim]No pipelines found.[/dim]")
        return
    print_table(rows, title="CI/CD Pipelines")


@app.command("analyze")
def pipeline_analyze(
    name: str = typer.Argument(..., help="Pipeline name to analyze."),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
) -> None:
    """Show stage-by-stage status of a pipeline."""
    cfg = _require_init()
    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    try:
        from cloudctl.providers.aws.provider import AWSProvider
        session = AWSProvider(profile=profile, region=region)._session
        cp = session.client("codepipeline", region_name=region)
        state = cp.get_pipeline_state(name=name)
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    rows = []
    for stage in state.get("stageStates", []):
        exec_info = stage.get("latestExecution", {})
        rows.append({
            "Stage": stage.get("stageName", "—"),
            "Status": exec_info.get("status", "—"),
            "Last Updated": str(exec_info.get("lastStatusChange", "—"))[:19],
        })

    if not rows:
        console.print("[dim]No stage data.[/dim]")
        return
    print_table(rows, title=f"Pipeline: {name}")

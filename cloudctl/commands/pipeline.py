"""cloudctl pipeline — list/analyze CI/CD pipelines across AWS, Azure, and GCP."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import (
    console,
    get_aws_provider,
    get_gcp_provider,
    require_init,
)
from cloudctl.output.formatter import cloud_label, error, print_table, warn

app = typer.Typer(help="Inspect CI/CD pipelines (CodePipeline, Azure DevOps, Cloud Build).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region to query")


@app.command("list")
def pipeline_list(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List CI/CD pipelines."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for p in get_aws_provider(profile_name, region).list_pipelines(account=profile_name, region=region):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": profile_name,
                        "Name": p["name"], "Type": "CodePipeline",
                        "Updated": p["updated"], "Region": p["region"],
                    })
            except Exception as e:
                warn(f"[AWS/{profile_name}] {e}")

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        warn("[Azure] Azure DevOps Pipelines require AZURE_DEVOPS_ORG_URL + AZURE_DEVOPS_PAT env vars.")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        try:
            for b in get_gcp_provider(project_id=account).list_cloud_build(
                account=account or "gcp", region=region
            ):
                rows.append({
                    "Cloud": cloud_label("gcp"), "Account": b["account"],
                    "Name": b["name"], "Type": "Cloud Build",
                    "Updated": b.get("create_time", "—"), "Region": b.get("region", "global"),
                })
            for d in get_gcp_provider(project_id=account).list_cloud_deploy(
                account=account or "gcp", region=region
            ):
                rows.append({
                    "Cloud": cloud_label("gcp"), "Account": d["account"],
                    "Name": d["name"], "Type": "Cloud Deploy",
                    "Updated": d.get("create_time", "—"), "Region": d.get("region", "—"),
                })
        except Exception as e:
            warn(f"[GCP] {e}")

    if not rows:
        console.print("[dim]No pipelines found.[/dim]")
        return
    print_table(rows, title=f"CI/CD Pipelines ({len(rows)})")


@app.command("analyze")
def pipeline_analyze(
    name:    str           = typer.Argument(..., help="Pipeline name to analyze."),
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """Show stage-by-stage status of a pipeline. AWS only."""
    cfg = require_init()

    if cloud != "aws":
        warn("analyze only supports AWS CodePipeline currently.")
        raise typer.Exit(1)

    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    try:
        provider = get_aws_provider(profile, region)
        cp = provider._session.client("codepipeline", region_name=region)
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

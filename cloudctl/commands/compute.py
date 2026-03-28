"""cloudctl compute — list/describe/stop/start across AWS, Azure, and GCP."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import (
    console,
    get_aws_provider,
    get_azure_provider,
    get_gcp_provider,
    require_init,
)
from cloudctl.output.formatter import cloud_label, error, print_table, success, warn

app = typer.Typer(help="Manage compute instances (EC2, VMs, GCE).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")


@app.command("list")
def compute_list(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
    state:   Optional[str] = typer.Option(None, "--state", "-s", help="Filter by state: running|stopped|terminated"),
    tag:     Optional[str] = typer.Option(None, "--tag",   "-t", help="Filter by tag Key=Value (AWS only)"),
) -> None:
    """List compute instances."""
    cfg = require_init()

    tag_filter: Optional[dict] = None
    if tag:
        if "=" not in tag:
            error("--tag must be Key=Value format.")
            raise typer.Exit(1)
        k, v = tag.split("=", 1)
        tag_filter = {k: v}

    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        if not targets and cloud == "aws":
            warn(f"No AWS profile matching '{account}'. Run: cloudctl accounts list")
            raise typer.Exit(1)
        for profile_name in targets:
            try:
                for inst in get_aws_provider(profile_name, region).list_compute(
                    account=profile_name, region=region, state=state, tags=tag_filter
                ):
                    rows.append({
                        "Cloud": cloud_label(inst.cloud), "Account": inst.account,
                        "ID": inst.id, "Name": inst.name, "Type": inst.type,
                        "State": inst.state, "Region": inst.region,
                        "Public IP": inst.public_ip or "—",
                    })
            except Exception as e:
                warn(f"[AWS/{profile_name}] {e}")

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        try:
            for inst in get_azure_provider(subscription_id=account).list_compute(
                account=account or "azure", region=region, state=state
            ):
                rows.append({
                    "Cloud": cloud_label(inst.cloud), "Account": inst.account,
                    "ID": inst.id, "Name": inst.name, "Type": inst.type,
                    "State": inst.state, "Region": inst.region,
                    "Public IP": inst.public_ip or "—",
                })
        except Exception as e:
            warn(f"[Azure] {e}")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        try:
            for inst in get_gcp_provider(project_id=account).list_compute(
                account=account or "gcp", region=region, state=state
            ):
                rows.append({
                    "Cloud": cloud_label(inst.cloud), "Account": inst.account,
                    "ID": inst.id, "Name": inst.name, "Type": inst.type,
                    "State": inst.state, "Region": inst.region,
                    "Public IP": inst.public_ip or "—",
                })
        except Exception as e:
            warn(f"[GCP] {e}")

    if not rows:
        console.print("[dim]No instances found.[/dim]")
        return
    print_table(rows, title=f"Compute Instances ({len(rows)})")


@app.command("describe")
def compute_describe(
    instance_id: str           = typer.Argument(..., help="Instance ID to describe."),
    cloud:       str           = _CLOUD,
    account:     Optional[str] = _ACCOUNT,
    region:      Optional[str] = _REGION,
) -> None:
    """Show full details for a compute instance."""
    cfg = require_init()

    if cloud == "aws":
        profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
        if not profile:
            error("No AWS profile configured.")
            raise typer.Exit(1)
        provider = get_aws_provider(profile, region)
        acct = profile
    elif cloud == "azure":
        provider = get_azure_provider(subscription_id=account)
        acct = account or "azure"
    elif cloud == "gcp":
        provider = get_gcp_provider(project_id=account)
        acct = account or "gcp"
    else:
        error("describe requires a specific --cloud (aws|azure|gcp).")
        raise typer.Exit(1)

    try:
        inst = provider.describe_compute(account=acct, instance_id=instance_id)
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    print_table([{"Field": k, "Value": str(v)} for k, v in {
        "Cloud": cloud_label(inst.cloud), "ID": inst.id, "Name": inst.name,
        "State": inst.state, "Type": inst.type, "Region": inst.region,
        "Account": inst.account, "Public IP": inst.public_ip or "—",
        "Private IP": inst.private_ip or "—", "Launched": inst.launched_at or "—",
        "Tags": ", ".join(f"{k}={v}" for k, v in inst.tags.items()) or "—",
    }.items()], title=f"Instance: {instance_id}")


@app.command("stop")
def compute_stop(
    instance_id: str           = typer.Argument(..., help="Instance ID to stop."),
    cloud:       str           = _CLOUD,
    account:     Optional[str] = _ACCOUNT,
    region:      Optional[str] = _REGION,
    yes:         bool          = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
) -> None:
    """Stop a compute instance."""
    cfg = require_init()
    if not yes:
        typer.confirm(f"Stop instance {instance_id}?", abort=True)

    if cloud == "aws":
        profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
        if not profile:
            error("No AWS profile configured.")
            raise typer.Exit(1)
        provider, acct = get_aws_provider(profile, region), profile
    elif cloud == "azure":
        provider, acct = get_azure_provider(subscription_id=account), account or "azure"
    elif cloud == "gcp":
        provider, acct = get_gcp_provider(project_id=account), account or "gcp"
    else:
        error("stop requires a specific --cloud (aws|azure|gcp).")
        raise typer.Exit(1)

    try:
        provider.stop_compute(account=acct, instance_id=instance_id)
        success(f"Stopping [bold]{instance_id}[/bold]")
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)


@app.command("start")
def compute_start(
    instance_id: str           = typer.Argument(..., help="Instance ID to start."),
    cloud:       str           = _CLOUD,
    account:     Optional[str] = _ACCOUNT,
    region:      Optional[str] = _REGION,
    yes:         bool          = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
) -> None:
    """Start a stopped compute instance."""
    cfg = require_init()
    if not yes:
        typer.confirm(f"Start instance {instance_id}?", abort=True)

    if cloud == "aws":
        profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
        if not profile:
            error("No AWS profile configured.")
            raise typer.Exit(1)
        provider, acct = get_aws_provider(profile, region), profile
    elif cloud == "azure":
        provider, acct = get_azure_provider(subscription_id=account), account or "azure"
    elif cloud == "gcp":
        provider, acct = get_gcp_provider(project_id=account), account or "gcp"
    else:
        error("start requires a specific --cloud (aws|azure|gcp).")
        raise typer.Exit(1)

    try:
        provider.start_compute(account=acct, instance_id=instance_id)
        success(f"Starting [bold]{instance_id}[/bold]")
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

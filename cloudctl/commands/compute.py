"""cloudctl compute — list/describe/stop/start."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import cloud_label, error, print_table, success, warn
from cloudctl.providers.aws.provider import AWSProvider

app = typer.Typer(help="Manage compute instances (EC2, VMs).")
console = Console()


def _get_aws_provider(profile: str, region: Optional[str]) -> AWSProvider:
    try:
        return AWSProvider(profile=profile, region=region)
    except ValueError as e:
        error(str(e))
        raise typer.Exit(1)


def _require_init() -> ConfigManager:
    cfg = ConfigManager()
    if not cfg.is_initialized:
        warn("cloudctl not initialized. Run: [cyan]cloudctl init[/cyan]")
        raise typer.Exit(1)
    return cfg


@app.command("list")
def compute_list(
    cloud: str = typer.Option("aws", "--cloud", "-c", help="Cloud to query: aws | all"),
    account: Optional[str] = typer.Option(None, "--account", "-a", help="Profile/account name."),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Region to query."),
    state: Optional[str] = typer.Option(None, "--state", "-s", help="Filter by state: running|stopped|terminated"),
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Filter by tag Key=Value."),
) -> None:
    """List compute instances."""
    cfg = _require_init()

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

        if not targets:
            warn(f"No AWS profile matching '{account}'. Run: cloudctl accounts list")
            raise typer.Exit(1)

        for profile_name in targets:
            try:
                provider = _get_aws_provider(profile_name, region)
                instances = provider.list_compute(
                    account=profile_name, region=region, state=state, tags=tag_filter
                )
                for inst in instances:
                    rows.append({
                        "Cloud": cloud_label(inst.cloud),
                        "Account": inst.account,
                        "ID": inst.id,
                        "Name": inst.name,
                        "Type": inst.type,
                        "State": inst.state,
                        "Region": inst.region,
                        "Public IP": inst.public_ip or "—",
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[dim]No instances found.[/dim]")
        return

    print_table(rows, title="Compute Instances")


@app.command("describe")
def compute_describe(
    instance_id: str = typer.Argument(..., help="Instance ID to describe."),
    account: Optional[str] = typer.Option(None, "--account", "-a", help="Profile/account name."),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
) -> None:
    """Show full details for a compute instance."""
    cfg = _require_init()
    profile = account or next(iter(p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    try:
        provider = _get_aws_provider(profile, region)
        inst = provider.describe_compute(account=profile, instance_id=instance_id)
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    rows = [
        {"Field": k, "Value": str(v)}
        for k, v in {
            "ID": inst.id,
            "Name": inst.name,
            "State": inst.state,
            "Type": inst.type,
            "Region": inst.region,
            "Account": inst.account,
            "Public IP": inst.public_ip or "—",
            "Private IP": inst.private_ip or "—",
            "Launched": inst.launched_at or "—",
            "Tags": ", ".join(f"{k}={v}" for k, v in inst.tags.items()) or "—",
        }.items()
    ]
    print_table(rows, title=f"Instance: {instance_id}")


@app.command("stop")
def compute_stop(
    instance_id: str = typer.Argument(..., help="Instance ID to stop."),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
) -> None:
    """Stop a compute instance."""
    cfg = _require_init()
    profile = account or next(iter(p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    if not yes:
        typer.confirm(f"Stop instance {instance_id}?", abort=True)

    try:
        provider = _get_aws_provider(profile, region)
        provider.stop_compute(account=profile, instance_id=instance_id)
        success(f"Stopping [bold]{instance_id}[/bold]")
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)


@app.command("start")
def compute_start(
    instance_id: str = typer.Argument(..., help="Instance ID to start."),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
) -> None:
    """Start a stopped compute instance."""
    cfg = _require_init()
    profile = account or next(iter(p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    if not yes:
        typer.confirm(f"Start instance {instance_id}?", abort=True)

    try:
        provider = _get_aws_provider(profile, region)
        provider.start_compute(account=profile, instance_id=instance_id)
        success(f"Starting [bold]{instance_id}[/bold]")
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

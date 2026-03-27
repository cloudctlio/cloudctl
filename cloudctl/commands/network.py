"""cloudctl network — VPCs, security groups."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import cloud_label, error, print_table, warn

app = typer.Typer(help="Inspect cloud networking (VPCs, security groups).")
console = Console()


def _require_init() -> ConfigManager:
    cfg = ConfigManager()
    if not cfg.is_initialized:
        warn("cloudctl not initialized. Run: [cyan]cloudctl init[/cyan]")
        raise typer.Exit(1)
    return cfg


def _aws_provider(profile: str, region: Optional[str] = None):
    from cloudctl.providers.aws.provider import AWSProvider
    return AWSProvider(profile=profile, region=region)


@app.command("vpcs")
def network_vpcs(
    cloud: str = typer.Option("aws", "--cloud", "-c"),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
) -> None:
    """List VPCs."""
    cfg = _require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                vpcs = _aws_provider(profile_name, region).list_vpcs(account=profile_name, region=region)
                for v in vpcs:
                    rows.append({
                        "Cloud": cloud_label("aws"),
                        "Account": v["account"],
                        "VPC ID": v["id"],
                        "Name": v["name"],
                        "CIDR": v["cidr"],
                        "State": v["state"],
                        "Default": "yes" if v["default"] else "no",
                        "Region": v["region"],
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[dim]No VPCs found.[/dim]")
        return
    print_table(rows, title="VPCs")


@app.command("security-groups")
def network_security_groups(
    cloud: str = typer.Option("aws", "--cloud", "-c"),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
    vpc_id: Optional[str] = typer.Option(None, "--vpc", help="Filter by VPC ID."),
) -> None:
    """List security groups."""
    cfg = _require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                sgs = _aws_provider(profile_name, region).list_security_groups(
                    account=profile_name, region=region, vpc_id=vpc_id
                )
                for sg in sgs:
                    rows.append({
                        "Cloud": cloud_label("aws"),
                        "Account": sg["account"],
                        "ID": sg["id"],
                        "Name": sg["name"],
                        "VPC": sg["vpc_id"],
                        "Inbound": sg["inbound_rules"],
                        "Outbound": sg["outbound_rules"],
                        "Region": sg["region"],
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[dim]No security groups found.[/dim]")
        return
    print_table(rows, title="Security Groups")

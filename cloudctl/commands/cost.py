"""cloudctl cost — summary, by-service."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import cloud_label, error, print_table, warn

app = typer.Typer(help="View cloud costs (AWS Cost Explorer, Azure Cost, GCP Billing).")
console = Console()


def _require_init() -> ConfigManager:
    cfg = ConfigManager()
    if not cfg.is_initialized:
        warn("cloudctl not initialized. Run: [cyan]cloudctl init[/cyan]")
        raise typer.Exit(1)
    return cfg


def _aws_provider(profile: str):
    from cloudctl.providers.aws.provider import AWSProvider
    return AWSProvider(profile=profile)


@app.command("summary")
def cost_summary(
    cloud: str = typer.Option("aws", "--cloud", "-c"),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    days: int = typer.Option(30, "--days", "-d", help="Number of days to look back."),
) -> None:
    """Show total cost summary by month."""
    cfg = _require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for entry in _aws_provider(profile_name).cost_summary(account=profile_name, days=days):
                    rows.append({
                        "Cloud": cloud_label("aws"),
                        "Account": entry["account"],
                        "Period": entry["period"],
                        "Total Cost": entry["cost"],
                        "Currency": entry["currency"],
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[dim]No cost data found. Ensure Cost Explorer is enabled in your AWS account.[/dim]")
        return
    print_table(rows, title=f"Cost Summary (last {days} days)")


@app.command("by-service")
def cost_by_service(
    cloud: str = typer.Option("aws", "--cloud", "-c"),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    days: int = typer.Option(30, "--days", "-d", help="Number of days to look back."),
) -> None:
    """Show cost breakdown by service."""
    cfg = _require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for entry in _aws_provider(profile_name).cost_by_service(account=profile_name, days=days):
                    rows.append({
                        "Cloud": cloud_label("aws"),
                        "Account": entry["account"],
                        "Service": entry["service"],
                        "Period": entry["period"],
                        "Cost": entry["cost"],
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[dim]No cost data found.[/dim]")
        return
    print_table(rows, title=f"Cost by Service (last {days} days)")

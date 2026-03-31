"""cloudctl cost — summary, by-service across AWS, Azure, and GCP."""
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
from cloudctl.output.formatter import cloud_label, print_table, warn

app = typer.Typer(help="View cloud costs (AWS Cost Explorer, Azure Cost, GCP Billing).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_DAYS    = typer.Option(30,     "--days",    "-d", help="Number of days to look back.")

_TOTAL_COST = "Total Cost"


def _aws_cost_summary_rows(cfg, account, days) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    for profile_name in targets:
        try:
            for entry in get_aws_provider(profile_name).cost_summary(account=profile_name, days=days):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": entry["account"],
                    "Period": entry["period"], _TOTAL_COST: entry["cost"],
                    "Currency": entry["currency"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_cost_summary_rows(account, days) -> list[dict]:
    rows: list[dict] = []
    try:
        for entry in get_azure_provider(subscription_id=account).cost_summary(account=account or "azure", days=days):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": entry["account"],
                "Period": entry["period"], _TOTAL_COST: entry["cost"],
                "Currency": entry.get("currency", "USD"),
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_cost_summary_rows(account, days) -> list[dict]:
    rows: list[dict] = []
    try:
        for entry in get_gcp_provider(project_id=account).cost_summary(account=account or "gcp", days=days):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": entry["account"],
                "Period": entry["period"], _TOTAL_COST: entry["cost"],
                "Currency": entry.get("currency", "USD"),
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


def _aws_cost_by_service_rows(cfg, account, days) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    for profile_name in targets:
        try:
            for entry in get_aws_provider(profile_name).cost_by_service(account=profile_name, days=days):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": entry["account"],
                    "Service": entry["service"], "Period": entry["period"],
                    "Cost": entry["cost"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_cost_by_service_rows(account, days) -> list[dict]:
    rows: list[dict] = []
    try:
        for entry in get_azure_provider(subscription_id=account).cost_by_service(account=account or "azure", days=days):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": entry["account"],
                "Service": entry["service"], "Period": entry["period"],
                "Cost": entry["cost"],
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_cost_by_service_rows(account, days) -> list[dict]:
    rows: list[dict] = []
    try:
        for entry in get_gcp_provider(project_id=account).cost_by_service(account=account or "gcp", days=days):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": entry["account"],
                "Service": entry["service"], "Period": entry["period"],
                "Cost": entry["cost"],
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


@app.command("summary")
def cost_summary(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    days:    int           = _DAYS,
) -> None:
    """Show total cost summary by month."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_cost_summary_rows(cfg, account, days)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_cost_summary_rows(account, days)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_cost_summary_rows(account, days)

    if not rows:
        console.print("[dim]No cost data found. Ensure Cost Explorer / Cost Management is enabled.[/dim]")
        return
    print_table(rows, title=f"Cost Summary (last {days} days)")


@app.command("by-service")
def cost_by_service(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    days:    int           = _DAYS,
) -> None:
    """Show cost breakdown by service."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_cost_by_service_rows(cfg, account, days)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_cost_by_service_rows(account, days)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_cost_by_service_rows(account, days)

    if not rows:
        console.print("[dim]No cost data found.[/dim]")
        return
    print_table(rows, title=f"Cost by Service (last {days} days)")

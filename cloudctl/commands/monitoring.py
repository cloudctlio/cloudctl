"""cloudctl monitoring — alerts and dashboards across AWS, Azure, and GCP."""
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

app = typer.Typer(help="View monitoring alerts and dashboards (CloudWatch, Azure Monitor, Cloud Monitoring).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")


def _aws_alert_rows(cfg, account, region) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    for profile_name in targets:
        try:
            for alarm in get_aws_provider(profile_name, region).list_cloudwatch_alarms(
                account=profile_name, region=region
            ):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": alarm["account"],
                    "Name": alarm["name"], "State": alarm["state"],
                    "Metric": alarm["metric"], "Region": alarm["region"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_alert_rows(account, region) -> list[dict]:
    rows: list[dict] = []
    try:
        for alert in get_azure_provider(subscription_id=account).list_monitor_alerts(
            account=account or "azure", region=region
        ):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": alert["account"],
                "Name": alert["name"], "State": alert["state"],
                "Metric": alert.get("description", "—"), "Region": alert["region"],
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_alert_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for alert in get_gcp_provider(project_id=account).list_monitoring_alerts(account=account or "gcp"):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": alert["account"],
                "Name": alert["name"], "State": alert["state"],
                "Metric": alert.get("conditions", "—"), "Region": alert.get("region", "global"),
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


def _aws_dashboard_rows(cfg, account, region) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    for profile_name in targets:
        try:
            for dash in get_aws_provider(profile_name, region).list_cloudwatch_dashboards(
                account=profile_name, region=region
            ):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": dash["account"],
                    "Name": dash["name"], "Modified": dash["modified"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


@app.command("alerts")
def monitoring_alerts(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List monitoring alerts / alarms."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_alert_rows(cfg, account, region)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_alert_rows(account, region)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_alert_rows(account)

    if not rows:
        console.print("[dim]No alerts found.[/dim]")
        return
    print_table(rows, title=f"Monitoring Alerts ({len(rows)})")


@app.command("dashboards")
def monitoring_dashboards(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List monitoring dashboards."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_dashboard_rows(cfg, account, region)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        warn("[Azure] Azure portal dashboards are not accessible via ARM API.")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] Cloud Monitoring custom dashboards require Monitoring API access.")

    if not rows:
        console.print("[dim]No dashboards found.[/dim]")
        return
    print_table(rows, title=f"Dashboards ({len(rows)})")

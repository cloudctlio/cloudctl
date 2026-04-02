"""cloudctl quotas — service quotas and limits across AWS, Azure, and GCP."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import (
    console,
    get_aws_provider,
    require_init,
    run_parallel,
)
from cloudctl.output.formatter import cloud_label, print_table, warn

app = typer.Typer(help="Inspect service quotas and limits (AWS Service Quotas).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")

_AWS_SERVICES = [
    "ec2", "s3", "lambda", "rds", "eks", "ecs", "dynamodb", "sqs", "sns",
]


def _calc_used_pct(q: dict) -> str:
    used  = q.get("used")
    value = q.get("value")
    if used is None or not value:
        return "—"
    try:
        return f"{float(used) / float(value) * 100:.0f}%"
    except (ZeroDivisionError, ValueError):
        return "—"


def _aws_quota_rows(cfg, account, region, service) -> list[dict]:
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    services = [service] if service else _AWS_SERVICES

    def _fetch_profile(profile_name: str) -> list[dict]:
        rows: list[dict] = []
        prov = get_aws_provider(profile_name, region)
        for svc in services:
            try:
                for q in prov.list_service_quotas(
                    account=profile_name, service_code=svc, region=region
                ):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": q["account"],
                        "Service": svc.upper(), "Quota": q["name"],
                        "Limit": q.get("value", "—"), "Used": q.get("used", "—"),
                        "Used%": _calc_used_pct(q), "Region": q.get("region", region or "—"),
                    })
            except Exception as e:
                warn(f"[AWS/{profile_name}/{svc}] {e}")
        return rows

    return run_parallel(_fetch_profile, targets)


@app.command("list")
def quotas_list(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
    service: Optional[str] = typer.Option(
        None, "--service", "-s",
        help=f"AWS service code to query (e.g. ec2, lambda). Defaults to: {', '.join(_AWS_SERVICES)}"
    ),
) -> None:
    """List service quotas and current usage."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_quota_rows(cfg, account, region, service)

    if cloud in ("azure",) and cloud not in cfg.clouds:
        warn("[Azure] Azure quota APIs require additional permissions. Use the Azure portal.")

    if cloud in ("gcp",) and cloud not in cfg.clouds:
        warn("[GCP] GCP quota APIs require resourcemanager.googleapis.com enabled.")

    if not rows:
        console.print("[dim]No quota data found.[/dim]")
        return
    print_table(rows, title=f"Service Quotas ({len(rows)})")

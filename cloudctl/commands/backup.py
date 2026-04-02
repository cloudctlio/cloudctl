"""cloudctl backup — backup vaults and jobs across AWS, Azure, and GCP."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import (
    console,
    get_aws_provider,
    get_azure_provider,
    get_gcp_provider,
    require_init,
    run_parallel,
)
from cloudctl.output.formatter import cloud_label, print_table, warn

app = typer.Typer(help="Inspect backup vaults and jobs (AWS Backup, Azure Backup, GCP Backup).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")


# ── AWS helpers ────────────────────────────────────────────────────────────────

def _aws_vault_rows(cfg, account, region) -> list[dict]:
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]

    def _fetch(profile_name: str) -> list[dict]:
        rows: list[dict] = []
        try:
            for v in get_aws_provider(profile_name, region).list_backup_vaults(
                account=profile_name, region=region
            ):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": v["account"],
                    "Name": v["name"], "Recovery Points": v.get("recovery_points", "—"),
                    "Locked": v.get("locked", "no"), "Region": v["region"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
        return rows

    return run_parallel(_fetch, targets)


def _aws_job_rows(cfg, account, region, state) -> list[dict]:
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]

    def _fetch(profile_name: str) -> list[dict]:
        rows: list[dict] = []
        try:
            for j in get_aws_provider(profile_name, region).list_backup_jobs(
                account=profile_name, region=region, state=state
            ):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": j["account"],
                    "Resource": j.get("resource_type", "—"), "State": j["state"],
                    "Created": j.get("created", "—"), "Region": j["region"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
        return rows

    return run_parallel(_fetch, targets)


# ── Azure helpers ──────────────────────────────────────────────────────────────

def _azure_vault_rows(account, region) -> list[dict]:
    rows: list[dict] = []
    try:
        for v in get_azure_provider(subscription_id=account).list_backup_vaults(
            account=account or "azure", region=region
        ):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": v["account"],
                "Name": v["name"], "Recovery Points": "—",
                "Locked": "—", "Region": v["region"],
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


# ── GCP helpers ────────────────────────────────────────────────────────────────

def _gcp_job_rows(account, region) -> list[dict]:
    rows: list[dict] = []
    try:
        for j in get_gcp_provider(project_id=account).list_backup_jobs(
            account=account or "gcp", region=region
        ):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": j["account"],
                "Resource": j.get("resource_type", "—"), "State": j.get("state", "—"),
                "Created": j.get("created", "—"), "Region": j.get("region", "—"),
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command("vaults")
def backup_vaults(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List backup vaults (AWS Backup, Azure Backup)."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_vault_rows(cfg, account, region)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_vault_rows(account, region)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] GCP Backup for GKE vaults — use: cloudctl backup jobs --cloud gcp")

    if not rows:
        console.print("[dim]No backup vaults found.[/dim]")
        return
    print_table(rows, title=f"Backup Vaults ({len(rows)})")


@app.command("jobs")
def backup_jobs(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
    state:   Optional[str] = typer.Option(None, "--state", "-s", help="Filter by state (RUNNING|COMPLETED|FAILED)"),
) -> None:
    """List backup jobs."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_job_rows(cfg, account, region, state)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_job_rows(account, region)

    if not rows:
        console.print("[dim]No backup jobs found.[/dim]")
        return
    print_table(rows, title=f"Backup Jobs ({len(rows)})")

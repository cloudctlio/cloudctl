"""cloudctl database — list/describe/snapshots across AWS, Azure, and GCP."""
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
from cloudctl.output.formatter import cloud_label, error, print_table, warn

app = typer.Typer(help="Manage cloud databases (RDS, Azure SQL, CloudSQL).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")


def _aws_database_rows(cfg, account, region, engine) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    if not targets and account:
        warn(f"No AWS profile matching '{account}'.")
        return rows
    for profile_name in targets:
        try:
            for db in get_aws_provider(profile_name, region).list_databases(account=profile_name, region=region):
                if engine and engine.lower() not in db.engine.lower():
                    continue
                rows.append({
                    "Cloud": cloud_label(db.cloud), "Account": db.account,
                    "ID": db.id, "Engine": db.engine,
                    "Class": db.instance_class or "—", "State": db.state,
                    "Region": db.region,
                    "Multi-AZ": "yes" if db.multi_az else "no",
                    "Storage": f"{db.storage_gb} GB" if db.storage_gb else "—",
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_database_rows(account, region, engine) -> list[dict]:
    rows: list[dict] = []
    try:
        for db in get_azure_provider(subscription_id=account).list_databases(
            account=account or "azure", region=region, engine=engine
        ):
            rows.append({
                "Cloud": cloud_label(db.cloud), "Account": db.account,
                "ID": db.id, "Engine": db.engine,
                "Class": db.instance_class or "—", "State": db.state,
                "Region": db.region, "Multi-AZ": "—",
                "Storage": f"{db.storage_gb} GB" if db.storage_gb else "—",
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_database_rows(account, region, engine) -> list[dict]:
    rows: list[dict] = []
    try:
        for db in get_gcp_provider(project_id=account).list_databases(
            account=account or "gcp", region=region, engine=engine
        ):
            rows.append({
                "Cloud": cloud_label(db.cloud), "Account": db.account,
                "ID": db.id, "Engine": db.engine,
                "Class": db.instance_class or "—", "State": db.state,
                "Region": db.region, "Multi-AZ": "—",
                "Storage": f"{db.storage_gb} GB" if db.storage_gb else "—",
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


@app.command("list")
def database_list(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
    engine:  Optional[str] = typer.Option(None, "--engine", "-e", help="Filter by engine (e.g. postgres, mysql, Azure SQL)"),
) -> None:
    """List database instances."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        aws_rows = _aws_database_rows(cfg, account, region, engine)
        if not aws_rows and cloud == "aws" and account:
            raise typer.Exit(1)
        rows += aws_rows

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_database_rows(account, region, engine)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_database_rows(account, region, engine)

    if not rows:
        console.print("[dim]No databases found.[/dim]")
        return
    print_table(rows, title=f"Databases ({len(rows)})")


@app.command("describe")
def database_describe(
    db_id:   str           = typer.Argument(..., help="DB instance identifier."),
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """Show full details for a database instance."""
    cfg = require_init()

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
        error("describe requires a specific --cloud (aws|azure|gcp).")
        raise typer.Exit(1)

    try:
        db = provider.describe_database(account=acct, db_id=db_id, region=region)
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    print_table([{"Field": k, "Value": str(v)} for k, v in {
        "Cloud": cloud_label(db.cloud), "ID": db.id, "Name": db.name,
        "Engine": db.engine, "State": db.state,
        "Class": db.instance_class or "—",
        "Storage": f"{db.storage_gb} GB" if db.storage_gb else "—",
        "Multi-AZ": "yes" if db.multi_az else "no",
        "Region": db.region, "Account": db.account,
        "Tags": ", ".join(f"{k}={v}" for k, v in db.tags.items()) or "—",
    }.items()], title=f"Database: {db_id}")


@app.command("snapshots")
def database_snapshots(
    db_id:   Optional[str] = typer.Argument(None, help="DB instance ID (omit for all). AWS only."),
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List RDS snapshots. AWS only."""
    cfg = require_init()
    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    try:
        snaps = get_aws_provider(profile, region).list_snapshots(account=profile, db_id=db_id, region=region)
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    if not snaps:
        console.print("[dim]No snapshots found.[/dim]")
        return
    print_table([{
        "Snapshot ID": s["id"], "DB": s["db"], "Engine": s["engine"],
        "Status": s["status"],
        "Size": f"{s['size_gb']} GB" if s["size_gb"] else "—",
        "Created": s["created_at"],
    } for s in snaps], title="RDS Snapshots")

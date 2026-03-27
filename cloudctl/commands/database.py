"""cloudctl database — list/describe/snapshots for RDS."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import cloud_label, error, print_table, warn
from cloudctl.providers.aws.provider import AWSProvider

app = typer.Typer(help="Manage cloud databases (RDS, Azure SQL, CloudSQL).")
console = Console()


def _require_init() -> ConfigManager:
    cfg = ConfigManager()
    if not cfg.is_initialized:
        warn("cloudctl not initialized. Run: [cyan]cloudctl init[/cyan]")
        raise typer.Exit(1)
    return cfg


@app.command("list")
def database_list(
    cloud: str = typer.Option("aws", "--cloud", "-c", help="Cloud to query: aws | all"),
    account: Optional[str] = typer.Option(None, "--account", "-a", help="Profile/account name."),
    region: Optional[str] = typer.Option(None, "--region", "-r", help="Region to query."),
) -> None:
    """List database instances."""
    cfg = _require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]

        if not targets:
            warn(f"No AWS profile matching '{account}'.")
            raise typer.Exit(1)

        for profile_name in targets:
            try:
                provider = AWSProvider(profile=profile_name, region=region)
                dbs = provider.list_databases(account=profile_name, region=region)
                for db in dbs:
                    rows.append({
                        "Cloud": cloud_label(db.cloud),
                        "Account": db.account,
                        "ID": db.id,
                        "Engine": db.engine,
                        "Class": db.instance_class or "—",
                        "State": db.state,
                        "Region": db.region,
                        "Multi-AZ": "yes" if db.multi_az else "no",
                        "Storage": f"{db.storage_gb} GB" if db.storage_gb else "—",
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[dim]No databases found.[/dim]")
        return

    print_table(rows, title="Databases")


@app.command("describe")
def database_describe(
    db_id: str = typer.Argument(..., help="DB instance identifier."),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
) -> None:
    """Show full details for a database instance."""
    cfg = _require_init()
    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    try:
        provider = AWSProvider(profile=profile, region=region)
        db = provider.describe_database(account=profile, db_id=db_id, region=region)
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    rows = [
        {"Field": k, "Value": str(v)}
        for k, v in {
            "ID": db.id,
            "Name": db.name,
            "Engine": db.engine,
            "State": db.state,
            "Class": db.instance_class or "—",
            "Storage": f"{db.storage_gb} GB" if db.storage_gb else "—",
            "Multi-AZ": "yes" if db.multi_az else "no",
            "Region": db.region,
            "Account": db.account,
            "Tags": ", ".join(f"{k}={v}" for k, v in db.tags.items()) or "—",
        }.items()
    ]
    print_table(rows, title=f"Database: {db_id}")


@app.command("snapshots")
def database_snapshots(
    db_id: Optional[str] = typer.Argument(None, help="DB instance ID (omit for all)."),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    region: Optional[str] = typer.Option(None, "--region", "-r"),
) -> None:
    """List RDS snapshots."""
    cfg = _require_init()
    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    try:
        provider = AWSProvider(profile=profile, region=region)
        snaps = provider.list_snapshots(account=profile, db_id=db_id, region=region)
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    if not snaps:
        console.print("[dim]No snapshots found.[/dim]")
        return

    rows = [{
        "Snapshot ID": s["id"],
        "DB": s["db"],
        "Engine": s["engine"],
        "Status": s["status"],
        "Size": f"{s['size_gb']} GB" if s["size_gb"] else "—",
        "Created": s["created_at"],
    } for s in snaps]

    print_table(rows, title="RDS Snapshots")

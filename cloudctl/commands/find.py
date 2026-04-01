"""cloudctl find — search for resources by name, tag, or type across clouds."""
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
from cloudctl.output.formatter import cloud_label, error, print_table, warn

app = typer.Typer(help="Find cloud resources by name, tag, or type across all clouds.")

_CLOUD   = typer.Option("all",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")


def _matches(name: str, query: str) -> bool:
    return query.lower() in name.lower()


def _aws_find_rows(cfg, account, region, query, tag) -> list[dict]:
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]

    def _fetch(profile_name: str) -> list[dict]:
        rows: list[dict] = []
        try:
            prov = get_aws_provider(profile_name, region)
            tag_filter = None
            if tag:
                k, _, v = tag.partition("=")
                tag_filter = {k: v} if v else None

            # Compute instances
            for inst in prov.list_compute(account=profile_name, region=region, tags=tag_filter):
                if not query or _matches(inst.name or inst.id, query):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": inst.account,
                        "Type": "EC2", "Name": inst.name or inst.id,
                        "State": inst.state, "Region": inst.region,
                    })
            # S3 buckets
            for b in prov.list_storage(account=profile_name, region=region):
                if not query or _matches(b.name, query):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": b.account,
                        "Type": "S3", "Name": b.name,
                        "State": "active", "Region": b.region or "global",
                    })
            # RDS instances
            for db in prov.list_databases(account=profile_name, region=region):
                if not query or _matches(db.id, query):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": db.account,
                        "Type": f"RDS/{db.engine}", "Name": db.id,
                        "State": db.state, "Region": db.region,
                    })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
        return rows

    return run_parallel(_fetch, targets)


def _azure_find_rows(account, region, query) -> list[dict]:
    rows: list[dict] = []
    try:
        prov = get_azure_provider(subscription_id=account)
        for inst in prov.list_compute(account=account or "azure", region=region):
            if not query or _matches(inst.name or inst.id, query):
                rows.append({
                    "Cloud": cloud_label("azure"), "Account": inst.account,
                    "Type": "VM", "Name": inst.name or inst.id,
                    "State": inst.state, "Region": inst.region,
                })
        for b in prov.list_storage(account=account or "azure", region=region):
            if not query or _matches(b.name, query):
                rows.append({
                    "Cloud": cloud_label("azure"), "Account": b.account,
                    "Type": "Blob", "Name": b.name,
                    "State": "active", "Region": b.region or "—",
                })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_find_rows(account, region, query) -> list[dict]:
    rows: list[dict] = []
    try:
        prov = get_gcp_provider(project_id=account)
        for inst in prov.list_compute(account=account or "gcp", region=region):
            if not query or _matches(inst.name or inst.id, query):
                rows.append({
                    "Cloud": cloud_label("gcp"), "Account": inst.account,
                    "Type": "GCE", "Name": inst.name or inst.id,
                    "State": inst.state, "Region": inst.region,
                })
        for b in prov.list_storage(account=account or "gcp", region=region):
            if not query or _matches(b.name, query):
                rows.append({
                    "Cloud": cloud_label("gcp"), "Account": b.account,
                    "Type": "GCS", "Name": b.name,
                    "State": "active", "Region": b.region or "global",
                })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


@app.command("find")
def find_resources(
    query:   Optional[str] = typer.Argument(None, help="Name substring to search for."),
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
    tag:     Optional[str] = typer.Option(None, "--tag", "-t", help="Filter by tag Key=Value (AWS only)."),
) -> None:
    """Find resources matching a name or tag across clouds."""
    if not query and not tag:
        error("Provide a name query or --tag Key=Value to search.")
        raise typer.Exit(1)

    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_find_rows(cfg, account, region, query, tag)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_find_rows(account, region, query)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_find_rows(account, region, query)

    if not rows:
        console.print(f"[dim]No resources matching '{query or tag}'.[/dim]")
        return
    print_table(rows, title=f"Resources matching '{query or tag}' ({len(rows)})")

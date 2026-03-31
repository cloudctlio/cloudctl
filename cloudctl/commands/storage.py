"""cloudctl storage — list/describe/ls/du across AWS, Azure, and GCP."""
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

app = typer.Typer(help="Manage cloud storage (S3, Blob, GCS).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")

_PUBLIC_YES = "[bold red]YES[/bold red]"
_NO_AWS_PROFILE = "No AWS profile configured."


def _storage_row(b) -> dict:
    return {
        "Cloud": cloud_label(b.cloud), "Account": b.account,
        "Name": b.name, "Region": b.region,
        "Public": _PUBLIC_YES if b.public else "no",
        "Created": b.created_at[:10] if b.created_at else "—",
    }


def _aws_storage_rows(cfg, account, public_only) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    if not targets and account:
        warn(f"No AWS profile matching '{account}'.")
        return rows
    for profile_name in targets:
        try:
            for b in get_aws_provider(profile_name).list_storage(account=profile_name, public_only=public_only):
                rows.append(_storage_row(b))
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_storage_rows(account, region, public_only) -> list[dict]:
    rows: list[dict] = []
    try:
        for b in get_azure_provider(subscription_id=account).list_storage(
            account=account or "azure", region=region, public_only=public_only
        ):
            rows.append(_storage_row(b))
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_storage_rows(account, region, public_only) -> list[dict]:
    rows: list[dict] = []
    try:
        for b in get_gcp_provider(project_id=account).list_storage(
            account=account or "gcp", region=region, public_only=public_only
        ):
            rows.append(_storage_row(b))
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


@app.command("list")
def storage_list(
    cloud:       str           = _CLOUD,
    account:     Optional[str] = _ACCOUNT,
    region:      Optional[str] = _REGION,
    public_only: bool          = typer.Option(False, "--public-only", help="Show only publicly accessible buckets."),
) -> None:
    """List storage buckets / containers."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        aws_rows = _aws_storage_rows(cfg, account, public_only)
        if not aws_rows and cloud == "aws" and account:
            raise typer.Exit(1)
        rows += aws_rows

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_storage_rows(account, region, public_only)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_storage_rows(account, region, public_only)

    if not rows:
        console.print("[dim]No buckets / containers found.[/dim]")
        return
    print_table(rows, title=f"Storage ({len(rows)})")


@app.command("describe")
def storage_describe(
    bucket:  str           = typer.Argument(..., help="Bucket / container name to describe."),
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
) -> None:
    """Show details for a storage bucket or container."""
    cfg = require_init()

    if cloud == "aws":
        profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
        if not profile:
            error(_NO_AWS_PROFILE)
            raise typer.Exit(1)
        provider, acct = get_aws_provider(profile), profile
    elif cloud == "azure":
        provider, acct = get_azure_provider(subscription_id=account), account or "azure"
    elif cloud == "gcp":
        provider, acct = get_gcp_provider(project_id=account), account or "gcp"
    else:
        error("describe requires a specific --cloud (aws|azure|gcp).")
        raise typer.Exit(1)

    try:
        b = provider.describe_storage(account=acct, bucket_name=bucket)
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    print_table([{"Field": k, "Value": str(v)} for k, v in {
        "Cloud": cloud_label(b.cloud), "Name": b.name, "Region": b.region,
        "Account": b.account, "Public": "YES" if b.public else "no",
        "Created": b.created_at[:10] if b.created_at else "—",
    }.items()], title=f"Storage: {bucket}")


@app.command("ls")
def storage_ls(
    path:      str           = typer.Argument(..., help="S3 path, e.g. my-bucket or my-bucket/prefix/"),
    account:   Optional[str] = _ACCOUNT,
    recursive: bool          = typer.Option(False, "--recursive", "-R", help="List all objects recursively."),
) -> None:
    """List objects in a bucket or prefix (like aws s3 ls). AWS only."""
    cfg = require_init()
    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error(_NO_AWS_PROFILE)
        raise typer.Exit(1)

    parts = path.strip("/").split("/", 1)
    bucket = parts[0]
    prefix = (parts[1] + "/") if len(parts) > 1 else ""

    try:
        import boto3
        s3 = boto3.Session(profile_name=profile).client("s3")
        kwargs: dict = {"Bucket": bucket, "Prefix": prefix}
        if not recursive:
            kwargs["Delimiter"] = "/"
        rows: list[dict] = []
        for page in s3.get_paginator("list_objects_v2").paginate(**kwargs):
            for obj in page.get("Contents", []):
                size = obj.get("Size", 0)
                rows.append({
                    "Type": "object", "Key": obj["Key"],
                    "Size": f"{size/1048576:.1f} MB" if size >= 1048576 else f"{size/1024:.1f} KB" if size >= 1024 else f"{size:,} B",
                    "Last Modified": str(obj.get("LastModified", ""))[:19],
                })
            for pfx in page.get("CommonPrefixes", []):
                rows.append({"Type": "prefix", "Key": pfx["Prefix"], "Size": "—", "Last Modified": "—"})
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    if not rows:
        console.print("[dim]No objects found.[/dim]")
        return
    print_table(rows, title=f"s3://{path}")


@app.command("du")
def storage_du(
    bucket:  str           = typer.Argument(..., help="Bucket name."),
    account: Optional[str] = _ACCOUNT,
    prefix:  Optional[str] = typer.Option(None, "--prefix", "-p", help="Limit to a key prefix."),
) -> None:
    """Show total size of a bucket or prefix. AWS only."""
    cfg = require_init()
    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error(_NO_AWS_PROFILE)
        raise typer.Exit(1)

    try:
        import boto3
        s3 = boto3.Session(profile_name=profile).client("s3")
        kwargs: dict = {"Bucket": bucket}
        if prefix:
            kwargs["Prefix"] = prefix
        total_bytes = total_objects = 0
        for page in s3.get_paginator("list_objects_v2").paginate(**kwargs):
            for obj in page.get("Contents", []):
                total_bytes += obj.get("Size", 0)
                total_objects += 1
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    gb = total_bytes / (1024 ** 3)
    mb = total_bytes / (1024 ** 2)
    size_str = f"{gb:.2f} GB" if gb >= 1 else f"{mb:.2f} MB" if mb >= 1 else f"{total_bytes:,} B"
    print_table([{
        "Path": f"s3://{bucket}/{prefix or ''}",
        "Objects": f"{total_objects:,}",
        "Total Size": size_str,
    }], title="Disk Usage")

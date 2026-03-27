"""cloudctl storage — list/describe S3 buckets."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import cloud_label, error, print_table, warn
from cloudctl.providers.aws.provider import AWSProvider

app = typer.Typer(help="Manage cloud storage (S3, Blob, GCS).")
console = Console()


def _require_init() -> ConfigManager:
    cfg = ConfigManager()
    if not cfg.is_initialized:
        warn("cloudctl not initialized. Run: [cyan]cloudctl init[/cyan]")
        raise typer.Exit(1)
    return cfg


@app.command("list")
def storage_list(
    cloud: str = typer.Option("aws", "--cloud", "-c", help="Cloud to query: aws | all"),
    account: Optional[str] = typer.Option(None, "--account", "-a", help="Profile/account name."),
    public_only: bool = typer.Option(False, "--public-only", help="Show only publicly accessible buckets."),
) -> None:
    """List storage buckets."""
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
                provider = AWSProvider(profile=profile_name)
                buckets = provider.list_storage(account=profile_name, public_only=public_only)
                for b in buckets:
                    rows.append({
                        "Cloud": cloud_label(b.cloud),
                        "Account": b.account,
                        "Name": b.name,
                        "Region": b.region,
                        "Public": "[bold red]YES[/bold red]" if b.public else "no",
                        "Created": b.created_at[:10] if b.created_at else "—",
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[dim]No buckets found.[/dim]")
        return

    print_table(rows, title="Storage Buckets")


@app.command("describe")
def storage_describe(
    bucket: str = typer.Argument(..., help="Bucket name to describe."),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
) -> None:
    """Show details for a storage bucket."""
    cfg = _require_init()
    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    try:
        provider = AWSProvider(profile=profile)
        b = provider.describe_storage(account=profile, bucket_name=bucket)
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    rows = [
        {"Field": k, "Value": str(v)}
        for k, v in {
            "Name": b.name,
            "Region": b.region,
            "Cloud": b.cloud.upper(),
            "Account": b.account,
            "Public": "YES" if b.public else "no",
        }.items()
    ]
    print_table(rows, title=f"Bucket: {bucket}")


@app.command("ls")
def storage_ls(
    path: str = typer.Argument(..., help="S3 path, e.g. my-bucket or my-bucket/prefix/"),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    recursive: bool = typer.Option(False, "--recursive", "-R", help="List all objects recursively."),
) -> None:
    """List objects in a bucket or prefix (like aws s3 ls)."""
    cfg = _require_init()
    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    parts = path.strip("/").split("/", 1)
    bucket = parts[0]
    prefix = (parts[1] + "/") if len(parts) > 1 else ""

    try:
        import boto3
        session = boto3.Session(profile_name=profile)
        s3 = session.client("s3")

        kwargs: dict = {"Bucket": bucket, "Prefix": prefix}
        if not recursive:
            kwargs["Delimiter"] = "/"

        rows: list[dict] = []
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(**kwargs):
            for obj in page.get("Contents", []):
                size = obj.get("Size", 0)
                rows.append({
                    "Type": "object",
                    "Key": obj["Key"],
                    "Size": f"{size:,} B" if size < 1024 else f"{size/1024:.1f} KB" if size < 1048576 else f"{size/1048576:.1f} MB",
                    "Last Modified": str(obj.get("LastModified", ""))[:19],
                })
            for prefix_obj in page.get("CommonPrefixes", []):
                rows.append({"Type": "prefix", "Key": prefix_obj["Prefix"], "Size": "—", "Last Modified": "—"})
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    if not rows:
        console.print("[dim]No objects found.[/dim]")
        return
    print_table(rows, title=f"s3://{path}")


@app.command("du")
def storage_du(
    bucket: str = typer.Argument(..., help="Bucket name to calculate size for."),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    prefix: Optional[str] = typer.Option(None, "--prefix", "-p", help="Limit to a key prefix."),
) -> None:
    """Show total size of a bucket or prefix."""
    cfg = _require_init()
    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    try:
        import boto3
        session = boto3.Session(profile_name=profile)
        s3 = session.client("s3")
        kwargs: dict = {"Bucket": bucket}
        if prefix:
            kwargs["Prefix"] = prefix
        paginator = s3.get_paginator("list_objects_v2")
        total_bytes = 0
        total_objects = 0
        for page in paginator.paginate(**kwargs):
            for obj in page.get("Contents", []):
                total_bytes += obj.get("Size", 0)
                total_objects += 1
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    gb = total_bytes / (1024 ** 3)
    mb = total_bytes / (1024 ** 2)
    size_str = f"{gb:.2f} GB" if gb >= 1 else f"{mb:.2f} MB" if mb >= 1 else f"{total_bytes:,} B"
    path = f"s3://{bucket}/{prefix or ''}"
    print_table([{"Path": path, "Objects": f"{total_objects:,}", "Total Size": size_str}], title="Disk Usage")

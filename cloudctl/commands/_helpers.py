"""Shared helpers used by every command module."""
from __future__ import annotations

import concurrent.futures
from typing import Callable, Optional

import typer
from rich.console import Console

from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import error, warn

console = Console()


def require_init() -> ConfigManager:
    """Load config or exit with a helpful message if not initialized."""
    cfg = ConfigManager()
    if not cfg.is_initialized:
        warn("cloudctl not initialized. Run: [cyan]cloudctl init[/cyan]")
        raise typer.Exit(1)
    return cfg


def aws_profiles(cfg: ConfigManager, account: Optional[str] = None) -> list[str]:
    """Return AWS profile names to query, filtered by --account if given."""
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    if not targets and account:
        warn(f"No AWS profile matching '{account}'. Run: cloudctl accounts list")
        raise typer.Exit(1)
    if not targets:
        warn("No AWS profiles configured. Run: cloudctl init")
        raise typer.Exit(1)
    return targets


def get_aws_provider(profile: str, region: Optional[str] = None):
    """Instantiate AWSProvider or exit with an error."""
    from cloudctl.providers.aws.provider import AWSProvider  # noqa: PLC0415
    try:
        return AWSProvider(profile=profile, region=region)
    except ValueError as e:
        error(str(e))
        raise typer.Exit(1)


def get_azure_provider(subscription_id: Optional[str] = None):
    """Instantiate AzureProvider or exit with an install hint."""
    try:
        from cloudctl.providers.azure.provider import AzureProvider  # noqa: PLC0415
    except ImportError:
        error("Azure SDK not installed. Run: [cyan]pip install 'cctl[azure]'[/cyan]")
        raise typer.Exit(1)
    try:
        return AzureProvider(subscription_id=subscription_id)
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)


def get_gcp_provider(project_id: Optional[str] = None):
    """Instantiate GCPProvider or exit with an install hint."""
    try:
        from cloudctl.providers.gcp.provider import GCPProvider  # noqa: PLC0415
    except ImportError:
        error("GCP SDK not installed. Run: [cyan]pip install 'cctl[gcp]'[/cyan]")
        raise typer.Exit(1)
    try:
        return GCPProvider(project_id=project_id)
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)


def run_parallel(fn: Callable, items: list, max_workers: int = 8) -> list:
    """Run fn(item) for each item in parallel, preserving order, swallowing exceptions."""
    results: list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fn, item): item for item in items}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if isinstance(result, list):
                    results.extend(result)
                elif result is not None:
                    results.append(result)
            except Exception as exc:
                warn(f"[parallel] {futures[future]}: {exc}")
    return results

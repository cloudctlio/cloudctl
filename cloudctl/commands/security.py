"""cloudctl security — audit, public-resources."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import cloud_label, print_table, warn

app = typer.Typer(help="Security posture checks across cloud accounts.")
console = Console()

_SEVERITY_COLOR = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "dim"}


def _require_init() -> ConfigManager:
    cfg = ConfigManager()
    if not cfg.is_initialized:
        warn("cloudctl not initialized. Run: [cyan]cloudctl init[/cyan]")
        raise typer.Exit(1)
    return cfg


def _aws_provider(profile: str):
    from cloudctl.providers.aws.provider import AWSProvider
    return AWSProvider(profile=profile)


@app.command("audit")
def security_audit(
    cloud: str = typer.Option("aws", "--cloud", "-c"),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
) -> None:
    """Run security checks: public buckets, open security groups, IAM users without MFA."""
    cfg = _require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                findings = _aws_provider(profile_name).security_audit(account=profile_name)
                for f in findings:
                    color = _SEVERITY_COLOR.get(f["severity"], "")
                    rows.append({
                        "Cloud": cloud_label("aws"),
                        "Account": f["account"],
                        "Severity": f"[{color}]{f['severity']}[/{color}]",
                        "Resource": f["resource"],
                        "Issue": f["issue"],
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[bold green]No security issues found.[/bold green]")
        return
    print_table(rows, title="Security Audit Findings")


@app.command("public-resources")
def security_public_resources(
    cloud: str = typer.Option("aws", "--cloud", "-c"),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
) -> None:
    """List all publicly accessible resources."""
    cfg = _require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                resources = _aws_provider(profile_name).list_public_resources(account=profile_name)
                for r in resources:
                    rows.append({
                        "Cloud": cloud_label("aws"),
                        "Account": r["account"],
                        "Type": r["type"],
                        "ID": r["id"],
                        "Region": r["region"],
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[bold green]No public resources found.[/bold green]")
        return
    print_table(rows, title="Publicly Accessible Resources")

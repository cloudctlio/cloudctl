"""cloudctl iam — roles, users, permission check."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import cloud_label, error, print_table, success, warn

app = typer.Typer(help="Inspect IAM roles, users, and permissions.")
console = Console()


def _require_init() -> ConfigManager:
    cfg = ConfigManager()
    if not cfg.is_initialized:
        warn("cloudctl not initialized. Run: [cyan]cloudctl init[/cyan]")
        raise typer.Exit(1)
    return cfg


def _aws_provider(profile: str):
    from cloudctl.providers.aws.provider import AWSProvider
    return AWSProvider(profile=profile)


@app.command("roles")
def iam_roles(
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    cloud: str = typer.Option("aws", "--cloud", "-c"),
) -> None:
    """List IAM roles."""
    cfg = _require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for role in _aws_provider(profile_name).list_iam_roles(account=profile_name):
                    rows.append({
                        "Cloud": cloud_label("aws"),
                        "Account": role["account"],
                        "Name": role["name"],
                        "ID": role["id"],
                        "Path": role["path"],
                        "Created": role["created"],
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[dim]No roles found.[/dim]")
        return
    print_table(rows, title="IAM Roles")


@app.command("users")
def iam_users(
    account: Optional[str] = typer.Option(None, "--account", "-a"),
    cloud: str = typer.Option("aws", "--cloud", "-c"),
) -> None:
    """List IAM users."""
    cfg = _require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for user in _aws_provider(profile_name).list_iam_users(account=profile_name):
                    rows.append({
                        "Cloud": cloud_label("aws"),
                        "Account": user["account"],
                        "Username": user["username"],
                        "ID": user["id"],
                        "Created": user["created"],
                        "Last Login": user["last_login"],
                    })
            except Exception as e:
                warn(f"[{profile_name}] {e}")

    if not rows:
        console.print("[dim]No users found.[/dim]")
        return
    print_table(rows, title="IAM Users")


@app.command("check")
def iam_check(
    action: str = typer.Argument(..., help="IAM action to check, e.g. s3:GetObject"),
    resource: str = typer.Argument("*", help="Resource ARN (default: *)"),
    account: Optional[str] = typer.Option(None, "--account", "-a"),
) -> None:
    """Check if current credentials can perform an IAM action."""
    cfg = _require_init()
    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    try:
        result = _aws_provider(profile).check_iam_permission(
            account=profile, action=action, resource=resource
        )
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    decision = result["decision"]
    color = "green" if decision == "allowed" else "red"
    console.print(f"\n  Action:   [bold]{result['action']}[/bold]")
    console.print(f"  Resource: {result['resource']}")
    console.print(f"  Principal: {result['principal']}")
    console.print(f"  Decision: [bold {color}]{decision.upper()}[/bold {color}]\n")

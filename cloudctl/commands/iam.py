"""cloudctl iam — roles, users, permission check across AWS, Azure, and GCP."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import console, get_aws_provider, require_init
from cloudctl.output.formatter import cloud_label, error, print_table, warn

app = typer.Typer(help="Inspect IAM roles, users, and permissions.")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")


@app.command("roles")
def iam_roles(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
) -> None:
    """List IAM roles / RBAC role assignments."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for role in get_aws_provider(profile_name).list_iam_roles(account=profile_name):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": role["account"],
                        "Name": role["name"], "ID": role["id"],
                        "Path": role["path"], "Created": role["created"],
                    })
            except Exception as e:
                warn(f"[AWS/{profile_name}] {e}")

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        warn("[Azure] RBAC listing coming in Day 7 — azure IAM commands not yet implemented.")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] IAM listing coming in Day 9 — gcp IAM commands not yet implemented.")

    if not rows:
        console.print("[dim]No roles found.[/dim]")
        return
    print_table(rows, title=f"IAM Roles ({len(rows)})")


@app.command("users")
def iam_users(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
) -> None:
    """List IAM users / service principals."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for user in get_aws_provider(profile_name).list_iam_users(account=profile_name):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": user["account"],
                        "Username": user["username"], "ID": user["id"],
                        "Created": user["created"], "Last Login": user["last_login"],
                    })
            except Exception as e:
                warn(f"[AWS/{profile_name}] {e}")

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        warn("[Azure] Managed Identities listing coming in Day 7.")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] Service Accounts listing coming in Day 9.")

    if not rows:
        console.print("[dim]No users found.[/dim]")
        return
    print_table(rows, title=f"IAM Users ({len(rows)})")


@app.command("check")
def iam_check(
    action:   str           = typer.Argument(..., help="IAM action to check, e.g. s3:GetObject"),
    resource: str           = typer.Argument("*", help="Resource ARN (default: *)"),
    account:  Optional[str] = _ACCOUNT,
) -> None:
    """Check if current credentials can perform an IAM action. AWS only."""
    cfg = require_init()
    profile = account or next((p["name"] for p in cfg.accounts.get("aws", [])), None)
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    try:
        result = get_aws_provider(profile).check_iam_permission(
            account=profile, action=action, resource=resource
        )
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    decision = result["decision"]
    color = "green" if decision == "allowed" else "red"
    console.print(f"\n  Action:    [bold]{result['action']}[/bold]")
    console.print(f"  Resource:  {result['resource']}")
    console.print(f"  Principal: {result['principal']}")
    console.print(f"  Decision:  [bold {color}]{decision.upper()}[/bold {color}]\n")

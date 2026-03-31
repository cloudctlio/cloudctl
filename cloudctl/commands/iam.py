"""cloudctl iam — roles, users, permission check across AWS, Azure, and GCP."""
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

app = typer.Typer(help="Inspect IAM roles, users, and permissions.")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")

_LAST_LOGIN = "Last Login"


def _aws_iam_roles_rows(cfg, account) -> list[dict]:
    rows: list[dict] = []
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
    return rows


def _azure_iam_roles_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for r in get_azure_provider(subscription_id=account).list_rbac_assignments(account=account or "azure"):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": r["account"],
                "Name": r["role"] if "role" in r else r["name"], "ID": r["id"],
                "Path": r.get("scope", "—"), "Created": r.get("principal_type", "—"),
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_iam_roles_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for role in get_gcp_provider(project_id=account).list_roles(account=account or "gcp"):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": role["account"],
                "Name": role["name"], "ID": role["id"],
                "Path": role.get("stage", "—"), "Created": role.get("description", "—"),
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


def _aws_iam_users_rows(cfg, account) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    for profile_name in targets:
        try:
            for user in get_aws_provider(profile_name).list_iam_users(account=profile_name):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": user["account"],
                    "Username": user["username"], "ID": user["id"],
                    "Created": user["created"], _LAST_LOGIN: user["last_login"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_iam_users_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for mi in get_azure_provider(subscription_id=account).list_managed_identities(account=account or "azure"):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": mi["account"],
                "Username": mi["name"], "ID": mi["id"],
                "Created": mi.get("type", "—"), _LAST_LOGIN: mi.get("region", "—"),
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_iam_users_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for sa in get_gcp_provider(project_id=account).list_service_accounts(account=account or "gcp"):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": sa["account"],
                "Username": sa["name"], "ID": sa["email"],
                "Created": sa.get("description", "—"), _LAST_LOGIN: sa.get("disabled", "—"),
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


@app.command("roles")
def iam_roles(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
) -> None:
    """List IAM roles / RBAC role assignments."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_iam_roles_rows(cfg, account)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_iam_roles_rows(account)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_iam_roles_rows(account)

    if not rows:
        console.print("[dim]No roles found.[/dim]")
        return
    print_table(rows, title=f"IAM Roles ({len(rows)})")


@app.command("users")
def iam_users(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
) -> None:
    """List IAM users / service principals / managed identities."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_iam_users_rows(cfg, account)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_iam_users_rows(account)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_iam_users_rows(account)

    if not rows:
        console.print("[dim]No users found.[/dim]")
        return
    print_table(rows, title=f"IAM Users / Identities ({len(rows)})")


@app.command("key-vaults")
def iam_key_vaults(
    account: Optional[str] = _ACCOUNT,
) -> None:
    """List Azure Key Vaults. Azure only."""
    try:
        vaults = get_azure_provider(subscription_id=account).list_key_vaults(account=account or "azure")
    except Exception as e:
        error(str(e))
        raise typer.Exit(1)

    if not vaults:
        console.print("[dim]No Key Vaults found.[/dim]")
        return
    print_table([{
        "Account": v["account"], "Name": v["name"],
        "SKU": v["sku"], "Region": v["region"],
    } for v in vaults], title=f"Key Vaults ({len(vaults)})")


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

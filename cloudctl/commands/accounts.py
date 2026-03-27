"""cloudctl accounts — list, verify, use."""
from __future__ import annotations

import typer
from rich.console import Console

from cloudctl.auth.token_manager import TokenManager
from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import cloud_label, error, print_table, success, warn

app = typer.Typer(help="Manage cloud accounts and profiles.")
console = Console()


@app.command("list")
def accounts_list(
    cloud: str = typer.Option("all", "--cloud", "-c", help="Filter by cloud (aws/azure/gcp/all)."),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table or json."),
) -> None:
    """List all configured cloud accounts."""
    cfg = ConfigManager()
    token_mgr = TokenManager()

    if not cfg.is_initialized:
        warn("cloudctl not initialized. Run: [cyan]cloudctl init[/cyan]")
        raise typer.Exit(1)

    rows: list[dict] = []

    # AWS
    if cloud in ("all", "aws") and "aws" in cfg.clouds:
        for profile in token_mgr.list_aws_profiles():
            rows.append({
                "Cloud": cloud_label("aws"),
                "Name": profile["name"],
                "Region": profile["region"],
                "Type": "SSO" if profile["sso"] else "IAM",
                "Source": profile["source"],
            })

    if not rows:
        console.print("[dim]No accounts found.[/dim]")
        return

    print_table(rows, title="Cloud Accounts")


@app.command("verify")
def accounts_verify(
    account: str = typer.Argument(..., help="Account name or profile to verify."),
) -> None:
    """Verify credentials for an account are valid."""
    token_mgr = TokenManager()
    profile = token_mgr.get_aws_profile(account)

    if not profile:
        error(f"Account '{account}' not found.")
        raise typer.Exit(1)

    console.print(f"Verifying [cyan]{account}[/cyan]…")
    try:
        import boto3
        session = boto3.Session(profile_name=account)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        success(
            f"Account ID: [bold]{identity['Account']}[/bold]  "
            f"ARN: {identity['Arn']}"
        )
    except Exception as e:
        error(f"Credentials invalid: {e}")
        raise typer.Exit(1)


@app.command("use")
def accounts_use(
    account: str = typer.Argument(..., help="Account name to set as default."),
) -> None:
    """Set the default account for cloudctl commands."""
    token_mgr = TokenManager()
    profile = token_mgr.get_aws_profile(account)

    if not profile:
        error(f"Account '{account}' not found.")
        raise typer.Exit(1)

    cfg = ConfigManager()
    cfg.set("default_account", account)
    cfg.save()
    success(f"Default account set to [bold]{account}[/bold].")

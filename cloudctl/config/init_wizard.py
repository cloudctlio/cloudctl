"""First-run setup wizard for cloudctl."""
from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel

from cloudctl.auth.token_manager import TokenManager
from cloudctl.config.manager import ConfigManager

console = Console()


def run_init_wizard() -> None:
    """Interactive first-run wizard. Detects existing credentials and writes config."""
    console.print(Panel.fit(
        "[bold cyan]⚡ cloudctl init[/bold cyan]\n"
        "Universal Cloud CLI — first-time setup",
        border_style="cyan",
    ))
    console.print()

    cfg = ConfigManager()
    token_mgr = TokenManager()

    # Detect available clouds
    detected: dict[str, bool] = {
        "aws": token_mgr.has_aws_credentials(),
        "azure": token_mgr.has_azure_credentials(),
        "gcp": token_mgr.has_gcp_credentials(),
    }

    console.print("[bold]Detected credentials:[/bold]")
    for cloud, found in detected.items():
        icon = "[green]✓[/green]" if found else "[dim]✗[/dim]"
        console.print(f"  {icon}  {cloud.upper()}")
    console.print()

    clouds_found = [c for c, ok in detected.items() if ok]

    if not clouds_found:
        console.print(
            "[yellow]No cloud credentials found.[/yellow]\n"
            "Configure at least one:\n"
            "  AWS   → aws configure\n"
            "  Azure → az login\n"
            "  GCP   → gcloud auth application-default login"
        )
        raise typer.Exit(1)

    # Ask which clouds to enable
    console.print("[bold]Which clouds do you want to use?[/bold]")
    enabled: list[str] = []
    for cloud in clouds_found:
        use = typer.confirm(f"  Enable {cloud.upper()}?", default=True)
        if use:
            enabled.append(cloud)

    if not enabled:
        console.print("[red]No clouds enabled. Exiting.[/red]")
        raise typer.Exit(1)

    cfg.set("clouds", enabled)
    cfg.save()

    # Discover accounts for each enabled cloud
    console.print()
    console.print("[bold]Discovering accounts…[/bold]")
    all_accounts: dict = {}

    if "aws" in enabled:
        aws_accounts = token_mgr.list_aws_profiles()
        all_accounts["aws"] = aws_accounts
        console.print(f"  [green]AWS:[/green] {len(aws_accounts)} profile(s) found")

    cfg.set_accounts(all_accounts)

    console.print()
    console.print(
        f"[bold green]✓ cloudctl initialized![/bold green]\n"
        f"  Config: ~/.cloudctl/config.yaml\n"
        f"  Clouds: {', '.join(c.upper() for c in enabled)}\n\n"
        f"  Next: [cyan]cloudctl accounts list[/cyan]"
    )

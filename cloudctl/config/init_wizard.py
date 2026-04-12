"""First-run setup wizard for cloudctl."""
from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel

from cloudctl.auth.token_manager import TokenManager
from cloudctl.config.manager import ConfigManager

console = Console()


def run_init_wizard() -> None:
    """Detect existing cloud credentials and write config. No prompts."""
    console.print(Panel.fit(
        "[bold cyan]⚡ cloudctl init[/bold cyan]\n"
        "Universal Cloud CLI — first-time setup",
        border_style="cyan",
    ))
    console.print()

    cfg = ConfigManager()
    token_mgr = TokenManager()

    # Detect available clouds — file checks only, no network calls
    detected: dict[str, bool] = {
        "aws": token_mgr.has_aws_credentials(),
        "azure": token_mgr.has_azure_credentials(),
        "gcp": token_mgr.has_gcp_credentials(),
    }

    enabled = [c for c, ok in detected.items() if ok]

    for cloud in ("aws", "azure", "gcp"):
        if detected[cloud]:
            console.print(f"  [green]✓[/green]  {cloud.upper()} credentials found")
        else:
            console.print(f"  [dim]✗  {cloud.upper()} — not configured[/dim]")
    console.print()

    if not enabled:
        console.print(
            "[yellow]No cloud credentials found.[/yellow]\n"
            "Configure at least one and re-run cloudctl init:\n"
            "  AWS   → aws configure  (or aws sso login)\n"
            "  Azure → az login\n"
            "  GCP   → gcloud auth application-default login"
        )
        raise typer.Exit(1)

    cfg.set("clouds", enabled)
    cfg.save()

    # Discover accounts for each enabled cloud (all file-based, no network)
    all_accounts: dict = {}

    if "aws" in enabled:
        aws_accounts = token_mgr.list_aws_profiles()
        all_accounts["aws"] = aws_accounts
        console.print(f"  [green]AWS:[/green] {len(aws_accounts)} profile(s) loaded")

    if "azure" in enabled:
        all_accounts["azure"] = []
        console.print("  [green]Azure:[/green] credentials detected (run [cyan]cloudctl accounts list[/cyan] to verify)")

    if "gcp" in enabled:
        all_accounts["gcp"] = []
        console.print("  [green]GCP:[/green] credentials detected (run [cyan]cloudctl accounts list[/cyan] to verify)")

    cfg.set_accounts(all_accounts)

    console.print()
    console.print(
        f"[bold green]✓ cloudctl initialized![/bold green]\n"
        f"  Config: ~/.cloudctl/config.yaml\n"
        f"  Clouds: {', '.join(c.upper() for c in enabled)}\n\n"
        f"  Next: [cyan]cloudctl accounts list[/cyan]"
    )

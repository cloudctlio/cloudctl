"""cloudctl profile — named configuration profiles (dev/prod/staging)."""
from __future__ import annotations

import json
from typing import Optional

import typer
from rich.console import Console

from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import error, print_table, success, warn

app = typer.Typer(help="Manage named cloudctl profiles (dev, prod, staging, ...).")
console = Console()


@app.command("list")
def profile_list() -> None:
    """List all saved profiles."""
    cfg = ConfigManager()
    profiles = cfg.profiles
    active = cfg.active_profile

    if not profiles and active == "default":
        console.print("[dim]No profiles saved. Create one with: cloudctl profile create <name>[/dim]")
        return

    rows = [{"Name": "default", "Active": "yes" if active == "default" else "—", "Settings": "(built-in)"}]
    for name, data in profiles.items():
        rows.append({
            "Name": name,
            "Active": "yes" if active == name else "—",
            "Settings": ", ".join(f"{k}={v}" for k, v in data.items()),
        })
    print_table(rows, title=f"Profiles ({len(rows)})")


@app.command("create")
def profile_create(
    name:    str           = typer.Argument(..., help="Profile name (e.g. prod, staging)."),
    cloud:   Optional[str] = typer.Option(None, "--cloud",   "-c", help="Default cloud for this profile."),
    account: Optional[str] = typer.Option(None, "--account", "-a", help="Default account/profile for this profile."),
    region:  Optional[str] = typer.Option(None, "--region",  "-r", help="Default region for this profile."),
    output:  Optional[str] = typer.Option(None, "--output",  "-o", help="Default output format for this profile."),
) -> None:
    """Create or update a named profile."""
    if name == "default":
        error("'default' is a reserved profile name.")
        raise typer.Exit(1)

    data: dict = {}
    if cloud:
        data["cloud"] = cloud
    if account:
        data["account"] = account
    if region:
        data["region"] = region
    if output:
        if output not in ("table", "json", "csv", "yaml"):
            error(f"Invalid output format '{output}'. Choose: table | json | csv | yaml")
            raise typer.Exit(1)
        data["output"] = output

    if not data:
        error("Provide at least one option: --cloud, --account, --region, or --output.")
        raise typer.Exit(1)

    cfg = ConfigManager()
    cfg.set_profile(name, data)
    success(f"Profile [bold]{name}[/bold] saved: {json.dumps(data)}")


@app.command("use")
def profile_use(
    name: str = typer.Argument(..., help="Profile name to activate."),
) -> None:
    """Switch to a named profile (also: set CLOUDCTL_PROFILE env var)."""
    cfg = ConfigManager()
    if not cfg.use_profile(name):
        error(f"Profile '{name}' not found. Run: cloudctl profile list")
        raise typer.Exit(1)
    success(f"Active profile set to [bold]{name}[/bold].")
    console.print(f"  Tip: export [cyan]CLOUDCTL_PROFILE={name}[/cyan] to override per-shell.")


@app.command("show")
def profile_show(
    name: Optional[str] = typer.Argument(None, help="Profile name (default: active profile)."),
) -> None:
    """Show settings for a profile."""
    cfg = ConfigManager()
    target = name or cfg.active_profile

    if target == "default":
        console.print("[bold]default[/bold] — built-in profile (no overrides).")
        console.print(f"  Active: [cyan]{'yes' if cfg.active_profile == 'default' else 'no'}[/cyan]")
        return

    data = cfg.get_profile(target)
    if not data:
        error(f"Profile '{target}' not found.")
        raise typer.Exit(1)

    rows = [{"Key": k, "Value": str(v)} for k, v in data.items()]
    rows.append({"Key": "active", "Value": "yes" if cfg.active_profile == target else "no"})
    print_table(rows, title=f"Profile: {target}")


@app.command("delete")
def profile_delete(
    name: str  = typer.Argument(..., help="Profile name to delete."),
    yes:  bool = typer.Option(False, "--yes", "-y", help="Skip confirmation."),
) -> None:
    """Delete a named profile."""
    if name == "default":
        error("Cannot delete the built-in 'default' profile.")
        raise typer.Exit(1)

    if not yes:
        typer.confirm(f"Delete profile '{name}'?", abort=True)

    cfg = ConfigManager()
    if not cfg.delete_profile(name):
        error(f"Profile '{name}' not found.")
        raise typer.Exit(1)
    success(f"Profile [bold]{name}[/bold] deleted.")

"""cloudctl config — get/set/list configuration values."""
from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import print_table, success, warn

app = typer.Typer(help="Manage cloudctl configuration (~/.cloudctl/config.yaml).")
console = Console()


@app.command("list")
def config_list() -> None:
    """List all configuration values."""
    cfg = ConfigManager()
    data = cfg._data
    if not data:
        console.print("[dim]No configuration found. Run: cloudctl init[/dim]")
        return
    rows = [{"Key": k, "Value": str(v)} for k, v in data.items()]
    print_table(rows, title="Configuration (~/.cloudctl/config.yaml)")


@app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Config key to read."),
) -> None:
    """Get a configuration value."""
    cfg = ConfigManager()
    value = cfg.get(key)
    if value is None:
        warn(f"Key '{key}' not set.")
        raise typer.Exit(1)
    console.print(f"[bold]{key}[/bold] = {value}")


@app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key to set."),
    value: str = typer.Argument(..., help="Value to set."),
) -> None:
    """Set a configuration value."""
    cfg = ConfigManager()
    cfg.set(key, value)
    cfg.save()
    success(f"Set [bold]{key}[/bold] = {value}")

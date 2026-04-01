"""
cctl — Universal Cloud CLI
One command for AWS, Azure, and GCP.
"""
from __future__ import annotations

import sys
from typing import Optional

import typer
from rich.console import Console

from cloudctl.__init__ import __version__
from cloudctl.commands import accounts as accounts_cmd
from cloudctl.commands import ai_cmd
from cloudctl.commands import analytics as analytics_cmd
from cloudctl.commands import backup as backup_cmd
from cloudctl.commands import compute as compute_cmd
from cloudctl.commands import config as config_cmd
from cloudctl.commands import containers as containers_cmd
from cloudctl.commands import cost as cost_cmd
from cloudctl.commands import database as database_cmd
from cloudctl.commands import diff as diff_cmd
from cloudctl.commands import find as find_cmd
from cloudctl.commands import iam as iam_cmd
from cloudctl.commands import network as network_cmd
from cloudctl.commands import messaging as messaging_cmd
from cloudctl.commands import monitoring as monitoring_cmd
from cloudctl.commands import pipeline as pipeline_cmd
from cloudctl.commands import profile as profile_cmd
from cloudctl.commands import quotas as quotas_cmd
from cloudctl.commands import security as security_cmd
from cloudctl.commands import storage as storage_cmd
from cloudctl.config.init_wizard import run_init_wizard
from cloudctl.config.manager import ConfigManager
from cloudctl.output.formatter import set_output_format

app = typer.Typer(
    name="cloudctl",
    help="⚡ Universal Cloud CLI — one command for AWS, Azure, and GCP.",
    no_args_is_help=True,
)
console = Console()

# Sub-command groups
app.add_typer(accounts_cmd.app,   name="accounts")
app.add_typer(ai_cmd.app,         name="ai")
app.add_typer(analytics_cmd.app,  name="analytics")
app.add_typer(backup_cmd.app,     name="backup")
app.add_typer(compute_cmd.app,    name="compute")
app.add_typer(config_cmd.app,     name="config")
app.add_typer(containers_cmd.app, name="containers")
app.add_typer(cost_cmd.app,       name="cost")
app.add_typer(database_cmd.app,   name="database")
app.add_typer(diff_cmd.app,       name="diff")
app.add_typer(find_cmd.app,       name="find")
app.add_typer(iam_cmd.app,        name="iam")
app.add_typer(messaging_cmd.app,  name="messaging")
app.add_typer(monitoring_cmd.app, name="monitoring")
app.add_typer(network_cmd.app,    name="network")
app.add_typer(pipeline_cmd.app,   name="pipeline")
app.add_typer(profile_cmd.app,    name="profile")
app.add_typer(quotas_cmd.app,     name="quotas")
app.add_typer(security_cmd.app,   name="security")
app.add_typer(storage_cmd.app,    name="storage")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"cloudctl [bold cyan]{__version__}[/bold cyan]")
        raise typer.Exit()


@app.callback()
def global_options(
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output format: table | json | csv | yaml  (overrides CLOUDCTL_OUTPUT env var)",
        metavar="FORMAT",
    ),
    profile: Optional[str] = typer.Option(
        None, "--profile", "-p",
        help="Named profile to use (overrides CLOUDCTL_PROFILE env var)",
        metavar="PROFILE",
    ),
    version: Optional[bool] = typer.Option(
        None, "--version", "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """⚡ Universal Cloud CLI — one command for AWS, Azure, and GCP."""
    import os
    # Apply profile defaults first (lowest precedence)
    active_profile = profile or os.environ.get("CLOUDCTL_PROFILE")
    if active_profile and active_profile != "default":
        try:
            cfg = ConfigManager()
            pdata = cfg.get_profile(active_profile)
            if pdata and not output and "output" in pdata:
                set_output_format(pdata["output"])
        except Exception:
            pass

    if output:
        valid = {"table", "json", "csv", "yaml"}
        if output.lower() not in valid:
            console.print(f"[red]Invalid --output '{output}'. Choose from: {', '.join(sorted(valid))}[/red]")
            raise typer.Exit(1)
        set_output_format(output)


@app.command()
def init() -> None:
    """Initialize cloudctl and detect existing cloud credentials."""
    run_init_wizard()


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    app()


if __name__ == "__main__":
    main()

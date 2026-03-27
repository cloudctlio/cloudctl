"""
cctl — Universal Cloud CLI
One command for AWS, Azure, and GCP.
"""
from __future__ import annotations

import sys
import typer
from rich.console import Console

from cloudctl.commands import accounts as accounts_cmd
from cloudctl.commands import compute as compute_cmd
from cloudctl.commands import config as config_cmd
from cloudctl.commands import cost as cost_cmd
from cloudctl.commands import database as database_cmd
from cloudctl.commands import iam as iam_cmd
from cloudctl.commands import network as network_cmd
from cloudctl.commands import pipeline as pipeline_cmd
from cloudctl.commands import security as security_cmd
from cloudctl.commands import storage as storage_cmd
from cloudctl.config.init_wizard import run_init_wizard

app = typer.Typer(
    name="cloudctl",
    help="⚡ Universal Cloud CLI — one command for AWS, Azure, and GCP.",
    no_args_is_help=True,
)
console = Console()

# Sub-command groups
app.add_typer(accounts_cmd.app, name="accounts")
app.add_typer(compute_cmd.app, name="compute")
app.add_typer(storage_cmd.app, name="storage")
app.add_typer(database_cmd.app, name="database")
app.add_typer(network_cmd.app, name="network")
app.add_typer(iam_cmd.app, name="iam")
app.add_typer(cost_cmd.app, name="cost")
app.add_typer(security_cmd.app, name="security")
app.add_typer(pipeline_cmd.app, name="pipeline")
app.add_typer(config_cmd.app, name="config")


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

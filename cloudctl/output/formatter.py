"""Auto table/JSON output based on TTY detection."""
import json
import sys

from rich.console import Console
from rich.table import Table

console = Console()
err_console = Console(stderr=True)

_CLOUD_LABELS = {
    "aws":   "[bold orange3]☁ AWS[/bold orange3]",
    "azure": "[bold blue]⬡ Azure[/bold blue]",
    "gcp":   "[bold yellow]◎ GCP[/bold yellow]",
}


def cloud_label(cloud: str) -> str:
    """Return a colored symbol + name for the given cloud provider."""
    return _CLOUD_LABELS.get(cloud.lower(), cloud.upper())


def is_tty() -> bool:
    return sys.stdout.isatty()


def print_table(rows: list[dict], title: str = "") -> None:
    """Print rows as a Rich table (TTY) or JSON (pipe)."""
    if not rows:
        console.print("[dim]No results.[/dim]")
        return

    if not is_tty():
        print(json.dumps(rows, default=str, indent=2))
        return

    table = Table(title=title, show_header=True, header_style="bold cyan")
    for col in rows[0].keys():
        table.add_column(col)
    for row in rows:
        table.add_row(*[str(v) if v is not None else "" for v in row.values()])
    console.print(table)


def print_json(data: dict | list) -> None:
    console.print_json(json.dumps(data, default=str))


def error(msg: str) -> None:
    err_console.print(f"[bold red]Error:[/bold red] {msg}")


def warn(msg: str) -> None:
    err_console.print(f"[bold yellow]Warning:[/bold yellow] {msg}")


def success(msg: str) -> None:
    console.print(f"[bold green]✓[/bold green] {msg}")

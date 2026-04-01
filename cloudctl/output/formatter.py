"""Output formatting — table, JSON, CSV, YAML with TTY auto-detection."""
from __future__ import annotations

import csv
import io
import json
import os
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

# Output format: resolved from --output flag, CLOUDCTL_OUTPUT env var, or TTY detection
_OUTPUT_FORMAT: str | None = None


def set_output_format(fmt: str) -> None:
    """Set the active output format (called early from CLI option)."""
    global _OUTPUT_FORMAT
    _OUTPUT_FORMAT = fmt.lower() if fmt else None


def get_output_format() -> str:
    """Resolve output format: explicit > env var > TTY auto-detect."""
    if _OUTPUT_FORMAT:
        return _OUTPUT_FORMAT
    env = os.environ.get("CLOUDCTL_OUTPUT", "").lower()
    if env in ("json", "csv", "yaml", "table"):
        return env
    return "table" if sys.stdout.isatty() else "json"


def cloud_label(cloud: str) -> str:
    """Return a colored symbol + name for the given cloud provider."""
    return _CLOUD_LABELS.get(cloud.lower(), cloud.upper())


def is_tty() -> bool:
    return sys.stdout.isatty()


def _rows_to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def _rows_to_yaml(rows: list[dict]) -> str:
    try:
        import yaml
        # Strip Rich markup before emitting YAML
        clean = [{k: _strip_markup(str(v)) for k, v in row.items()} for row in rows]
        return yaml.dump(clean, default_flow_style=False, allow_unicode=True)
    except ImportError:
        return json.dumps(rows, default=str, indent=2)


def _strip_markup(text: str) -> str:
    """Remove Rich markup tags like [bold red]...[/bold red]."""
    import re
    return re.sub(r"\[/?[^\]]+\]", "", text)


def print_table(rows: list[dict], title: str = "") -> None:
    """Print rows in the active output format (table / json / csv / yaml)."""
    if not rows:
        console.print("[dim]No results.[/dim]")
        return

    fmt = get_output_format()

    if fmt == "json":
        print(json.dumps(rows, default=str, indent=2))
    elif fmt == "csv":
        print(_rows_to_csv(rows), end="")
    elif fmt == "yaml":
        print(_rows_to_yaml(rows), end="")
    else:
        # Rich table (default)
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

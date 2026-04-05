"""cloudctl feedback — list, show, and clear stored feedback records."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import console
from cloudctl.output.formatter import print_table, warn

app = typer.Typer(help="View and manage stored AI feedback.")


@app.command("list")
def feedback_list(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of records to show"),
    cloud: Optional[str] = typer.Option(None, "--cloud", "-c", help="Filter by cloud"),
) -> None:
    """List recent feedback records."""
    from cloudctl.feedback.store import read_all  # noqa: PLC0415

    records = read_all(limit=limit)
    if cloud:
        records = [r for r in records if r.get("cloud") == cloud]

    if not records:
        console.print("[dim]No feedback records found.[/dim]")
        return

    rows = [
        {
            "Time":     r.get("timestamp", "")[:16],
            "Cloud":    r.get("cloud", "—"),
            "Rating":   r.get("rating", "—"),
            "Provider": r.get("provider", "—"),
            "Question": r.get("question", "")[:60],
        }
        for r in reversed(records)
    ]
    print_table(rows, title=f"Feedback Records ({len(rows)})")


@app.command("show")
def feedback_show(
    keyword: str = typer.Argument(..., help="Filter records by keyword"),
) -> None:
    """Show feedback records matching a keyword."""
    from cloudctl.feedback.store import read_all  # noqa: PLC0415

    records = read_all()
    matches = [r for r in records if keyword.lower() in r.get("question", "").lower()]
    if not matches:
        console.print(f"[dim]No records matching '{keyword}'.[/dim]")
        return

    for r in matches[-10:]:
        console.print(f"\n[bold]{r.get('timestamp', '')[:16]}[/bold]  "
                      f"[cyan]{r.get('cloud', '')}[/cyan]  "
                      f"Rating: {r.get('rating', '?')}")
        console.print(f"  Q: {r.get('question', '')}")
        answer = r.get("answer", "")
        if answer:
            console.print(f"  A: {answer[:120]}{'...' if len(answer) > 120 else ''}")


@app.command("clear")
def feedback_clear(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
) -> None:
    """Delete all stored feedback records."""
    from pathlib import Path  # noqa: PLC0415

    feedback_file = Path.home() / ".cloudctl" / "feedback" / "feedback.jsonl"
    if not feedback_file.exists():
        console.print("[dim]No feedback to clear.[/dim]")
        return

    if not yes:
        typer.confirm("Delete all feedback records?", abort=True)

    feedback_file.unlink()
    console.print("[green]Feedback cleared.[/green]")


@app.command("accuracy")
def feedback_accuracy() -> None:
    """Show learned accuracy patterns from feedback."""
    from cloudctl.feedback.store import load_patterns  # noqa: PLC0415

    patterns = load_patterns()
    if not patterns:
        console.print("[dim]No patterns learned yet. "
                      "Answer a few questions and rate them to build patterns.[/dim]")
        return

    total = patterns.get("total_records", 0)
    console.print(f"\n[bold]Learned from {total} feedback record(s)[/bold]\n")

    cloud_acc = patterns.get("cloud_accuracy", {})
    if cloud_acc:
        rows = [
            {"Cloud": c, "Accuracy": f"{v * 100:.0f}%"}
            for c, v in sorted(cloud_acc.items())
        ]
        print_table(rows, title="Accuracy by Cloud")

    kw_acc = patterns.get("keyword_accuracy", {})
    if kw_acc:
        rows = [
            {"Keyword": k, "Accuracy": f"{v * 100:.0f}%"}
            for k, v in sorted(kw_acc.items(), key=lambda x: -x[1])[:10]
        ]
        print_table(rows, title="Top Keywords by Accuracy")

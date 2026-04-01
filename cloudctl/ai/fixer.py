"""AI fixer — generates and optionally applies fix proposals for cloud issues."""
from __future__ import annotations

from typing import Optional

from rich.console import Console
from rich.panel import Panel

from cloudctl.config.manager import ConfigManager

console = Console()


class AIFixer:
    """
    Generates fix proposals for cloud issues using AI.
    Human approval is always required before applying.
    """

    def __init__(self, cfg: ConfigManager):
        from cloudctl.ai.factory import get_fix_ai  # noqa: PLC0415
        self._ai  = get_fix_ai(cfg)
        self._cfg = cfg

    def propose(self, issues: list[dict]) -> list[dict]:
        """Generate AI fix proposals for a list of issues. Returns proposals (not applied)."""
        proposals: list[dict] = []
        for issue in issues:
            try:
                fix = self._ai.generate_fix(issue)
                proposals.append({
                    "issue":    issue,
                    "fix":      fix,
                    "applied":  False,
                    "approved": False,
                })
            except Exception as e:
                proposals.append({
                    "issue":  issue,
                    "fix":    {"error": str(e)},
                    "applied":  False,
                    "approved": False,
                })
        return proposals

    def present_and_confirm(self, proposals: list[dict]) -> list[dict]:
        """
        Show each proposal to the user and ask for approval.
        Human always approves — never auto-apply.
        """
        import typer  # noqa: PLC0415
        for proposal in proposals:
            issue = proposal["issue"]
            fix   = proposal["fix"]

            console.print(Panel(
                f"[bold]Issue:[/bold] {issue.get('issue', issue)}\n"
                f"[bold]Resource:[/bold] {issue.get('resource', '—')}\n"
                f"[bold]Severity:[/bold] {issue.get('severity', '—')}",
                title="[yellow]Fix Required[/yellow]",
            ))
            console.print(Panel(
                _format_fix(fix),
                title="[cyan]Proposed Fix[/cyan]",
            ))

            approved = typer.confirm("Apply this fix?", default=False)
            proposal["approved"] = approved

        return proposals

    def apply(self, proposals: list[dict]) -> list[dict]:
        """Apply approved proposals. Dispatches to the appropriate fixer."""
        from cloudctl.fixers.registry import get_fixer  # noqa: PLC0415
        for proposal in proposals:
            if not proposal.get("approved"):
                continue
            issue = proposal["issue"]
            try:
                fixer = get_fixer(issue)
                if fixer:
                    fixer.apply(issue, proposal["fix"])
                    proposal["applied"] = True
                    console.print(f"[green]Applied fix for: {issue.get('resource', issue)}[/green]")
                else:
                    console.print(f"[dim]No fixer available for: {issue.get('resource', issue)}[/dim]")
            except Exception as e:
                console.print(f"[red]Fix failed: {e}[/red]")
        return proposals


def _format_fix(fix: dict) -> str:
    if "error" in fix:
        return f"[red]AI error: {fix['error']}[/red]"
    lines: list[str] = []
    for k, v in fix.items():
        lines.append(f"[bold]{k}:[/bold] {v}")
    return "\n".join(lines) if lines else str(fix)

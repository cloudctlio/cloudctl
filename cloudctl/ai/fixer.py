"""AI fixer — generates fix proposals and applies approved ones through the policy gate."""
from __future__ import annotations

from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel

from cloudctl.config.manager import ConfigManager

console = Console()


class AIFixer:
    """
    Generates fix proposals for cloud issues using AI.

    A human confirms each proposal, and every confirmed fix then goes through
    the policy gate (scoped short-lived credentials, a declared plan, policy
    engines, signed approval where required). Nothing is applied when the
    gate is not configured or rejects the change.
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

            approved = typer.confirm("Send this fix to the policy gate?", default=False)
            proposal["approved"] = approved

        return proposals

    def apply(self, proposals: list[dict], *, gate: Any = None, env_name: Optional[str] = None,
              approval_id: Optional[str] = None, requester: Optional[str] = None) -> list[dict]:
        """Apply approved proposals, each one through the policy gate.

        ``gate`` defaults to the gate built from the control-plane config; if
        that config is missing or invalid, nothing is applied.
        """
        from cloudctl.fixers.registry import get_fixer  # noqa: PLC0415
        from cloudctl.gate.models import ConfigError  # noqa: PLC0415

        approved = [p for p in proposals if p.get("approved")]
        if not approved:
            return proposals
        if gate is None:
            try:
                gate = _default_gate()
            except ConfigError as e:
                console.print(f"[red]Not applying any fix: {e}[/red]")
                for p in approved:
                    p["gate"] = {"outcome": "rejected", "stage": "config", "reasons": [str(e)]}
                return proposals

        for proposal in approved:
            issue = proposal["issue"]
            fix = proposal["fix"]
            if "error" in fix:
                console.print(f"[dim]Skipping {issue.get('resource', issue)}: no usable proposal[/dim]")
                continue
            fixer = get_fixer(issue)
            if not fixer:
                console.print(f"[dim]No fixer available for: {issue.get('resource', issue)}[/dim]")
                continue
            try:
                outcome = gated_apply(gate, fixer, issue, fix, env_name=env_name, approval_id=approval_id,
                                      requester=requester)
            except Exception as e:  # noqa: BLE001
                console.print(f"[red]Fix failed: {e}[/red]")
                proposal["gate"] = {"outcome": "error", "reasons": [str(e)]}
                continue
            proposal["gate"] = outcome.decision.to_dict()
            proposal["applied"] = bool(outcome.applied)
            _print_decision(issue, outcome)
        return proposals


class GatedOutcome:
    def __init__(self, decision: Any, applied: bool) -> None:
        self.decision = decision
        self.applied = applied


def _default_gate() -> Any:
    from cloudctl.gate.config import load_config  # noqa: PLC0415
    from cloudctl.gate.gate import PolicyGate  # noqa: PLC0415
    return PolicyGate.from_config(load_config())


def resolve_env_for_issue(config: Any, fixer: Any, issue: dict, env_name: Optional[str]) -> Any:
    account = str(issue.get("account", "") or "") or None
    if fixer.cloud == "aws":
        return config.resolve_environment(name=env_name, cloud="aws", profile=account)
    return config.resolve_environment(name=env_name, cloud=fixer.cloud or None, account=account)


def gated_apply(gate: Any, fixer: Any, issue: dict, fix: dict, *, env_name: Optional[str] = None,
                approval_id: Optional[str] = None, requester: Optional[str] = None,
                model_context: Optional[dict] = None) -> GatedOutcome:
    """One fix through the five stages; apply only on authorization."""
    from cloudctl.gate.gate import default_requester  # noqa: PLC0415
    from cloudctl.gate.models import ChangeRequest, ConfigError, GateDecision, Outcome  # noqa: PLC0415
    from cloudctl.gate.plan.api import ApiActionPlanner  # noqa: PLC0415

    try:
        env = resolve_env_for_issue(gate.config, fixer, issue, env_name)
    except ConfigError as e:
        return GatedOutcome(GateDecision(request_id="-", outcome=Outcome.REJECTED, stage="config",
                                         reasons=(str(e),)), False)
    request = ChangeRequest(
        kind="api_action", environment=env.name,
        summary=f"{type(fixer).__name__}: {issue.get('issue', '')} on {issue.get('resource', '')}"[:500],
        requester=requester or default_requester(),
        context=dict(model_context or {}),
    )
    result = gate.evaluate(request, ApiActionPlanner(fixer, issue, fix), approval_id=approval_id)
    if not result.authorized:
        return GatedOutcome(result.decision, False)
    with result.authorization as auth:
        auth.execute(lambda creds, _plan: fixer.apply(issue, fix, creds=creds),
                     what=f"{type(fixer).__name__}.apply")
    return GatedOutcome(result.decision, True)


def _print_decision(issue: dict, outcome: GatedOutcome) -> None:
    d = outcome.decision
    res = issue.get("resource", issue)
    if outcome.applied:
        console.print(f"[green]Applied fix for: {res}[/green] (gate request {d.request_id})")
        return
    if d.outcome.value == "pending_approval":
        console.print(f"[yellow]Waiting for approval: {res}[/yellow]\n"
                      f"  An approver runs: cloudctl gate approve {d.request_id}\n"
                      f"  Then re-run this command with --approval {d.request_id}")
        return
    console.print(f"[red]Gate rejected the fix for {res} at {d.stage}:[/red] " + "; ".join(d.reasons))
    for f in d.findings[:10]:
        console.print(f"  [{f.severity.name}] {f.rule_id} {f.resource}: {f.message}")


def _format_fix(fix: dict) -> str:
    if "error" in fix:
        return f"[red]AI error: {fix['error']}[/red]"
    lines: list[str] = []
    for k, v in fix.items():
        lines.append(f"[bold]{k}:[/bold] {v}")
    return "\n".join(lines) if lines else str(fix)

"""cloudctl ask — one-shot and interactive cloud AI sessions."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import console, require_init
from cloudctl.output.formatter import warn

app = typer.Typer(help="Ask an AI question about your cloud infrastructure.")

_CLOUD   = typer.Option("all",  "--cloud",   "-c", help="Cloud: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="Profile / subscription / project")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region to focus on")
_SESSION = typer.Option(None,   "--session", "-s", help="Resume a previous session ID")


@app.command("ask")
def ask_command(
    question: Optional[str] = typer.Argument(None, help="Question to ask (omit for interactive mode)"),
    cloud:    str           = _CLOUD,
    account:  Optional[str] = _ACCOUNT,
    region:   Optional[str] = _REGION,
    session:  Optional[str] = _SESSION,
) -> None:
    """
    Ask your cloud a question. Omit QUESTION for an interactive session.

    Examples:
      cloudctl ask "which services have no alarms?"
      cloudctl ask "why is prod slow?" --cloud aws
      cloudctl ask  # interactive REPL
      cloudctl ask --session abc123  # resume previous session
    """
    cfg = require_init()

    try:
        from cloudctl.ai.factory import is_ai_configured  # noqa: PLC0415
    except ImportError:
        warn("AI module not installed. Run: [cyan]pip install 'cctl[ai]'[/cyan]")
        raise typer.Exit(1)

    if not is_ai_configured(cfg):
        warn("AI not configured. Run: [cyan]cloudctl config set ai.provider <provider>[/cyan]")
        raise typer.Exit(1)

    if question:
        _one_shot(cfg, question, cloud, account, region)
    else:
        _interactive(cfg, cloud, account, region, session)


def _one_shot(cfg, question: str, cloud: str, account: Optional[str], region: Optional[str]) -> None:
    """Single question → answer."""
    from cloudctl.ai.agent import CloudAgent  # noqa: PLC0415
    from cloudctl.ai import confidence as confidence_mod  # noqa: PLC0415

    agent  = CloudAgent(cfg)
    result = agent.run(question=question, cloud=cloud, account=account, region=region)

    console.print(f"\n[bold]Answer:[/bold]")
    console.print(result.answer)

    if result.rounds > 1:
        console.print(f"\n[dim]Used {result.rounds} data rounds. "
                      f"Categories: {', '.join(result.context_categories_used)}[/dim]")
    console.print(f"[dim]Confidence: {result.confidence_level}[/dim]\n")


def _interactive(
    cfg,
    cloud: str,
    account: Optional[str],
    region: Optional[str],
    session_id: Optional[str],
) -> None:
    """Interactive multi-turn session."""
    from cloudctl.agent.session import new_session, load, save  # noqa: PLC0415
    from cloudctl.ai.agent import CloudAgent  # noqa: PLC0415

    # Load or create session
    if session_id:
        state = load(session_id)
        if not state:
            warn(f"Session '{session_id}' not found. Starting a new session.")
            state = new_session(cloud=cloud, account=account, region=region)
    else:
        state = new_session(cloud=cloud, account=account, region=region)

    agent = CloudAgent(cfg)

    console.print(f"\n[bold cyan]cloudctl interactive session[/bold cyan]  "
                  f"[dim](session: {state.session_id})[/dim]")
    console.print(f"[dim]Cloud: {cloud}  •  Type [bold]exit[/bold] or [bold]quit[/bold] to end[/dim]\n")

    # Replay previous turns if resuming
    if state.turns:
        console.print(f"[dim]Resuming {len(state.turns)} previous turn(s).[/dim]\n")

    while True:
        try:
            raw = _prompt_user()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Session ended.[/dim]")
            break

        text = raw.strip()
        if not text:
            continue
        if text.lower() in ("exit", "quit", "q", ":q"):
            console.print("[dim]Session saved. Goodbye.[/dim]")
            break

        # Add user turn
        state.add_turn("user", text)

        # Build context with session history
        history_ctx = {"conversation_history": state.history_text()}

        # Ask agent
        result = agent.run(
            question=text,
            cloud=state.cloud,
            account=state.account,
            region=state.region,
        )

        # Merge new context into session cache
        state.merge_context(state.context_cache)
        state.add_turn("assistant", result.answer)

        console.print(f"\n[bold]Answer:[/bold]")
        console.print(result.answer)
        console.print(f"[dim]Confidence: {result.confidence_level}[/dim]\n")

        # Prompt for feedback
        rating = _ask_rating()
        if rating:
            _record_feedback(cfg, text, result.answer, rating, cloud)

        save(state)


def _prompt_user() -> str:
    """Read a line of input with a styled prompt."""
    try:
        from prompt_toolkit import prompt as pt_prompt  # noqa: PLC0415
        return pt_prompt("cloudctl> ")
    except ImportError:
        return input("cloudctl> ")


def _ask_rating() -> Optional[int]:
    """Ask for optional 1-5 rating. Returns None if skipped."""
    try:
        raw = input("Rate this answer 1-5 (or press Enter to skip): ").strip()
        if not raw:
            return None
        v = int(raw)
        if 1 <= v <= 5:
            return v
    except (ValueError, EOFError, KeyboardInterrupt):
        pass
    return None


def _record_feedback(cfg, question: str, answer: str, rating: int, cloud: str) -> None:
    try:
        from cloudctl.ai.feedback import record  # noqa: PLC0415
        provider = cfg.get("ai.provider") or "unknown"
        record(
            question=question,
            context={},
            answer=answer,
            rating=rating,
            provider=provider,
            cloud=cloud,
        )
    except Exception:  # noqa: BLE001
        pass

"""Agent session — persistent state for multi-turn cloud conversations."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


_SESSIONS_DIR = Path.home() / ".cloudctl" / "sessions"


@dataclass
class Turn:
    role:      str   # "user" | "assistant"
    content:   str
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class SessionState:
    session_id:       str
    cloud:            str = "all"
    account:          Optional[str] = None
    region:           Optional[str] = None
    turns:            list[Turn] = field(default_factory=list)
    context_cache:    dict = field(default_factory=dict)
    service_mappings: dict = field(default_factory=dict)  # {hint: resource_id}
    created_at:       str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def add_turn(self, role: str, content: str) -> None:
        self.turns.append(Turn(role=role, content=content))

    def history_text(self, max_turns: int = 10) -> str:
        """Return last N turns as plain text for AI context."""
        recent = self.turns[-max_turns:]
        return "\n".join(f"{t.role.upper()}: {t.content}" for t in recent)

    def merge_context(self, new_ctx: dict) -> None:
        """Merge new context data into the session cache."""
        for k, v in new_ctx.items():
            if k not in self.context_cache:
                self.context_cache[k] = v
            elif isinstance(v, dict) and isinstance(self.context_cache[k], dict):
                self.context_cache[k].update(v)
            elif isinstance(v, list) and isinstance(self.context_cache[k], list):
                self.context_cache[k].extend(v)
            else:
                self.context_cache[k] = v


def _session_path(session_id: str) -> Path:
    return _SESSIONS_DIR / f"{session_id}.json"


def load(session_id: str) -> Optional[SessionState]:
    """Load a session from disk. Returns None if not found."""
    path = _session_path(session_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        turns = [Turn(**t) for t in data.pop("turns", [])]
        s = SessionState(**data)
        s.turns = turns
        return s
    except Exception:  # noqa: BLE001
        return None


def save(state: SessionState) -> None:
    """Persist session state to disk."""
    _SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    d = asdict(state)
    _session_path(state.session_id).write_text(
        json.dumps(d, indent=2, default=str),
        encoding="utf-8",
    )


def new_session(
    cloud: str = "all",
    account: Optional[str] = None,
    region: Optional[str] = None,
) -> SessionState:
    """Create and persist a new session."""
    import uuid  # noqa: PLC0415
    sid   = uuid.uuid4().hex[:12]
    state = SessionState(
        session_id=sid,
        cloud=cloud,
        account=account,
        region=region,
    )
    save(state)
    return state


def list_sessions(limit: int = 10) -> list[dict]:
    """Return metadata for the most recent sessions."""
    _SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    paths = sorted(_SESSIONS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    result = []
    for p in paths[:limit]:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            result.append({
                "session_id": d.get("session_id"),
                "cloud":      d.get("cloud"),
                "turns":      len(d.get("turns", [])),
                "created_at": d.get("created_at"),
            })
        except Exception:  # noqa: BLE001
            pass
    return result

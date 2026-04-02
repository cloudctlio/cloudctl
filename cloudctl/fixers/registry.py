"""Fixer registry — maps issue types to fixer implementations."""
from __future__ import annotations

from typing import Optional

from cloudctl.fixers.base import BaseFixer

_REGISTRY: list[type[BaseFixer]] = []


def register(cls: type[BaseFixer]) -> type[BaseFixer]:
    """Decorator to register a fixer class."""
    _REGISTRY.append(cls)
    return cls


def get_fixer(issue: dict) -> Optional[BaseFixer]:
    """
    Return the first registered fixer that can handle this issue.
    Returns None if no fixer is available.
    """
    _ensure_loaded()
    for cls in _REGISTRY:
        try:
            instance = cls()
            if instance.can_fix(issue):
                return instance
        except Exception:
            pass
    return None


def list_fixers() -> list[dict]:
    """List all registered fixers and the issue types they handle."""
    _ensure_loaded()
    return [
        {
            "fixer": cls.__name__,
            "cloud": cls.cloud or "all",
            "handles": ", ".join(cls.supported_issue_types) or "—",
        }
        for cls in _REGISTRY
    ]


_loaded = False


def _ensure_loaded() -> None:
    """Lazy-import all fixer modules so decorators run and populate _REGISTRY."""
    global _loaded
    if _loaded:
        return
    _loaded = True
    _modules = [
        "cloudctl.fixers.aws.security",
        "cloudctl.fixers.aws.cost",
        "cloudctl.fixers.azure.security",
        "cloudctl.fixers.azure.cost",
        "cloudctl.fixers.gcp.security",
        "cloudctl.fixers.gcp.cost",
    ]
    for mod in _modules:
        try:
            __import__(mod)
        except ImportError:
            pass

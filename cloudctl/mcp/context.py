"""Shared config singleton for the MCP server."""
from __future__ import annotations
from cloudctl.config.manager import ConfigManager

_cfg: ConfigManager | None = None

def get_cfg() -> ConfigManager:
    global _cfg
    if _cfg is None:
        _cfg = ConfigManager()
    return _cfg

def reload_cfg() -> ConfigManager:
    global _cfg
    _cfg = ConfigManager()
    return _cfg

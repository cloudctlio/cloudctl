"""Reads and writes ~/.cloudctl/config.yaml."""
from __future__ import annotations

import os
from pathlib import Path

import yaml

CONFIG_DIR = Path.home() / ".cloudctl"
CONFIG_FILE = CONFIG_DIR / "config.yaml"

_DEFAULT: dict = {
    "version": 1,
    "clouds": [],
    "default_output": "table",
    "accounts": {},
}


class ConfigManager:
    def __init__(self) -> None:
        self._data: dict = {}
        self._load()

    def _load(self) -> None:
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open() as f:
                self._data = yaml.safe_load(f) or {}
        else:
            self._data = dict(_DEFAULT)

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with CONFIG_FILE.open("w") as f:
            yaml.dump(self._data, f, default_flow_style=False)

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def set(self, key: str, value) -> None:
        self._data[key] = value

    @property
    def is_initialized(self) -> bool:
        return CONFIG_FILE.exists() and bool(self._data.get("clouds"))

    @property
    def clouds(self) -> list[str]:
        return self._data.get("clouds", [])

    @property
    def accounts(self) -> dict:
        return self._data.get("accounts", {})

    def set_accounts(self, accounts: dict) -> None:
        self._data["accounts"] = accounts
        self.save()

"""Tests for cloudctl.config.manager — file-based config with tmp paths."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cloudctl.config.manager import ConfigManager


@pytest.fixture()
def tmp_config(tmp_path, monkeypatch):
    """Redirect ConfigManager to a temporary directory."""
    config_dir = tmp_path / ".cloudctl"
    config_file = config_dir / "config.yaml"
    monkeypatch.setattr("cloudctl.config.manager.CONFIG_DIR", config_dir)
    monkeypatch.setattr("cloudctl.config.manager.CONFIG_FILE", config_file)
    return config_file


class TestConfigManagerDefaults:
    def test_not_initialized_when_no_file(self, tmp_config):
        cfg = ConfigManager()
        assert cfg.is_initialized is False

    def test_clouds_empty_by_default(self, tmp_config):
        cfg = ConfigManager()
        assert cfg.clouds == []

    def test_accounts_empty_by_default(self, tmp_config):
        cfg = ConfigManager()
        assert cfg.accounts == {}


class TestConfigManagerSaveLoad:
    def test_save_and_reload(self, tmp_config):
        cfg = ConfigManager()
        cfg.set("clouds", ["aws"])
        cfg.save()

        cfg2 = ConfigManager()
        assert cfg2.clouds == ["aws"]

    def test_is_initialized_after_save_with_clouds(self, tmp_config):
        cfg = ConfigManager()
        cfg.set("clouds", ["aws"])
        cfg.save()

        cfg2 = ConfigManager()
        assert cfg2.is_initialized is True

    def test_set_accounts_persists(self, tmp_config):
        cfg = ConfigManager()
        cfg.set_accounts({"aws": [{"name": "prod", "region": "us-east-1"}]})

        cfg2 = ConfigManager()
        assert cfg2.accounts["aws"][0]["name"] == "prod"

    def test_get_with_default(self, tmp_config):
        cfg = ConfigManager()
        assert cfg.get("nonexistent", "fallback") == "fallback"

    def test_config_dir_created_on_save(self, tmp_config):
        cfg = ConfigManager()
        cfg.set("clouds", ["gcp"])
        cfg.save()
        assert tmp_config.exists()

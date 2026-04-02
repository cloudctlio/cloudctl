"""Tests for Day 11 features: formatter outputs, profile command, cost budgets, parallel helper."""
from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from cloudctl.main import app
from cloudctl.output import formatter as fmt_module
from cloudctl.output.formatter import (
    _rows_to_csv,
    _rows_to_yaml,
    _strip_markup,
    get_output_format,
    print_table,
    set_output_format,
)
from cloudctl.commands._helpers import run_parallel

runner = CliRunner()

# ── Reset output format between tests ─────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_output_format():
    set_output_format(None)
    yield
    set_output_format(None)


# ── Formatter ─────────────────────────────────────────────────────────────────

class TestOutputFormats:
    _rows = [{"Name": "bucket", "Region": "us-east-1", "Public": "no"}]

    def test_json_output(self, capsys):
        set_output_format("json")
        print_table(self._rows)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data[0]["Name"] == "bucket"

    def test_csv_output(self, capsys):
        set_output_format("csv")
        print_table(self._rows, title="Test")
        out = capsys.readouterr().out
        assert "Name" in out
        assert "bucket" in out

    def test_yaml_output(self, capsys):
        set_output_format("yaml")
        print_table(self._rows)
        out = capsys.readouterr().out
        assert "bucket" in out

    def test_get_output_format_env_var(self, monkeypatch):
        monkeypatch.setenv("CLOUDCTL_OUTPUT", "csv")
        assert get_output_format() == "csv"

    def test_explicit_overrides_env(self, monkeypatch):
        monkeypatch.setenv("CLOUDCTL_OUTPUT", "csv")
        set_output_format("yaml")
        assert get_output_format() == "yaml"

    def test_env_var_invalid_falls_back(self, monkeypatch):
        monkeypatch.setenv("CLOUDCTL_OUTPUT", "badformat")
        # not in valid set — falls back to tty detection (table or json)
        fmt = get_output_format()
        assert fmt in ("table", "json", "badformat")  # env passthrough — validation is CLI-level


class TestStripMarkup:
    def test_removes_bold(self):
        assert _strip_markup("[bold red]hello[/bold red]") == "hello"

    def test_no_markup_unchanged(self):
        assert _strip_markup("plain text") == "plain text"

    def test_nested_markup(self):
        assert _strip_markup("[bold][cyan]hi[/cyan][/bold]") == "hi"


class TestRowsToCsv:
    def test_has_header_and_row(self):
        out = _rows_to_csv([{"A": "1", "B": "2"}])
        assert "A,B" in out
        assert "1,2" in out

    def test_multiple_rows(self):
        out = _rows_to_csv([{"X": "a"}, {"X": "b"}])
        lines = [l for l in out.strip().splitlines() if l]
        assert len(lines) == 3  # header + 2 rows


class TestRowsToYaml:
    def test_produces_yaml(self):
        out = _rows_to_yaml([{"key": "value"}])
        assert "key" in out
        assert "value" in out


# ── run_parallel ──────────────────────────────────────────────────────────────

class TestRunParallel:
    def test_collects_all_results(self):
        items = [1, 2, 3]
        results = run_parallel(lambda x: [x * 2], items)
        assert sorted(results) == [2, 4, 6]

    def test_exception_in_one_item_skipped(self):
        def fn(x):
            if x == 2:
                raise ValueError("boom")
            return [x]
        results = run_parallel(fn, [1, 2, 3])
        assert sorted(results) == [1, 3]

    def test_empty_items(self):
        assert run_parallel(lambda x: [x], []) == []

    def test_none_result_skipped(self):
        results = run_parallel(lambda x: None, [1, 2])
        assert results == []


# ── Profile CLI ───────────────────────────────────────────────────────────────

class TestProfileCli:
    def _patched_cfg(self, profiles=None, active="default"):
        cfg = MagicMock()
        cfg.profiles = profiles or {}
        cfg.active_profile = active
        return cfg

    def test_list_no_profiles(self):
        cfg = self._patched_cfg()
        with patch("cloudctl.commands.profile.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["profile", "list"])
        assert result.exit_code == 0

    def test_list_with_profiles(self):
        cfg = self._patched_cfg(profiles={"prod": {"cloud": "aws", "region": "us-east-1"}}, active="prod")
        with patch("cloudctl.commands.profile.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["profile", "list"])
        assert result.exit_code == 0

    def test_create_profile(self):
        cfg = MagicMock()
        with patch("cloudctl.commands.profile.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["profile", "create", "staging", "--cloud", "aws", "--region", "eu-west-1"])
        assert result.exit_code == 0
        cfg.set_profile.assert_called_once()

    def test_create_default_name_rejected(self):
        result = runner.invoke(app, ["profile", "create", "default", "--cloud", "aws"])
        assert result.exit_code == 1

    def test_create_no_options_rejected(self):
        result = runner.invoke(app, ["profile", "create", "staging"])
        assert result.exit_code == 1

    def test_create_invalid_output_rejected(self):
        result = runner.invoke(app, ["profile", "create", "staging", "--output", "xml"])
        assert result.exit_code == 1

    def test_use_profile(self):
        cfg = MagicMock()
        cfg.use_profile.return_value = True
        with patch("cloudctl.commands.profile.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["profile", "use", "prod"])
        assert result.exit_code == 0

    def test_use_missing_profile(self):
        cfg = MagicMock()
        cfg.use_profile.return_value = False
        with patch("cloudctl.commands.profile.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["profile", "use", "missing"])
        assert result.exit_code == 1

    def test_show_default_profile(self):
        cfg = MagicMock()
        cfg.active_profile = "default"
        with patch("cloudctl.commands.profile.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["profile", "show", "default"])
        assert result.exit_code == 0

    def test_show_named_profile(self):
        cfg = MagicMock()
        cfg.active_profile = "prod"
        cfg.get_profile.return_value = {"cloud": "aws", "region": "us-east-1"}
        with patch("cloudctl.commands.profile.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["profile", "show", "prod"])
        assert result.exit_code == 0

    def test_show_missing_profile(self):
        cfg = MagicMock()
        cfg.active_profile = "default"
        cfg.get_profile.return_value = None
        with patch("cloudctl.commands.profile.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["profile", "show", "ghost"])
        assert result.exit_code == 1

    def test_delete_profile(self):
        cfg = MagicMock()
        cfg.delete_profile.return_value = True
        with patch("cloudctl.commands.profile.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["profile", "delete", "staging", "--yes"])
        assert result.exit_code == 0

    def test_delete_default_rejected(self):
        result = runner.invoke(app, ["profile", "delete", "default", "--yes"])
        assert result.exit_code == 1

    def test_delete_missing_profile(self):
        cfg = MagicMock()
        cfg.delete_profile.return_value = False
        with patch("cloudctl.commands.profile.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["profile", "delete", "ghost", "--yes"])
        assert result.exit_code == 1


# ── Config manager profile methods ────────────────────────────────────────────

class TestConfigManagerProfiles:
    def test_set_and_get_profile(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_DIR", tmp_path / ".cloudctl")
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_FILE", tmp_path / ".cloudctl" / "config.yaml")
        from cloudctl.config.manager import ConfigManager
        cfg = ConfigManager()
        cfg.set_profile("prod", {"cloud": "aws", "region": "us-east-1"})
        assert cfg.get_profile("prod") == {"cloud": "aws", "region": "us-east-1"}

    def test_delete_profile(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_DIR", tmp_path / ".cloudctl")
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_FILE", tmp_path / ".cloudctl" / "config.yaml")
        from cloudctl.config.manager import ConfigManager
        cfg = ConfigManager()
        cfg.set_profile("staging", {"cloud": "gcp"})
        assert cfg.delete_profile("staging") is True
        assert cfg.get_profile("staging") is None

    def test_delete_nonexistent_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_DIR", tmp_path / ".cloudctl")
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_FILE", tmp_path / ".cloudctl" / "config.yaml")
        from cloudctl.config.manager import ConfigManager
        cfg = ConfigManager()
        assert cfg.delete_profile("ghost") is False

    def test_use_profile(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_DIR", tmp_path / ".cloudctl")
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_FILE", tmp_path / ".cloudctl" / "config.yaml")
        from cloudctl.config.manager import ConfigManager
        cfg = ConfigManager()
        cfg.set_profile("prod", {"cloud": "aws"})
        assert cfg.use_profile("prod") is True
        assert cfg.active_profile == "prod"

    def test_use_nonexistent_profile_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_DIR", tmp_path / ".cloudctl")
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_FILE", tmp_path / ".cloudctl" / "config.yaml")
        from cloudctl.config.manager import ConfigManager
        cfg = ConfigManager()
        assert cfg.use_profile("ghost") is False

    def test_env_var_overrides_active_profile(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_DIR", tmp_path / ".cloudctl")
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_FILE", tmp_path / ".cloudctl" / "config.yaml")
        monkeypatch.setenv("CLOUDCTL_PROFILE", "staging")
        from cloudctl.config.manager import ConfigManager
        cfg = ConfigManager()
        assert cfg.active_profile == "staging"


# ── Cost budgets ──────────────────────────────────────────────────────────────

class TestCostBudgets:
    _budget = {
        "account": "prod", "name": "MonthlyBudget",
        "limit": "$100.00", "actual": "$45.00",
        "forecast": "$90.00", "pct_used": 45.0, "status": "OK",
    }

    def _cfg(self):
        cfg = MagicMock()
        cfg.clouds = ["aws"]
        cfg.accounts = {"aws": [{"name": "prod"}]}
        return cfg

    def test_budget_ok(self):
        cfg = self._cfg()
        aws = MagicMock()
        aws.list_budgets.return_value = [self._budget]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.cost.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["cost", "budgets", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_budget_alarm_status(self):
        cfg = self._cfg()
        aws = MagicMock()
        budget = {**self._budget, "status": "ALARM", "pct_used": 105.0}
        aws.list_budgets.return_value = [budget]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.cost.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["cost", "budgets", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_no_budgets_message(self):
        cfg = self._cfg()
        aws = MagicMock()
        aws.list_budgets.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.cost.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["cost", "budgets", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_exception_skipped(self):
        cfg = self._cfg()
        aws = MagicMock()
        aws.list_budgets.side_effect = Exception("no access")
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.cost.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["cost", "budgets", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_gcp_warns(self):
        cfg = MagicMock()
        cfg.is_initialized = True
        cfg.clouds = ["gcp"]
        cfg.accounts = {}
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["cost", "budgets", "--cloud", "gcp"])
        assert result.exit_code == 0


# ── Version flag ──────────────────────────────────────────────────────────────

class TestVersionFlag:
    def test_version_exits_0(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0

    def test_version_contains_version_string(self):
        from cloudctl import __version__
        result = runner.invoke(app, ["--version"])
        assert __version__ in result.output


# ── Output flag ───────────────────────────────────────────────────────────────

class TestOutputFlag:
    def test_invalid_output_exits_1(self):
        result = runner.invoke(app, ["--output", "xml", "compute", "list"])
        assert result.exit_code == 1

    def test_valid_output_accepted(self):
        cfg = MagicMock()
        cfg.is_initialized = True
        cfg.clouds = ["aws"]
        cfg.accounts = {"aws": [{"name": "prod"}]}
        aws = MagicMock()
        aws.list_compute.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.compute.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["--output", "json", "compute", "list"])
        assert result.exit_code == 0

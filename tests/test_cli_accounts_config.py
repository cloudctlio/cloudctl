"""CLI tests for accounts and config commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from cloudctl.main import app

runner = CliRunner()


def _initialized_cfg(clouds=("aws",), profiles=({"name": "prod", "region": "us-east-1", "sso": False, "source": "config"},)):
    cfg = MagicMock()
    cfg.is_initialized = True
    cfg.clouds = list(clouds)
    cfg._data = {"clouds": list(clouds), "default_output": "table"}
    cfg.accounts = {"aws": [{"name": p["name"]} for p in profiles]}
    return cfg


class TestAccountsList:
    def test_shows_profiles(self):
        cfg = _initialized_cfg()
        profiles = [{"name": "prod", "region": "us-east-1", "sso": False, "source": "config"}]
        with patch("cloudctl.commands.accounts.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.accounts.TokenManager") as MockTM:
            MockTM.return_value.list_aws_profiles.return_value = profiles
            result = runner.invoke(app, ["accounts", "list"])
        assert result.exit_code == 0

    def test_not_initialized_exits(self):
        cfg = MagicMock()
        cfg.is_initialized = False
        with patch("cloudctl.commands.accounts.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["accounts", "list"])
        assert result.exit_code == 1

    def test_no_accounts_found(self):
        cfg = _initialized_cfg(clouds=("azure",))
        with patch("cloudctl.commands.accounts.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.accounts.TokenManager"):
            result = runner.invoke(app, ["accounts", "list"])
        assert result.exit_code == 0

    def test_sso_profile_type(self):
        cfg = _initialized_cfg()
        profiles = [{"name": "sso-prod", "region": "us-east-1", "sso": True, "source": "config"}]
        with patch("cloudctl.commands.accounts.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.accounts.TokenManager") as MockTM:
            MockTM.return_value.list_aws_profiles.return_value = profiles
            result = runner.invoke(app, ["accounts", "list"])
        assert result.exit_code == 0


class TestAccountsVerify:
    def test_valid_credentials(self):
        tm = MagicMock()
        tm.get_aws_profile.return_value = {"name": "prod"}
        mock_session = MagicMock()
        mock_session.client.return_value.get_caller_identity.return_value = {
            "Account": "123456789", "Arn": "arn:aws:iam::123456789:root"
        }
        with patch("cloudctl.commands.accounts.TokenManager", return_value=tm), \
             patch("boto3.Session", return_value=mock_session):
            result = runner.invoke(app, ["accounts", "verify", "prod"])
        assert result.exit_code == 0

    def test_account_not_found(self):
        tm = MagicMock()
        tm.get_aws_profile.return_value = None
        with patch("cloudctl.commands.accounts.TokenManager", return_value=tm):
            result = runner.invoke(app, ["accounts", "verify", "nonexistent"])
        assert result.exit_code == 1

    def test_invalid_credentials(self):
        tm = MagicMock()
        tm.get_aws_profile.return_value = {"name": "prod"}
        mock_session = MagicMock()
        mock_session.client.return_value.get_caller_identity.side_effect = Exception("No creds")
        with patch("cloudctl.commands.accounts.TokenManager", return_value=tm), \
             patch("boto3.Session", return_value=mock_session):
            result = runner.invoke(app, ["accounts", "verify", "prod"])
        assert result.exit_code == 1


class TestAccountsUse:
    def test_sets_default(self):
        tm = MagicMock()
        tm.get_aws_profile.return_value = {"name": "prod"}
        cfg = MagicMock()
        with patch("cloudctl.commands.accounts.TokenManager", return_value=tm), \
             patch("cloudctl.commands.accounts.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["accounts", "use", "prod"])
        assert result.exit_code == 0
        cfg.set.assert_called_once_with("default_account", "prod")
        cfg.save.assert_called_once()

    def test_not_found_exits(self):
        tm = MagicMock()
        tm.get_aws_profile.return_value = None
        with patch("cloudctl.commands.accounts.TokenManager", return_value=tm):
            result = runner.invoke(app, ["accounts", "use", "missing"])
        assert result.exit_code == 1


class TestConfigCommands:
    def test_list_shows_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_DIR", tmp_path / ".cloudctl")
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_FILE", tmp_path / ".cloudctl" / "config.yaml")
        result = runner.invoke(app, ["config", "list"])
        assert result.exit_code == 0

    def test_get_existing_key(self, tmp_path, monkeypatch):
        config_dir = tmp_path / ".cloudctl"
        config_file = config_dir / "config.yaml"
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_DIR", config_dir)
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_FILE", config_file)
        from cloudctl.config.manager import ConfigManager
        cfg = ConfigManager()
        cfg.set("mykey", "myvalue")
        cfg.save()
        result = runner.invoke(app, ["config", "get", "mykey"])
        assert result.exit_code == 0

    def test_get_missing_key_exits(self, tmp_path, monkeypatch):
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_DIR", tmp_path / ".cloudctl")
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_FILE", tmp_path / ".cloudctl" / "config.yaml")
        result = runner.invoke(app, ["config", "get", "doesnotexist"])
        assert result.exit_code == 1

    def test_set_key(self, tmp_path, monkeypatch):
        config_dir = tmp_path / ".cloudctl"
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_DIR", config_dir)
        monkeypatch.setattr("cloudctl.config.manager.CONFIG_FILE", config_dir / "config.yaml")
        result = runner.invoke(app, ["config", "set", "theme", "dark"])
        assert result.exit_code == 0

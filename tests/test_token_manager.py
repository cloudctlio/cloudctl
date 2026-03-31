"""Tests for cloudctl.auth.token_manager."""
from __future__ import annotations

import configparser
from pathlib import Path

import pytest

from cloudctl.auth.token_manager import TokenManager


@pytest.fixture()
def tm():
    return TokenManager()


class TestHasAwsCredentials:
    def test_true_when_config_exists(self, tmp_path, monkeypatch):
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        (aws_dir / "config").write_text("[default]\nregion=us-east-1\n")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert TokenManager().has_aws_credentials() is True

    def test_false_when_nothing_exists(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert TokenManager().has_aws_credentials() is False


class TestListAwsProfiles:
    def test_reads_config_profiles(self, tmp_path, monkeypatch):
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        (aws_dir / "config").write_text(
            "[profile prod]\nregion=us-east-1\n"
            "[profile staging]\nregion=eu-west-1\nsso_start_url=https://sso.example.com\n"
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        profiles = TokenManager().list_aws_profiles()
        names = {p["name"] for p in profiles}
        assert "prod" in names
        assert "staging" in names

    def test_sso_flag_set(self, tmp_path, monkeypatch):
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        (aws_dir / "config").write_text(
            "[profile sso-user]\nregion=us-east-1\nsso_start_url=https://sso.example.com\n"
        )
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        profiles = TokenManager().list_aws_profiles()
        assert profiles[0]["sso"] is True

    def test_reads_credentials_file(self, tmp_path, monkeypatch):
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        (aws_dir / "credentials").write_text("[myprofile]\naws_access_key_id=AKIA\naws_secret_access_key=secret\n")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        profiles = TokenManager().list_aws_profiles()
        assert any(p["name"] == "myprofile" for p in profiles)

    def test_credentials_not_duplicated_if_in_config(self, tmp_path, monkeypatch):
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        (aws_dir / "config").write_text("[profile shared]\nregion=us-east-1\n")
        (aws_dir / "credentials").write_text("[shared]\naws_access_key_id=AKIA\n")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        profiles = TokenManager().list_aws_profiles()
        names = [p["name"] for p in profiles]
        assert names.count("shared") == 1

    def test_empty_when_no_files(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert TokenManager().list_aws_profiles() == []


class TestGetAwsProfile:
    def test_returns_profile_by_name(self, tmp_path, monkeypatch):
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        (aws_dir / "config").write_text("[profile prod]\nregion=us-east-1\n")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        profile = TokenManager().get_aws_profile("prod")
        assert profile is not None
        assert profile["name"] == "prod"

    def test_returns_none_for_missing_profile(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert TokenManager().get_aws_profile("nonexistent") is None


class TestHasAzureCredentials:
    def test_true_when_token_cache_exists(self, tmp_path, monkeypatch):
        azure_dir = tmp_path / ".azure"
        azure_dir.mkdir()
        (azure_dir / "msal_token_cache.json").write_text("{}")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert TokenManager().has_azure_credentials() is True

    def test_false_when_nothing_exists(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert TokenManager().has_azure_credentials() is False


class TestHasGcpCredentials:
    def test_true_when_adc_exists(self, tmp_path, monkeypatch):
        gcloud_dir = tmp_path / ".config" / "gcloud"
        gcloud_dir.mkdir(parents=True)
        (gcloud_dir / "application_default_credentials.json").write_text("{}")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert TokenManager().has_gcp_credentials() is True

    def test_false_when_nothing_exists(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert TokenManager().has_gcp_credentials() is False

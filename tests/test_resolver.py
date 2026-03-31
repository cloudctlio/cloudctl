"""Tests for cloudctl.resolvers.account_resolver."""
from __future__ import annotations

from unittest.mock import MagicMock

from cloudctl.config.manager import ConfigManager
from cloudctl.resolvers.account_resolver import ResolvedAccount, resolve


def _cfg(clouds, accounts):
    cfg = MagicMock(spec=ConfigManager)
    cfg.clouds = clouds
    cfg.accounts = accounts
    return cfg


class TestResolve:
    def test_single_aws_profile(self):
        cfg = _cfg(["aws"], {"aws": [{"name": "prod"}]})
        result = resolve(cfg, cloud="aws")
        assert len(result) == 1
        assert result[0].cloud == "aws"
        assert result[0].account_id == "prod"

    def test_account_filter(self):
        cfg = _cfg(["aws"], {"aws": [{"name": "prod"}, {"name": "staging"}]})
        result = resolve(cfg, cloud="aws", account="prod")
        assert len(result) == 1
        assert result[0].account_id == "prod"

    def test_account_not_matching_returns_empty(self):
        cfg = _cfg(["aws"], {"aws": [{"name": "prod"}]})
        result = resolve(cfg, cloud="aws", account="staging")
        assert result == []

    def test_all_clouds_queries_each(self):
        cfg = _cfg(["aws", "gcp"], {
            "aws": [{"name": "prod"}],
            "gcp": [{"name": "my-project"}],
        })
        result = resolve(cfg, cloud="all")
        clouds = {r.cloud for r in result}
        assert "aws" in clouds
        assert "gcp" in clouds

    def test_cloud_not_in_config_skipped(self):
        cfg = _cfg(["aws"], {"aws": [{"name": "prod"}]})
        result = resolve(cfg, cloud="gcp")
        assert result == []

    def test_region_propagated(self):
        cfg = _cfg(["aws"], {"aws": [{"name": "prod"}]})
        result = resolve(cfg, cloud="aws", region="eu-west-1")
        assert result[0].region == "eu-west-1"

    def test_profile_with_id_key(self):
        cfg = _cfg(["azure"], {"azure": [{"id": "sub-123"}]})
        result = resolve(cfg, cloud="azure")
        assert result[0].account_id == "sub-123"

    def test_returns_resolved_account_type(self):
        cfg = _cfg(["aws"], {"aws": [{"name": "prod"}]})
        result = resolve(cfg, cloud="aws")
        assert isinstance(result[0], ResolvedAccount)

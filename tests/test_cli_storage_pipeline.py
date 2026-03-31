"""CLI tests for storage (ls/du) and pipeline (analyze) to hit uncovered branches."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from cloudctl.main import app

runner = CliRunner()


def _cfg(profiles=({"name": "prod"},)):
    cfg = MagicMock()
    cfg.is_initialized = True
    cfg.clouds = ["aws"]
    cfg.accounts = {"aws": list(profiles)}
    return cfg


# ── storage ls / du ───────────────────────────────────────────────────────────

class TestStorageLs:
    def _page(self, keys=(), prefixes=()):
        return {
            "Contents": [{"Key": k, "Size": 1024, "LastModified": "2024-01-01T00:00:00"} for k in keys],
            "CommonPrefixes": [{"Prefix": p} for p in prefixes],
        }

    def test_ls_lists_objects(self):
        cfg = _cfg()
        mock_s3 = MagicMock()
        mock_s3.get_paginator.return_value.paginate.return_value = [self._page(keys=["file.txt"])]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("boto3.Session") as mock_session:
            mock_session.return_value.client.return_value = mock_s3
            result = runner.invoke(app, ["storage", "ls", "my-bucket"])
        assert result.exit_code == 0

    def test_ls_with_prefix(self):
        cfg = _cfg()
        mock_s3 = MagicMock()
        mock_s3.get_paginator.return_value.paginate.return_value = [self._page(keys=["logs/file.txt"])]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("boto3.Session") as mock_session:
            mock_session.return_value.client.return_value = mock_s3
            result = runner.invoke(app, ["storage", "ls", "my-bucket/logs/"])
        assert result.exit_code == 0

    def test_ls_shows_prefixes(self):
        cfg = _cfg()
        mock_s3 = MagicMock()
        mock_s3.get_paginator.return_value.paginate.return_value = [self._page(prefixes=["folder/"])]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("boto3.Session") as mock_session:
            mock_session.return_value.client.return_value = mock_s3
            result = runner.invoke(app, ["storage", "ls", "my-bucket"])
        assert result.exit_code == 0

    def test_ls_empty_bucket(self):
        cfg = _cfg()
        mock_s3 = MagicMock()
        mock_s3.get_paginator.return_value.paginate.return_value = [self._page()]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("boto3.Session") as mock_session:
            mock_session.return_value.client.return_value = mock_s3
            result = runner.invoke(app, ["storage", "ls", "my-bucket"])
        assert result.exit_code == 0

    def test_ls_error_exits(self):
        cfg = _cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("boto3.Session") as mock_session:
            mock_session.return_value.client.return_value.get_paginator.side_effect = Exception("no access")
            result = runner.invoke(app, ["storage", "ls", "my-bucket"])
        assert result.exit_code == 1

    def test_ls_recursive_flag(self):
        cfg = _cfg()
        mock_s3 = MagicMock()
        mock_s3.get_paginator.return_value.paginate.return_value = [self._page(keys=["a/b/c.txt"])]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("boto3.Session") as mock_session:
            mock_session.return_value.client.return_value = mock_s3
            result = runner.invoke(app, ["storage", "ls", "my-bucket", "--recursive"])
        assert result.exit_code == 0


class TestStorageDu:
    def _page(self, sizes=()):
        return {"Contents": [{"Size": s} for s in sizes]}

    def test_du_bytes(self):
        cfg = _cfg()
        mock_s3 = MagicMock()
        mock_s3.get_paginator.return_value.paginate.return_value = [self._page(sizes=[500, 200])]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("boto3.Session") as mock_session:
            mock_session.return_value.client.return_value = mock_s3
            result = runner.invoke(app, ["storage", "du", "my-bucket"])
        assert result.exit_code == 0

    def test_du_with_prefix(self):
        cfg = _cfg()
        mock_s3 = MagicMock()
        mock_s3.get_paginator.return_value.paginate.return_value = [self._page(sizes=[1024 * 1024 * 5])]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("boto3.Session") as mock_session:
            mock_session.return_value.client.return_value = mock_s3
            result = runner.invoke(app, ["storage", "du", "my-bucket", "--prefix", "logs/"])
        assert result.exit_code == 0

    def test_du_error_exits(self):
        cfg = _cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("boto3.Session") as mock_session:
            mock_session.return_value.client.return_value.get_paginator.side_effect = Exception("denied")
            result = runner.invoke(app, ["storage", "du", "my-bucket"])
        assert result.exit_code == 1

    def test_du_empty_bucket(self):
        cfg = _cfg()
        mock_s3 = MagicMock()
        mock_s3.get_paginator.return_value.paginate.return_value = [{"Contents": []}]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("boto3.Session") as mock_session:
            mock_session.return_value.client.return_value = mock_s3
            result = runner.invoke(app, ["storage", "du", "my-bucket"])
        assert result.exit_code == 0


# ── pipeline analyze ──────────────────────────────────────────────────────────

class TestPipelineAnalyze:
    def _mock_state(self, stages=()):
        return {"stageStates": stages}

    def test_analyze_shows_stages(self):
        cfg = _cfg()
        mock_provider = MagicMock()
        mock_cp = MagicMock()
        mock_cp.get_pipeline_state.return_value = self._mock_state([
            {"stageName": "Source", "latestExecution": {"status": "Succeeded", "lastStatusChange": "2024-01-01"}},
            {"stageName": "Deploy", "latestExecution": {"status": "InProgress", "lastStatusChange": "2024-01-02"}},
        ])
        mock_provider._session.client.return_value = mock_cp
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.pipeline.get_aws_provider", return_value=mock_provider):
            result = runner.invoke(app, ["pipeline", "analyze", "deploy-prod", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_analyze_empty_stages(self):
        cfg = _cfg()
        mock_provider = MagicMock()
        mock_cp = MagicMock()
        mock_cp.get_pipeline_state.return_value = self._mock_state()
        mock_provider._session.client.return_value = mock_cp
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.pipeline.get_aws_provider", return_value=mock_provider):
            result = runner.invoke(app, ["pipeline", "analyze", "my-pipe", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_analyze_error_exits(self):
        cfg = _cfg()
        mock_provider = MagicMock()
        mock_provider._session.client.side_effect = Exception("no access")
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.pipeline.get_aws_provider", return_value=mock_provider):
            result = runner.invoke(app, ["pipeline", "analyze", "my-pipe", "--cloud", "aws"])
        assert result.exit_code == 1

    def test_analyze_non_aws_warns(self):
        cfg = _cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["pipeline", "analyze", "my-pipe", "--cloud", "gcp"])
        assert result.exit_code == 1

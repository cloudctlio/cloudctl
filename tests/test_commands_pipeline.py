"""Tests for cloudctl.commands.pipeline helper functions."""
from __future__ import annotations

from unittest.mock import patch

from cloudctl.commands.pipeline import _aws_pipeline_rows, _gcp_pipeline_rows


_PIPE = {"name": "deploy-prod", "updated": "2024-01-01", "region": "us-east-1"}
_BUILD = {"account": "proj-1", "name": "build-1", "create_time": "2024-01-01", "region": "us-central1"}
_DEPLOY = {"account": "proj-1", "name": "deploy-1", "create_time": "2024-01-02", "region": "us-central1"}


class TestAwsPipelineRows:
    def test_returns_pipeline_row(self, fake_cfg, mock_aws):
        mock_aws.list_pipelines.return_value = [_PIPE]
        with patch("cloudctl.commands.pipeline.get_aws_provider", return_value=mock_aws):
            rows = _aws_pipeline_rows(fake_cfg, None, None)
        assert len(rows) == 1
        assert rows[0]["Type"] == "CodePipeline"
        assert rows[0]["Name"] == "deploy-prod"

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_pipelines.side_effect = Exception("creds")
        with patch("cloudctl.commands.pipeline.get_aws_provider", return_value=mock_aws):
            rows = _aws_pipeline_rows(fake_cfg, None, None)
        assert rows == []

    def test_empty_pipelines(self, fake_cfg, mock_aws):
        mock_aws.list_pipelines.return_value = []
        with patch("cloudctl.commands.pipeline.get_aws_provider", return_value=mock_aws):
            rows = _aws_pipeline_rows(fake_cfg, None, None)
        assert rows == []


class TestGcpPipelineRows:
    def test_returns_build_and_deploy_rows(self, mock_gcp):
        mock_gcp.list_cloud_build.return_value = [_BUILD]
        mock_gcp.list_cloud_deploy.return_value = [_DEPLOY]
        with patch("cloudctl.commands.pipeline.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_pipeline_rows(None, None)
        types = {r["Type"] for r in rows}
        assert "Cloud Build" in types
        assert "Cloud Deploy" in types

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_cloud_build.side_effect = Exception("quota")
        with patch("cloudctl.commands.pipeline.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_pipeline_rows(None, None)
        assert rows == []

    def test_missing_region_defaults_global(self, mock_gcp):
        build = {**_BUILD}
        del build["region"]
        mock_gcp.list_cloud_build.return_value = [build]
        mock_gcp.list_cloud_deploy.return_value = []
        with patch("cloudctl.commands.pipeline.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_pipeline_rows(None, None)
        assert rows[0]["Region"] == "global"

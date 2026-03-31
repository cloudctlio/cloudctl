"""Tests for cloudctl.commands.compute helper functions."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cloudctl.commands.compute import (
    _aws_compute_rows,
    _azure_compute_rows,
    _gcp_compute_rows,
)
from tests.conftest import make_instance


class TestAwsComputeRows:
    def test_returns_rows(self, fake_cfg, mock_aws):
        inst = make_instance()
        mock_aws.list_compute.return_value = [inst]
        with patch("cloudctl.commands.compute.get_aws_provider", return_value=mock_aws):
            rows = _aws_compute_rows(fake_cfg, None, None, None, None)
        assert len(rows) == 1
        assert rows[0]["ID"] == "i-1"
        assert rows[0]["State"] == "running"

    def test_public_ip_fallback(self, fake_cfg, mock_aws):
        inst = make_instance(public_ip=None)
        mock_aws.list_compute.return_value = [inst]
        with patch("cloudctl.commands.compute.get_aws_provider", return_value=mock_aws):
            rows = _aws_compute_rows(fake_cfg, None, None, None, None)
        assert rows[0]["Public IP"] == "—"

    def test_unknown_account_warns(self, fake_cfg, capsys):
        rows = _aws_compute_rows(fake_cfg, "nonexistent", None, None, None)
        assert rows == []

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_compute.side_effect = Exception("no creds")
        with patch("cloudctl.commands.compute.get_aws_provider", return_value=mock_aws):
            rows = _aws_compute_rows(fake_cfg, None, None, None, None)
        assert rows == []

    def test_empty_profiles(self, mock_aws):
        cfg = MagicMock()
        cfg.accounts = {"aws": []}
        rows = _aws_compute_rows(cfg, None, None, None, None)
        assert rows == []


class TestAzureComputeRows:
    def test_returns_rows(self, mock_azure):
        inst = make_instance(cloud="azure", account="sub-1")
        mock_azure.list_compute.return_value = [inst]
        with patch("cloudctl.commands.compute.get_azure_provider", return_value=mock_azure):
            rows = _azure_compute_rows("sub-1", None, None)
        assert len(rows) == 1
        assert rows[0]["Cloud"] is not None

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.list_compute.side_effect = Exception("auth error")
        with patch("cloudctl.commands.compute.get_azure_provider", return_value=mock_azure):
            rows = _azure_compute_rows(None, None, None)
        assert rows == []

    def test_no_public_ip(self, mock_azure):
        inst = make_instance(cloud="azure", public_ip=None)
        mock_azure.list_compute.return_value = [inst]
        with patch("cloudctl.commands.compute.get_azure_provider", return_value=mock_azure):
            rows = _azure_compute_rows(None, None, None)
        assert rows[0]["Public IP"] == "—"


class TestGcpComputeRows:
    def test_returns_rows(self, mock_gcp):
        inst = make_instance(cloud="gcp", account="my-project")
        mock_gcp.list_compute.return_value = [inst]
        with patch("cloudctl.commands.compute.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_compute_rows("my-project", None, None)
        assert len(rows) == 1

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_compute.side_effect = Exception("quota error")
        with patch("cloudctl.commands.compute.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_compute_rows(None, None, None)
        assert rows == []

    def test_state_passed_through(self, mock_gcp):
        inst = make_instance(cloud="gcp", state="TERMINATED")
        mock_gcp.list_compute.return_value = [inst]
        with patch("cloudctl.commands.compute.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_compute_rows(None, None, "TERMINATED")
        assert rows[0]["State"] == "TERMINATED"

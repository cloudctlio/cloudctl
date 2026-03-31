"""Tests for cloudctl.commands.cost helper functions."""
from __future__ import annotations

from unittest.mock import patch

from cloudctl.commands.cost import (
    _aws_cost_by_service_rows,
    _aws_cost_summary_rows,
    _azure_cost_by_service_rows,
    _azure_cost_summary_rows,
    _gcp_cost_by_service_rows,
    _gcp_cost_summary_rows,
)
from tests.conftest import make_cost_entry, make_service_entry


class TestAwsCostSummaryRows:
    def test_returns_rows(self, fake_cfg, mock_aws):
        mock_aws.cost_summary.return_value = [make_cost_entry()]
        with patch("cloudctl.commands.cost.get_aws_provider", return_value=mock_aws):
            rows = _aws_cost_summary_rows(fake_cfg, None, 30)
        assert len(rows) == 1
        assert rows[0]["Total Cost"] == "$10.00"
        assert rows[0]["Currency"] == "USD"

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.cost_summary.side_effect = Exception("no cost explorer")
        with patch("cloudctl.commands.cost.get_aws_provider", return_value=mock_aws):
            rows = _aws_cost_summary_rows(fake_cfg, None, 30)
        assert rows == []


class TestAzureCostSummaryRows:
    def test_returns_rows(self, mock_azure):
        mock_azure.cost_summary.return_value = [make_cost_entry()]
        with patch("cloudctl.commands.cost.get_azure_provider", return_value=mock_azure):
            rows = _azure_cost_summary_rows(None, 30)
        assert len(rows) == 1
        assert rows[0]["Period"] == "2024-01"

    def test_currency_defaults_usd(self, mock_azure):
        entry = make_cost_entry()
        del entry["currency"]
        mock_azure.cost_summary.return_value = [entry]
        with patch("cloudctl.commands.cost.get_azure_provider", return_value=mock_azure):
            rows = _azure_cost_summary_rows(None, 30)
        assert rows[0]["Currency"] == "USD"

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.cost_summary.side_effect = Exception("auth")
        with patch("cloudctl.commands.cost.get_azure_provider", return_value=mock_azure):
            rows = _azure_cost_summary_rows(None, 30)
        assert rows == []


class TestGcpCostSummaryRows:
    def test_returns_rows(self, mock_gcp):
        mock_gcp.cost_summary.return_value = [make_cost_entry()]
        with patch("cloudctl.commands.cost.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_cost_summary_rows(None, 30)
        assert len(rows) == 1

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.cost_summary.side_effect = Exception("billing not enabled")
        with patch("cloudctl.commands.cost.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_cost_summary_rows(None, 30)
        assert rows == []


class TestAwsCostByServiceRows:
    def test_returns_rows(self, fake_cfg, mock_aws):
        mock_aws.cost_by_service.return_value = [make_service_entry()]
        with patch("cloudctl.commands.cost.get_aws_provider", return_value=mock_aws):
            rows = _aws_cost_by_service_rows(fake_cfg, None, 30)
        assert len(rows) == 1
        assert rows[0]["Service"] == "EC2"

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.cost_by_service.side_effect = Exception("quota")
        with patch("cloudctl.commands.cost.get_aws_provider", return_value=mock_aws):
            rows = _aws_cost_by_service_rows(fake_cfg, None, 30)
        assert rows == []


class TestAzureCostByServiceRows:
    def test_returns_rows(self, mock_azure):
        mock_azure.cost_by_service.return_value = [make_service_entry()]
        with patch("cloudctl.commands.cost.get_azure_provider", return_value=mock_azure):
            rows = _azure_cost_by_service_rows(None, 30)
        assert len(rows) == 1

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.cost_by_service.side_effect = Exception("auth")
        with patch("cloudctl.commands.cost.get_azure_provider", return_value=mock_azure):
            rows = _azure_cost_by_service_rows(None, 30)
        assert rows == []


class TestGcpCostByServiceRows:
    def test_returns_rows(self, mock_gcp):
        mock_gcp.cost_by_service.return_value = [make_service_entry()]
        with patch("cloudctl.commands.cost.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_cost_by_service_rows(None, 30)
        assert len(rows) == 1

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.cost_by_service.side_effect = Exception("billing")
        with patch("cloudctl.commands.cost.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_cost_by_service_rows(None, 30)
        assert rows == []

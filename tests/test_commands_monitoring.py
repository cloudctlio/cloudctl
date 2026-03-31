"""Tests for cloudctl.commands.monitoring helper functions."""
from __future__ import annotations

from unittest.mock import patch

from cloudctl.commands.monitoring import (
    _aws_alert_rows,
    _aws_dashboard_rows,
    _azure_alert_rows,
    _gcp_alert_rows,
)


_ALARM = {"account": "prod", "name": "HighCPU", "state": "ALARM", "metric": "CPUUtilization", "region": "us-east-1"}
_ALERT = {"account": "sub-1", "name": "MetricAlert", "state": "Enabled", "description": "CPU > 80", "region": "eastus"}
_GCP_ALERT = {"account": "proj-1", "name": "GCPAlert", "state": "enabled", "conditions": "cpu > 0.8", "region": "global"}
_DASH = {"account": "prod", "name": "MyDash", "modified": "2024-01-01"}


class TestAwsAlertRows:
    def test_returns_alarm_rows(self, fake_cfg, mock_aws):
        mock_aws.list_cloudwatch_alarms.return_value = [_ALARM]
        with patch("cloudctl.commands.monitoring.get_aws_provider", return_value=mock_aws):
            rows = _aws_alert_rows(fake_cfg, None, None)
        assert len(rows) == 1
        assert rows[0]["Name"] == "HighCPU"
        assert rows[0]["State"] == "ALARM"

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_cloudwatch_alarms.side_effect = Exception("creds")
        with patch("cloudctl.commands.monitoring.get_aws_provider", return_value=mock_aws):
            rows = _aws_alert_rows(fake_cfg, None, None)
        assert rows == []

    def test_empty_alarms(self, fake_cfg, mock_aws):
        mock_aws.list_cloudwatch_alarms.return_value = []
        with patch("cloudctl.commands.monitoring.get_aws_provider", return_value=mock_aws):
            rows = _aws_alert_rows(fake_cfg, None, None)
        assert rows == []


class TestAzureAlertRows:
    def test_returns_alert_rows(self, mock_azure):
        mock_azure.list_monitor_alerts.return_value = [_ALERT]
        with patch("cloudctl.commands.monitoring.get_azure_provider", return_value=mock_azure):
            rows = _azure_alert_rows(None, None)
        assert len(rows) == 1
        assert rows[0]["Name"] == "MetricAlert"

    def test_missing_description_uses_dash(self, mock_azure):
        alert = {**_ALERT}
        del alert["description"]
        mock_azure.list_monitor_alerts.return_value = [alert]
        with patch("cloudctl.commands.monitoring.get_azure_provider", return_value=mock_azure):
            rows = _azure_alert_rows(None, None)
        assert rows[0]["Metric"] == "—"

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.list_monitor_alerts.side_effect = Exception("auth")
        with patch("cloudctl.commands.monitoring.get_azure_provider", return_value=mock_azure):
            rows = _azure_alert_rows(None, None)
        assert rows == []


class TestGcpAlertRows:
    def test_returns_alert_rows(self, mock_gcp):
        mock_gcp.list_monitoring_alerts.return_value = [_GCP_ALERT]
        with patch("cloudctl.commands.monitoring.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_alert_rows(None)
        assert len(rows) == 1
        assert rows[0]["Region"] == "global"

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_monitoring_alerts.side_effect = Exception("quota")
        with patch("cloudctl.commands.monitoring.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_alert_rows(None)
        assert rows == []


class TestAwsDashboardRows:
    def test_returns_dashboard_rows(self, fake_cfg, mock_aws):
        mock_aws.list_cloudwatch_dashboards.return_value = [_DASH]
        with patch("cloudctl.commands.monitoring.get_aws_provider", return_value=mock_aws):
            rows = _aws_dashboard_rows(fake_cfg, None, None)
        assert len(rows) == 1
        assert rows[0]["Name"] == "MyDash"

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_cloudwatch_dashboards.side_effect = Exception("creds")
        with patch("cloudctl.commands.monitoring.get_aws_provider", return_value=mock_aws):
            rows = _aws_dashboard_rows(fake_cfg, None, None)
        assert rows == []

"""Tests for cloudctl.commands.security helper functions."""
from __future__ import annotations

from unittest.mock import patch

from cloudctl.commands.security import (
    _aws_audit_rows,
    _aws_public_resource_rows,
    _azure_audit_rows,
    _azure_public_resource_rows,
    _format_finding_row,
    _gcp_audit_rows,
    _gcp_public_resource_rows,
)
from tests.conftest import make_finding


class TestFormatFindingRow:
    def test_high_severity(self):
        row = _format_finding_row("aws", make_finding(severity="HIGH"))
        assert "HIGH" in row["Severity"]
        assert row["Account"] == "prod"
        assert row["Resource"] == "s3://bucket"

    def test_medium_severity(self):
        row = _format_finding_row("aws", make_finding(severity="MEDIUM"))
        assert "MEDIUM" in row["Severity"]

    def test_low_severity(self):
        row = _format_finding_row("aws", make_finding(severity="LOW"))
        assert "LOW" in row["Severity"]

    def test_unknown_severity_no_crash(self):
        row = _format_finding_row("aws", make_finding(severity="CRITICAL"))
        assert "CRITICAL" in row["Severity"]


class TestAwsAuditRows:
    def test_returns_findings(self, fake_cfg, mock_aws):
        mock_aws.security_audit.return_value = [make_finding()]
        with patch("cloudctl.commands.security.get_aws_provider", return_value=mock_aws):
            rows = _aws_audit_rows(fake_cfg, None)
        assert len(rows) == 1
        assert "HIGH" in rows[0]["Severity"]

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.security_audit.side_effect = Exception("creds")
        with patch("cloudctl.commands.security.get_aws_provider", return_value=mock_aws):
            rows = _aws_audit_rows(fake_cfg, None)
        assert rows == []

    def test_empty_findings(self, fake_cfg, mock_aws):
        mock_aws.security_audit.return_value = []
        with patch("cloudctl.commands.security.get_aws_provider", return_value=mock_aws):
            rows = _aws_audit_rows(fake_cfg, None)
        assert rows == []


class TestAzureAuditRows:
    def test_returns_findings(self, mock_azure):
        mock_azure.security_audit.return_value = [make_finding(severity="MEDIUM")]
        with patch("cloudctl.commands.security.get_azure_provider", return_value=mock_azure):
            rows = _azure_audit_rows(None)
        assert len(rows) == 1

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.security_audit.side_effect = Exception("auth")
        with patch("cloudctl.commands.security.get_azure_provider", return_value=mock_azure):
            rows = _azure_audit_rows(None)
        assert rows == []


class TestGcpAuditRows:
    def test_returns_findings(self, mock_gcp):
        mock_gcp.security_audit.return_value = [make_finding()]
        with patch("cloudctl.commands.security.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_audit_rows(None)
        assert len(rows) == 1

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.security_audit.side_effect = Exception("quota")
        with patch("cloudctl.commands.security.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_audit_rows(None)
        assert rows == []


class TestPublicResourceRows:
    _resource = {"account": "prod", "type": "S3", "id": "bucket", "region": "us-east-1"}

    def test_aws_returns_rows(self, fake_cfg, mock_aws):
        mock_aws.list_public_resources.return_value = [self._resource]
        with patch("cloudctl.commands.security.get_aws_provider", return_value=mock_aws):
            rows = _aws_public_resource_rows(fake_cfg, None)
        assert len(rows) == 1
        assert rows[0]["Type"] == "S3"

    def test_aws_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_public_resources.side_effect = Exception("creds")
        with patch("cloudctl.commands.security.get_aws_provider", return_value=mock_aws):
            rows = _aws_public_resource_rows(fake_cfg, None)
        assert rows == []

    def test_azure_returns_rows(self, mock_azure):
        mock_azure.list_public_resources.return_value = [self._resource]
        with patch("cloudctl.commands.security.get_azure_provider", return_value=mock_azure):
            rows = _azure_public_resource_rows(None)
        assert len(rows) == 1

    def test_azure_exception_returns_empty(self, mock_azure):
        mock_azure.list_public_resources.side_effect = Exception("auth")
        with patch("cloudctl.commands.security.get_azure_provider", return_value=mock_azure):
            rows = _azure_public_resource_rows(None)
        assert rows == []

    def test_gcp_returns_rows(self, mock_gcp):
        mock_gcp.list_public_resources.return_value = [self._resource]
        with patch("cloudctl.commands.security.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_public_resource_rows(None)
        assert len(rows) == 1

    def test_gcp_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_public_resources.side_effect = Exception("quota")
        with patch("cloudctl.commands.security.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_public_resource_rows(None)
        assert rows == []

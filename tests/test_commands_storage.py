"""Tests for cloudctl.commands.storage helper functions."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cloudctl.commands.storage import (
    _aws_storage_rows,
    _azure_storage_rows,
    _format_bytes,
    _format_total_bytes,
    _gcp_storage_rows,
    _storage_row,
)
from tests.conftest import make_bucket


class TestFormatBytes:
    def test_bytes(self):
        assert _format_bytes(500) == "500 B"

    def test_kilobytes(self):
        assert "KB" in _format_bytes(2048)

    def test_megabytes(self):
        assert "MB" in _format_bytes(2 * 1024 * 1024)


class TestFormatTotalBytes:
    def test_bytes(self):
        assert "B" in _format_total_bytes(500)

    def test_megabytes(self):
        assert "MB" in _format_total_bytes(2 * 1024 * 1024)

    def test_gigabytes(self):
        assert "GB" in _format_total_bytes(2 * 1024 ** 3)


class TestStorageRow:
    def test_private_bucket(self):
        b = make_bucket(public=False)
        row = _storage_row(b)
        assert row["Public"] == "no"
        assert row["Name"] == "my-bucket"
        assert row["Created"] == "2024-01-01"

    def test_public_bucket(self):
        b = make_bucket(public=True)
        row = _storage_row(b)
        assert "YES" in row["Public"]

    def test_no_created_at(self):
        b = make_bucket(created_at=None)
        row = _storage_row(b)
        assert row["Created"] == "—"


class TestAwsStorageRows:
    def test_returns_rows(self, fake_cfg, mock_aws):
        mock_aws.list_storage.return_value = [make_bucket()]
        with patch("cloudctl.commands.storage.get_aws_provider", return_value=mock_aws):
            rows = _aws_storage_rows(fake_cfg, None, False)
        assert len(rows) == 1
        assert rows[0]["Name"] == "my-bucket"

    def test_unknown_account(self, fake_cfg):
        rows = _aws_storage_rows(fake_cfg, "staging", False)
        assert rows == []

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_storage.side_effect = Exception("creds")
        with patch("cloudctl.commands.storage.get_aws_provider", return_value=mock_aws):
            rows = _aws_storage_rows(fake_cfg, None, False)
        assert rows == []


class TestAzureStorageRows:
    def test_returns_rows(self, mock_azure):
        mock_azure.list_storage.return_value = [make_bucket(cloud="azure")]
        with patch("cloudctl.commands.storage.get_azure_provider", return_value=mock_azure):
            rows = _azure_storage_rows(None, None, False)
        assert len(rows) == 1

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.list_storage.side_effect = Exception("auth")
        with patch("cloudctl.commands.storage.get_azure_provider", return_value=mock_azure):
            rows = _azure_storage_rows(None, None, False)
        assert rows == []


class TestGcpStorageRows:
    def test_returns_rows(self, mock_gcp):
        mock_gcp.list_storage.return_value = [make_bucket(cloud="gcp")]
        with patch("cloudctl.commands.storage.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_storage_rows(None, None, False)
        assert len(rows) == 1

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_storage.side_effect = Exception("quota")
        with patch("cloudctl.commands.storage.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_storage_rows(None, None, False)
        assert rows == []

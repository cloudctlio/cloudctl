"""Tests for cloudctl.commands.network helper functions."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cloudctl.commands.network import (
    _aws_sg_rows,
    _aws_vpc_rows,
    _azure_sg_rows,
    _azure_vpc_rows,
    _gcp_sg_rows,
    _gcp_vpc_rows,
)
from tests.conftest import make_sg, make_vpc


class TestAwsVpcRows:
    def test_returns_vpc_row(self, fake_cfg, mock_aws):
        mock_aws.list_vpcs.return_value = [make_vpc()]
        with patch("cloudctl.commands.network.get_aws_provider", return_value=mock_aws):
            rows = _aws_vpc_rows(fake_cfg, None, None)
        assert len(rows) == 1
        assert rows[0]["VPC ID"] == "vpc-1"
        assert rows[0]["CIDR"] == "10.0.0.0/16"
        assert rows[0]["Default"] == "no"

    def test_default_vpc(self, fake_cfg, mock_aws):
        mock_aws.list_vpcs.return_value = [make_vpc(default=True)]
        with patch("cloudctl.commands.network.get_aws_provider", return_value=mock_aws):
            rows = _aws_vpc_rows(fake_cfg, None, None)
        assert rows[0]["Default"] == "yes"

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_vpcs.side_effect = Exception("creds")
        with patch("cloudctl.commands.network.get_aws_provider", return_value=mock_aws):
            rows = _aws_vpc_rows(fake_cfg, None, None)
        assert rows == []


class TestAzureVpcRows:
    def test_returns_vnet_row(self, mock_azure):
        mock_azure.list_vnets.return_value = [make_vpc(id="vnet-1")]
        with patch("cloudctl.commands.network.get_azure_provider", return_value=mock_azure):
            rows = _azure_vpc_rows(None)
        assert len(rows) == 1
        assert rows[0]["Default"] == "no"

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.list_vnets.side_effect = Exception("auth")
        with patch("cloudctl.commands.network.get_azure_provider", return_value=mock_azure):
            rows = _azure_vpc_rows(None)
        assert rows == []


class TestGcpVpcRows:
    def test_returns_vpc_row(self, mock_gcp):
        mock_gcp.list_vpcs.return_value = [make_vpc(id="gcp-vpc-1", default=True)]
        with patch("cloudctl.commands.network.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_vpc_rows(None)
        assert len(rows) == 1
        assert rows[0]["Default"] == "yes"

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_vpcs.side_effect = Exception("quota")
        with patch("cloudctl.commands.network.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_vpc_rows(None)
        assert rows == []


class TestAwsSgRows:
    def test_returns_sg_row(self, fake_cfg, mock_aws):
        mock_aws.list_security_groups.return_value = [make_sg()]
        with patch("cloudctl.commands.network.get_aws_provider", return_value=mock_aws):
            rows = _aws_sg_rows(fake_cfg, None, None, None)
        assert len(rows) == 1
        assert rows[0]["ID"] == "sg-1"
        assert rows[0]["VPC"] == "vpc-1"

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_security_groups.side_effect = Exception("creds")
        with patch("cloudctl.commands.network.get_aws_provider", return_value=mock_aws):
            rows = _aws_sg_rows(fake_cfg, None, None, None)
        assert rows == []


class TestAzureSgRows:
    def test_returns_nsg_row(self, mock_azure):
        mock_azure.list_nsgs.return_value = [make_sg(id="nsg-1")]
        with patch("cloudctl.commands.network.get_azure_provider", return_value=mock_azure):
            rows = _azure_sg_rows(None)
        assert len(rows) == 1

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.list_nsgs.side_effect = Exception("auth")
        with patch("cloudctl.commands.network.get_azure_provider", return_value=mock_azure):
            rows = _azure_sg_rows(None)
        assert rows == []


class TestGcpSgRows:
    def test_returns_fw_row(self, mock_gcp):
        mock_gcp.list_security_groups.return_value = [make_sg(id="fw-1")]
        with patch("cloudctl.commands.network.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_sg_rows(None, None)
        assert len(rows) == 1

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_security_groups.side_effect = Exception("quota")
        with patch("cloudctl.commands.network.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_sg_rows(None, None)
        assert rows == []

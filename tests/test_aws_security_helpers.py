"""Tests for AWSProvider security audit helpers — no AWS credentials needed."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cloudctl.providers.aws.provider import AWSProvider


@pytest.fixture()
def provider():
    with patch.object(AWSProvider, "__init__", lambda self, **kw: None):
        p = AWSProvider.__new__(AWSProvider)
        p._profile = "test"
        p._region = "us-east-1"
        return p


class TestRuleHasOpenCidr:
    def test_all_ports_and_open_cidr(self, provider):
        rule = {"FromPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        assert provider._rule_has_open_cidr(rule) is True

    def test_specific_port_not_flagged(self, provider):
        rule = {"FromPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        assert provider._rule_has_open_cidr(rule) is False

    def test_restricted_cidr_not_flagged(self, provider):
        rule = {"FromPort": -1, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}
        assert provider._rule_has_open_cidr(rule) is False

    def test_empty_ip_ranges(self, provider):
        rule = {"FromPort": -1, "IpRanges": []}
        assert provider._rule_has_open_cidr(rule) is False

    def test_no_from_port_key_defaults_negative_one(self, provider):
        rule = {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        assert provider._rule_has_open_cidr(rule) is True


class TestSgOpenFinding:
    def test_finding_structure(self, provider):
        sg = {"GroupId": "sg-abc123", "GroupName": "default"}
        finding = provider._sg_open_finding(sg, "prod")
        assert finding["severity"] == "HIGH"
        assert "sg-abc123" in finding["resource"]
        assert "default" in finding["resource"]
        assert finding["account"] == "prod"
        assert "0.0.0.0/0" in finding["issue"]

    def test_missing_group_name_handled(self, provider):
        sg = {"GroupId": "sg-xyz"}
        finding = provider._sg_open_finding(sg, "dev")
        assert "sg-xyz" in finding["resource"]


class TestAuditOpenSecurityGroups:
    def test_open_sg_detected(self, provider):
        sgs = [{
            "GroupId": "sg-1",
            "GroupName": "wide-open",
            "IpPermissions": [{"FromPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        }]
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": sgs}
        provider._ec2 = MagicMock(return_value=mock_ec2)

        findings = provider._audit_open_security_groups("prod")
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_restricted_sg_not_flagged(self, provider):
        sgs = [{
            "GroupId": "sg-2",
            "GroupName": "restricted",
            "IpPermissions": [{"FromPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        }]
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": sgs}
        provider._ec2 = MagicMock(return_value=mock_ec2)

        findings = provider._audit_open_security_groups("prod")
        assert findings == []

    def test_exception_returns_empty(self, provider):
        provider._ec2 = MagicMock(side_effect=Exception("No creds"))
        findings = provider._audit_open_security_groups("prod")
        assert findings == []

    def test_no_security_groups(self, provider):
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        provider._ec2 = MagicMock(return_value=mock_ec2)

        findings = provider._audit_open_security_groups("prod")
        assert findings == []

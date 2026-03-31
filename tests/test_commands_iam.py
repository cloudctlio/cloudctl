"""Tests for cloudctl.commands.iam helper functions."""
from __future__ import annotations

from unittest.mock import patch

from cloudctl.commands.iam import (
    _aws_iam_roles_rows,
    _aws_iam_users_rows,
    _azure_iam_roles_rows,
    _azure_iam_users_rows,
    _gcp_iam_roles_rows,
    _gcp_iam_users_rows,
)


_ROLE   = {"account": "prod", "name": "AdminRole", "id": "AROA123", "path": "/", "created": "2024-01-01"}
_USER   = {"account": "prod", "username": "alice", "id": "AIDA123", "created": "2024-01-01", "last_login": "2024-06-01"}
_RBAC   = {"account": "sub-1", "role": "Contributor", "id": "/sub/role-123", "scope": "/subscriptions/sub-1", "principal_type": "User"}
_MI     = {"account": "sub-1", "name": "my-identity", "id": "/mi/123", "type": "UserAssigned", "region": "eastus"}
_GROLE  = {"account": "proj-1", "name": "roles/viewer", "id": "roles/viewer", "stage": "GA", "description": "View access"}
_GSA    = {"account": "proj-1", "name": "svc@proj.iam.gsa.com", "email": "svc@proj.iam.gsa.com", "description": "SVC", "disabled": False}


class TestAwsIamRolesRows:
    def test_returns_role_row(self, fake_cfg, mock_aws):
        mock_aws.list_iam_roles.return_value = [_ROLE]
        with patch("cloudctl.commands.iam.get_aws_provider", return_value=mock_aws):
            rows = _aws_iam_roles_rows(fake_cfg, None)
        assert len(rows) == 1
        assert rows[0]["Name"] == "AdminRole"
        assert rows[0]["Path"] == "/"

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_iam_roles.side_effect = Exception("creds")
        with patch("cloudctl.commands.iam.get_aws_provider", return_value=mock_aws):
            rows = _aws_iam_roles_rows(fake_cfg, None)
        assert rows == []

    def test_account_filter(self, fake_cfg, mock_aws):
        rows = _aws_iam_roles_rows(fake_cfg, "nonexistent")
        assert rows == []


class TestAzureIamRolesRows:
    def test_returns_rbac_row_with_role_key(self, mock_azure):
        mock_azure.list_rbac_assignments.return_value = [_RBAC]
        with patch("cloudctl.commands.iam.get_azure_provider", return_value=mock_azure):
            rows = _azure_iam_roles_rows(None)
        assert rows[0]["Name"] == "Contributor"
        assert rows[0]["Path"] == "/subscriptions/sub-1"

    def test_falls_back_to_name_key(self, mock_azure):
        rbac = {"account": "sub-1", "name": "Reader", "id": "/role/456", "scope": "/"}
        mock_azure.list_rbac_assignments.return_value = [rbac]
        with patch("cloudctl.commands.iam.get_azure_provider", return_value=mock_azure):
            rows = _azure_iam_roles_rows(None)
        assert rows[0]["Name"] == "Reader"

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.list_rbac_assignments.side_effect = Exception("auth")
        with patch("cloudctl.commands.iam.get_azure_provider", return_value=mock_azure):
            rows = _azure_iam_roles_rows(None)
        assert rows == []


class TestGcpIamRolesRows:
    def test_returns_role_row(self, mock_gcp):
        mock_gcp.list_roles.return_value = [_GROLE]
        with patch("cloudctl.commands.iam.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_iam_roles_rows(None)
        assert rows[0]["Name"] == "roles/viewer"
        assert rows[0]["Path"] == "GA"

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_roles.side_effect = Exception("quota")
        with patch("cloudctl.commands.iam.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_iam_roles_rows(None)
        assert rows == []


class TestAwsIamUsersRows:
    def test_returns_user_row(self, fake_cfg, mock_aws):
        mock_aws.list_iam_users.return_value = [_USER]
        with patch("cloudctl.commands.iam.get_aws_provider", return_value=mock_aws):
            rows = _aws_iam_users_rows(fake_cfg, None)
        assert rows[0]["Username"] == "alice"
        assert rows[0]["Last Login"] == "2024-06-01"

    def test_exception_skipped(self, fake_cfg, mock_aws):
        mock_aws.list_iam_users.side_effect = Exception("creds")
        with patch("cloudctl.commands.iam.get_aws_provider", return_value=mock_aws):
            rows = _aws_iam_users_rows(fake_cfg, None)
        assert rows == []


class TestAzureIamUsersRows:
    def test_returns_managed_identity_row(self, mock_azure):
        mock_azure.list_managed_identities.return_value = [_MI]
        with patch("cloudctl.commands.iam.get_azure_provider", return_value=mock_azure):
            rows = _azure_iam_users_rows(None)
        assert rows[0]["Username"] == "my-identity"
        assert rows[0]["Last Login"] == "eastus"

    def test_exception_returns_empty(self, mock_azure):
        mock_azure.list_managed_identities.side_effect = Exception("auth")
        with patch("cloudctl.commands.iam.get_azure_provider", return_value=mock_azure):
            rows = _azure_iam_users_rows(None)
        assert rows == []


class TestGcpIamUsersRows:
    def test_returns_service_account_row(self, mock_gcp):
        mock_gcp.list_service_accounts.return_value = [_GSA]
        with patch("cloudctl.commands.iam.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_iam_users_rows(None)
        assert rows[0]["Username"] == "svc@proj.iam.gsa.com"
        assert rows[0]["ID"] == "svc@proj.iam.gsa.com"

    def test_exception_returns_empty(self, mock_gcp):
        mock_gcp.list_service_accounts.side_effect = Exception("quota")
        with patch("cloudctl.commands.iam.get_gcp_provider", return_value=mock_gcp):
            rows = _gcp_iam_users_rows(None)
        assert rows == []

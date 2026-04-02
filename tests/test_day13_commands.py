"""Tests for Day 13 commands: containers, analytics, backup, quotas, find, diff."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from cloudctl.main import app

runner = CliRunner()


def _aws_cfg(accounts=None):
    cfg = MagicMock()
    cfg.is_initialized = True
    cfg.clouds = ["aws"]
    cfg.accounts = {"aws": accounts or [{"name": "prod"}]}
    return cfg


def _empty_aws_cfg():
    cfg = _aws_cfg()
    return cfg


# ── containers ─────────────────────────────────────────────────────────────────

class TestContainersClusters:
    def _aws(self):
        aws = MagicMock()
        aws.list_ecs_clusters.return_value = [
            {"account": "prod", "name": "my-cluster", "status": "ACTIVE", "region": "us-east-1"}
        ]
        aws.list_eks_clusters.return_value = []
        aws.list_app_runner_services.return_value = []
        return aws

    def test_list_clusters_aws(self):
        cfg = _aws_cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.containers.get_aws_provider", return_value=self._aws()):
            result = runner.invoke(app, ["containers", "clusters", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_list_clusters_no_results(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_ecs_clusters.return_value = []
        aws.list_eks_clusters.return_value = []
        aws.list_app_runner_services.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.containers.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["containers", "clusters", "--cloud", "aws"])
        assert result.exit_code == 0
        assert "No clusters" in result.output

    def test_list_clusters_exception_skipped(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_ecs_clusters.side_effect = Exception("no access")
        aws.list_eks_clusters.return_value = []
        aws.list_app_runner_services.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.containers.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["containers", "clusters", "--cloud", "aws"])
        assert result.exit_code == 0


class TestContainersFunctions:
    def test_list_functions_aws(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_lambda_functions.return_value = [
            {"account": "prod", "name": "my-fn", "runtime": "python3.11",
             "memory_mb": 128, "region": "us-east-1"}
        ]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.containers.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["containers", "functions", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_list_functions_no_results(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_lambda_functions.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.containers.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["containers", "functions", "--cloud", "aws"])
        assert result.exit_code == 0
        assert "No functions" in result.output


class TestContainersRegistries:
    def test_list_registries_aws(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_ecr_repositories.return_value = [
            {"account": "prod", "name": "my-repo", "uri": "123.dkr.ecr.us-east-1.amazonaws.com/my-repo",
             "region": "us-east-1"}
        ]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.containers.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["containers", "registries", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_list_registries_no_results(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_ecr_repositories.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.containers.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["containers", "registries", "--cloud", "aws"])
        assert result.exit_code == 0
        assert "No registries" in result.output


# ── analytics ─────────────────────────────────────────────────────────────────

class TestAnalyticsWarehouses:
    def test_list_warehouses_aws(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_redshift_clusters.return_value = [
            {"account": "prod", "name": "dw-prod", "status": "available",
             "nodes": 2, "region": "us-east-1"}
        ]
        aws.list_opensearch_domains.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.analytics.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["analytics", "warehouses", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_list_warehouses_no_results(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_redshift_clusters.return_value = []
        aws.list_opensearch_domains.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.analytics.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["analytics", "warehouses", "--cloud", "aws"])
        assert result.exit_code == 0
        assert "No data warehouses" in result.output


class TestAnalyticsJobs:
    def test_list_jobs_aws(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_athena_workgroups.return_value = [
            {"account": "prod", "name": "primary", "state": "ENABLED", "region": "us-east-1"}
        ]
        aws.list_glue_jobs.return_value = []
        aws.list_emr_clusters.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.analytics.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["analytics", "jobs", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_list_jobs_no_results(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_athena_workgroups.return_value = []
        aws.list_glue_jobs.return_value = []
        aws.list_emr_clusters.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.analytics.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["analytics", "jobs", "--cloud", "aws"])
        assert result.exit_code == 0
        assert "No analytics jobs" in result.output


class TestAnalyticsAI:
    def test_list_ai_aws(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_sagemaker_endpoints.return_value = [
            {"account": "prod", "name": "ep-1", "status": "InService", "region": "us-east-1"}
        ]
        aws.list_bedrock_models.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.analytics.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["analytics", "ai", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_list_ai_no_results(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_sagemaker_endpoints.return_value = []
        aws.list_bedrock_models.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.analytics.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["analytics", "ai", "--cloud", "aws"])
        assert result.exit_code == 0
        assert "No AI/ML" in result.output


# ── backup ─────────────────────────────────────────────────────────────────────

class TestBackupVaults:
    def test_list_vaults_aws(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_backup_vaults.return_value = [
            {"account": "prod", "name": "Default", "recovery_points": 10,
             "locked": False, "region": "us-east-1"}
        ]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.backup.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["backup", "vaults", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_list_vaults_no_results(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_backup_vaults.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.backup.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["backup", "vaults", "--cloud", "aws"])
        assert result.exit_code == 0
        assert "No backup vaults" in result.output

    def test_list_vaults_exception_skipped(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_backup_vaults.side_effect = Exception("AccessDenied")
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.backup.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["backup", "vaults", "--cloud", "aws"])
        assert result.exit_code == 0


class TestBackupJobs:
    def test_list_jobs_aws(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_backup_jobs.return_value = [
            {"account": "prod", "resource_type": "EBS", "state": "COMPLETED",
             "created": "2024-01-01", "region": "us-east-1"}
        ]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.backup.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["backup", "jobs", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_list_jobs_with_state_filter(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_backup_jobs.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.backup.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["backup", "jobs", "--cloud", "aws", "--state", "RUNNING"])
        assert result.exit_code == 0
        aws.list_backup_jobs.assert_called_with(account="prod", region=None, state="RUNNING")


# ── quotas ─────────────────────────────────────────────────────────────────────

class TestQuotasList:
    def test_list_quotas_aws(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_service_quotas.return_value = [
            {"account": "prod", "name": "Running On-Demand Instances", "value": 32,
             "used": 10, "region": "us-east-1"}
        ]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.quotas.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["quotas", "list", "--cloud", "aws", "--service", "ec2"])
        assert result.exit_code == 0

    def test_list_quotas_no_results(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_service_quotas.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.quotas.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["quotas", "list", "--cloud", "aws", "--service", "ec2"])
        assert result.exit_code == 0
        assert "No quota data" in result.output

    def test_list_quotas_exception_skipped(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_service_quotas.side_effect = Exception("ServiceQuotasNotEnabled")
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.quotas.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["quotas", "list", "--cloud", "aws", "--service", "ec2"])
        assert result.exit_code == 0

    def test_list_quotas_used_pct_calculated(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_service_quotas.return_value = [
            {"account": "prod", "name": "Instances", "value": 100, "used": 50, "region": "us-east-1"}
        ]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.quotas.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["quotas", "list", "--cloud", "aws", "--service", "ec2"])
        assert result.exit_code == 0
        assert "50%" in result.output


# ── find ──────────────────────────────────────────────────────────────────────

class TestFindResources:
    def _aws(self):
        from types import SimpleNamespace
        aws = MagicMock()
        aws.list_compute.return_value = [
            SimpleNamespace(
                id="i-1", name="web-server", type="t3.micro", state="running",
                region="us-east-1", account="prod"
            )
        ]
        aws.list_storage.return_value = []
        aws.list_databases.return_value = []
        return aws

    def test_find_by_query(self):
        cfg = _aws_cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.find.get_aws_provider", return_value=self._aws()):
            result = runner.invoke(app, ["find", "find", "web", "--cloud", "aws"])
        assert result.exit_code == 0
        assert "web" in result.output.lower()

    def test_find_no_query_no_tag_exits(self):
        result = runner.invoke(app, ["find", "find", "--cloud", "aws"])
        assert result.exit_code == 1

    def test_find_no_results(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_compute.return_value = []
        aws.list_storage.return_value = []
        aws.list_databases.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.find.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["find", "find", "nonexistent-xyz", "--cloud", "aws"])
        assert result.exit_code == 0
        assert "No resources" in result.output

    def test_find_exception_skipped(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_compute.side_effect = Exception("no access")
        aws.list_storage.return_value = []
        aws.list_databases.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.find.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["find", "find", "web", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_find_by_tag(self):
        cfg = _aws_cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.find.get_aws_provider", return_value=self._aws()):
            result = runner.invoke(app, ["find", "find", "--cloud", "aws", "--tag", "Env=prod"])
        assert result.exit_code == 0


# ── diff ──────────────────────────────────────────────────────────────────────

class TestDiffAccounts:
    def _aws(self, names):
        from types import SimpleNamespace
        aws = MagicMock()
        aws.list_compute.return_value = [
            SimpleNamespace(id=n, name=n, type="t3", state="running", region="us-east-1", account="prod")
            for n in names
        ]
        aws.list_storage.return_value = []
        aws.list_databases.return_value = []
        return aws

    def test_diff_accounts(self):
        cfg = _aws_cfg()
        left_aws  = self._aws(["web-1", "web-2"])
        right_aws = self._aws(["web-1", "db-1"])

        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.diff.get_aws_provider", side_effect=[left_aws, right_aws]):
            result = runner.invoke(app, ["diff", "accounts", "prod", "staging"])
        assert result.exit_code == 0

    def test_diff_accounts_aws_not_configured(self):
        cfg = MagicMock()
        cfg.is_initialized = True
        cfg.clouds = ["gcp"]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["diff", "accounts", "prod", "staging"])
        assert result.exit_code == 1

    def test_diff_accounts_invalid_type(self):
        cfg = _aws_cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["diff", "accounts", "prod", "staging", "--type", "badtype"])
        assert result.exit_code == 1

    def test_diff_accounts_no_resources(self):
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_compute.return_value = []
        aws.list_storage.return_value = []
        aws.list_databases.return_value = []

        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.diff.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["diff", "accounts", "prod", "staging"])
        assert result.exit_code == 0
        assert "No resources" in result.output


class TestDiffRegions:
    def test_diff_regions(self):
        from types import SimpleNamespace
        cfg = _aws_cfg()
        aws = MagicMock()
        aws.list_compute.return_value = [
            SimpleNamespace(id="i-1", name="web-1", type="t3", state="running",
                            region="us-east-1", account="prod")
        ]
        aws.list_storage.return_value = []
        aws.list_databases.return_value = []

        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.diff.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["diff", "regions", "us-east-1", "eu-west-1"])
        assert result.exit_code == 0

    def test_diff_regions_no_profile(self):
        cfg = MagicMock()
        cfg.is_initialized = True
        cfg.clouds = ["aws"]
        cfg.accounts = {"aws": []}
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["diff", "regions", "us-east-1", "eu-west-1"])
        assert result.exit_code == 1

    def test_diff_regions_aws_not_configured(self):
        cfg = MagicMock()
        cfg.is_initialized = True
        cfg.clouds = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["diff", "regions", "us-east-1", "eu-west-1"])
        assert result.exit_code == 1

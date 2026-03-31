"""CLI-level tests using Typer CliRunner to cover command routing bodies."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from cloudctl.main import app
from tests.conftest import (
    make_bucket,
    make_cost_entry,
    make_db,
    make_finding,
    make_instance,
    make_pipeline,
    make_sg,
    make_vpc,
)

runner = CliRunner()


def _cfg(clouds=("aws",), profiles=({"name": "prod"},)):
    cfg = MagicMock()
    cfg.is_initialized = True
    cfg.clouds = list(clouds)
    cfg.accounts = {"aws": list(profiles)} if "aws" in clouds else {}
    return cfg


# ── compute ───────────────────────────────────────────────────────────────────

class TestComputeListCli:
    def test_aws_list_shows_table(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_compute.return_value = [make_instance()]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.compute.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["compute", "list", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_no_instances_exits_cleanly(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_compute.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.compute.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["compute", "list", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_invalid_tag_format_exits_1(self):
        cfg = _cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["compute", "list", "--tag", "badformat"])
        assert result.exit_code == 1

    def test_describe_aws(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.describe_compute.return_value = make_instance(tags={"Env": "prod"})
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.compute.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["compute", "describe", "i-1", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_describe_invalid_cloud(self):
        cfg = _cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["compute", "describe", "i-1", "--cloud", "unknown"])
        assert result.exit_code == 1

    def test_stop_yes_flag(self):
        cfg = _cfg()
        aws = MagicMock()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.compute.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["compute", "stop", "i-1", "--cloud", "aws", "--yes"])
        assert result.exit_code == 0

    def test_start_yes_flag(self):
        cfg = _cfg()
        aws = MagicMock()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.compute.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["compute", "start", "i-1", "--cloud", "aws", "--yes"])
        assert result.exit_code == 0

    def test_stop_invalid_cloud(self):
        cfg = _cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["compute", "stop", "i-1", "--cloud", "x", "--yes"])
        assert result.exit_code == 1

    def test_start_invalid_cloud(self):
        cfg = _cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["compute", "start", "i-1", "--cloud", "x", "--yes"])
        assert result.exit_code == 1


# ── storage ───────────────────────────────────────────────────────────────────

class TestStorageListCli:
    def test_list_shows_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_storage.return_value = [make_bucket()]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.storage.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["storage", "list", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_no_buckets_exits_cleanly(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_storage.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.storage.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["storage", "list", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_describe_aws(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.describe_storage.return_value = make_bucket()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.storage.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["storage", "describe", "my-bucket", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_describe_invalid_cloud(self):
        cfg = _cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["storage", "describe", "bucket", "--cloud", "unknown"])
        assert result.exit_code == 1


# ── database ──────────────────────────────────────────────────────────────────

class TestDatabaseListCli:
    def test_list_aws(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_databases.return_value = [make_db()]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.database.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["database", "list", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_no_databases(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_databases.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.database.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["database", "list", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_describe_aws(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.describe_database.return_value = make_db(tags={"Env": "prod"})
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.database.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["database", "describe", "db-1", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_describe_invalid_cloud(self):
        cfg = _cfg()
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg):
            result = runner.invoke(app, ["database", "describe", "db-1", "--cloud", "unknown"])
        assert result.exit_code == 1

    def test_snapshots_aws(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_snapshots.return_value = [
            {"id": "snap-1", "db": "mydb", "engine": "postgres",
             "status": "available", "size_gb": 20, "created_at": "2024-01-01"}
        ]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.database.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["database", "snapshots"])
        assert result.exit_code == 0


# ── security ──────────────────────────────────────────────────────────────────

class TestSecurityCli:
    def test_audit_no_findings(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.security_audit.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.security.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["security", "audit", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_audit_with_findings(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.security_audit.return_value = [make_finding()]
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.security.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["security", "audit", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_public_resources_no_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_public_resources.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.security.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["security", "public-resources", "--cloud", "aws"])
        assert result.exit_code == 0


# ── cost ──────────────────────────────────────────────────────────────────────

class TestCostCli:
    def test_summary_no_data(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.cost_summary.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.cost.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["cost", "summary", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_by_service_no_data(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.cost_by_service.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.cost.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["cost", "by-service", "--cloud", "aws"])
        assert result.exit_code == 0


# ── monitoring ────────────────────────────────────────────────────────────────

class TestMonitoringCli:
    def test_alerts_no_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_cloudwatch_alarms.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.monitoring.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["monitoring", "alerts", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_dashboards_no_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_cloudwatch_dashboards.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.monitoring.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["monitoring", "dashboards", "--cloud", "aws"])
        assert result.exit_code == 0


# ── network ───────────────────────────────────────────────────────────────────

class TestNetworkCli:
    def test_vpcs_no_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_vpcs.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.network.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["network", "vpcs", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_security_groups_no_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_security_groups.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.network.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["network", "security-groups", "--cloud", "aws"])
        assert result.exit_code == 0


# ── iam ───────────────────────────────────────────────────────────────────────

class TestIamCli:
    def test_roles_no_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_iam_roles.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.iam.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["iam", "roles", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_users_no_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_iam_users.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.iam.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["iam", "users", "--cloud", "aws"])
        assert result.exit_code == 0


# ── messaging ─────────────────────────────────────────────────────────────────

class TestMessagingCli:
    def test_queues_no_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_sqs_queues.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.messaging.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["messaging", "queues", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_topics_no_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_sns_topics.return_value = []
        aws.list_eventbridge_buses.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.messaging.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["messaging", "topics", "--cloud", "aws"])
        assert result.exit_code == 0

    def test_streams_no_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_kinesis_streams.return_value = []
        aws.list_msk_clusters.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.messaging.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["messaging", "streams", "--cloud", "aws"])
        assert result.exit_code == 0


# ── pipeline ──────────────────────────────────────────────────────────────────

class TestPipelineCli:
    def test_list_no_results(self):
        cfg = _cfg()
        aws = MagicMock()
        aws.list_pipelines.return_value = []
        with patch("cloudctl.commands._helpers.ConfigManager", return_value=cfg), \
             patch("cloudctl.commands.pipeline.get_aws_provider", return_value=aws):
            result = runner.invoke(app, ["pipeline", "list", "--cloud", "aws"])
        assert result.exit_code == 0

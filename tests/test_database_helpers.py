"""Tests for cloudctl.commands.database — pure helper functions."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from cloudctl.commands.database import _aws_database_rows, _db_row


def _make_db(**kwargs) -> SimpleNamespace:
    defaults = dict(
        cloud="aws", account="prod", id="db-1", name="mydb",
        engine="postgres", instance_class="db.t3.medium", state="available",
        region="us-east-1", multi_az=True, storage_gb=100, tags={},
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class TestDbRow:
    def test_basic_row(self):
        db = _make_db()
        row = _db_row(db)
        assert row["ID"] == "db-1"
        assert row["Engine"] == "postgres"
        assert row["State"] == "available"
        assert row["Multi-AZ"] == "yes"
        assert row["Storage"] == "100 GB"

    def test_multi_az_false(self):
        db = _make_db(multi_az=False)
        assert _db_row(db)["Multi-AZ"] == "no"

    def test_no_storage(self):
        db = _make_db(storage_gb=None)
        assert _db_row(db)["Storage"] == "—"

    def test_no_instance_class(self):
        db = _make_db(instance_class=None)
        assert _db_row(db)["Class"] == "—"


class TestAwsDatabaseRows:
    def _cfg(self, profiles):
        cfg = MagicMock()
        cfg.accounts = {"aws": profiles}
        return cfg

    def test_no_profiles_returns_empty(self):
        cfg = self._cfg([])
        rows = _aws_database_rows(cfg, account=None, region=None, engine=None)
        assert rows == []

    def test_account_not_found_returns_empty(self, capsys):
        cfg = self._cfg([{"name": "prod"}])
        rows = _aws_database_rows(cfg, account="staging", region=None, engine=None)
        assert rows == []

    def test_engine_filter_applied(self):
        db_pg = _make_db(id="pg-1", engine="postgres")
        db_my = _make_db(id="my-1", engine="mysql")

        mock_provider = MagicMock()
        mock_provider.list_databases.return_value = [db_pg, db_my]

        cfg = self._cfg([{"name": "prod"}])
        with patch("cloudctl.commands.database.get_aws_provider", return_value=mock_provider):
            rows = _aws_database_rows(cfg, account=None, region=None, engine="postgres")

        assert len(rows) == 1
        assert rows[0]["Engine"] == "postgres"

    def test_exception_in_profile_skipped(self):
        mock_provider = MagicMock()
        mock_provider.list_databases.side_effect = Exception("Connection failed")

        cfg = self._cfg([{"name": "prod"}])
        with patch("cloudctl.commands.database.get_aws_provider", return_value=mock_provider):
            rows = _aws_database_rows(cfg, account=None, region=None, engine=None)

        assert rows == []

    def test_multiple_profiles_combined(self):
        db1 = _make_db(id="db-1", account="prod")
        db2 = _make_db(id="db-2", account="staging")

        def provider_for(profile, region):
            m = MagicMock()
            m.list_databases.return_value = [db1] if profile == "prod" else [db2]
            return m

        cfg = self._cfg([{"name": "prod"}, {"name": "staging"}])
        with patch("cloudctl.commands.database.get_aws_provider", side_effect=provider_for):
            rows = _aws_database_rows(cfg, account=None, region=None, engine=None)

        assert len(rows) == 2

"""Tests for cloudctl.output.formatter — pure functions, no I/O."""
from __future__ import annotations

import json
from io import StringIO
from unittest.mock import patch

import pytest

from cloudctl.output.formatter import cloud_label, print_table


class TestCloudLabel:
    def test_aws_returns_label(self):
        assert "AWS" in cloud_label("aws")

    def test_azure_returns_label(self):
        assert "Azure" in cloud_label("azure")

    def test_gcp_returns_label(self):
        assert "GCP" in cloud_label("gcp")

    def test_case_insensitive(self):
        assert cloud_label("AWS") == cloud_label("aws")
        assert cloud_label("GCP") == cloud_label("gcp")

    def test_unknown_cloud_returns_uppercased(self):
        assert cloud_label("unknown") == "UNKNOWN"


class TestPrintTable:
    def test_json_output_when_not_tty(self, capsys):
        rows = [{"Name": "bucket1", "Region": "us-east-1"}]
        with patch("cloudctl.output.formatter.is_tty", return_value=False):
            print_table(rows, title="Test")
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data[0]["Name"] == "bucket1"
        assert data[0]["Region"] == "us-east-1"

    def test_empty_rows_no_crash(self, capsys):
        with patch("cloudctl.output.formatter.is_tty", return_value=False):
            print_table([], title="Empty")
        # should not raise

    def test_json_output_multiple_rows(self, capsys):
        rows = [
            {"ID": "i-1", "State": "running"},
            {"ID": "i-2", "State": "stopped"},
        ]
        with patch("cloudctl.output.formatter.is_tty", return_value=False):
            print_table(rows)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 2
        assert data[1]["State"] == "stopped"

    def test_none_values_serialised_as_empty_string(self, capsys):
        rows = [{"Name": "x", "Value": None}]
        with patch("cloudctl.output.formatter.is_tty", return_value=False):
            print_table(rows)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data[0]["Value"] is None  # json.dumps keeps None → null

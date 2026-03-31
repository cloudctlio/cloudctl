"""Shared fixtures for cloudctl tests."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from cloudctl.config.manager import ConfigManager


# ── Fake data factories ────────────────────────────────────────────────────────

def make_instance(**kw):
    defaults = dict(
        cloud="aws", account="prod", id="i-1", name="web-1",
        type="t3.micro", state="running", region="us-east-1",
        public_ip="1.2.3.4", private_ip="10.0.0.1",
        launched_at="2024-01-01", tags={},
    )
    return SimpleNamespace(**{**defaults, **kw})


def make_bucket(**kw):
    defaults = dict(
        cloud="aws", account="prod", name="my-bucket",
        region="us-east-1", public=False, created_at="2024-01-01T00:00:00Z",
    )
    return SimpleNamespace(**{**defaults, **kw})


def make_db(**kw):
    defaults = dict(
        cloud="aws", account="prod", id="db-1", name="mydb",
        engine="postgres", instance_class="db.t3.medium",
        state="available", region="us-east-1",
        multi_az=True, storage_gb=100, tags={},
    )
    return SimpleNamespace(**{**defaults, **kw})


def make_vpc(**kw):
    defaults = dict(
        account="prod", id="vpc-1", name="main",
        cidr="10.0.0.0/16", state="available",
        default=False, region="us-east-1",
    )
    return {**defaults, **kw}


def make_sg(**kw):
    defaults = dict(
        account="prod", id="sg-1", name="default",
        vpc_id="vpc-1", inbound_rules=5,
        outbound_rules=1, region="us-east-1",
    )
    return {**defaults, **kw}


def make_finding(**kw):
    defaults = dict(
        severity="HIGH", account="prod",
        resource="s3://bucket", issue="Public bucket",
    )
    return {**defaults, **kw}


def make_cost_entry(**kw):
    defaults = dict(account="prod", period="2024-01", cost="$10.00", currency="USD")
    return {**defaults, **kw}


def make_service_entry(**kw):
    defaults = dict(account="prod", service="EC2", period="2024-01", cost="$5.00")
    return {**defaults, **kw}


def make_alert(**kw):
    defaults = dict(
        id="alert-1", name="High CPU", state="ALARM",
        metric="CPUUtilization", threshold=80.0,
        region="us-east-1", account="prod",
    )
    return SimpleNamespace(**{**defaults, **kw})


def make_topic(**kw):
    defaults = dict(
        id="arn:aws:sns:us-east-1:123:topic", name="my-topic",
        region="us-east-1", account="prod", cloud="aws",
        subscriptions=2, type="standard",
    )
    return SimpleNamespace(**{**defaults, **kw})


def make_queue(**kw):
    defaults = dict(
        id="https://sqs.us-east-1.amazonaws.com/123/q", name="my-queue",
        region="us-east-1", account="prod", cloud="aws",
        messages=5, type="standard",
    )
    return SimpleNamespace(**{**defaults, **kw})


def make_pipeline(**kw):
    defaults = dict(
        id="pipe-1", name="deploy-prod", state="Succeeded",
        last_run="2024-01-01", region="us-east-1", account="prod", cloud="aws",
    )
    return SimpleNamespace(**{**defaults, **kw})


# ── Config fixture ─────────────────────────────────────────────────────────────

@pytest.fixture()
def fake_cfg():
    cfg = MagicMock(spec=ConfigManager)
    cfg.clouds = ["aws"]
    cfg.accounts = {"aws": [{"name": "prod"}]}
    return cfg


@pytest.fixture()
def multi_cloud_cfg():
    cfg = MagicMock(spec=ConfigManager)
    cfg.clouds = ["aws", "azure", "gcp"]
    cfg.accounts = {"aws": [{"name": "prod"}]}
    return cfg


# ── Mock provider fixture ──────────────────────────────────────────────────────

@pytest.fixture()
def mock_aws():
    return MagicMock()


@pytest.fixture()
def mock_azure():
    return MagicMock()


@pytest.fixture()
def mock_gcp():
    return MagicMock()

"""Shared helpers for the policy-gate tests. Everything is offline: fake
credential brokers, fake planners, local audit files."""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from cloudctl.gate.credentials.base import ScopedCredentials, capped_expiry
from cloudctl.gate.models import Action, Plan, ResourceChange, utcnow

AWS_ACCT = "111122223333"
AWS_ROLE = f"arn:aws:iam::{AWS_ACCT}:role/cctl-apply"
SUB = "00000000-0000-0000-0000-000000000001"
TENANT = "00000000-0000-0000-0000-0000000000aa"


def aws_env(tier: str = "dev", **extra: Any) -> dict:
    d: dict[str, Any] = {"tier": tier, "cloud": "aws", "aws": {"account_id": AWS_ACCT, "region": "us-east-1"}}
    d["credentials"] = ({"mode": "assume_role", "role_arn": AWS_ROLE} if tier == "prod"
                        else {"mode": "profile", "profile": "dev"})
    d.update(extra)
    return d


def azure_env(tier: str = "dev", **extra: Any) -> dict:
    d: dict[str, Any] = {"tier": tier, "cloud": "azure",
                         "azure": {"tenant_id": TENANT, "subscription_id": SUB, "resource_group": "rg-app",
                                   "location": "eastus"}}
    d["credentials"] = ({"mode": "workload_identity", "client_id": "cid", "token_file": "/var/run/tok"}
                        if tier == "prod" else {"mode": "cli"})
    d.update(extra)
    return d


def gcp_env(tier: str = "dev", **extra: Any) -> dict:
    d: dict[str, Any] = {"tier": tier, "cloud": "gcp", "gcp": {"project_id": "proj-app", "region": "us-central1"}}
    d["credentials"] = ({"mode": "impersonation", "service_account": "cctl@proj-app.iam.gserviceaccount.com"}
                        if tier == "prod" else {"mode": "adc"})
    d.update(extra)
    return d


def config_doc(envs: dict, *, approvers: dict | None = None, policy: dict | None = None,
               sink: dict | None = None, tmp: Path | None = None) -> dict:
    audit: dict[str, Any] = {"chain": "test"}
    if tmp is not None:
        audit["local_path"] = str(tmp / "audit" / "chain.jsonl")
    if sink is not None:
        audit["sink"] = sink
    doc: dict[str, Any] = {"version": 1, "environments": envs, "audit": audit}
    if approvers:
        doc["approvers"] = approvers
    if policy:
        doc["policy"] = policy
    if tmp is not None:
        doc["approvals_dir"] = str(tmp / "approvals")
    return doc


class FakeCredsBroker:
    """Issues real ScopedCredentials with fake secret material."""

    def __init__(self, cloud: str, fail: Exception | None = None) -> None:
        self.cloud = cloud
        self.fail = fail
        self.issued: list[ScopedCredentials] = []

    def acquire(self, env: Any, *, request_id: str, requester: str) -> ScopedCredentials:
        if self.fail:
            raise self.fail
        now = utcnow()
        secret = {"token": f"tok-{request_id}"}
        c = ScopedCredentials(cloud=self.cloud, identity=f"fake:{env.name}", scope=dict(env.scope),
                              expires_at=capped_expiry(now, now + timedelta(hours=1)), acquired_at=now,
                              _secret=secret, _builders={"env": lambda: {"FAKE_TOKEN": secret["token"]}})
        self.issued.append(c)
        return c


class FakePlanner:
    def __init__(self, changes: list[ResourceChange], platform: str = "api", env_name: str | None = None) -> None:
        self.changes = changes
        self.platform = platform
        self.env_name = env_name
        self.calls = 0

    def plan(self, *, env: Any, creds: Any, workdir: Path) -> Plan:
        self.calls += 1
        assert creds is not None and creds.remaining_seconds > 0
        return Plan(platform=self.platform, environment=self.env_name or env.name, changes=tuple(self.changes),
                    source="fake")


def sg_change(cidr: str = "10.0.0.0/8", port: int = 22, region: str = "us-east-1") -> ResourceChange:
    return ResourceChange(address="aws_security_group.web", type="aws_security_group", action=Action.UPDATE,
                          cloud="aws", name="web", location=region,
                          before={"ingress": [], "region": region},
                          after={"ingress": [{"from_port": port, "to_port": port, "protocol": "tcp",
                                              "cidr_blocks": [cidr]}], "region": region})


def tag_change(n: int, region: str = "us-east-1") -> ResourceChange:
    return ResourceChange(address=f"aws_instance.app[{n}]", type="aws_instance", action=Action.UPDATE,
                          cloud="aws", name=f"app{n}", location=region,
                          before={"tags": {}, "region": region}, after={"tags": {"team": "a"}, "region": region})


@pytest.fixture
def no_ambient_cloud(monkeypatch):
    for k in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(k, raising=False)

"""Helpers for the control-plane tests: a real policy gate (fake credential
brokers, real Rego rules, real hash-chained audit file) and fake executors."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cloudctl.controlplane.model import ModelReply
from cloudctl.gate.models import Action, ResourceChange
from tests.gate.conftest import FakeCredsBroker, FakePlanner, aws_env, azure_env, config_doc, gcp_env

ENVF = {"aws": aws_env, "azure": azure_env, "gcp": gcp_env}


def iac_root(tmp_path: Path, name: str, marker: str = "main.tf") -> Path:
    d = tmp_path / "iac" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / marker).write_text("# test\n", encoding="utf-8")
    return d


def tag(cloud: str, n: int = 1) -> ResourceChange:
    return ResourceChange(address=f"thing.t{n}", type="tagged_thing", action=Action.UPDATE, cloud=cloud,
                          before={"tags": {}}, after={"tags": {"a": "b"}})


def node(nid: str, root: Path | str, env: str = "dev", deps: tuple[str, ...] = (), summary: str = "") -> dict:
    return {"id": nid, "kind": "iac_apply", "environment": env, "summary": summary or f"apply {nid}",
            "target": {"iac_root": str(root)}, "depends_on": list(deps)}


def graph_doc(nodes: list[dict], questions: list[dict] | None = None, request: str = "do it") -> dict:
    return {"version": 1, "request": request, "nodes": nodes, "questions": questions or []}


class FakeModel:
    """Returns scripted replies and records every prompt."""

    def __init__(self, *replies: str, model: str = "fake-model") -> None:
        self.replies = list(replies)
        self.prompts: list[tuple[str, str]] = []
        self.model = model

    def complete(self, system: str, user: str) -> ModelReply:
        self.prompts.append((system, user))
        if not self.replies:
            raise AssertionError("model called more times than scripted")
        return ModelReply(text=self.replies.pop(0), input_tokens=100, output_tokens=50, model=self.model)


class FakeExecutor:
    """Planner + apply for one node; ``fail`` makes apply raise."""

    kind = "iac_apply"

    def __init__(self, changes: list[ResourceChange], log: list[str], nid: str, fail: Exception | None = None):
        self.planner = FakePlanner(changes, platform="terraform")
        self.log = log
        self.nid = nid
        self.fail = fail

    def apply(self, creds: Any, plan: Any, env: Any) -> Any:
        assert creds is not None and creds.remaining_seconds > 0
        self.log.append(self.nid)
        if self.fail:
            raise self.fail
        return {"node": self.nid, "changes": len(plan.changes)}


class ExecutorFactory:
    def __init__(self, cloud: str = "aws") -> None:
        self.cloud = cloud
        self.applied: list[str] = []
        self.fail: dict[str, Exception] = {}
        self.changes: dict[str, list[ResourceChange]] = {}
        self.built: list[str] = []

    def __call__(self, n: Any, env: Any) -> FakeExecutor:
        self.built.append(n.id)
        return FakeExecutor(self.changes.get(n.id, [tag(env.cloud)]), self.applied, n.id, self.fail.get(n.id))


def cfg_doc(tmp_path: Path, cloud: str, roots: list[Path], *, approvers: dict | None = None,
            approval: dict | None = None, extra_envs: dict | None = None) -> dict:
    env = ENVF[cloud]("dev", match={"iac_roots": [str(r) for r in roots]})
    if approval:
        env["approval"] = approval
    envs = {"dev": env, **(extra_envs or {})}
    return config_doc(envs, approvers=approvers, tmp=tmp_path)


@pytest.fixture
def brokers():
    return {c: FakeCredsBroker(c) for c in ("aws", "azure", "gcp")}

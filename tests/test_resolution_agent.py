"""Resolution agent: model-agnostic client, results reconciled against what the
tools actually did, file access confined to --iac-root. Offline: scripted model,
fake terraform/gh on PATH, a local bare git remote."""
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cloudctl.ai import resolution_agent as ra

_GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@t"}


def _sh(cmd, cwd):
    subprocess.run(cmd, cwd=cwd, shell=True, check=True, capture_output=True,
                   env={**os.environ, **_GIT_ENV})


@pytest.fixture
def repo(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in {"terraform": "echo ok", "gh": "echo https://example.invalid/pr/1"}.items():
        f = bin_dir / name
        f.write_text(f"#!/bin/sh\n{body}\n")
        f.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("CLOUDCTL_TERRAFORM_BIN", str(bin_dir / "terraform"))
    for k, v in _GIT_ENV.items():
        monkeypatch.setenv(k, v)
    origin = tmp_path / "origin.git"
    _sh(f"git init -q --bare -b main {origin}", tmp_path)
    r = tmp_path / "iac"
    r.mkdir()
    (r / "variables.tf").write_text('variable "wcu" {\n  default = 1\n}\n')
    _sh(f"git init -q -b main && git add . && git commit -qm init && git remote add origin {origin} "
        "&& git push -q -u origin main", r)
    return r


def _client(steps):
    it = iter(steps)
    c = MagicMock()
    c.converse.side_effect = lambda **kw: next(it)
    return c


def _tu(i, name, inp):
    return {"stopReason": "tool_use", "output": {"message": {"role": "assistant", "content": [
        {"toolUse": {"toolUseId": f"t{i}", "name": name, "input": inp}}]}}}


def _end(d):
    return {"stopReason": "end_turn", "output": {"message": {"role": "assistant",
            "content": [{"text": json.dumps(d)}]}}}


def _full_script(r, claim="success"):
    return [
        _tu(1, "git_create_branch", {"branch_name": "fix/wcu", "base_branch": "main"}),
        _tu(2, "read_iac_file", {"path": str(r / "variables.tf")}),
        _tu(3, "write_iac_change", {"path": str(r / "variables.tf"), "old_content": "default = 1",
                                    "new_content": "default = 10"}),
        _tu(4, "validate_change", {"directory": str(r), "tool": "terraform"}),
        _tu(5, "git_commit_push", {"message": "Raise WCU", "paths": [str(r / "variables.tf")]}),
        _tu(6, "create_pull_request", {"title": "Raise WCU", "body": "b", "base_branch": "main"}),
        _end({"status": claim, "pr_url": "https://model-made-this-up/pr/9", "pr_summary": "Raise WCU"}),
    ]


def _run(r, steps, **kw):
    client = _client(steps)
    with patch("cloudctl.ai.model_providers.make_model_client", return_value=client):
        out = ra.run(diagnosis={"root_cause": "x", "deployment_source": "terraform"},
                     iac_root=str(r), base_branch="main", profile=None, region="us-east-1", **kw)
    return out, client


def test_success_uses_pr_url_from_gh_not_the_model(repo):
    out, _ = _run(repo, _full_script(repo))
    assert out["status"] == "success"
    assert out["pr_url"] == "https://example.invalid/pr/1"
    assert out["branch"] == "fix/wcu"


def test_model_id_comes_from_cloudctl_model(repo, monkeypatch):
    monkeypatch.setenv("CLOUDCTL_MODEL", "gpt-test-model")
    _, client = _run(repo, _full_script(repo))
    assert {c.kwargs["modelId"] for c in client.converse.call_args_list} == {"gpt-test-model"}


def test_commit_failure_is_reported_even_when_model_claims_success(repo, monkeypatch):
    # Break the remote so the push fails; the model still claims success.
    _sh("git remote set-url origin /nonexistent/remote.git", repo)
    out, _ = _run(repo, _full_script(repo))
    assert out["status"] == "error"
    assert "git_commit_push" in out["detail"]
    assert out["pr_url"] == ""
    assert out["files_changed"]


def test_declined_plan_gate_never_reports_success(repo):
    out, _ = _run(repo, _full_script(repo), approve=lambda stage, detail: False)
    assert out["status"] == "error"
    assert "nothing was committed" in out["detail"]
    assert (repo / "variables.tf").read_text().count("default = 1") == 1


def test_files_outside_iac_root_are_refused(repo, tmp_path):
    outside = tmp_path / "secret.json"
    outside.write_text("{}")
    steps = [_tu(1, "read_iac_file", {"path": str(outside)}),
             _tu(2, "write_iac_change", {"path": "../secret.json", "old_content": "{}", "new_content": "[]"}),
             _end({"status": "manual_required", "manual_steps": ["do it by hand"]})]
    out, client = _run(repo, steps)
    results = [m for m in client.converse.call_args_list[-1].kwargs["messages"] if m["role"] == "user"][1:]
    texts = [blk["toolResult"]["content"][0]["text"] for m in results for blk in m["content"]]
    assert all("outside the IaC root" in t for t in texts)
    assert outside.read_text() == "{}"
    assert out["status"] == "manual_required"


def test_push_gate_validates_cdk_repos_with_cdk(repo, monkeypatch):
    (repo / "cdk.json").write_text("{}")
    seen = []
    with patch("cloudctl.mcp.tools.resolve.validate_change",
               side_effect=lambda d, tool="terraform": (seen.append(tool), json.dumps({"success": True}))[1]):
        _run(repo, _full_script(repo), approve=lambda s, d: True)
    assert "cdk" in seen and "terraform" not in seen[-1:]


def test_reconcile_is_pure():
    out = ra._reconcile({"status": "success", "pr_url": "fake"},
                        {"pushed": True, "pr_url": "", "errors": ["create_pull_request: gh missing"]})
    assert out["status"] == "error" and "PR was not created" in out["detail"]

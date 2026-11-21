"""`cloudctl change ...` commands, offline (fake model, fake brokers, fake executors)."""
import json

import pytest
from typer.testing import CliRunner

pytest.importorskip("regopy")

from cloudctl.commands import change_cmd  # noqa: E402
from cloudctl.controlplane.orchestrator import Orchestrator, QueuedRollback  # noqa: E402
from cloudctl.controlplane.state import LocalRunStore  # noqa: E402
from cloudctl.gate.audit import AuditLog, LocalFileSink  # noqa: E402
from cloudctl.gate.config import parse_config  # noqa: E402
from cloudctl.gate.gate import PolicyGate  # noqa: E402
from cloudctl.gate.policy.rego import RegoEngine  # noqa: E402
from tests.controlplane.conftest import ExecutorFactory, FakeModel, cfg_doc, graph_doc, iac_root, node  # noqa: E402
from tests.gate.conftest import FakeCredsBroker  # noqa: E402

runner = CliRunner()


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CLOUDCTL_RUNS_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("CLOUDCTL_ROLLBACKS_DIR", str(tmp_path / "rb"))
    change_cmd.console.width = 200
    roots = {n: iac_root(tmp_path, n) for n in ("net", "app")}
    cfg = parse_config(cfg_doc(tmp_path, "gcp", list(roots.values())))
    audit = AuditLog(LocalFileSink(tmp_path / "audit.jsonl"), chain="test", actor="alice")
    rego = RegoEngine.from_config(builtin=True, rule_paths=[], rego_paths=[], params={})
    gate = PolicyGate(cfg, audit=audit, brokers={"gcp": FakeCredsBroker("gcp")}, policy=([], [rego]))
    factory = ExecutorFactory("gcp")
    monkeypatch.setattr(change_cmd, "_gate", lambda path: gate)
    monkeypatch.setattr(change_cmd, "_orchestrator", lambda g: Orchestrator(
        g, LocalRunStore(), rollback=QueuedRollback(), executor_factory=factory, requester="alice"))
    return {"roots": roots, "factory": factory, "tmp": tmp_path, "gate": gate}


def _graph_file(env, nodes):
    p = env["tmp"] / "graph.json"
    p.write_text(json.dumps(graph_doc(nodes)))
    return p


def _invoke(*args, input=None):
    return runner.invoke(change_cmd.app, [str(a) for a in args], input=input, catch_exceptions=False)


def test_compile_writes_a_graph_and_applies_nothing(env, monkeypatch):
    from cloudctl.controlplane import model as M
    doc = graph_doc([node("net", env["roots"]["net"]), node("app", env["roots"]["app"], deps=("net",))])
    monkeypatch.setattr(M.ConverseAdapter, "from_environment", classmethod(lambda cls, **k: FakeModel(json.dumps(doc))))
    out = env["tmp"] / "g.json"
    r = _invoke("compile", "ship the app", "-o", out)
    assert r.exit_code == 0, r.output
    assert "net [iac_apply in dev]" in r.output and "app [iac_apply in dev] after net" in r.output
    assert json.loads(out.read_text())["request"] == "ship the app"
    assert env["factory"].applied == []


def test_compile_questions_exit_3(env, monkeypatch):
    from cloudctl.controlplane import model as M
    q = graph_doc([], questions=[{"id": "env", "question": "Which project?", "options": ["dev"]}])
    monkeypatch.setattr(M.ConverseAdapter, "from_environment", classmethod(lambda cls, **k: FakeModel(json.dumps(q))))
    r = _invoke("compile", "make it faster")
    assert r.exit_code == 3 and "Which project? (dev)" in r.output


def test_run_status_list_and_failure_exit_codes(env):
    g = _graph_file(env, [node("net", env["roots"]["net"]), node("app", env["roots"]["app"], deps=("net",))])
    assert _invoke("run", g, input="n\n").exit_code == 1 and env["factory"].applied == []
    r = _invoke("run", g, "--yes", "--json")
    assert r.exit_code == 0, r.output
    run = json.loads(r.output[r.output.index("{"):])
    assert run["status"] == "succeeded" and env["factory"].applied == ["net", "app"]
    assert "succeeded" in _invoke("status", run["run_id"]).output
    assert run["run_id"] in _invoke("list").output

    env["factory"].fail["net"] = RuntimeError("quota exceeded")
    r = _invoke("run", g, "--yes")
    assert r.exit_code == 2 and "quota exceeded" in r.output and "rollback request" in r.output
    assert "quota exceeded" in _invoke("rollbacks").output


def test_run_rejects_bad_graph_files(env):
    p = env["tmp"] / "bad.json"
    p.write_text("{not json")
    assert _invoke("run", p, "--yes").exit_code == 1
    g = _graph_file(env, [node("x", env["tmp"] / "elsewhere")])
    r = _invoke("run", g, "--yes")
    assert r.exit_code == 1 and "not an IaC root" in r.output


def test_resume_parses_approvals(env):
    assert _invoke("resume", "0" * 32, "--approval", "nonode").exit_code == 1
    r = _invoke("resume", "0" * 32, "--approval", "a=b")
    assert r.exit_code == 1 and "no run" in r.output

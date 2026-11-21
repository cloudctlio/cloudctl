"""Orchestrator: dependency order through the real gate, approvals, failure
handling (no retry, downstream skipped, targeted rollback request), resume."""
import json
import os
import stat

import pytest

pytest.importorskip("regopy")

from cloudctl.controlplane import state as S  # noqa: E402
from cloudctl.controlplane.graph import GraphError, parse_graph  # noqa: E402
from cloudctl.controlplane.orchestrator import Orchestrator, OrchestratorError, QueuedRollback  # noqa: E402
from cloudctl.gate.audit import AuditLog, LocalFileSink  # noqa: E402
from cloudctl.gate.config import parse_config  # noqa: E402
from cloudctl.gate.gate import PolicyGate  # noqa: E402
from cloudctl.gate.models import Action, CredentialError, ResourceChange  # noqa: E402
from cloudctl.gate.policy.rego import RegoEngine  # noqa: E402
from tests.controlplane.conftest import ExecutorFactory, cfg_doc, graph_doc, iac_root, node, tag  # noqa: E402


def _gate(tmp_path, cfg, brokers):
    audit = AuditLog(LocalFileSink(tmp_path / "audit" / "chain.jsonl"), chain="test", actor="alice")
    rego = RegoEngine.from_config(builtin=True, rule_paths=[], rego_paths=[], params={})
    return PolicyGate(cfg, audit=audit, brokers=brokers, policy=([], [rego]))


def _setup(tmp_path, brokers, cloud="aws", names=("net", "db", "app", "solo"), **kw):
    roots = {n: iac_root(tmp_path, n) for n in names}
    cfg = parse_config(cfg_doc(tmp_path, cloud, list(roots.values()), **kw))
    gate = _gate(tmp_path, cfg, brokers)
    factory = ExecutorFactory(cloud)
    orch = Orchestrator(gate, S.LocalRunStore(tmp_path / "runs"), rollback=QueuedRollback(tmp_path / "rb"),
                        executor_factory=factory, requester="alice")
    return orch, factory, roots, gate


def _diamond(roots):
    return parse_graph(graph_doc([node("net", roots["net"]), node("db", roots["db"], deps=("net",)),
                                  node("app", roots["app"], deps=("db",)), node("solo", roots["solo"])]))


def _events(gate):
    return [r["event"] for r in gate.audit.sink.read_all()]


@pytest.mark.parametrize("cloud", ["aws", "azure", "gcp"])
def test_runs_every_node_in_dependency_order_with_its_own_credentials(tmp_path, brokers, cloud):
    orch, factory, roots, gate = _setup(tmp_path, brokers, cloud)
    run = orch.start(_diamond(roots))
    assert run.status == S.SUCCEEDED
    assert factory.applied == ["net", "db", "app", "solo"]
    assert len(brokers[cloud].issued) == 4                        # one scoped credential per node
    for c in brokers[cloud].issued:                               # each destroyed after its apply
        with pytest.raises(CredentialError):
            c.ensure_valid()
    assert run.nodes["db"].result == {"node": "db", "changes": 1}
    ev = _events(gate)
    assert ev[0] == "orchestrator.run.start" and ev[-1] == "orchestrator.run.status"
    assert ev.count("execution.end") == 4 and gate.audit.verify().ok


def test_failed_node_skips_downstream_queues_targeted_rollback_and_never_retries(tmp_path, brokers):
    orch, factory, roots, gate = _setup(tmp_path, brokers)
    factory.fail["db"] = RuntimeError("apply blew up")
    run = orch.start(_diamond(roots))
    n = run.nodes
    assert (n["net"].status, n["db"].status, n["app"].status, n["solo"].status) == \
        (S.SUCCEEDED, S.FAILED, S.SKIPPED, S.SUCCEEDED)
    assert "apply blew up" in n["db"].error and "db did not succeed" in n["app"].reasons[0]
    assert factory.applied == ["net", "db", "solo"]
    [rb] = QueuedRollback(tmp_path / "rb").pending()
    assert rb["node_id"] == "db" and rb["target"] == {"iac_root": str(roots["db"])}
    assert rb["applied_before"] == ["net"] and n["db"].rollback_id == rb["id"]
    if os.name != "nt":                                   # Windows has no POSIX modes
        assert stat.S_IMODE(os.stat(tmp_path / "rb" / f"{rb['id']}.json").st_mode) == 0o600
    assert "orchestrator.rollback.requested" in _events(gate)

    again = orch.resume(run.run_id)                               # resume does not re-run a failed node
    assert again.nodes["db"].status == S.FAILED and factory.applied == ["net", "db", "solo"]
    assert run.status == S.FAILED


def test_rejected_node_changes_nothing_and_skips_downstream_without_rollback(tmp_path, brokers):
    orch, factory, roots, _ = _setup(tmp_path, brokers)
    open_ssh = ResourceChange(address="aws_security_group.web", type="aws_security_group", action=Action.UPDATE,
                              cloud="aws", location="us-east-1", before={"ingress": [], "region": "us-east-1"},
                              after={"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp",
                                                  "cidr_blocks": ["0.0.0.0/0"]}], "region": "us-east-1"})
    factory.changes["net"] = [open_ssh]
    run = orch.start(_diamond(roots))
    assert run.nodes["net"].status == S.REJECTED and run.nodes["net"].stage == "approval"
    assert run.nodes["db"].status == S.SKIPPED and run.nodes["app"].status == S.SKIPPED
    assert run.nodes["solo"].status == S.SUCCEEDED and factory.applied == ["solo"]
    assert QueuedRollback(tmp_path / "rb").pending() == []


def test_unknown_iac_tool_rejects_the_node_at_config(tmp_path, brokers):
    orch, factory, roots, _ = _setup(tmp_path, brokers)
    from cloudctl.controlplane.executors import ExecutionError

    def boom(n, env):
        if n.id == "solo":
            raise ExecutionError("cannot tell which IaC tool")
        return ExecutorFactory()(n, env)
    orch.executor_factory = boom
    run = orch.start(_diamond(roots))
    assert run.nodes["solo"].status == S.REJECTED and run.nodes["solo"].stage == "config"
    assert run.nodes["app"].status == S.SUCCEEDED


def test_approval_blocks_downstream_then_resume_with_signed_approval(tmp_path, brokers):
    pytest.importorskip("cedarpy")
    pytest.importorskip("cryptography")
    from cloudctl.gate.approval.signing import generate_keypair, load_private_key, sign, write_private_key
    pem, pub = generate_keypair()
    write_private_key(tmp_path / "bob.pem", pem)
    orch, factory, roots, gate = _setup(tmp_path, brokers, approvers={"bob": {"public_key": pub}},
                                        approval={"approvers": ["bob"], "threshold": 1})
    factory.changes["db"] = [tag("aws", 1), tag("aws", 2)]       # over the threshold: needs approval
    run = orch.start(_diamond(roots))
    n = run.nodes
    assert n["db"].status == S.AWAITING_APPROVAL and n["app"].status == S.BLOCKED
    assert n["net"].status == n["solo"].status == S.SUCCEEDED and run.status == S.AWAITING_APPROVAL
    rid = n["db"].approval_id

    with pytest.raises(OrchestratorError, match="not awaiting approval"):
        orch.resume(run.run_id, {"net": rid})
    gate.approvals.put_approval(sign(gate.approvals.get_request(rid), "bob", load_private_key(tmp_path / "bob.pem")))
    done = orch.resume(run.run_id, {"db": rid})
    assert done.status == S.SUCCEEDED and factory.applied == ["net", "solo", "db", "app"]
    assert done.nodes["db"].evaluations == 2


def test_resume_without_approval_keeps_waiting(tmp_path, brokers):
    pytest.importorskip("cedarpy")
    orch, factory, roots, _ = _setup(tmp_path, brokers, approvers={"bob": {"public_key": "x" * 44}},
                                     approval={"approvers": ["bob"], "threshold": 0})
    run = orch.start(parse_graph(graph_doc([node("net", roots["net"])])))
    assert run.status == S.AWAITING_APPROVAL
    assert orch.resume(run.run_id).status == S.AWAITING_APPROVAL and factory.applied == []


def test_only_the_requester_can_resume(tmp_path, brokers):
    orch, _, roots, _ = _setup(tmp_path, brokers)
    run = orch.start(_diamond(roots))
    orch.requester = "mallory"
    with pytest.raises(OrchestratorError, match="belongs to 'alice'"):
        orch.resume(run.run_id)


def test_crash_mid_apply_is_recorded_as_failure_on_resume(tmp_path, brokers):
    orch, factory, roots, _ = _setup(tmp_path, brokers)
    graph = parse_graph(graph_doc([node("net", roots["net"]), node("db", roots["db"], deps=("net",))]))
    run = S.RunState.new(graph.to_dict(), graph.digest(), "alice", graph.order())
    run.nodes["net"].status = S.RUNNING
    orch.store.save(run)
    after = orch.resume(run.run_id)
    assert after.nodes["net"].status == S.FAILED and "outcome is unknown" in after.nodes["net"].error
    assert after.nodes["db"].status == S.SKIPPED and factory.applied == []
    assert QueuedRollback(tmp_path / "rb").pending()[0]["node_id"] == "net"


def test_tampered_stored_graph_is_refused(tmp_path, brokers):
    orch, _, roots, _ = _setup(tmp_path, brokers)
    run = orch.start(parse_graph(graph_doc([node("net", roots["net"])])))
    p = tmp_path / "runs" / f"{run.run_id}.json"
    d = json.loads(p.read_text())
    d["graph"]["nodes"][0]["summary"] = "something else"
    p.write_text(json.dumps(d))
    with pytest.raises(OrchestratorError, match="does not match its digest"):
        orch.resume(run.run_id)


def test_start_validates_targets_and_questions(tmp_path, brokers):
    orch, _, roots, _ = _setup(tmp_path, brokers)
    with pytest.raises(GraphError, match="not an IaC root"):
        orch.start(parse_graph(graph_doc([node("x", tmp_path / "elsewhere")])))
    with pytest.raises(OrchestratorError, match="open questions"):
        orch.start(parse_graph(graph_doc([], questions=[{"id": "q", "question": "which?"}])))


def test_run_lock_stops_a_second_driver(tmp_path, brokers):
    orch, _, roots, _ = _setup(tmp_path, brokers)
    run = orch.start(parse_graph(graph_doc([node("net", roots["net"])])))
    with orch.store.lock(run.run_id):
        with pytest.raises(S.StateError, match="locked"):
            orch.resume(run.run_id)
    orch.resume(run.run_id)


def test_audit_failure_stops_the_run(tmp_path, brokers):
    from cloudctl.gate.models import AuditError
    orch, factory, roots, gate = _setup(tmp_path, brokers)

    def broken(*a, **k):
        raise AuditError("disk full")
    gate.audit.append = broken
    with pytest.raises(AuditError):
        orch.start(_diamond(roots))
    assert factory.applied == []


def test_store_is_private_atomic_and_rejects_bad_ids(tmp_path):
    store = S.LocalRunStore(tmp_path / "runs")
    g = parse_graph(graph_doc([node("a", "/r")]))
    run = S.RunState.new(g.to_dict(), g.digest(), "alice", g.order())
    store.save(run)
    p = tmp_path / "runs" / f"{run.run_id}.json"
    if os.name != "nt":                                   # Windows has no POSIX modes
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(tmp_path / "runs").st_mode) == 0o700
    assert store.load(run.run_id).nodes["a"].status == S.PENDING
    assert [r.run_id for r in store.list()] == [run.run_id]
    assert not list((tmp_path / "runs").glob(".run-*"))
    with pytest.raises(S.StateError):
        store.load("../../etc/passwd")
    d = json.loads(p.read_text())
    d["nodes"]["a"]["status"] = "teleported"
    p.write_text(json.dumps(d))
    with pytest.raises(S.StateError, match="unknown status"):
        store.load(run.run_id)


def test_run_status_rollup():
    g = parse_graph(graph_doc([node("a", "/r"), node("b", "/s")]))
    r = S.RunState.new(g.to_dict(), g.digest(), "alice", g.order())
    assert r.status == S.RUNNING
    r.nodes["a"].status, r.nodes["b"].status = S.SUCCEEDED, S.SKIPPED
    assert r.status == "partial"
    r.nodes["b"].status = S.REJECTED
    assert r.status == S.FAILED
    r.nodes["b"].status = S.SUCCEEDED
    assert r.status == S.SUCCEEDED

"""The shared-state contract on every backend (memory, and DynamoDB, Cosmos DB
and Firestore against in-memory fakes of their SDKs), and the stores built on it."""
import threading

import pytest

from cloudctl.controlplane import kv as K
from cloudctl.controlplane import state as S
from cloudctl.controlplane.shared import KvApprovalStore, KvDriftStore, KvRollbackQueue, KvRunStore
from cloudctl.gate.models import ApprovalError
from tests.service.fakes import FakeCosmosContainer, FakeDynamo, FakeFirestore


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture(autouse=True)
def _cosmos_match(monkeypatch):
    monkeypatch.setattr(K, "_if_not_modified", lambda: "IfNotModified")


def make(kind, clock):
    if kind == "memory":
        return K.MemoryKV(clock=clock)
    if kind == "dynamodb":
        return K.DynamoDBKV("t", client=FakeDynamo(), clock=clock)
    if kind == "cosmos":
        return K.CosmosKV(FakeCosmosContainer(), clock=clock)
    return K.FirestoreKV(FakeFirestore(), clock=clock)


BACKENDS = ["memory", "dynamodb", "cosmos", "firestore"]


@pytest.mark.parametrize("kind", BACKENDS)
def test_conditional_writes(kind):
    kv = make(kind, Clock())
    kv.check_ready()
    assert kv.get("runs", "a1") is None
    v1 = kv.put("runs", "a1", {"n": 1, "f": 0.5}, expect=K.ABSENT)
    with pytest.raises(K.Conflict):
        kv.put("runs", "a1", {"n": 9}, expect=K.ABSENT)
    it = kv.get("runs", "a1")
    assert it.doc == {"n": 1, "f": 0.5} and it.version == v1
    v2 = kv.put("runs", "a1", {"n": 2}, expect=v1)
    with pytest.raises(K.Conflict):
        kv.put("runs", "a1", {"n": 3}, expect=v1)                 # stale version loses
    assert kv.get("runs", "a1").doc == {"n": 2} and v2 != v1
    kv.put("runs", "a1", {"n": 4})                                 # unconditional
    for i in range(5):
        kv.put("runs", f"b{i}", {"i": i})
    kv.put("drift", "x1", {"other": True})
    assert sorted(i.key for i in kv.scan("runs")) == ["a1", "b0", "b1", "b2", "b3", "b4"]
    kv.delete("runs", "b0")
    assert kv.get("runs", "b0") is None
    with pytest.raises(K.KVError):
        kv.get("Runs!", "a1")
    with pytest.raises(K.KVError):
        kv.get("runs", "../x")
    with pytest.raises(K.KVError):
        kv.put("runs", "big", {"x": "y" * (K.MAX_DOC_BYTES + 1)})


@pytest.mark.parametrize("kind", BACKENDS)
def test_leases_expire_and_belong_to_one_owner(kind):
    clock = Clock()
    kv = make(kind, clock)
    assert kv.acquire("run-1", "w1", 60)
    assert not kv.acquire("run-1", "w2", 60)
    assert kv.acquire("run-1", "w1", 60)                          # renew
    clock.t += 61
    assert kv.acquire("run-1", "w2", 60)                          # w1 lapsed
    kv.release("run-1", "w1")                                      # not w1's any more: no effect
    assert not kv.acquire("run-1", "w1", 60)
    kv.release("run-1", "w2")
    assert kv.acquire("run-1", "w1", 60)


def test_readiness_checks_refuse_misconfigured_stores():
    with pytest.raises(K.KVError, match="TTL"):
        K.DynamoDBKV("t", client=FakeDynamo(ttl_enabled=False)).check_ready()
    with pytest.raises(K.KVError, match="/ns"):
        K.CosmosKV(FakeCosmosContainer(pk="/id")).check_ready()
    with pytest.raises(K.KVError, match="TTL"):
        K.CosmosKV(FakeCosmosContainer(default_ttl=None)).check_ready()
    with pytest.raises(K.KVError, match="unknown state backend"):
        K.kv_from_settings({"backend": "redis"})


def test_lease_context_renews_and_reports_loss():
    kv = K.MemoryKV()
    with pytest.raises(ValueError):
        K.Lease(kv, "x", "a", ttl_seconds=5)
    with K.Lease(kv, "x", "a", ttl_seconds=30) as lease:
        assert not kv.acquire("x", "b", 30)
        with pytest.raises(K.Conflict):
            K.Lease(kv, "x", "b", 30).__enter__()
        assert not lease.lost.is_set()
    assert kv.acquire("x", "b", 30)                                # released on exit


@pytest.mark.parametrize("kind", BACKENDS)
def test_run_store_on_shared_state(kind):
    kv = make(kind, Clock())
    st = KvRunStore(kv)
    g = {"version": 1, "request": "r", "questions": [], "nodes": []}
    run = S.RunState.new(g, "d" * 64, "alice", ["a"])
    st.save(run)
    assert st.load(run.run_id).to_dict()["requester"] == "alice"
    assert [r.run_id for r in st.list()] == [run.run_id]
    with pytest.raises(S.StateError):
        st.load("0" * 32)
    with pytest.raises(S.StateError):
        st.load("nope")
    with st.lock(run.run_id):
        with pytest.raises(S.StateError, match="another worker"):
            with st.lock(run.run_id):
                pass


@pytest.mark.parametrize("kind", BACKENDS)
def test_approvals_are_write_once_on_shared_state(kind):
    from cloudctl.gate.approval.signing import (ApprovalRequest, generate_keypair, load_private_key, sign,
                                                write_private_key)
    kv = make(kind, Clock())
    st = KvApprovalStore(kv)
    req = ApprovalRequest.new(request_id="req-00000001", environment="prod", tier="prod", plan_digest="p" * 64,
                              summary="s", requester="alice", counts={"add": 1}, max_severity="NONE",
                              ttl_seconds=3600, reasons=())
    st.put_request(req)
    with pytest.raises(ApprovalError):
        st.put_request(req)
    assert [r.request_id for r in st.pending()] == ["req-00000001"]
    pem, _ = generate_keypair()
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "k.pem"
        write_private_key(p, pem)
        signed = sign(req, "bob", load_private_key(p))
    st.put_approval(signed)
    assert st.get_approval("req-00000001").approver == "bob"
    assert list(st.pending()) == []
    st.consume("req-00000001", "p" * 64)
    assert st.is_consumed("req-00000001")
    with pytest.raises(ApprovalError, match="already used"):
        st.consume("req-00000001", "p" * 64)


def test_consume_race_has_one_winner():
    kv = K.MemoryKV()
    st = KvApprovalStore(kv)
    wins, errs = [], []

    def go():
        try:
            st.consume("req-00000002", "x")
            wins.append(1)
        except ApprovalError:
            errs.append(1)

    ts = [threading.Thread(target=go) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(wins) == 1 and len(errs) == 7


@pytest.mark.parametrize("kind", BACKENDS)
def test_rollback_queue_and_drift_store(kind):
    from cloudctl.controlplane.drift import DriftEvent
    from cloudctl.controlplane.orchestrator import RollbackRequest
    kv = make(kind, Clock())
    q = KvRollbackQueue(kv)
    r = RollbackRequest(run_id="a" * 32, node_id="n", environment="e", kind="iac_apply",
                        target={"iac_root": "/r"}, gate_request_id="g", plan_digest="p", error="x", applied_before=[])
    q.request(r)
    assert [p["id"] for p in q.pending()] == [r.id] and "done" not in q.pending()[0]
    q.done(r.id)
    assert q.pending() == []
    ds = KvDriftStore(kv)
    ev = DriftEvent(environment="e", tier="dev", cloud="gcp", root="/r", platform="terraform", plan_digest="x",
                    drift_class="config_drift", severity="LOW", confidence=0.5, factors=[], decision={}, items=[],
                    reasons=[])
    ds.save(ev)
    assert ds.load(ev.id).to_dict() == ev.to_dict()
    assert ds.live_for("e", "/r").id == ev.id
    with pytest.raises(KeyError):
        ds.load("../x")
    with ds.lock():
        with pytest.raises(RuntimeError, match="another drift pass"):
            with ds.lock():
                pass

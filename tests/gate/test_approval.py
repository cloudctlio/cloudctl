"""Signed approvals: Ed25519 signing, write-once store, Cedar authorization."""
import dataclasses
import os

import pytest

pytest.importorskip("cedarpy")
pytest.importorskip("cryptography")

from cloudctl.gate.approval.authz import authorize_approval  # noqa: E402
from cloudctl.gate.approval.signing import (  # noqa: E402
    ApprovalRequest, SignedApproval, generate_keypair, load_private_key, public_key_b64, sign, verify_signature,
    write_private_key,
)
from cloudctl.gate.approval.store import LocalApprovalStore  # noqa: E402
from cloudctl.gate.models import ApprovalError  # noqa: E402


def _req(rid="req-00000001", ttl=900, **kw):
    base = dict(request_id=rid, environment="prod", tier="prod", plan_digest="sha256:abc", summary="tag 12 instances",
                requester="alice", counts={"add": 0, "modify": 12, "destroy": 0}, max_severity="MEDIUM",
                ttl_seconds=ttl)
    base.update(kw)
    return ApprovalRequest.new(**base)


def _key(tmp_path, passphrase=None, name="bob.pem"):
    pem, pub = generate_keypair(passphrase)
    path = tmp_path / name
    write_private_key(path, pem)
    return path, pub


def test_sign_and_verify_roundtrip(tmp_path):
    path, pub = _key(tmp_path)
    key = load_private_key(path)
    assert public_key_b64(key) == pub
    signed = sign(_req(), "bob", key)
    verify_signature(signed, pub)
    again = SignedApproval.from_dict(signed.to_dict())
    verify_signature(again, pub)


@pytest.mark.parametrize("field,value", [
    ("plan_digest", "sha256:evil"), ("environment", "dev"), ("counts", {"add": 0, "modify": 500, "destroy": 9}),
    ("max_severity", "LOW"), ("expires_at", "2099-01-01T00:00:00Z"), ("requester", "mallory"),
])
def test_any_tampered_field_breaks_signature(tmp_path, field, value):
    path, pub = _key(tmp_path)
    signed = sign(_req(), "bob", load_private_key(path))
    forged = dataclasses.replace(signed, request=dataclasses.replace(signed.request, **{field: value}))
    with pytest.raises(ApprovalError, match="does not verify"):
        verify_signature(forged, pub)


def test_wrong_key_rejected(tmp_path):
    path, _ = _key(tmp_path)
    _, other_pub = _key(tmp_path, name="eve.pem")
    with pytest.raises(ApprovalError, match="does not verify"):
        verify_signature(sign(_req(), "bob", load_private_key(path)), other_pub)


def test_bad_encoding_rejected(tmp_path):
    path, pub = _key(tmp_path)
    signed = dataclasses.replace(sign(_req(), "bob", load_private_key(path)), signature="!!!")
    with pytest.raises(ApprovalError, match="encoding"):
        verify_signature(signed, pub)


def test_encrypted_key_needs_passphrase(tmp_path):
    path, pub = _key(tmp_path, passphrase=b"correct horse")
    with pytest.raises(ApprovalError, match="cannot load"):
        load_private_key(path)
    assert public_key_b64(load_private_key(path, b"correct horse")) == pub


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_world_readable_key_refused(tmp_path):
    path, _ = _key(tmp_path)
    os.chmod(path, 0o644)
    with pytest.raises(ApprovalError, match="chmod 600"):
        load_private_key(path)


def test_expiry_and_request_roundtrip():
    r = _req(ttl=1)
    assert ApprovalRequest.from_dict(r.to_dict()) == r
    assert not r.expired()
    expired = dataclasses.replace(r, expires_at="2000-01-01T00:00:00Z")
    assert expired.expired()
    with pytest.raises(ApprovalError, match="version"):
        ApprovalRequest.from_dict({**r.to_dict(), "version": 99})
    with pytest.raises(ApprovalError, match="malformed"):
        ApprovalRequest.from_dict({"version": 1})


# ── store ────────────────────────────────────────────────────────────────────

def test_store_write_once_pending_consume(tmp_path):
    store = LocalApprovalStore(tmp_path / "approvals")
    r = _req()
    store.put_request(r)
    with pytest.raises(ApprovalError, match="write-once"):
        store.put_request(r)
    assert [p.request_id for p in store.pending()] == [r.request_id]
    assert store.get_request(r.request_id) == r
    assert store.get_approval(r.request_id) is None

    path, _ = _key(tmp_path)
    signed = sign(r, "bob", load_private_key(path))
    store.put_approval(signed)
    with pytest.raises(ApprovalError, match="write-once"):
        store.put_approval(signed)
    assert store.get_approval(r.request_id).signature == signed.signature
    assert list(store.pending()) == []

    assert not store.is_consumed(r.request_id)
    store.consume(r.request_id, r.plan_digest)
    assert store.is_consumed(r.request_id)
    with pytest.raises(ApprovalError, match="already used"):
        store.consume(r.request_id, r.plan_digest)


def test_store_rejects_bad_ids_and_orphan_approvals(tmp_path):
    store = LocalApprovalStore(tmp_path / "a")
    for bad in ("../../etc/passwd", "short", "a/b-cdefgh", ""):
        with pytest.raises(ApprovalError, match="invalid approval request id"):
            store.get_request(bad)
    path, _ = _key(tmp_path)
    with pytest.raises(ApprovalError, match="no approval request"):
        store.put_approval(sign(_req(rid="req-orphan01"), "bob", load_private_key(path)))


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_store_files_are_private(tmp_path):
    store = LocalApprovalStore(tmp_path / "a")
    p = store.put_request(_req())
    assert os.stat(p).st_mode & 0o077 == 0
    assert os.stat(tmp_path / "a").st_mode & 0o077 == 0


# ── Cedar ────────────────────────────────────────────────────────────────────

def _authz(**kw):
    base = dict(approver="bob", approver_environments=["prod"], environment="prod", tier="prod",
                requester="alice", max_severity="MEDIUM", counts={"modify": 12}, expired=False)
    base.update(kw)
    authorize_approval(**base)


def test_cedar_allows_listed_approver():
    _authz()
    _authz(max_severity="NONE")


@pytest.mark.parametrize("kw", [
    {"requester": "bob"},                 # separation of duties
    {"requester": "  BOB "},              # case/whitespace-insensitive
    {"max_severity": "HIGH"},
    {"max_severity": "CRITICAL"},
    {"max_severity": "NOT-A-SEVERITY"},   # unknown treated as worst
    {"approver_environments": ["dev"]},   # not an approver for prod
    {"expired": True},
])
def test_cedar_denials(kw):
    with pytest.raises(ApprovalError, match="not authorized"):
        _authz(**kw)


def test_cedar_extra_policy_can_only_restrict():
    extra = 'forbid (principal, action == Action::"approve", resource) when { context.destroy_count > 0 };'
    _authz(extra_policies=extra)
    with pytest.raises(ApprovalError):
        _authz(counts={"destroy": 1}, extra_policies=extra)


def test_cedar_syntax_error_fails_closed():
    with pytest.raises(ApprovalError):
        _authz(extra_policies="permit (oops")

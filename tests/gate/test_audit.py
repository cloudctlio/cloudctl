"""Hash-chained audit: local file, S3 Object Lock, Azure immutable blob, GCS
bucket lock. Tamper detection, secret redaction, fail-closed writes."""
import json
import sys
import types
from unittest.mock import MagicMock

import pytest

from cloudctl.gate.audit.chain import AuditLog, redact
from cloudctl.gate.audit.local import LocalFileSink
from cloudctl.gate.audit.objectstore import (
    AzureImmutableBlobBackend, GcsBucketLockBackend, ObjectStoreSink, S3ObjectLockBackend,
)
from cloudctl.gate.models import AuditError


def _local(tmp_path, **kw):
    return AuditLog(LocalFileSink(tmp_path / "a.jsonl", **kw), chain="t", actor="tester")


def test_chain_appends_and_verifies(tmp_path):
    log = _local(tmp_path)
    for i in range(5):
        log.append("gate.request", {"i": i})
    res = log.verify()
    assert res.ok and res.records == 5 and res.head.seq == 4


@pytest.mark.parametrize("tamper", ["edit", "delete", "reorder"])
def test_any_tampering_breaks_the_chain(tmp_path, tamper):
    log = _local(tmp_path)
    for i in range(4):
        log.append("gate.request", {"i": i})
    p = tmp_path / "a.jsonl"
    lines = p.read_text().splitlines()
    if tamper == "edit":
        rec = json.loads(lines[1])
        rec["data"]["i"] = 99
        lines[1] = json.dumps(rec)
    elif tamper == "delete":
        del lines[1]
    else:
        lines[1], lines[2] = lines[2], lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert not log.verify().ok


def test_rotation_keeps_the_chain_and_never_truncates(tmp_path):
    log = _local(tmp_path, max_bytes=400)
    for i in range(12):
        log.append("tool.call", {"i": i, "pad": "x" * 50})
    segs = LocalFileSink(tmp_path / "a.jsonl").segments()
    assert len(segs) > 1
    res = log.verify()
    assert res.ok and res.records == 12


def test_unreadable_tail_fails_closed(tmp_path):
    (tmp_path / "a.jsonl").write_text("not json\n")
    with pytest.raises(AuditError):
        _local(tmp_path).append("gate.request", {})


def test_redaction_removes_secrets():
    out = redact({"password": "p", "token": "t", "plan_digest": "abc", "note": "key AKIAABCDEFGHIJKLMNOP here",
                  "nested": [{"api_key": "k"}], "big": "x" * 5000})
    assert out["password"] == out["token"] == "[REDACTED]"
    assert out["plan_digest"] == "abc"
    assert "AKIA" not in out["note"]
    assert out["nested"][0]["api_key"] == "[REDACTED]"
    assert "truncated" in out["big"]


def test_records_carry_no_secret_values(tmp_path):
    log = _local(tmp_path)
    log.append("gate.credentials", {"identity": "role", "session_token": "SECRET-123"})
    assert "SECRET-123" not in (tmp_path / "a.jsonl").read_text()


def test_bad_event_names_are_refused(tmp_path):
    with pytest.raises(ValueError):
        _local(tmp_path).append("Bad Event", {})


# ── object stores ────────────────────────────────────────────────────────────

class MemBackend:
    store = "mem://x"

    def __init__(self, immutable=True):
        self.objs = {}
        self.immutable = immutable

    def check_immutability(self, retain_days):
        if not self.immutable:
            raise AuditError("not immutable")

    def put_if_absent(self, key, body, retain_days):
        if key in self.objs:
            return False
        self.objs[key] = body
        return True

    def list_keys(self, prefix, start_after=""):
        for k in sorted(self.objs):
            if k.startswith(prefix) and k > start_after:
                yield k

    def get(self, key):
        return self.objs[key]


def test_object_store_chain_and_write_once():
    be = MemBackend()
    log = AuditLog(ObjectStoreSink(be, prefix="cctl", chain="c1", retain_days=30), chain="c1")
    for i in range(3):
        log.append("gate.decision", {"i": i})
    assert sorted(be.objs) == [f"cctl/c1/{i:012d}.json" for i in range(3)]
    assert log.verify().ok
    # a second writer that lost the race gets False and retries at the next seq
    other = AuditLog(ObjectStoreSink(be, prefix="cctl", chain="c1", retain_days=30), chain="c1")
    other.append("gate.decision", {"i": 3})
    assert log.verify().records == 4


def test_object_store_refuses_a_mutable_bucket():
    log = AuditLog(ObjectStoreSink(MemBackend(immutable=False), prefix="p", chain="c", retain_days=1), chain="c")
    with pytest.raises(AuditError, match="not immutable"):
        log.append("gate.request", {})


def _client_error(code, status):
    e = Exception(code)
    e.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}
    return e


def test_s3_backend_checks_object_lock_and_uses_conditional_writes():
    c = MagicMock()
    c.get_object_lock_configuration.return_value = {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}
    c.get_bucket_versioning.return_value = {"Status": "Enabled"}
    be = S3ObjectLockBackend("audit", client=c, kms_key_id="kms-1")
    be.check_immutability(400)
    assert be.put_if_absent("k", b"{}", 400) is True
    kw = c.put_object.call_args.kwargs
    assert kw["IfNoneMatch"] == "*" and kw["ObjectLockMode"] == "COMPLIANCE" and kw["SSEKMSKeyId"] == "kms-1"
    c.put_object.side_effect = _client_error("PreconditionFailed", 412)
    assert be.put_if_absent("k", b"{}", 400) is False
    c.put_object.side_effect = _client_error("AccessDenied", 403)
    with pytest.raises(AuditError):
        be.put_if_absent("k", b"{}", 400)


def test_s3_backend_refuses_bucket_without_object_lock():
    c = MagicMock()
    c.get_object_lock_configuration.return_value = {}
    with pytest.raises(AuditError, match="Object Lock"):
        S3ObjectLockBackend("audit", client=c).check_immutability(1)


@pytest.fixture
def fake_azure_blob(monkeypatch):
    class ResourceExistsError(Exception):
        pass
    core = types.ModuleType("azure.core.exceptions")
    core.ResourceExistsError = ResourceExistsError
    blob = types.ModuleType("azure.storage.blob")
    blob.ContentSettings = lambda **kw: kw
    blob.ImmutabilityPolicy = lambda **kw: kw
    for name, mod in {"azure": types.ModuleType("azure"), "azure.core": types.ModuleType("azure.core"),
                      "azure.core.exceptions": core, "azure.storage": types.ModuleType("azure.storage"),
                      "azure.storage.blob": blob}.items():
        monkeypatch.setitem(sys.modules, name, mod)
    return ResourceExistsError


def test_azure_backend_locked_immutability_and_write_once(fake_azure_blob):
    cc = MagicMock()
    cc.get_container_properties.return_value = types.SimpleNamespace(immutable_storage_with_versioning_enabled=True)
    be = AzureImmutableBlobBackend("https://acct.blob.core.windows.net", "audit", container_client=cc)
    be.check_immutability(30)
    assert be.put_if_absent("k", b"{}", 30)
    kw = cc.upload_blob.call_args.kwargs
    assert kw["overwrite"] is False and kw["immutability_policy"]["policy_mode"] == "Locked"
    cc.upload_blob.side_effect = fake_azure_blob("exists")
    assert be.put_if_absent("k", b"{}", 30) is False
    cc.get_container_properties.return_value = types.SimpleNamespace(immutable_storage_with_versioning_enabled=False)
    with pytest.raises(AuditError):
        be.check_immutability(30)


def test_gcs_backend_needs_a_locked_long_enough_retention():
    client = MagicMock()
    bucket = client.bucket.return_value
    bucket.retention_policy_locked = True
    bucket.retention_period = 400 * 86400
    be = GcsBucketLockBackend("audit", client=client)
    be.check_immutability(400)
    bucket.retention_period = 10
    with pytest.raises(AuditError, match="less than"):
        be.check_immutability(400)
    bucket.retention_policy_locked = False
    with pytest.raises(AuditError, match="locked"):
        be.check_immutability(1)
    blob = bucket.blob.return_value
    assert be.put_if_absent("k", b"{}", 1)
    assert blob.upload_from_string.call_args.kwargs["if_generation_match"] == 0
    err = Exception("precondition")
    err.code = 412
    blob.upload_from_string.side_effect = err
    assert be.put_if_absent("k", b"{}", 1) is False


def test_diagnosis_audit_is_chained_and_never_raises(tmp_path, monkeypatch):
    from cloudctl.ai import guardrails as g
    monkeypatch.setattr(g, "_AUDIT_LOG_PATH", tmp_path / "diag.jsonl")
    g.audit_log_tool_call(session_id="s", tool_name="describe", resource_name="r", allowed=True)
    g.audit_log_agent_call(session_id="s", event="end", account_id="a", region="r", query_hash="h")
    assert g._audit_log().verify().ok
    (tmp_path / "diag.jsonl").write_text("garbage\n")
    g.audit_log_tool_call(session_id="s", tool_name="t", resource_name="r", allowed=True)   # no raise

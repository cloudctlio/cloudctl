"""Immutable object-store audit sinks: S3 Object Lock, Azure immutable Blob
storage and GCS bucket lock.

Each record is one object at ``<prefix>/<chain>/<seq:012d>.json``. Keys are
zero-padded so the store's lexicographic listing is chain order. Writes are
create-only (S3 ``If-None-Match: *``, Azure ``overwrite=False``, GCS
``if_generation_match=0``): two writers racing for the same seq cannot both
win, so the chain never forks. Retention is enforced by the store itself:

* **S3** — the bucket must have Object Lock enabled; every object is written
  with ``ObjectLockMode`` (COMPLIANCE by default) and a retain-until date.
* **Azure** — the container must have version-level immutability support;
  every blob gets a *locked* time-based immutability policy.
* **GCS** — the bucket must have a *locked* retention policy.

``check_ready`` verifies that configuration and raises if it is absent, so a
production environment cannot silently fall back to a mutable store.
"""
from __future__ import annotations

import json
import re
import threading
from datetime import timedelta
from typing import Any, Iterator, Mapping, Optional, Protocol

from cloudctl.gate.audit.chain import EMPTY_HEAD, ChainHead
from cloudctl.gate.models import AuditError, utcnow

_SEQ_RE = re.compile(r"/(\d{12})\.json$")


class ObjectBackend(Protocol):
    store: str

    def put_if_absent(self, key: str, body: bytes, retain_days: int) -> bool: ...
    def list_keys(self, prefix: str, start_after: str = "") -> Iterator[str]: ...
    def get(self, key: str) -> bytes: ...
    def check_immutability(self, retain_days: int) -> None: ...


class ObjectStoreSink:
    immutable = True

    def __init__(self, backend: ObjectBackend, *, prefix: str, chain: str,
                 retain_days: int) -> None:
        if retain_days < 1:
            raise ValueError("retain_days must be >= 1")
        self.backend = backend
        self.base = f"{prefix.strip('/')}/{chain}/" if prefix.strip("/") else f"{chain}/"
        self.retain_days = retain_days
        self.name = f"{backend.store}:{self.base}"
        self._cache: Optional[tuple[str, ChainHead]] = None
        self._lock = threading.Lock()
        self._ready = False

    def _key(self, seq: int) -> str:
        return f"{self.base}{seq:012d}.json"

    def check_ready(self) -> None:
        if not self._ready:
            self.backend.check_immutability(self.retain_days)
            self._ready = True

    def head(self) -> ChainHead:
        with self._lock:
            start_after = self._cache[0] if self._cache else ""
            last_key = ""
            for key in self.backend.list_keys(self.base, start_after=start_after):
                if _SEQ_RE.search(key):
                    last_key = key
            if not last_key:
                if self._cache:
                    return self._cache[1]
                return EMPTY_HEAD
            rec = json.loads(self.backend.get(last_key))
            head = ChainHead(seq=int(rec["seq"]), hash=str(rec["hash"]))
            if not last_key.endswith(f"{head.seq:012d}.json"):
                raise AuditError(f"object {last_key} holds seq {head.seq}; the chain store is corrupt")
            self._cache = (last_key, head)
            return head

    def append(self, record: Mapping[str, Any]) -> bool:
        self.check_ready()
        body = json.dumps(record, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
        key = self._key(int(record["seq"]))
        ok = self.backend.put_if_absent(key, body, self.retain_days)
        if ok:
            with self._lock:
                self._cache = (key, ChainHead(seq=int(record["seq"]), hash=str(record["hash"])))
        return ok

    def read_all(self) -> Iterator[Mapping[str, Any]]:
        for key in self.backend.list_keys(self.base):
            if _SEQ_RE.search(key):
                yield json.loads(self.backend.get(key))


# ── S3 Object Lock ────────────────────────────────────────────────────────────

class S3ObjectLockBackend:
    def __init__(self, bucket: str, *, client: Any = None, region: Optional[str] = None,
                 profile: Optional[str] = None, mode: str = "COMPLIANCE",
                 kms_key_id: Optional[str] = None) -> None:
        if mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise ValueError("S3 object lock mode must be COMPLIANCE or GOVERNANCE")
        self.bucket = bucket
        self.mode = mode
        self.kms_key_id = kms_key_id
        self.store = f"s3://{bucket}"
        if client is None:
            import boto3  # noqa: PLC0415
            client = boto3.Session(profile_name=profile, region_name=region).client("s3")
        self.client = client

    def check_immutability(self, retain_days: int) -> None:
        try:
            cfg = self.client.get_object_lock_configuration(Bucket=self.bucket)
        except Exception as e:  # noqa: BLE001
            raise AuditError(f"cannot read Object Lock configuration of s3://{self.bucket}: {e}") from e
        if cfg.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
            raise AuditError(f"s3://{self.bucket} does not have Object Lock enabled")
        try:
            ver = self.client.get_bucket_versioning(Bucket=self.bucket)
        except Exception as e:  # noqa: BLE001
            raise AuditError(f"cannot read versioning of s3://{self.bucket}: {e}") from e
        if ver.get("Status") != "Enabled":
            raise AuditError(f"s3://{self.bucket} does not have versioning enabled")

    def put_if_absent(self, key: str, body: bytes, retain_days: int) -> bool:
        kwargs: dict[str, Any] = dict(
            Bucket=self.bucket, Key=key, Body=body, ContentType="application/json",
            IfNoneMatch="*", ChecksumAlgorithm="SHA256",
            ObjectLockMode=self.mode,
            ObjectLockRetainUntilDate=utcnow() + timedelta(days=retain_days),
        )
        if self.kms_key_id:
            kwargs.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=self.kms_key_id)
        try:
            self.client.put_object(**kwargs)
            return True
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            status = getattr(e, "response", {}).get("ResponseMetadata", {}).get("HTTPStatusCode")
            if code in ("PreconditionFailed", "ConditionalRequestConflict") or status in (409, 412):
                return False
            raise AuditError(f"S3 audit write to s3://{self.bucket}/{key} failed: {e}") from e

    def list_keys(self, prefix: str, start_after: str = "") -> Iterator[str]:
        kwargs: dict[str, Any] = {"Bucket": self.bucket, "Prefix": prefix}
        if start_after:
            kwargs["StartAfter"] = start_after
        for page in self.client.get_paginator("list_objects_v2").paginate(**kwargs):
            for obj in page.get("Contents", []) or []:
                yield obj["Key"]

    def get(self, key: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()


# ── Azure immutable Blob storage ──────────────────────────────────────────────

class AzureImmutableBlobBackend:
    def __init__(self, account_url: str, container: str, *, credential: Any = None,
                 container_client: Any = None) -> None:
        self.store = f"{account_url.rstrip('/')}/{container}"
        if container_client is None:
            try:
                from azure.storage.blob import ContainerClient  # noqa: PLC0415
            except ImportError as e:
                raise AuditError("Azure audit sink needs azure-storage-blob "
                                 "(pip install 'cctl[azure]')") from e
            if credential is None:
                from azure.identity import DefaultAzureCredential  # noqa: PLC0415
                credential = DefaultAzureCredential()
            container_client = ContainerClient(account_url=account_url, container_name=container,
                                               credential=credential)
        self.cc = container_client

    def check_immutability(self, retain_days: int) -> None:
        try:
            props = self.cc.get_container_properties()
        except Exception as e:  # noqa: BLE001
            raise AuditError(f"cannot read container {self.store}: {e}") from e
        if not getattr(props, "immutable_storage_with_versioning_enabled", False):
            raise AuditError(f"{self.store} does not have version-level immutability enabled")

    def put_if_absent(self, key: str, body: bytes, retain_days: int) -> bool:
        from azure.core.exceptions import ResourceExistsError  # noqa: PLC0415
        from azure.storage.blob import ContentSettings, ImmutabilityPolicy  # noqa: PLC0415
        try:
            self.cc.upload_blob(
                name=key, data=body, overwrite=False,
                content_settings=ContentSettings(content_type="application/json"),
                immutability_policy=ImmutabilityPolicy(
                    expiry_time=utcnow() + timedelta(days=retain_days), policy_mode="Locked"),
            )
            return True
        except ResourceExistsError:
            return False
        except Exception as e:  # noqa: BLE001
            raise AuditError(f"Azure audit write to {self.store}/{key} failed: {e}") from e

    def list_keys(self, prefix: str, start_after: str = "") -> Iterator[str]:
        for b in self.cc.list_blobs(name_starts_with=prefix):
            if not start_after or b.name > start_after:
                yield b.name

    def get(self, key: str) -> bytes:
        return self.cc.download_blob(key).readall()


# ── GCS bucket lock ───────────────────────────────────────────────────────────

class GcsBucketLockBackend:
    def __init__(self, bucket: str, *, client: Any = None, credentials: Any = None,
                 project: Optional[str] = None) -> None:
        self.store = f"gs://{bucket}"
        if client is None:
            try:
                from google.cloud import storage  # noqa: PLC0415
            except ImportError as e:
                raise AuditError("GCS audit sink needs google-cloud-storage "
                                 "(pip install 'cctl[gcp]')") from e
            client = storage.Client(project=project, credentials=credentials)
        self.client = client
        self.bucket = client.bucket(bucket)

    def check_immutability(self, retain_days: int) -> None:
        try:
            self.bucket.reload()
        except Exception as e:  # noqa: BLE001
            raise AuditError(f"cannot read bucket {self.store}: {e}") from e
        if not self.bucket.retention_policy_locked:
            raise AuditError(f"{self.store} does not have a locked retention policy")
        period = self.bucket.retention_period or 0
        if period < retain_days * 86400:
            raise AuditError(f"{self.store} retains objects for {period}s, less than "
                             f"the configured {retain_days} days")

    def put_if_absent(self, key: str, body: bytes, retain_days: int) -> bool:
        try:
            from google.api_core.exceptions import PreconditionFailed  # noqa: PLC0415
        except ImportError:  # pragma: no cover
            PreconditionFailed = ()  # type: ignore[assignment]
        blob = self.bucket.blob(key)
        try:
            blob.upload_from_string(body, content_type="application/json", if_generation_match=0)
            return True
        except PreconditionFailed:  # type: ignore[misc]
            return False
        except Exception as e:  # noqa: BLE001
            if getattr(e, "code", None) == 412:
                return False
            raise AuditError(f"GCS audit write to {self.store}/{key} failed: {e}") from e

    def list_keys(self, prefix: str, start_after: str = "") -> Iterator[str]:
        kwargs: dict[str, Any] = {"prefix": prefix}
        if start_after:
            kwargs["start_offset"] = start_after
        for b in self.client.list_blobs(self.bucket, **kwargs):
            if b.name != start_after:
                yield b.name

    def get(self, key: str) -> bytes:
        return self.bucket.blob(key).download_as_bytes()

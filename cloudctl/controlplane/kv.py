"""Shared state for the control-plane service: one small key-value contract
with three managed backends, so replicas on any cloud agree on runs, drift
events, approvals and locks.

========================  =================================================
Backend                    Conditional writes / leases
========================  =================================================
``dynamodb`` (AWS)         ``ConditionExpression`` on ``PutItem``
``cosmos`` (Azure)         ETag ``IfNotModified`` / ``create_item``
``firestore`` (GCP)        ``create()`` / ``last_update_time`` precondition
``memory``                 a lock; for tests and a single local process
========================  =================================================

The contract:

- ``get(ns, key)`` returns an :class:`Item` (``doc`` and an opaque
  ``version``) or ``None``.
- ``put(ns, key, doc, expect=...)``: ``expect=ABSENT`` creates only;
  ``expect=<version>`` replaces only that version; ``expect=None`` writes
  unconditionally. A failed condition raises :class:`Conflict`.
- ``scan(ns)`` yields every item in a namespace.
- ``acquire(name, owner, ttl)`` / ``renew`` / ``release``: a lease that
  expires on its own, so a crashed replica never holds a lock for ever.

Documents are stored as one JSON string, so no backend mangles numbers or
nested types, and are capped at 350 KB (DynamoDB's item limit is 400 KB).
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Mapping, Optional, Protocol

ABSENT = "__absent__"
MAX_DOC_BYTES = 350_000
_NS = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")


class KVError(Exception):
    pass


class Conflict(KVError):
    """A conditional write lost: the item exists, or changed, or the lease is held."""


@dataclass(frozen=True)
class Item:
    key: str
    doc: dict[str, Any]
    version: str


class KVStore(Protocol):
    name: str

    def get(self, ns: str, key: str) -> Optional[Item]: ...
    def put(self, ns: str, key: str, doc: Mapping[str, Any], *, expect: Optional[str] = None) -> str: ...
    def scan(self, ns: str) -> Iterator[Item]: ...
    def delete(self, ns: str, key: str) -> None: ...
    def acquire(self, name: str, owner: str, ttl_seconds: int) -> bool: ...
    def release(self, name: str, owner: str) -> None: ...
    def check_ready(self) -> None: ...


def _check(ns: str, key: str) -> None:
    if not _NS.match(ns or ""):
        raise KVError(f"invalid namespace {ns!r}")
    if not _KEY.match(key or ""):
        raise KVError(f"invalid key {key!r}")


def encode(doc: Mapping[str, Any]) -> str:
    body = json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
    if len(body.encode()) > MAX_DOC_BYTES:
        raise KVError(f"document is {len(body.encode())} bytes; the limit is {MAX_DOC_BYTES}")
    return body


def _lease_doc(owner: str, ttl: int, now: float) -> dict[str, Any]:
    return {"owner": owner, "expires_at": now + ttl}


# ── memory ──────────────────────────────────────────────────────────────────

class MemoryKV:
    name = "memory"

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._data: dict[tuple[str, str], tuple[str, int]] = {}
        self._lock = threading.Lock()
        self.clock = clock

    def check_ready(self) -> None:
        return None

    def get(self, ns: str, key: str) -> Optional[Item]:
        _check(ns, key)
        with self._lock:
            v = self._data.get((ns, key))
        return Item(key, json.loads(v[0]), str(v[1])) if v else None

    def put(self, ns: str, key: str, doc: Mapping[str, Any], *, expect: Optional[str] = None) -> str:
        _check(ns, key)
        body = encode(doc)
        with self._lock:
            cur = self._data.get((ns, key))
            if expect == ABSENT and cur is not None:
                raise Conflict(f"{ns}/{key} already exists")
            if expect not in (None, ABSENT) and (cur is None or str(cur[1]) != expect):
                raise Conflict(f"{ns}/{key} changed")
            ver = (cur[1] + 1) if cur else 1
            self._data[(ns, key)] = (body, ver)
            return str(ver)

    def scan(self, ns: str) -> Iterator[Item]:
        if not _NS.match(ns or ""):
            raise KVError(f"invalid namespace {ns!r}")
        with self._lock:
            rows = [(k, v) for (n, k), v in self._data.items() if n == ns]
        for k, (body, ver) in sorted(rows):
            yield Item(k, json.loads(body), str(ver))

    def delete(self, ns: str, key: str) -> None:
        _check(ns, key)
        with self._lock:
            self._data.pop((ns, key), None)

    def acquire(self, name: str, owner: str, ttl_seconds: int) -> bool:
        _check("lease", name)
        now = self.clock()
        with self._lock:
            cur = self._data.get(("lease", name))
            if cur:
                d = json.loads(cur[0])
                if d["owner"] != owner and d["expires_at"] > now:
                    return False
            ver = (cur[1] + 1) if cur else 1
            self._data[("lease", name)] = (encode(_lease_doc(owner, ttl_seconds, now)), ver)
            return True

    def release(self, name: str, owner: str) -> None:
        with self._lock:
            cur = self._data.get(("lease", name))
            if cur and json.loads(cur[0])["owner"] == owner:
                del self._data[("lease", name)]


# ── DynamoDB ────────────────────────────────────────────────────────────────

class DynamoDBKV:
    """Table with partition key ``ns`` (S), sort key ``k`` (S), and TTL on
    attribute ``ttl``. Attributes: ``doc`` (JSON string), ``v`` (N)."""

    name = "dynamodb"

    def __init__(self, table: str, *, client: Any = None, region: Optional[str] = None,
                 clock: Callable[[], float] = time.time) -> None:
        if client is None:
            import boto3  # noqa: PLC0415
            client = boto3.client("dynamodb", region_name=region)
        self.client = client
        self.table = table
        self.clock = clock

    def _cond_failed(self, e: Exception) -> bool:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        return code == "ConditionalCheckFailedException"

    def check_ready(self) -> None:
        try:
            t = self.client.describe_table(TableName=self.table)["Table"]
            ttl = self.client.describe_time_to_live(TableName=self.table)["TimeToLiveDescription"]
        except Exception as e:  # noqa: BLE001
            raise KVError(f"DynamoDB table {self.table}: {e}") from e
        keys = {k["AttributeName"]: k["KeyType"] for k in t.get("KeySchema", [])}
        if keys != {"ns": "HASH", "k": "RANGE"}:
            raise KVError(f"DynamoDB table {self.table} needs partition key 'ns' and sort key 'k'")
        if ttl.get("TimeToLiveStatus") != "ENABLED" or ttl.get("AttributeName") != "ttl":
            raise KVError(f"DynamoDB table {self.table} needs TTL enabled on attribute 'ttl'")

    def get(self, ns: str, key: str) -> Optional[Item]:
        _check(ns, key)
        r = self.client.get_item(TableName=self.table, Key={"ns": {"S": ns}, "k": {"S": key}}, ConsistentRead=True)
        it = r.get("Item")
        if not it:
            return None
        return Item(key, json.loads(it["doc"]["S"]), it["v"]["N"])

    def put(self, ns: str, key: str, doc: Mapping[str, Any], *, expect: Optional[str] = None) -> str:
        _check(ns, key)
        body = encode(doc)
        kw: dict[str, Any] = {}
        if expect == ABSENT:
            kw = {"ConditionExpression": "attribute_not_exists(k)"}
            ver = 1
        elif expect is not None:
            kw = {"ConditionExpression": "v = :ev", "ExpressionAttributeValues": {":ev": {"N": expect}}}
            ver = int(expect) + 1
        else:
            cur = self.get(ns, key)
            ver = int(cur.version) + 1 if cur else 1
        try:
            self.client.put_item(TableName=self.table, Item={"ns": {"S": ns}, "k": {"S": key}, "doc": {"S": body},
                                                             "v": {"N": str(ver)}}, **kw)
        except Exception as e:  # noqa: BLE001
            if self._cond_failed(e):
                raise Conflict(f"{ns}/{key}: condition failed") from None
            raise KVError(f"DynamoDB put {ns}/{key}: {e}") from e
        return str(ver)

    def scan(self, ns: str) -> Iterator[Item]:
        if not _NS.match(ns or ""):
            raise KVError(f"invalid namespace {ns!r}")
        kw: dict[str, Any] = {"TableName": self.table, "KeyConditionExpression": "ns = :ns",
                              "ExpressionAttributeValues": {":ns": {"S": ns}}, "ConsistentRead": True}
        while True:
            r = self.client.query(**kw)
            for it in r.get("Items", []):
                yield Item(it["k"]["S"], json.loads(it["doc"]["S"]), it["v"]["N"])
            if not r.get("LastEvaluatedKey"):
                return
            kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def delete(self, ns: str, key: str) -> None:
        _check(ns, key)
        self.client.delete_item(TableName=self.table, Key={"ns": {"S": ns}, "k": {"S": key}})

    def acquire(self, name: str, owner: str, ttl_seconds: int) -> bool:
        _check("lease", name)
        now = self.clock()
        doc = _lease_doc(owner, ttl_seconds, now)
        try:
            self.client.put_item(
                TableName=self.table,
                Item={"ns": {"S": "lease"}, "k": {"S": name}, "doc": {"S": encode(doc)}, "v": {"N": "1"},
                      "owner": {"S": owner}, "expires_at": {"N": repr(doc["expires_at"])},
                      "ttl": {"N": str(int(doc["expires_at"]) + 86400)}},
                ConditionExpression="attribute_not_exists(k) OR expires_at < :now OR #o = :me",
                ExpressionAttributeNames={"#o": "owner"},
                ExpressionAttributeValues={":now": {"N": repr(now)}, ":me": {"S": owner}})
            return True
        except Exception as e:  # noqa: BLE001
            if self._cond_failed(e):
                return False
            raise KVError(f"DynamoDB lease {name}: {e}") from e

    def release(self, name: str, owner: str) -> None:
        try:
            self.client.delete_item(TableName=self.table, Key={"ns": {"S": "lease"}, "k": {"S": name}},
                                    ConditionExpression="#o = :me", ExpressionAttributeNames={"#o": "owner"},
                                    ExpressionAttributeValues={":me": {"S": owner}})
        except Exception as e:  # noqa: BLE001
            if not self._cond_failed(e):
                raise KVError(f"DynamoDB lease {name}: {e}") from e


# ── Cosmos DB ───────────────────────────────────────────────────────────────

def _if_not_modified() -> Any:
    from azure.core import MatchConditions  # noqa: PLC0415
    return MatchConditions.IfNotModified


class CosmosKV:
    """A Cosmos DB (NoSQL API) container with partition key ``/ns`` and
    default TTL turned on (``-1``, so only leases expire). Item id is the key."""

    name = "cosmos"

    def __init__(self, container: Any, *, clock: Callable[[], float] = time.time) -> None:
        self.c = container
        self.clock = clock

    @classmethod
    def connect(cls, endpoint: str, database: str, container: str) -> "CosmosKV":
        from azure.cosmos import CosmosClient  # noqa: PLC0415
        from azure.identity import DefaultAzureCredential  # noqa: PLC0415
        client = CosmosClient(endpoint, credential=DefaultAzureCredential())  # Entra ID; no account keys
        return cls(client.get_database_client(database).get_container_client(container))

    @staticmethod
    def _status(e: Exception) -> int:
        return int(getattr(e, "status_code", 0) or 0)

    def check_ready(self) -> None:
        try:
            props = self.c.read()
        except Exception as e:  # noqa: BLE001
            raise KVError(f"Cosmos container: {e}") from e
        paths = (props.get("partitionKey") or {}).get("paths") or []
        if paths != ["/ns"]:
            raise KVError("the Cosmos container needs partition key /ns")
        if props.get("defaultTtl") is None:
            raise KVError("the Cosmos container needs default TTL turned on (-1) so leases expire")

    def _read(self, ns: str, key: str) -> Optional[dict]:
        try:
            return self.c.read_item(item=key, partition_key=ns)
        except Exception as e:  # noqa: BLE001
            if self._status(e) == 404:
                return None
            raise KVError(f"Cosmos read {ns}/{key}: {e}") from e

    def get(self, ns: str, key: str) -> Optional[Item]:
        _check(ns, key)
        it = self._read(ns, key)
        return Item(key, json.loads(it["doc"]), it["_etag"]) if it else None

    def put(self, ns: str, key: str, doc: Mapping[str, Any], *, expect: Optional[str] = None) -> str:
        _check(ns, key)
        body = {"id": key, "ns": ns, "doc": encode(doc)}
        try:
            if expect == ABSENT:
                r = self.c.create_item(body=body)
            elif expect is not None:
                r = self.c.replace_item(item=key, body=body, etag=expect, match_condition=_if_not_modified())
            else:
                r = self.c.upsert_item(body=body)
        except Exception as e:  # noqa: BLE001
            if self._status(e) in (409, 412):
                raise Conflict(f"{ns}/{key}: condition failed") from None
            raise KVError(f"Cosmos write {ns}/{key}: {e}") from e
        return r["_etag"]

    def scan(self, ns: str) -> Iterator[Item]:
        if not _NS.match(ns or ""):
            raise KVError(f"invalid namespace {ns!r}")
        for it in self.c.query_items(query="SELECT * FROM c WHERE c.ns = @ns",
                                     parameters=[{"name": "@ns", "value": ns}], partition_key=ns):
            yield Item(it["id"], json.loads(it["doc"]), it["_etag"])

    def delete(self, ns: str, key: str) -> None:
        _check(ns, key)
        try:
            self.c.delete_item(item=key, partition_key=ns)
        except Exception as e:  # noqa: BLE001
            if self._status(e) != 404:
                raise KVError(f"Cosmos delete {ns}/{key}: {e}") from e

    def acquire(self, name: str, owner: str, ttl_seconds: int) -> bool:
        _check("lease", name)
        now = self.clock()
        body = {"id": name, "ns": "lease", "doc": encode(_lease_doc(owner, ttl_seconds, now)),
                "ttl": int(ttl_seconds) + 86400}
        cur = self._read("lease", name)
        try:
            if cur is None:
                self.c.create_item(body=body)
                return True
            d = json.loads(cur["doc"])
            if d["owner"] != owner and d["expires_at"] > now:
                return False
            self.c.replace_item(item=name, body=body, etag=cur["_etag"], match_condition=_if_not_modified())
            return True
        except Exception as e:  # noqa: BLE001
            if self._status(e) in (409, 412):
                return False
            raise KVError(f"Cosmos lease {name}: {e}") from e

    def release(self, name: str, owner: str) -> None:
        cur = self._read("lease", name)
        if cur and json.loads(cur["doc"])["owner"] == owner:
            try:
                self.c.delete_item(item=name, partition_key="lease", etag=cur["_etag"],
                                   match_condition=_if_not_modified())
            except Exception as e:  # noqa: BLE001
                if self._status(e) not in (404, 412):
                    raise KVError(f"Cosmos lease {name}: {e}") from e


# ── Firestore ───────────────────────────────────────────────────────────────

class FirestoreKV:
    """Firestore (native mode): one collection per namespace, named
    ``<prefix>_<ns>``; document id is the key. A TTL policy on field
    ``expire_at`` (a timestamp) in the lease collection lets a TTL policy clean old leases up."""

    name = "firestore"

    def __init__(self, client: Any, *, prefix: str = "cctl", clock: Callable[[], float] = time.time) -> None:
        self.client = client
        self.prefix = prefix
        self.clock = clock

    @classmethod
    def connect(cls, project: str, database: str = "(default)", prefix: str = "cctl") -> "FirestoreKV":
        from google.cloud import firestore  # noqa: PLC0415
        return cls(firestore.Client(project=project, database=database), prefix=prefix)

    def _ref(self, ns: str, key: str) -> Any:
        return self.client.collection(f"{self.prefix}_{ns}").document(key)

    @staticmethod
    def _kind(e: Exception) -> str:
        return type(e).__name__

    def check_ready(self) -> None:
        try:
            self._ref("lease", "readiness-probe").get()
        except Exception as e:  # noqa: BLE001
            raise KVError(f"Firestore: {e}") from e

    def get(self, ns: str, key: str) -> Optional[Item]:
        _check(ns, key)
        snap = self._ref(ns, key).get()
        if not snap.exists:
            return None
        return Item(key, json.loads(snap.to_dict()["doc"]), _ts(snap.update_time))

    def put(self, ns: str, key: str, doc: Mapping[str, Any], *, expect: Optional[str] = None) -> str:
        _check(ns, key)
        ref = self._ref(ns, key)
        data = {"doc": encode(doc)}
        try:
            if expect == ABSENT:
                r = ref.create(data)
            elif expect is not None:
                snap = ref.get()
                if not snap.exists or _ts(snap.update_time) != expect:
                    raise Conflict(f"{ns}/{key} changed")
                r = ref.update(data, option=self.client.write_option(last_update_time=snap.update_time))
            else:
                r = ref.set(data)
        except Conflict:
            raise
        except Exception as e:  # noqa: BLE001
            if self._kind(e) in ("AlreadyExists", "FailedPrecondition", "Conflict"):
                raise Conflict(f"{ns}/{key}: condition failed") from None
            raise KVError(f"Firestore write {ns}/{key}: {e}") from e
        return _ts(r.update_time)

    def scan(self, ns: str) -> Iterator[Item]:
        if not _NS.match(ns or ""):
            raise KVError(f"invalid namespace {ns!r}")
        for snap in self.client.collection(f"{self.prefix}_{ns}").stream():
            yield Item(snap.id, json.loads(snap.to_dict()["doc"]), _ts(snap.update_time))

    def delete(self, ns: str, key: str) -> None:
        _check(ns, key)
        self._ref(ns, key).delete()

    def acquire(self, name: str, owner: str, ttl_seconds: int) -> bool:
        _check("lease", name)
        now = self.clock()
        ref = self._ref("lease", name)
        # Firestore TTL policies only act on timestamp fields.
        from datetime import datetime, timezone  # noqa: PLC0415
        expire_at = datetime.fromtimestamp(now + ttl_seconds + 86400, tz=timezone.utc)
        data = {"doc": encode(_lease_doc(owner, ttl_seconds, now)), "expire_at": expire_at}
        snap = ref.get()
        try:
            if not snap.exists:
                ref.create(data)
                return True
            d = json.loads(snap.to_dict()["doc"])
            if d["owner"] != owner and d["expires_at"] > now:
                return False
            ref.update(data, option=self.client.write_option(last_update_time=snap.update_time))
            return True
        except Exception as e:  # noqa: BLE001
            if self._kind(e) in ("AlreadyExists", "FailedPrecondition", "Conflict"):
                return False
            raise KVError(f"Firestore lease {name}: {e}") from e

    def release(self, name: str, owner: str) -> None:
        ref = self._ref("lease", name)
        snap = ref.get()
        if snap.exists and json.loads(snap.to_dict()["doc"])["owner"] == owner:
            try:
                ref.delete(option=self.client.write_option(last_update_time=snap.update_time))
            except Exception as e:  # noqa: BLE001
                if self._kind(e) not in ("FailedPrecondition", "NotFound"):
                    raise KVError(f"Firestore lease {name}: {e}") from e


def _ts(t: Any) -> str:
    return t.isoformat() if hasattr(t, "isoformat") else str(t)


# ── factory and a renewing lease ────────────────────────────────────────────

def kv_from_settings(settings: Mapping[str, Any]) -> KVStore:
    kind = settings.get("backend", "memory")
    if kind == "dynamodb":
        return DynamoDBKV(settings["table"], region=settings.get("region"))
    if kind == "cosmos":
        return CosmosKV.connect(settings["endpoint"], settings["database"], settings["container"])
    if kind == "firestore":
        return FirestoreKV.connect(settings["project"], settings.get("database", "(default)"),
                                   settings.get("prefix", "cctl"))
    if kind == "memory":
        return MemoryKV()
    raise KVError(f"unknown state backend {kind!r}; one of dynamodb, cosmos, firestore, memory")


class Lease:
    """Holds a lease and renews it in the background (every third of its TTL)
    until released. If a renewal is lost, ``lost`` is set; callers check it
    before an irreversible step."""

    def __init__(self, kv: KVStore, name: str, owner: str, ttl_seconds: int = 900) -> None:
        if ttl_seconds < 30:
            raise ValueError("lease ttl must be at least 30 seconds")
        self.kv, self.name, self.owner, self.ttl = kv, name, owner, ttl_seconds
        self.lost = threading.Event()
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None

    def __enter__(self) -> "Lease":
        if not self.kv.acquire(self.name, self.owner, self.ttl):
            raise Conflict(f"{self.name} is held by another worker")
        self._t = threading.Thread(target=self._renew, name=f"lease-{self.name}", daemon=True)
        self._t.start()
        return self

    def _renew(self) -> None:
        while not self._stop.wait(self.ttl / 3):
            try:
                if not self.kv.acquire(self.name, self.owner, self.ttl):
                    self.lost.set()
                    return
            except KVError:
                self.lost.set()
                return

    def __exit__(self, *exc: Any) -> None:
        self._stop.set()
        if self._t:
            self._t.join(timeout=5)
        try:
            self.kv.release(self.name, self.owner)
        except KVError:
            pass

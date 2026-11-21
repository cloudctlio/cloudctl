"""In-memory stand-ins for the three managed state services, faithful to the
SDK calls cctl makes (and only those): DynamoDB (boto3 client), Cosmos DB
(azure-cosmos ContainerProxy) and Firestore (google-cloud-firestore Client)."""
from __future__ import annotations

import copy
import itertools
from datetime import datetime, timedelta, timezone
from typing import Any

# ── DynamoDB ────────────────────────────────────────────────────────────────


class DynamoError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeDynamo:
    def __init__(self, ttl_enabled: bool = True, page: int = 2):
        self.items: dict[tuple[str, str], dict] = {}
        self.ttl_enabled = ttl_enabled
        self.page = page

    def describe_table(self, TableName):
        return {"Table": {"KeySchema": [{"AttributeName": "ns", "KeyType": "HASH"},
                                        {"AttributeName": "k", "KeyType": "RANGE"}]}}

    def describe_time_to_live(self, TableName):
        return {"TimeToLiveDescription": {"TimeToLiveStatus": "ENABLED" if self.ttl_enabled else "DISABLED",
                                          "AttributeName": "ttl"}}

    def get_item(self, TableName, Key, ConsistentRead):
        assert ConsistentRead is True
        it = self.items.get((Key["ns"]["S"], Key["k"]["S"]))
        return {"Item": copy.deepcopy(it)} if it else {}

    def _cond(self, cur, expr, names, values):
        names = names or {}
        values = values or {}
        if expr is None:
            return True
        clauses = [c.strip() for c in expr.split(" OR ")]
        for c in clauses:
            if c == "attribute_not_exists(k)" and cur is None:
                return True
            if c == "v = :ev" and cur is not None and cur["v"]["N"] == values[":ev"]["N"]:
                return True
            if c == "expires_at < :now" and cur is not None and float(cur["expires_at"]["N"]) < float(values[":now"]["N"]):
                return True
            if c == "#o = :me" and cur is not None and cur[names["#o"]]["S"] == values[":me"]["S"]:
                return True
            if c not in ("attribute_not_exists(k)", "v = :ev", "expires_at < :now", "#o = :me"):
                raise AssertionError(f"unexpected condition {c!r}")
        return False

    def put_item(self, TableName, Item, ConditionExpression=None, ExpressionAttributeNames=None,
                 ExpressionAttributeValues=None):
        key = (Item["ns"]["S"], Item["k"]["S"])
        if not self._cond(self.items.get(key), ConditionExpression, ExpressionAttributeNames,
                          ExpressionAttributeValues):
            raise DynamoError("ConditionalCheckFailedException")
        self.items[key] = copy.deepcopy(Item)

    def delete_item(self, TableName, Key, ConditionExpression=None, ExpressionAttributeNames=None,
                    ExpressionAttributeValues=None):
        key = (Key["ns"]["S"], Key["k"]["S"])
        if not self._cond(self.items.get(key), ConditionExpression, ExpressionAttributeNames,
                          ExpressionAttributeValues):
            raise DynamoError("ConditionalCheckFailedException")
        self.items.pop(key, None)

    def query(self, TableName, KeyConditionExpression, ExpressionAttributeValues, ConsistentRead,
              ExclusiveStartKey=None):
        assert KeyConditionExpression == "ns = :ns"
        ns = ExpressionAttributeValues[":ns"]["S"]
        rows = sorted((k, v) for (n, k), v in self.items.items() if n == ns)
        start = 0
        if ExclusiveStartKey:
            start = [k for k, _ in rows].index(ExclusiveStartKey["k"]["S"]) + 1
        chunk = rows[start:start + self.page]
        out = {"Items": [copy.deepcopy(v) for _, v in chunk]}
        if start + self.page < len(rows):
            out["LastEvaluatedKey"] = {"ns": {"S": ns}, "k": {"S": chunk[-1][0]}}
        return out


# ── Cosmos DB ───────────────────────────────────────────────────────────────


class CosmosError(Exception):
    def __init__(self, status_code: int):
        super().__init__(str(status_code))
        self.status_code = status_code


class FakeCosmosContainer:
    def __init__(self, pk: str = "/ns", default_ttl: Any = -1):
        self.items: dict[tuple[str, str], dict] = {}
        self._etag = itertools.count(1)
        self.pk = pk
        self.default_ttl = default_ttl

    def read(self):
        return {"partitionKey": {"paths": [self.pk]}, "defaultTtl": self.default_ttl}

    def _stamp(self, body):
        b = copy.deepcopy(body)
        b["_etag"] = f'"{next(self._etag)}"'
        self.items[(b["ns"], b["id"])] = b
        return copy.deepcopy(b)

    def read_item(self, item, partition_key):
        it = self.items.get((partition_key, item))
        if it is None:
            raise CosmosError(404)
        return copy.deepcopy(it)

    def create_item(self, body):
        if (body["ns"], body["id"]) in self.items:
            raise CosmosError(409)
        return self._stamp(body)

    def replace_item(self, item, body, etag=None, match_condition=None):
        cur = self.items.get((body["ns"], item))
        if cur is None:
            raise CosmosError(404)
        if match_condition is not None and cur["_etag"] != etag:
            raise CosmosError(412)
        return self._stamp(body)

    def upsert_item(self, body):
        return self._stamp(body)

    def query_items(self, query, parameters, partition_key):
        assert "@ns" in query and parameters[0]["value"] == partition_key
        return [copy.deepcopy(v) for (n, _), v in sorted(self.items.items()) if n == partition_key]

    def delete_item(self, item, partition_key, etag=None, match_condition=None):
        cur = self.items.get((partition_key, item))
        if cur is None:
            raise CosmosError(404)
        if match_condition is not None and cur["_etag"] != etag:
            raise CosmosError(412)
        del self.items[(partition_key, item)]


# ── Firestore ───────────────────────────────────────────────────────────────


class AlreadyExists(Exception):
    pass


class FailedPrecondition(Exception):
    pass


class NotFound(Exception):
    pass


class _Snap:
    def __init__(self, id_, data, update_time):
        self.id = id_
        self._data = data
        self.update_time = update_time
        self.exists = data is not None

    def to_dict(self):
        return copy.deepcopy(self._data)


class _WriteResult:
    def __init__(self, update_time):
        self.update_time = update_time


class _Option:
    def __init__(self, last_update_time):
        self.last_update_time = last_update_time


class _Ref:
    def __init__(self, db, coll, id_):
        self.db, self.coll, self.id = db, coll, id_

    @property
    def _key(self):
        return (self.coll, self.id)

    def get(self):
        d = self.db.docs.get(self._key)
        return _Snap(self.id, d[0] if d else None, d[1] if d else None)

    def _write(self, data):
        t = self.db.tick()
        self.db.docs[self._key] = (copy.deepcopy(data), t)
        return _WriteResult(t)

    def create(self, data):
        if self._key in self.db.docs:
            raise AlreadyExists("exists")
        return self._write(data)

    def set(self, data):
        return self._write(data)

    def _check(self, option):
        cur = self.db.docs.get(self._key)
        if cur is None:
            raise NotFound("missing")
        if option is not None and option.last_update_time != cur[1]:
            raise FailedPrecondition("changed")

    def update(self, data, option=None):
        self._check(option)
        merged = {**self.db.docs[self._key][0], **data}
        return self._write(merged)

    def delete(self, option=None):
        if option is not None:
            self._check(option)
        self.db.docs.pop(self._key, None)


class _Coll:
    def __init__(self, db, name):
        self.db, self.name = db, name

    def document(self, id_):
        return _Ref(self.db, self.name, id_)

    def stream(self):
        for (c, i), (d, t) in sorted(self.db.docs.items()):
            if c == self.name:
                yield _Snap(i, d, t)


class FakeFirestore:
    def __init__(self):
        self.docs: dict[tuple[str, str], tuple[dict, datetime]] = {}
        self._t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def tick(self):
        self._t += timedelta(microseconds=1)
        return self._t

    def collection(self, name):
        return _Coll(self, name)

    def write_option(self, last_update_time):
        return _Option(last_update_time)

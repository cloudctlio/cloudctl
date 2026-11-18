"""Resolve a value (ARN, queue URL, plain name, CloudFormation intrinsic) to the
resource keys it names.

Names collide in real apps (a queue and a table both called ``orders``), so a
full ARN or URL must match exactly, an ARN's tail only matches resources of
the same service, and a bare name that fits several types is narrowed by the
words of the key that holds it (``TABLE_NAME`` -> the table, ``QUEUE_URL`` ->
the queue).
"""

from __future__ import annotations

import re
from typing import Any

from cloudctl.debug.diff_first.model import Resource
from cloudctl.debug.diff_first.normalize import _ARN_RE, _URL_RE, _maybe_json, norm_key

_WORD_RE = re.compile(r"[A-Z][a-z0-9]*|[a-z0-9]+")


def type_words(cfn_type: str) -> set[str]:
    parts = cfn_type.split("::")
    words = {w.lower() for w in _WORD_RE.findall(parts[-1])} if parts else set()
    if len(parts) >= 2:
        words.add(parts[1].lower())
    return {w for w in words if len(w) >= 3}


def _known_words() -> set[str]:
    from cloudctl.debug.diff_first.normalize import TF_TO_CFN
    words: set[str] = set()
    for t in TF_TO_CFN.values():
        words |= type_words(t)
    return words - {"event", "events", "source", "target", "policy", "attachment", "url"}


def type_service(cfn_type: str) -> str:
    parts = cfn_type.split("::")
    return norm_key(parts[1]) if len(parts) >= 2 else ""


_SERVICE_ALIASES = {"apigateway": "apigatewayv2", "execute-api": "apigatewayv2"}


def arn_service(arn: str) -> str:
    try:
        svc = norm_key(arn.split(":")[2])
    except IndexError:
        return ""
    return _SERVICE_ALIASES.get(svc, svc)


_KNOWN_WORDS = _known_words()


class Resolver:
    def __init__(self, resources: dict[str, Resource]):
        self.resources = resources
        self.by_arn: dict[str, set[str]] = {}
        self.by_url: dict[str, set[str]] = {}
        self.by_name: dict[str, set[str]] = {}
        for k, r in resources.items():
            if r.arn:
                self.by_arn.setdefault(r.arn.lower(), set()).add(k)
            for v in (r.physical_id, r.name):
                if not v:
                    continue
                low = v.lower()
                if low.startswith("https://"):
                    self.by_url.setdefault(low, set()).add(k)
                    self.by_name.setdefault(low.rsplit("/", 1)[-1], set()).add(k)
                elif low.startswith("arn:"):
                    self.by_arn.setdefault(low, set()).add(k)
                elif len(low) >= 3:
                    self.by_name.setdefault(low, set()).add(k)

    def _narrow(self, keys: set[str], hint: str) -> set[str]:
        if not keys or not hint:
            return keys
        h = norm_key(hint)
        picked = {k for k in keys if any(w in h for w in type_words(self.resources[k].type))}
        if picked:
            return picked
        # The key names another kind of resource (TABLE_NAME holding a name
        # that only a queue has): not a reference to this one.
        if any(w in h for w in _KNOWN_WORDS):
            return set()
        return keys

    def _by_service(self, keys: set[str], svc: str) -> set[str]:
        if not svc:
            return keys
        return {k for k in keys if type_service(self.resources[k].type) == svc}

    def resolve_str(self, s: str, hint: str = "") -> set[str]:
        low = s.strip().lower()
        if len(low) < 3:
            return set()
        out: set[str] = set()
        arns = _ARN_RE.findall(low)
        urls = _URL_RE.findall(s)
        for a in arns:
            a = a.rstrip("*").rstrip(":").rstrip("/")
            hit = self.by_arn.get(a)
            if hit:
                out |= hit
                continue
            svc = arn_service(a)
            resource_part = a.split(":", 5)[-1] if a.count(":") >= 5 else ""
            segs = [x for x in re.split(r"[:/]", resource_part) if len(x) >= 3]
            for seg in reversed(segs):
                hit = self._by_service(self.by_name.get(seg, set()), svc)
                if hit:
                    out |= hit
                    break
        for u in urls:
            hit = self.by_url.get(u.lower()) or self._by_service(
                self.by_name.get(u.lower().rsplit("/", 1)[-1], set()), "sqs")
            out |= hit
        if not arns and not urls:
            out |= self._narrow(self.by_name.get(low, set()), hint)
        return out

    def resolve(self, value: Any, owner: Resource | None = None, hint: str = "",
                depth: int = 0) -> set[str]:
        out: set[str] = set()
        if depth > 8:
            return out
        value = _maybe_json(value)
        if isinstance(value, dict):
            if len(value) == 1 and (next(iter(value)) == "Ref" or str(next(iter(value))).startswith("Fn::")):
                return out          # CloudFormation intrinsic: resolved by logical id elsewhere
            for k, v in value.items():
                out |= self.resolve(v, owner, str(k), depth + 1)
        elif isinstance(value, (list, tuple)):
            for v in value:
                out |= self.resolve(v, owner, hint, depth + 1)
        elif isinstance(value, str):
            # a resource's own name/ARN/URL inside its config is not a reference
            if owner is None or value.strip().lower() not in owner.tokens():
                out |= self.resolve_str(value, hint)
        if owner is not None:
            out.discard(owner.key)
        return out

"""Canonical JSON and digests.

Everything the gate hashes or signs (plans, approval requests, audit records)
goes through :func:`canonical_json`, so the same logical value always yields
the same bytes on every platform: sorted keys, no insignificant whitespace,
ASCII-only output, and no NaN/Infinity.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Serialise *value* to canonical JSON bytes.

    Raises ``ValueError`` for values JSON cannot represent exactly (NaN,
    Infinity) and ``TypeError`` for non-JSON types, so a digest is never
    computed over a lossy encoding.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    """SHA-256 hex digest of the canonical JSON form of *value*."""
    return sha256_hex(canonical_json(value))

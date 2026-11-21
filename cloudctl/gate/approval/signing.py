"""Ed25519-signed approvals.

An approval is a signature by a named approver over the canonical JSON of an
approval request. The request binds the approval to one environment, one
exact plan (its digest), one requester and an expiry, so an approval cannot
be replayed against a different or regenerated plan.

Keys: each approver holds an Ed25519 private key (PEM, optionally encrypted
with a passphrase). The control-plane config lists only their public keys
(raw 32 bytes, base64). ``cloudctl gate keygen`` creates a pair.
"""
from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from cloudctl.gate.canonical import canonical_json
from cloudctl.gate.models import ApprovalError, utcnow

REQUEST_VERSION = 1


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PrivateKey, Ed25519PublicKey,
        )
    except ImportError as e:
        raise ApprovalError("signed approvals need the `cryptography` package (pip install 'cctl[gate]')") from e
    return InvalidSignature, serialization, Ed25519PrivateKey, Ed25519PublicKey


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> datetime:
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise ApprovalError(f"bad timestamp {s!r}") from None


@dataclass(frozen=True)
class ApprovalRequest:
    """What an approver signs. Every field is bound by the signature."""

    request_id: str
    environment: str
    tier: str
    plan_digest: str
    summary: str
    requester: str
    created_at: str
    expires_at: str
    nonce: str
    counts: Mapping[str, int]
    max_severity: str          # highest finding severity, or "NONE"
    reasons: tuple[str, ...] = ()
    version: int = REQUEST_VERSION

    @classmethod
    def new(cls, *, request_id: str, environment: str, tier: str, plan_digest: str, summary: str,
            requester: str, counts: Mapping[str, int], max_severity: str, ttl_seconds: int,
            reasons: tuple[str, ...] = ()) -> "ApprovalRequest":
        now = utcnow()
        return cls(request_id=request_id, environment=environment, tier=tier, plan_digest=plan_digest,
                   summary=summary[:500], requester=requester, created_at=_iso(now),
                   expires_at=_iso(now + timedelta(seconds=ttl_seconds)), nonce=secrets.token_hex(16),
                   counts=dict(counts), max_severity=max_severity, reasons=tuple(reasons))

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "request_id": self.request_id, "environment": self.environment,
                "tier": self.tier, "plan_digest": self.plan_digest, "summary": self.summary,
                "requester": self.requester, "created_at": self.created_at, "expires_at": self.expires_at,
                "nonce": self.nonce, "counts": dict(self.counts), "max_severity": self.max_severity,
                "reasons": list(self.reasons)}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ApprovalRequest":
        try:
            if int(d["version"]) != REQUEST_VERSION:
                raise ApprovalError(f"unsupported approval request version {d['version']!r}")
            return cls(request_id=str(d["request_id"]), environment=str(d["environment"]),
                       tier=str(d["tier"]), plan_digest=str(d["plan_digest"]), summary=str(d["summary"]),
                       requester=str(d["requester"]), created_at=str(d["created_at"]),
                       expires_at=str(d["expires_at"]), nonce=str(d["nonce"]),
                       counts={str(k): int(v) for k, v in dict(d["counts"]).items()},
                       max_severity=str(d["max_severity"]), reasons=tuple(str(r) for r in d.get("reasons", [])))
        except (KeyError, TypeError, ValueError) as e:
            raise ApprovalError(f"malformed approval request: {e}") from None

    def signing_bytes(self) -> bytes:
        return b"cctl-approval-v1\n" + canonical_json(self.to_dict())

    def expired(self, now: Optional[datetime] = None) -> bool:
        return (now or utcnow()) >= parse_iso(self.expires_at)


@dataclass(frozen=True)
class SignedApproval:
    request: ApprovalRequest
    approver: str
    signature: str            # base64 Ed25519 signature over request.signing_bytes()
    signed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {"request": self.request.to_dict(), "approver": self.approver,
                "signature": self.signature, "signed_at": self.signed_at}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "SignedApproval":
        try:
            return cls(request=ApprovalRequest.from_dict(d["request"]), approver=str(d["approver"]),
                       signature=str(d["signature"]), signed_at=str(d["signed_at"]))
        except (KeyError, TypeError) as e:
            raise ApprovalError(f"malformed approval: {e}") from None


# ── keys ─────────────────────────────────────────────────────────────────────

def generate_keypair(passphrase: Optional[bytes] = None) -> tuple[bytes, str]:
    """Return (private key PEM, public key base64)."""
    _, ser, Priv, _ = _crypto()
    key = Priv.generate()
    enc = ser.BestAvailableEncryption(passphrase) if passphrase else ser.NoEncryption()
    pem = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, enc)
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return pem, base64.b64encode(pub).decode("ascii")


def write_private_key(path: Path, pem: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)


def load_private_key(path: Path, passphrase: Optional[bytes] = None) -> Any:
    _, ser, Priv, _ = _crypto()
    try:
        mode = path.stat().st_mode & 0o077
    except OSError as e:
        raise ApprovalError(f"cannot read approver key {path}: {e}") from e
    if mode and os.name != "nt":
        raise ApprovalError(f"approver key {path} is readable by other users; chmod 600 it")
    try:
        key = ser.load_pem_private_key(path.read_bytes(), password=passphrase)
    except (TypeError, ValueError) as e:
        raise ApprovalError(f"cannot load approver key {path}: {e}") from e
    if not isinstance(key, Priv):
        raise ApprovalError(f"{path} is not an Ed25519 private key")
    return key


def public_key_b64(private_key: Any) -> str:
    _, ser, _, _ = _crypto()
    raw = private_key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def sign(request: ApprovalRequest, approver: str, private_key: Any) -> SignedApproval:
    sig = private_key.sign(request.signing_bytes())
    return SignedApproval(request=request, approver=approver,
                          signature=base64.b64encode(sig).decode("ascii"), signed_at=_iso(utcnow()))


def verify_signature(approval: SignedApproval, public_key_b64_value: str) -> None:
    InvalidSignature, _, _, Pub = _crypto()
    try:
        raw = base64.b64decode(public_key_b64_value, validate=True)
        pub = Pub.from_public_bytes(raw)
        sig = base64.b64decode(approval.signature, validate=True)
    except (ValueError, TypeError) as e:
        raise ApprovalError(f"bad key or signature encoding for approver {approval.approver!r}: {e}") from None
    try:
        pub.verify(sig, approval.request.signing_bytes())
    except InvalidSignature:
        raise ApprovalError(f"signature by {approval.approver!r} does not verify") from None

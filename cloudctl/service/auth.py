"""Who is calling: OIDC bearer tokens, verified against the issuer's JWKS.

The requester recorded on every run, approval and audit event comes from the
verified token, never from a request body. Roles come from a token claim
(``groups`` by default) mapped to cctl roles in the service settings:

- ``reader``: read runs, drift events, pending approvals
- ``operator``: compile and run change graphs, scan and repair drift
- ``approver``: submit signed approvals (signed offline with the approver's own key)
- ``auditor``: verify the audit chain
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

ROLES = ("reader", "operator", "approver", "auditor")
ALLOWED_ALGS = ("RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA")


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    subject: str          # the requester name used everywhere (email or sub)
    roles: frozenset[str]
    approver: Optional[str] = None   # the gate's approver name for this person, if the token carries one
    claims: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def has(self, role: str) -> bool:
        return role in self.roles


@dataclass(frozen=True)
class AuthSettings:
    issuer: str
    audience: str
    jwks_url: str = ""
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    subject_claim: str = "email"
    roles_claim: str = "groups"
    approver_claim: str = "preferred_username"   # must equal a name under the gate config's `approvers`
    role_map: Mapping[str, Sequence[str]] = field(default_factory=dict)   # cctl role -> group names
    leeway_seconds: int = 60

    def __post_init__(self) -> None:
        if not self.issuer.startswith("https://"):
            raise ValueError("auth.issuer must be an https:// URL")
        if not self.audience:
            raise ValueError("auth.audience is required")
        bad = set(self.algorithms) - set(ALLOWED_ALGS)
        if bad or not self.algorithms:
            raise ValueError(f"auth.algorithms: not allowed {sorted(bad)}; use asymmetric algorithms only")
        unknown = set(self.role_map) - set(ROLES)
        if unknown:
            raise ValueError(f"auth.role_map: unknown roles {sorted(unknown)}")


class OIDCVerifier:
    def __init__(self, settings: AuthSettings, *, key_resolver: Any = None) -> None:
        import jwt  # noqa: PLC0415
        self.s = settings
        self._jwt = jwt
        if key_resolver is None:
            url = settings.jwks_url or settings.issuer.rstrip("/") + "/.well-known/jwks.json"
            if not url.startswith("https://"):
                raise ValueError("the JWKS URL must be https://")
            client = jwt.PyJWKClient(url, cache_keys=True, lifespan=600, timeout=10)
            key_resolver = lambda token: client.get_signing_key_from_jwt(token).key  # noqa: E731
        self._key = key_resolver

    def verify(self, authorization: Optional[str]) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise AuthError("missing bearer token")
        token = authorization[len("Bearer "):].strip()
        if len(token) > 16_384:
            raise AuthError("token too large")
        try:
            claims = self._jwt.decode(
                token, self._key(token), algorithms=list(self.s.algorithms), audience=self.s.audience,
                issuer=self.s.issuer, leeway=self.s.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]})
        except Exception as e:  # noqa: BLE001 — every failure is the same 401
            raise AuthError(f"invalid token: {type(e).__name__}") from None
        subject = str(claims.get(self.s.subject_claim) or claims["sub"])
        groups = claims.get(self.s.roles_claim) or []
        if isinstance(groups, str):
            groups = [groups]
        roles = {role for role, names in self.s.role_map.items() if set(names) & set(map(str, groups))}
        if roles & {"operator", "approver", "auditor"}:
            roles.add("reader")
        appr = claims.get(self.s.approver_claim)
        return Principal(subject=subject, roles=frozenset(roles), approver=str(appr) if appr else None,
                         claims=claims)

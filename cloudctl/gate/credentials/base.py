"""Scoped, short-lived credentials: one interface for AWS, Azure and GCP.

A :class:`ScopedCredentials` object holds secret material only in process
memory. It cannot be pickled, its ``repr`` never shows secrets, and the gate
refuses to use it more than ``MAX_LIFETIME_SECONDS`` after acquisition, even
when the cloud's own token would live longer (Azure AD tokens last 60-90
minutes; the gate still caps use at 900 s).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping, Optional, Protocol

from cloudctl.gate.models import CredentialError, utcnow

#: Article contract: 900-second sessions per operation.
MAX_LIFETIME_SECONDS = 900

#: Ambient variables stripped from every plan/apply subprocess so a child can
#: only ever use the scoped credentials the gate handed it.
AMBIENT_CREDENTIAL_VARS = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
    "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "ARM_CLIENT_ID", "ARM_CLIENT_SECRET", "ARM_CLIENT_CERTIFICATE_PATH",
    "ARM_CLIENT_CERTIFICATE_PASSWORD", "ARM_OIDC_TOKEN", "ARM_OIDC_TOKEN_FILE_PATH",
    "ARM_USE_MSI", "ARM_USE_OIDC", "ARM_USE_CLI", "ARM_SUBSCRIPTION_ID", "ARM_TENANT_ID",
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID", "AZURE_FEDERATED_TOKEN_FILE",
    "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_USERNAME", "AZURE_PASSWORD",
    "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN",
    "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT", "CLOUDSDK_AUTH_ACCESS_TOKEN",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "CLOUDSDK_CORE_PROJECT", "GOOGLE_PROJECT",
    "KUBECONFIG",
)


@dataclass
class ScopedCredentials:
    """Short-lived credentials for one environment and one operation."""

    cloud: str
    identity: str                         # role ARN / client id / service-account email
    scope: Mapping[str, str]              # account_id+region / subscription+resource_group / project
    expires_at: datetime                  # min(cloud expiry, acquired + 900 s)
    acquired_at: datetime
    _secret: dict[str, Any] = field(repr=False)
    _builders: Mapping[str, Callable[..., Any]] = field(repr=False, default_factory=dict)
    _destroyed: bool = field(default=False, repr=False)

    def __repr__(self) -> str:  # never show secret material
        return (f"ScopedCredentials(cloud={self.cloud!r}, identity={self.identity!r}, "
                f"scope={dict(self.scope)!r}, expires_at={self.expires_at.isoformat()!r})")

    __str__ = __repr__

    def __reduce__(self):  # refuse pickling: credentials never leave memory
        raise TypeError("ScopedCredentials cannot be serialised")

    def __deepcopy__(self, memo):
        raise TypeError("ScopedCredentials cannot be copied")

    @property
    def remaining_seconds(self) -> float:
        return (self.expires_at - utcnow()).total_seconds()

    def ensure_valid(self, min_remaining: float = 30.0) -> None:
        if self._destroyed:
            raise CredentialError("credentials were already used and destroyed")
        if self.remaining_seconds < min_remaining:
            raise CredentialError(
                f"scoped credentials for {self.identity} expire in "
                f"{max(0, int(self.remaining_seconds))}s; re-run the gate")

    def secret(self, key: str) -> Any:
        self.ensure_valid(min_remaining=1.0)
        return self._secret[key]

    def client(self, kind: str, *args: Any, **kwargs: Any) -> Any:
        """Build an SDK object bound to these credentials.

        AWS: ``client("session")`` → boto3.Session.
        Azure: ``client("credential")`` → azure TokenCredential.
        GCP: ``client("credentials")`` → google.auth Credentials.
        """
        self.ensure_valid(min_remaining=5.0)
        try:
            builder = self._builders[kind]
        except KeyError:
            raise CredentialError(f"{self.cloud} credentials cannot build {kind!r}") from None
        return builder(*args, **kwargs)

    def subprocess_env(self, base: Optional[Mapping[str, str]] = None) -> dict[str, str]:
        """Environment for a plan/apply subprocess: the parent's environment
        minus every ambient credential variable, plus these credentials."""
        self.ensure_valid(min_remaining=5.0)
        env = {k: v for k, v in (base if base is not None else os.environ).items()
               if k not in AMBIENT_CREDENTIAL_VARS}
        env.update(self._builders["env"]() if "env" in self._builders else {})
        return env

    def destroy(self) -> None:
        """Drop every reference to secret material."""
        for k in list(self._secret):
            self._secret[k] = None
        self._secret.clear()
        self._builders = {}
        self._destroyed = True


def capped_expiry(acquired: datetime, cloud_expiry: Optional[datetime]) -> datetime:
    cap = acquired + timedelta(seconds=MAX_LIFETIME_SECONDS)
    if cloud_expiry is None:
        return cap
    return min(cap, cloud_expiry)


class CredentialBroker(Protocol):
    cloud: str

    def acquire(self, env: Any, *, request_id: str, requester: str) -> ScopedCredentials: ...


def require(value: Optional[str], what: str) -> str:
    if not value:
        raise CredentialError(f"missing {what} in the environment's credentials config")
    return value

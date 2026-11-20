"""Credential stage: one broker per cloud behind one interface."""
from __future__ import annotations

from typing import Any, Mapping, Optional

from cloudctl.gate.credentials.base import (  # noqa: F401
    AMBIENT_CREDENTIAL_VARS,
    MAX_LIFETIME_SECONDS,
    CredentialBroker,
    ScopedCredentials,
)
from cloudctl.gate.models import CredentialError


def default_brokers() -> dict[str, Any]:
    """Lazily-constructed brokers; SDK imports happen only for the cloud used."""
    return {"aws": _Lazy("aws"), "azure": _Lazy("azure"), "gcp": _Lazy("gcp")}


class _Lazy:
    def __init__(self, cloud: str) -> None:
        self.cloud = cloud
        self._impl: Optional[Any] = None

    def acquire(self, env: Any, *, request_id: str, requester: str) -> ScopedCredentials:
        if self._impl is None:
            if self.cloud == "aws":
                from cloudctl.gate.credentials.aws import AwsAssumeRoleBroker  # noqa: PLC0415
                self._impl = AwsAssumeRoleBroker()
            elif self.cloud == "azure":
                from cloudctl.gate.credentials.azure import AzureBroker  # noqa: PLC0415
                self._impl = AzureBroker()
            elif self.cloud == "gcp":
                from cloudctl.gate.credentials.gcp import GcpImpersonationBroker  # noqa: PLC0415
                self._impl = GcpImpersonationBroker()
            else:  # pragma: no cover
                raise CredentialError(f"no credential broker for {self.cloud}")
        return self._impl.acquire(env, request_id=request_id, requester=requester)


def broker_for(brokers: Mapping[str, Any], cloud: str) -> Any:
    try:
        return brokers[cloud]
    except KeyError:
        raise CredentialError(f"no credential broker configured for cloud {cloud!r}") from None

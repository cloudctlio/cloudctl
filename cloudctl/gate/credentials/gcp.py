"""GCP: service-account impersonation, 900-second access token, per operation."""
from __future__ import annotations

from datetime import timezone
from typing import Any, Callable, Optional

from cloudctl.gate.credentials.base import MAX_LIFETIME_SECONDS, ScopedCredentials, capped_expiry
from cloudctl.gate.models import CredentialError, utcnow

CLOUD_PLATFORM = "https://www.googleapis.com/auth/cloud-platform"


class GcpImpersonationBroker:
    cloud = "gcp"

    def __init__(self, default_fn: Optional[Callable[..., Any]] = None,
                 impersonated_cls: Any = None, request_cls: Any = None) -> None:
        self._default = default_fn
        self._imp = impersonated_cls
        self._req = request_cls

    def _libs(self) -> tuple[Any, Any, Any]:
        if self._default and self._imp and self._req:
            return self._default, self._imp, self._req
        try:
            import google.auth  # noqa: PLC0415
            from google.auth import impersonated_credentials  # noqa: PLC0415
            from google.auth.transport.requests import Request  # noqa: PLC0415
        except ImportError as e:
            raise CredentialError("GCP credentials need google-auth (pip install 'cctl[gcp]')") from e
        return (self._default or google.auth.default,
                self._imp or impersonated_credentials.Credentials,
                self._req or Request)

    def acquire(self, env: Any, *, request_id: str, requester: str) -> ScopedCredentials:
        default, Impersonated, Request = self._libs()
        project = env.scope["project_id"]
        mode = env.credentials.mode
        try:
            source, _ = default(scopes=[CLOUD_PLATFORM])
        except Exception as e:  # noqa: BLE001
            raise CredentialError(f"no Google application-default credentials: {e}") from e
        acquired = utcnow()
        if mode == "impersonation":
            sa = env.credentials.params["service_account"]
            creds = Impersonated(source_credentials=source, target_principal=sa,
                                 target_scopes=[CLOUD_PLATFORM],
                                 delegates=list(env.credentials.params.get("delegates") or []),
                                 lifetime=MAX_LIFETIME_SECONDS)
            identity = sa
        elif mode == "adc":
            creds = source
            identity = getattr(source, "service_account_email", None) or "application-default"
        else:
            raise CredentialError(f"unsupported GCP credentials mode {mode!r}")
        try:
            creds.refresh(Request())
        except Exception as e:  # noqa: BLE001
            raise CredentialError(f"GCP token for {identity} failed: {e}") from e
        expiry = getattr(creds, "expiry", None)
        if expiry is not None and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        secret = {"credentials": creds}

        def credentials() -> Any:
            return secret["credentials"]

        def env_vars() -> dict[str, str]:
            token = secret["credentials"].token
            return {"GOOGLE_OAUTH_ACCESS_TOKEN": token, "CLOUDSDK_AUTH_ACCESS_TOKEN": token,
                    "GOOGLE_PROJECT": project, "CLOUDSDK_CORE_PROJECT": project}

        return ScopedCredentials(
            cloud="gcp", identity=identity,
            scope={"project_id": project, "region": env.scope.get("region", "")},
            expires_at=capped_expiry(acquired, expiry), acquired_at=acquired,
            _secret=secret, _builders={"credentials": credentials, "env": env_vars},
        )
